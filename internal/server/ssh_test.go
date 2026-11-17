package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"agpass/internal/api"
	"agpass/internal/events"
	"agpass/internal/peer"
	"agpass/internal/sshagent"
	"agpass/internal/vault"
)

// testSSHServer accepts publickey auth with want and answers any exec with
// "authenticated". It returns its normalized host name.
func testSSHServer(t *testing.T, want ssh.PublicKey) string {
	t.Helper()
	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostKey, _ := ssh.NewSignerFromKey(hostPriv)
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			if sshagent.SameKey(k, want) {
				return nil, nil
			}
			return nil, fmt.Errorf("unknown key")
		},
	}
	cfg.AddHostKey(hostKey)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					ch, creqs, err := nc.Accept()
					if err != nil {
						return
					}
					for r := range creqs {
						r.Reply(r.Type == "exec", nil)
						if r.Type == "exec" {
							ch.Write([]byte("authenticated\n"))
							ch.SendRequest("exit-status", false, ssh.Marshal(struct{ C uint32 }{0}))
							ch.Close()
						}
					}
				}
			}()
		}
	}()
	host, _ := sshagent.NormalizeHost(ln.Addr().String())
	return host
}

func runSSH(sock, host string) (string, error) {
	h, port, _ := net.SplitHostPort(sshagent.HostPort(host))
	out, err := exec.Command("/usr/bin/ssh", "-F", "/dev/null",
		"-o", "IdentityAgent="+sock, "-o", "IdentityFile=none", "-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR",
		"-p", port, "test@"+h, "echo").CombinedOutput()
	return string(out), err
}

// The real OpenSSH client authenticates through the agpass agent only to the
// host the session is allowed, even when another server accepts the key.
func TestSSHAgentWithOpenSSH(t *testing.T) {
	if _, err := os.Stat("/usr/bin/ssh"); err != nil {
		t.Skip("no /usr/bin/ssh")
	}
	if _, _, err := peer.NewResolver().FindAgent(os.Getpid()); err != nil {
		t.Skip("not running under a known agent; the agent socket needs one")
	}
	dir, err := os.MkdirTemp("/tmp", "agp")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	const pw = "correct-horse-1"
	if _, err := vault.Create(KeyPath(dir), pw); err != nil {
		t.Fatal(err)
	}
	var logged []events.Event
	log := events.New(nil, false)
	_, ch, cancelSub, _ := log.Subscribe(func() ([]events.Event, error) { return nil, nil })
	defer cancelSub()
	s := New(dir, log)
	if err := s.Unlock(pw); err != nil {
		t.Fatal(err)
	}
	if err := s.Listen(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Serve(ctx)

	priv, auth, _ := sshagent.Generate("test")
	if _, err := s.st.SetItem(api.SystemFolder, SSHItem, []api.Field{
		{Key: "private_key", Type: api.TypeSensitive, Value: string(priv)},
		{Key: "public_key", Value: auth},
	}, nil, "human"); err != nil {
		t.Fatal(err)
	}
	signer, _ := sshagent.Signer(priv)
	allowed := testSSHServer(t, signer.PublicKey())
	other := testSSHServer(t, signer.PublicKey())
	sock := AgentSocketPath(dir)

	// 1. No permission yet: the agent offers no key.
	if out, err := runSSH(sock, allowed); err == nil {
		t.Fatalf("ssh succeeded without permission: %s", out)
	}

	// 2. Allowed for one host (pinned like `agpass ssh allow` does).
	c, err := s.agentCaller(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.pinHost(ctx, c, allowed); err != nil {
		t.Fatal(err)
	}
	if _, err := s.st.SSHGrant(c.session.ID, allowed, "test", ""); err != nil {
		t.Fatal(err)
	}
	if out, err := runSSH(sock, allowed); err != nil || !strings.Contains(out, "authenticated") {
		t.Fatalf("ssh to allowed host failed: %v %s", err, out)
	}

	kh, err := os.ReadFile(KnownHostsPath(dir))
	h, port, _ := net.SplitHostPort(allowed)
	if err != nil || !strings.Contains(string(kh), "["+h+"]:"+port+" ssh-ed25519 ") || strings.Count(string(kh), "\n") != 2 {
		t.Fatalf("known_hosts should hold only the allowed host:\n%s %v", kh, err)
	}

	// 3. Another server that accepts the same key is still refused by the
	// agent (here without client-side host checking, to test the agent).
	if out, err := runSSH(sock, other); err == nil {
		t.Fatalf("ssh to a host without permission succeeded: %s", out)
	}

	time.Sleep(200 * time.Millisecond)
	for drained := false; !drained; {
		select {
		case e := <-ch:
			logged = append(logged, e)
		default:
			drained = true
		}
	}
	var signed, denied int
	for _, e := range logged {
		if e.Action == "ssh-sign" && e.Level == events.LevelOK && e.Target == allowed {
			signed++
		}
		if e.Action == "ssh-sign" && e.Level == events.LevelDeny {
			denied++
			t.Logf("denied: %s %s", e.Target, e.Msg)
		}
	}
	if signed != 1 || denied < 1 {
		t.Fatalf("want 1 signature for %s and a denial, got signed=%d denied=%d: %+v", allowed, signed, denied, logged)
	}
}

// Concurrent grants all rewrite known_hosts; every write must succeed and the
// file must end up complete, with no stray temp files.
func TestKnownHostsConcurrentWrites(t *testing.T) {
	dir := t.TempDir()
	const pw = "correct-horse-1"
	if _, err := vault.Create(KeyPath(dir), pw); err != nil {
		t.Fatal(err)
	}
	s := New(dir, events.New(nil, false))
	if err := s.Unlock(pw); err != nil {
		t.Fatal(err)
	}
	defer s.st.Close()
	_, authorized, err := sshagent.Generate("")
	if err != nil {
		t.Fatal(err)
	}
	const n = 30
	for i := range n {
		if err := s.st.PinHostKeys(fmt.Sprintf("h%d.example", i), []string{authorized}); err != nil {
			t.Fatal(err)
		}
	}
	const writers = 200
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make(chan error, writers)
	for range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- s.writeKnownHosts()
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(KnownHostsPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		if !strings.Contains(string(b), fmt.Sprintf("\nh%d.example ", i)) {
			t.Errorf("known_hosts is missing h%d.example", i)
		}
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".known_hosts-*")); len(left) > 0 {
		t.Errorf("temp files left behind: %v", left)
	}
}
