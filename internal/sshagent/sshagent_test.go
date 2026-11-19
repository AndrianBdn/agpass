package sshagent

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestGenerateAndNormalize(t *testing.T) {
	priv, auth, err := Generate("agpass@test")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(auth, "ssh-ed25519 ") || !strings.HasSuffix(auth, " agpass@test") {
		t.Fatalf("authorized line %q", auth)
	}
	s, err := Signer(priv)
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(auth))
	if !SameKey(pub, s.PublicKey()) {
		t.Fatal("public key does not match private key")
	}

	// A passphrase-protected key imports with the passphrase only.
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	block, err := ssh.MarshalPrivateKeyWithPassphrase(k, "x", []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	enc := pem.EncodeToMemory(block)
	if _, _, err := Normalize(enc, nil, ""); !IsPassphraseError(err) {
		t.Fatalf("want passphrase error, got %v", err)
	}
	plain, _, err := Normalize(enc, []byte("pw"), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Signer(plain); err != nil {
		t.Fatalf("normalized key is not usable without passphrase: %v", err)
	}
}

func TestNormalizeHost(t *testing.T) {
	for in, want := range map[string]string{
		"github.com":           "github.com",
		"git@GitHub.com":       "github.com",
		"ssh://git@h:22":       "h",
		"server:2222":          "server:2222",
		"ssh://deploy@x:2200/": "x:2200",
		"10.0.0.5":             "10.0.0.5",
		"[::1]":                "::1",
		"[::1]:2222":           "[::1]:2222",
		"my_host.internal":     "my_host.internal",
	} {
		if got, err := NormalizeHost(in); err != nil || got != want {
			t.Errorf("NormalizeHost(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	// Nothing that means something in a known_hosts line.
	for _, bad := range []string{"", "a b", "h:0", "h:99999", "a\tb", "a\nb", "a,b", "*.example.com", "!h", "|1|x", "-oProxyCommand=x", "h/x"} {
		if _, err := NormalizeHost(bad); err == nil {
			t.Errorf("NormalizeHost(%q) should fail", bad)
		}
	}
}

func TestSessionBind(t *testing.T) {
	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	host, _ := ssh.NewSignerFromKey(hostPriv)
	sid := []byte("session-id-123")
	sig, _ := host.Sign(rand.Reader, sid)
	msg := ssh.Marshal(struct {
		HostKey    []byte
		SessionID  []byte
		Signature  []byte
		Forwarding bool
	}{host.PublicKey().Marshal(), sid, ssh.Marshal(sig), false})
	b, err := ParseSessionBind(msg)
	if err != nil || string(b.SessionID) != string(sid) || !SameKey(b.HostKey, host.PublicKey()) {
		t.Fatalf("valid bind: %+v %v", b, err)
	}

	// Claiming a session ID the host key didn't sign fails.
	forged := ssh.Marshal(struct {
		HostKey    []byte
		SessionID  []byte
		Signature  []byte
		Forwarding bool
	}{host.PublicKey().Marshal(), []byte("other-session"), ssh.Marshal(sig), false})
	if _, err := ParseSessionBind(forged); err == nil {
		t.Fatal("forged session-bind accepted")
	}
}

func TestParseUserAuth(t *testing.T) {
	key := testKey(t)
	host := testKey(t)
	req := func(method string, extra ...[]byte) []byte {
		b := ssh.Marshal(struct {
			SessionID []byte
			Type      byte
			User      string
			Service   string
			Method    string
			HasSig    bool
			Algo      string
			Key       []byte
		}{[]byte("sid"), 50, "git", "ssh-connection", method, true, key.Type(), key.Marshal()})
		for _, e := range extra {
			b = append(b, ssh.Marshal(struct{ B []byte }{e})...)
		}
		return b
	}

	ua, err := ParseUserAuth(req("publickey"))
	if err != nil || string(ua.SessionID) != "sid" || ua.User != "git" || !SameKey(ua.PublicKey, key) || ua.HostKey != nil {
		t.Fatalf("publickey: %+v %v", ua, err)
	}
	// OpenSSH 8.9+ against servers that support it (GitHub): the method
	// is publickey-hostbound-v00@openssh.com and the host key follows.
	ua, err = ParseUserAuth(req("publickey-hostbound-v00@openssh.com", host.Marshal()))
	if err != nil || !SameKey(ua.HostKey, host) || !SameKey(ua.PublicKey, key) {
		t.Fatalf("hostbound: %+v %v", ua, err)
	}

	for name, data := range map[string][]byte{
		"arbitrary data":          []byte("arbitrary data to sign"),
		"password method":         req("password"),
		"hostbound without host":  req("publickey-hostbound-v00@openssh.com"),
		"publickey with trailing": req("publickey", host.Marshal()),
		"hostbound bad host key":  req("publickey-hostbound-v00@openssh.com", []byte("junk")),
	} {
		if _, err := ParseUserAuth(data); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func testKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	_, auth, err := Generate("")
	if err != nil {
		t.Fatal(err)
	}
	k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(auth))
	if err != nil {
		t.Fatal(err)
	}
	return k
}
