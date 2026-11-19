package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"agpass/internal/api"
	"agpass/internal/events"
	"agpass/internal/llm"
	"agpass/internal/peer"
	"agpass/internal/sshagent"
	"agpass/internal/store"
)

// SSHItem is SYSTEM/ssh: the shared agent key (fields private_key, public_key).
// Only the human reads or replaces it; sessions use it through the agent.
const SSHItem = "ssh"

// AgentSocketPath is the SSH agent socket (SSH_AUTH_SOCK / IdentityAgent).
func AgentSocketPath(dir string) string { return filepath.Join(dir, "agent.sock") }

// KnownHostsPath holds the pinned host keys in known_hosts format, for
// `agpass ssh command` (UserKnownHostsFile with strict checking).
func KnownHostsPath(dir string) string { return filepath.Join(dir, "known_hosts") }

// writeKnownHosts rewrites the known_hosts file from the pinned keys. It
// holds a lock across reading the keys and replacing the file, so concurrent
// grants can't interleave or leave an older snapshot in place.
func (s *Server) writeKnownHosts() error {
	s.agent.khMu.Lock()
	defer s.agent.khMu.Unlock()
	pairs, err := s.st.AllHostKeys()
	if err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString("# Written by agpass from the host keys it pinned. Do not edit.\n")
	for _, p := range pairs {
		host := p[0]
		if h, port, err := net.SplitHostPort(host); err == nil {
			host = "[" + h + "]:" + port
		}
		b.WriteString(host + " " + p[1] + "\n")
	}
	f, err := os.CreateTemp(s.Dir, ".known_hosts-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name()) // no-op after a successful rename
	if _, err := f.WriteString(b.String()); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), KnownHostsPath(s.Dir))
}

type agentState struct {
	mu     sync.Mutex
	ln     net.Listener
	conns  map[net.Conn]struct{}
	closed bool           // stopAgent ran: no new connections
	wg     sync.WaitGroup // connections being served
	khMu   sync.Mutex     // serializes writeKnownHosts
}

func (s *Server) listenAgent() error {
	sock := AgentSocketPath(s.Dir)
	if len(sock) > 103 {
		return fmt.Errorf("socket path too long for macOS: %s", sock)
	}
	os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return err
	}
	if err := os.Chmod(sock, 0o600); err != nil {
		ln.Close()
		return err
	}
	s.agent.ln = ln
	s.agent.conns = map[net.Conn]struct{}{}
	return s.writeKnownHosts()
}

// serveAgent answers SSH agent connections until stopAgent.
func (s *Server) serveAgent() {
	for {
		conn, err := s.agent.ln.Accept()
		if err != nil {
			return
		}
		s.agent.mu.Lock()
		if s.agent.closed { // accepted while stopAgent was closing the others
			s.agent.mu.Unlock()
			conn.Close()
			continue
		}
		s.agent.conns[conn] = struct{}{}
		s.agent.wg.Add(1)
		s.agent.mu.Unlock()
		go func() {
			defer s.agent.wg.Done()
			defer func() {
				s.agent.mu.Lock()
				delete(s.agent.conns, conn)
				s.agent.mu.Unlock()
				conn.Close()
			}()
			pid, _ := peer.PeerPID(conn)
			agent.ServeAgent(&connAgent{s: s, pid: pid}, conn)
		}()
	}
}

// stopAgent closes the listener and every connection. Serve then waits for
// agent.wg, so no connection is still using the store when it closes.
func (s *Server) stopAgent() {
	s.agent.ln.Close()
	s.agent.mu.Lock()
	s.agent.closed = true
	for c := range s.agent.conns {
		c.Close()
	}
	s.agent.mu.Unlock()
	os.Remove(AgentSocketPath(s.Dir))
}

// sshKey returns the agent key, or store.ErrNotFound when there is none.
func (s *Server) sshKey() (ssh.Signer, error) {
	it, err := s.st.GetItem(api.SystemFolder, SSHItem)
	if err != nil {
		return nil, err
	}
	for _, f := range it.Fields {
		if f.Key == "private_key" {
			return sshagent.Signer([]byte(f.Value))
		}
	}
	return nil, store.ErrNotFound
}

func authorizedKey(k ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
}

// connAgent serves one SSH agent connection. The client is an ssh process;
// the session is the Claude process above it.
type connAgent struct {
	s   *Server
	pid int

	mu         sync.Mutex
	binds      []sshagent.Bind
	listDenied bool
}

var errReadOnly = errors.New("the agpass agent is read-only")

func (a *connAgent) caller() (*caller, error) {
	if a.pid == 0 {
		return nil, errors.New("cannot identify the ssh client process")
	}
	if !a.s.Unlocked() {
		return nil, errors.New("agpass is starting up")
	}
	return a.s.agentCaller(a.pid)
}

// List shows the key only to sessions allowed to use it somewhere, so other
// ssh clients move on to their own keys.
func (a *connAgent) List() ([]*agent.Key, error) {
	signer, err := a.s.sshKey()
	if err != nil {
		return nil, nil
	}
	c, err := a.caller()
	if err != nil {
		return nil, nil
	}
	grants, err := a.s.st.SSHGrants(c.session.ID)
	if err != nil {
		return nil, err
	}
	if !c.elevated && len(grants) == 0 {
		a.mu.Lock()
		first := !a.listDenied
		a.listDenied = true
		a.mu.Unlock()
		if first {
			a.s.Log.Emit(events.Event{Level: events.LevelDeny, Action: "ssh", Actor: c.String(),
				Msg: "no SSH permission yet: agpass ssh allow --host HOST --reason ..."})
		}
		return nil, nil
	}
	pub := signer.PublicKey()
	return []*agent.Key{{Format: pub.Type(), Blob: pub.Marshal(), Comment: "agpass"}}, nil
}

func (a *connAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.SignWithFlags(key, data, 0)
}

// SignWithFlags signs only a publickey authentication for the server the
// client proved it is connected to (session-bind), and only for hosts the
// session is allowed.
func (a *connAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	a.s.inflight.Add(1)
	defer a.s.inflight.Done()
	signer, err := a.s.sshKey()
	if err != nil || !sshagent.SameKey(key, signer.PublicKey()) {
		return nil, errors.New("unknown key")
	}
	c, err := a.caller()
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	binds := append([]sshagent.Bind(nil), a.binds...)
	a.mu.Unlock()

	target := "?"
	deny := func(msg string) (*ssh.Signature, error) {
		a.s.Log.Emit(events.Event{Level: events.LevelDeny, Action: "ssh-sign", Actor: c.String(), Target: target, Msg: msg})
		return nil, errors.New(msg)
	}
	if len(binds) == 0 {
		return deny("the ssh client did not say which server it connects to (needs OpenSSH 8.9 or newer)")
	}
	for _, b := range binds {
		if b.Forwarding {
			return deny("forwarded agent use is not allowed")
		}
	}
	bind := binds[len(binds)-1]
	ua, err := sshagent.ParseUserAuth(data)
	if err != nil {
		return deny(err.Error())
	}
	if !bytes.Equal(ua.SessionID, bind.SessionID) {
		return deny("the data to sign is not for the server the client connected to")
	}
	if ua.HostKey != nil && !sshagent.SameKey(ua.HostKey, bind.HostKey) {
		return deny("the host key in the data to sign is not the server the client connected to")
	}
	if !sshagent.SameKey(ua.PublicKey, key) {
		return deny("the data to sign is for a different key")
	}

	hosts, err := a.s.st.HostsForKey(authorizedKey(bind.HostKey))
	if err != nil {
		return nil, err
	}
	grants, err := a.s.st.SSHGrants(c.session.ID)
	if err != nil {
		return nil, err
	}
	allowed := ""
	for _, h := range hosts {
		for _, g := range grants {
			if g.Host == h {
				allowed = h
			}
		}
	}
	switch {
	case allowed != "":
		target = allowed
	case len(hosts) > 0:
		target = strings.Join(hosts, ",")
	default:
		target = "unknown host " + ssh.FingerprintSHA256(bind.HostKey)
	}
	if allowed == "" && !c.elevated {
		return deny("no SSH permission for this host: agpass ssh allow --host HOST --reason ...")
	}
	sig, err := sshagent.SignWithFlags(signer, data, flags&agent.SignatureFlagRsaSha256 != 0, flags&agent.SignatureFlagRsaSha512 != 0)
	if err != nil {
		return nil, err
	}
	a.s.Log.Emit(events.Event{Level: events.LevelOK, Action: "ssh-sign", Actor: c.String(), Target: target, Msg: "authenticated with the agpass key"})
	return sig, nil
}

// Extension records session-bind@openssh.com: which server the client is
// talking to, proven by the server's signature.
func (a *connAgent) Extension(extensionType string, contents []byte) ([]byte, error) {
	if extensionType != "session-bind@openssh.com" {
		return nil, agent.ErrExtensionUnsupported
	}
	b, err := sshagent.ParseSessionBind(contents)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	a.binds = append(a.binds, b)
	a.mu.Unlock()
	return nil, nil
}

func (a *connAgent) Add(agent.AddedKey) error       { return errReadOnly }
func (a *connAgent) Remove(ssh.PublicKey) error     { return errReadOnly }
func (a *connAgent) RemoveAll() error               { return errReadOnly }
func (a *connAgent) Lock([]byte) error              { return errReadOnly }
func (a *connAgent) Unlock([]byte) error            { return errReadOnly }
func (a *connAgent) Signers() ([]ssh.Signer, error) { return nil, errReadOnly }

// ---- HTTP: key management (human) and permissions (sessions) ----

func (s *Server) sshKeyResponse(signer ssh.Signer) api.SSHKeyResponse {
	it, _ := s.st.GetItem(api.SystemFolder, SSHItem)
	pub := authorizedKey(signer.PublicKey())
	for _, f := range it.Fields {
		if f.Key == "public_key" && f.Value != "" {
			pub = f.Value
		}
	}
	return api.SSHKeyResponse{PublicKey: pub, Fingerprint: ssh.FingerprintSHA256(signer.PublicKey()), Socket: AgentSocketPath(s.Dir)}
}

// storeSSHKey saves a key unless one exists and force is false.
func (s *Server) storeSSHKey(c *caller, privPEM []byte, authorized string, force bool, how string) (any, error) {
	if old, err := s.sshKey(); err == nil && !force {
		return nil, errf(http.StatusConflict, api.ErrConflict,
			"an SSH key already exists (%s); pass --force to replace it (its public key then stops working everywhere)", ssh.FingerprintSHA256(old.PublicKey()))
	}
	fields := []api.Field{
		{Key: "private_key", Type: api.TypeSensitive, Value: string(privPEM)},
		{Key: "public_key", Type: api.TypeText, Value: authorized},
	}
	if _, err := s.st.SetItem(api.SystemFolder, SSHItem, fields, nil, c.String()); err != nil {
		return nil, err
	}
	signer, err := sshagent.Signer(privPEM)
	if err != nil {
		return nil, err
	}
	resp := s.sshKeyResponse(signer)
	s.Log.Emit(events.Event{Level: events.LevelWarn, Action: "ssh-key", Actor: c.String(), Target: api.SystemFolder + "/" + SSHItem, Msg: how + " " + resp.Fingerprint})
	return resp, nil
}

func (s *Server) sshKeygen(r *http.Request, c *caller) (any, error) {
	var req api.SSHKeyRequest
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	comment := req.Comment
	if comment == "" {
		host, _ := os.Hostname()
		comment = "agpass@" + strings.TrimSuffix(host, ".local")
	}
	priv, auth, err := sshagent.Generate(comment)
	if err != nil {
		return nil, err
	}
	return s.storeSSHKey(c, priv, auth, req.Force, "generated")
}

func (s *Server) sshImport(r *http.Request, c *caller) (any, error) {
	var req api.SSHKeyRequest
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	priv, auth, err := sshagent.Normalize([]byte(req.PrivateKey), nil, req.Comment)
	if err != nil {
		return nil, errf(http.StatusBadRequest, api.ErrBadRequest, "invalid private key: %v", err)
	}
	return s.storeSSHKey(c, priv, auth, req.Force, "imported")
}

func (s *Server) sshPubkey(r *http.Request, c *caller) (any, error) {
	signer, err := s.sshKey()
	if errors.Is(err, store.ErrNotFound) {
		return nil, errf(http.StatusNotFound, api.ErrNotFound, "no SSH key yet; the user can create one with `agpass ssh keygen`")
	}
	if err != nil {
		return nil, err
	}
	return s.sshKeyResponse(signer), nil
}

// sshAllow lets the session use the key for one host: automatically for its
// repository's host or when elevated, otherwise if the gatekeeper agrees.
// The host's keys are pinned on first use, so the agent can tell later
// which host a connection really goes to.
func (s *Server) sshAllow(r *http.Request, c *caller) (any, error) {
	if c.admin {
		return nil, errf(http.StatusBadRequest, api.ErrBadRequest, "ssh allow is for agent sessions")
	}
	var req api.SSHAllowRequest
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	host, err := sshagent.NormalizeHost(req.Host)
	if err != nil {
		return nil, errf(http.StatusBadRequest, api.ErrBadRequest, "%v", err)
	}
	if strings.TrimSpace(req.Reason) == "" {
		return nil, errf(http.StatusBadRequest, api.ErrBadRequest, "a reason is required: say what you need SSH to %s for", host)
	}
	cwd, repo, err := s.sessionRepo(c)
	if err != nil {
		return nil, err
	}
	resp := api.SSHAllowResponse{Host: host}
	repoHost, _, _ := strings.Cut(repo, "/")
	switch {
	case c.elevated:
		resp.By, resp.Explanation = "admin", "admin session"
	case repoHost != "" && host == repoHost:
		resp.By, resp.Explanation = "repo-host", "the session's repository "+repo+" is on "+host
	default:
		key, model := s.gatekeeper()
		if key == "" {
			resp.Explanation = fmt.Sprintf("%s is not the host of this session's repository (%s), and the LLM gatekeeper is not configured; the user can elevate this session or set up the gatekeeper", host, orNone(repo))
			break
		}
		folders, err := s.sessionFolders(c)
		if err != nil {
			return nil, err
		}
		d, err := llm.DecideSSH(r.Context(), key, model, llm.SSHRequest{Host: host, Repo: repo, Cwd: cwd, Reason: req.Reason, Folders: folders})
		if err != nil {
			s.Log.Emit(events.Event{Level: events.LevelWarn, Action: "llm", Actor: c.String(), Msg: err.Error()})
			resp.Explanation = "LLM gatekeeper failed: " + err.Error()
			break
		}
		resp.Explanation = d.Explanation
		if d.Allow {
			resp.By = "llm"
		}
	}
	if resp.By == "" {
		s.Log.Emit(events.Event{Level: events.LevelDeny, Action: "ssh-allow", Actor: c.String(), Target: host, Msg: truncate(req.Reason, 80)})
		return resp, nil
	}

	pinned, err := s.pinHost(r.Context(), c, host)
	if err != nil {
		return nil, err
	}
	if _, err := s.st.SSHGrant(c.session.ID, host, resp.By, resp.Explanation); err != nil {
		return nil, err
	}
	resp.Granted, resp.HostKeys = true, pinned
	s.Log.Emit(events.Event{Level: events.LevelOK, Action: "ssh-allow", Actor: c.String(), Target: host, Msg: resp.By + ": " + truncate(req.Reason, 80)})
	return resp, nil
}

// sshUnpin forgets a host's pinned keys, for when the host changed them (a
// rotation, a rebuilt server). The next `ssh allow` for the host pins what it
// serves then. Only the human does this: trusting a changed host key is the
// decision pinning exists for.
func (s *Server) sshUnpin(r *http.Request, c *caller) (any, error) {
	var req api.SSHUnpinRequest
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	host, err := sshagent.NormalizeHost(req.Host)
	if err != nil {
		return nil, errf(http.StatusBadRequest, api.ErrBadRequest, "%v", err)
	}
	n, err := s.st.UnpinHost(host)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, errf(http.StatusNotFound, api.ErrNotFound, "no host keys are pinned for %s", host)
	}
	if err := s.writeKnownHosts(); err != nil {
		return nil, err
	}
	s.Log.Emit(events.Event{Level: events.LevelWarn, Action: "ssh-unpin", Actor: c.String(), Target: host,
		Msg: fmt.Sprintf("forgot %d host keys; the next ssh allow pins the host again", n)})
	return api.SSHUnpinResponse{Host: host, Removed: n}, nil
}

// pinHost returns the fingerprints of host's pinned keys, fetching and
// pinning them from the network the first time.
func (s *Server) pinHost(ctx context.Context, c *caller, host string) ([]string, error) {
	keys, err := s.st.HostKeys(host)
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		scanned, err := sshagent.ScanHostKeys(sctx, host)
		if err != nil {
			return nil, errf(http.StatusBadGateway, api.ErrInternal, "could not fetch the host keys of %s, so no permission was granted: %v", host, err)
		}
		for _, k := range scanned {
			keys = append(keys, authorizedKey(k))
		}
		if err := s.st.PinHostKeys(host, keys); err != nil {
			return nil, err
		}
		s.Log.Emit(events.Event{Level: events.LevelInfo, Action: "ssh-pin", Actor: c.String(), Target: host, Msg: fmt.Sprintf("pinned %d host keys", len(keys))})
	}
	// Rewrite on every grant, not just new pins, so a file that lost a host
	// (or was edited) heals on the next allow.
	if err := s.writeKnownHosts(); err != nil {
		return nil, err
	}
	var fps []string
	for _, k := range keys {
		if pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k)); err == nil {
			fps = append(fps, pk.Type()+" "+ssh.FingerprintSHA256(pk))
		}
	}
	return fps, nil
}

// sessionFolders describes the folders the session has, for the gatekeeper.
func (s *Server) sessionFolders(c *caller) ([]llm.FolderInfo, error) {
	have, err := s.grantSet(c)
	if err != nil {
		return nil, err
	}
	folders, err := s.st.ListFolders()
	if err != nil {
		return nil, err
	}
	var out []llm.FolderInfo
	for _, f := range folders {
		if have[f.Name] {
			out = append(out, llm.FolderInfo{Name: f.Name, Project: f.Project, Description: f.Description, Repos: f.Repos, WrittenBy: writtenBy(f)})
		}
	}
	return out, nil
}

func writtenBy(f api.Folder) string {
	if f.UpdatedBy == "human" || f.UpdatedBy == "server" {
		return "owner"
	}
	return "agent"
}
