// Package server is the agpass daemon: HTTP over a Unix socket.
//
// Callers are identified by the socket peer pid: the server walks up its
// ancestry to the nearest process running signed agent code (e.g. Claude
// Code). Each such process gets a session, bound to its (pid, start time),
// on its first request; grants decide what it can read. Humans authenticate
// per request with the master password (X-Agpass-Master).
package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"agpass/internal/api"
	"agpass/internal/events"
	"agpass/internal/peer"
	"agpass/internal/store"
	"agpass/internal/vault"
)

const (
	adminMaxFails   = 5
	adminLockout    = 5 * time.Minute
	failWindow      = 10 * time.Minute
	otpTTL          = 10 * time.Minute // time to redeem a minted admin code
	codeMaxFails    = 10
	ElevateDuration = time.Hour // admin access from one code
	shutdownGrace   = 5 * time.Second
)

type Server struct {
	Dir           string
	AllowRollback bool
	Log           *events.Log

	mu         sync.Mutex
	kf         *vault.KeyFile
	dek        []byte
	st         *store.Store
	adminFails []time.Time
	adminLock  time.Time
	otps       map[string]time.Time // sha256(admin code) -> expiry
	codeFails  []time.Time

	// masterMu admits one master-password check at a time: each Argon2
	// verify takes 128 MiB, and failures must be counted before the next
	// guess is evaluated.
	masterMu  sync.Mutex
	inflight  sync.WaitGroup // running handlers, drained before the store closes
	ln        net.Listener
	agent     agentState // SSH agent socket
	resolver  *peer.Resolver
	findAgent func(pid int) (peer.Proc, peer.Agent, error) // resolver.FindAgent; tests replace it
}

var ErrNoVault = errors.New("no vault yet: run `agpass setup` to create one")

func New(dir string, log *events.Log) *Server {
	s := &Server{Dir: dir, Log: log, otps: map[string]time.Time{}, resolver: peer.NewResolver()}
	s.findAgent = s.resolver.FindAgent
	return s
}

func SocketPath(dir string) string { return filepath.Join(dir, "agpass.sock") }
func KeyPath(dir string) string    { return filepath.Join(dir, "agpass.key") }

// Unlock opens the existing vault. It never creates one.
func (s *Server) Unlock(password string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st != nil {
		return nil
	}
	if !vault.Exists(KeyPath(s.Dir)) {
		return ErrNoVault
	}
	kf, err := vault.Load(KeyPath(s.Dir))
	if err != nil {
		return err
	}
	dek, err := kf.Unwrap(password)
	if err != nil {
		return err
	}
	return s.open(dek, "vault unlocked")
}

// open loads the key file and opens the store; s.mu must be held.
func (s *Server) open(dek []byte, msg string) error {
	kf, err := vault.Load(KeyPath(s.Dir))
	if err != nil {
		return err
	}
	st, err := store.Open(s.Dir, dek, s.AllowRollback)
	if err != nil {
		return err
	}
	s.kf, s.dek, s.st = kf, dek, st
	s.Log.Attach(st.AddEvent)
	s.Log.Emit(events.Event{Level: events.LevelOK, Action: "unlock", Actor: "human", Msg: msg})
	return nil
}

func (s *Server) Unlocked() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st != nil
}

// Listen creates the Unix socket. Call Serve next.
func (s *Server) Listen() error {
	sock := SocketPath(s.Dir)
	if len(sock) > 103 {
		return fmt.Errorf("socket path too long for macOS (%d > 103 bytes): %s; set AGPASS_DIR to a shorter directory", len(sock), sock)
	}
	if c, err := net.Dial("unix", sock); err == nil {
		c.Close()
		return fmt.Errorf("agpass is already running (%s)", sock)
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
	s.ln = ln
	if err := s.listenAgent(); err != nil {
		ln.Close()
		return err
	}
	return nil
}

// Serve answers requests on the socket from Listen until ctx is cancelled.
func (s *Server) Serve(ctx context.Context) error {
	sock, ln := SocketPath(s.Dir), s.ln
	// Requests run on reqCtx, which is cancelled if they don't finish within
	// the grace period after shutdown starts (e.g. a slow LLM call).
	reqCtx, cancelReqs := context.WithCancel(context.Background())
	defer cancelReqs()
	srv := &http.Server{
		Handler:           s.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second, // a request body that never arrives can't hold a handler
		IdleTimeout:       2 * time.Minute,
		BaseContext:       func(net.Listener) context.Context { return reqCtx },
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			pid, err := peer.PeerPID(c)
			return context.WithValue(ctx, peerKey{}, peerInfo{pid, err})
		},
	}
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		select {
		case <-ctx.Done():
		case <-reqCtx.Done(): // Serve failed on its own
			return
		}
		s.Log.Emit(events.Event{Level: events.LevelInfo, Action: "shutdown", Msg: "waiting for running requests"})
		sctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
		defer cancel()
		if srv.Shutdown(sctx) != nil {
			// Grace period over: abort what is still running. Cancelling
			// stops LLM calls; closing the connections unblocks handlers
			// still reading a request body.
			cancelReqs()
			srv.Close()
		}
	}()
	s.Log.Emit(events.Event{Level: events.LevelInfo, Action: "listen", Target: tilde(sock), Msg: "agpass " + api.Version})
	agentDone := make(chan struct{})
	go func() { s.serveAgent(); close(agentDone) }()
	err := srv.Serve(ln)
	if !errors.Is(err, http.ErrServerClosed) {
		cancelReqs()
	}
	<-shutdownDone
	s.stopAgent()
	<-agentDone
	// Handlers may still be running after Shutdown returns; give them a
	// bounded time to notice the cancellation before the store closes.
	drained := make(chan struct{})
	go func() { s.inflight.Wait(); s.agent.wg.Wait(); close(drained) }()
	select {
	case <-drained:
	case <-time.After(shutdownGrace):
		s.Log.Emit(events.Event{Level: events.LevelWarn, Action: "shutdown", Msg: "requests still running; closing anyway"})
	}
	os.Remove(sock)
	s.Log.Emit(events.Event{Level: events.LevelInfo, Action: "stopped", Msg: "agpass server stopped"})
	s.Log.Detach()
	s.mu.Lock()
	if s.st != nil {
		s.st.Close()
		s.st = nil
	}
	s.mu.Unlock()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// ---- caller resolution ----

type peerKey struct{}

type peerInfo struct {
	pid int
	err error
}

type caller struct {
	admin    bool // the human, with the master password
	elevated bool // an agent session with unexpired admin access (agpass elevate)
	agent    peer.Proc
	name     string // agent name, e.g. claude
	session  *store.Session
}

// full reports whether the caller may access every folder, SYSTEM included.
func (c *caller) full() bool { return c.admin || c.elevated }

func (c *caller) String() string {
	if c.admin {
		return "human"
	}
	s := fmt.Sprintf("%s:%d", c.name, c.agent.PID)
	if c.session != nil {
		s += " " + c.session.ID
	}
	if c.elevated {
		s += " [admin]"
	}
	return s
}

type authMode int

const (
	authNone    authMode = iota // no identity needed
	authAdmin                   // master password required
	authSession                 // admin, or an agent process (its session is created on first use)
)

type apiErr struct {
	status int
	code   string
	msg    string
}

func (e *apiErr) Error() string { return e.msg }

func errf(status int, code, format string, a ...any) error {
	return &apiErr{status, code, fmt.Sprintf(format, a...)}
}

type handlerFunc func(r *http.Request, c *caller) (any, error)

func (s *Server) handle(mode authMode, h handlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.inflight.Add(1)
		defer s.inflight.Done()
		w.Header().Set(api.HeaderVersion, api.Version)
		c, err := s.authenticate(r, mode)
		var out any
		if err == nil {
			out, err = h(r, c)
		}
		if err != nil {
			var ae *apiErr
			if !errors.As(err, &ae) {
				ae = &apiErr{http.StatusInternalServerError, api.ErrInternal, err.Error()}
				s.Log.Emit(events.Event{Level: events.LevelWarn, Action: "error", Target: r.URL.Path, Msg: err.Error()})
			}
			writeJSON(w, ae.status, api.Error{Code: ae.code, Message: ae.msg})
			return
		}
		writeJSON(w, http.StatusOK, out)
	}
}

func (s *Server) authenticate(r *http.Request, mode authMode) (*caller, error) {
	if mode == authNone {
		return &caller{}, nil
	}
	if !s.Unlocked() {
		return nil, errf(http.StatusServiceUnavailable, api.ErrLocked, "agpass is starting up; try again in a moment")
	}
	if pw := r.Header.Get(api.HeaderMaster); pw != "" {
		if err := s.checkMaster(pw); err != nil {
			return nil, err
		}
		return &caller{admin: true}, nil
	}
	if mode == authAdmin {
		return nil, errf(http.StatusUnauthorized, api.ErrNeedAdmin, "this command needs the master password")
	}
	pi, _ := r.Context().Value(peerKey{}).(peerInfo)
	if pi.err != nil || pi.pid == 0 {
		return nil, errf(http.StatusBadRequest, api.ErrBadRequest, "cannot identify peer process")
	}
	return s.agentCaller(pi.pid)
}

// agentCaller finds the agent process above pid and its session, creating
// the session on first use.
func (s *Server) agentCaller(pid int) (*caller, error) {
	proc, agent, err := s.findAgent(pid)
	if errors.Is(err, peer.ErrNoAgent) {
		return nil, errf(http.StatusUnauthorized, api.ErrNeedAdmin, "not running under a recognised agent; use the master password")
	}
	if err != nil {
		return nil, err
	}
	c := &caller{agent: proc, name: agent.Name}
	// Any verified agent process gets a session on its first request; what
	// it may read is decided by grants (repository match, gatekeeper, or
	// folders it created).
	cwd, _ := peer.Cwd(proc.PID)
	sess, created, err := s.st.UpsertSession(store.Session{
		ID: randomID("s-"), PID: proc.PID, StartUS: proc.StartUS,
		Agent: agent.Name, Exe: proc.Exe, Cwd: cwd,
	})
	if err != nil {
		return nil, err
	}
	c.session = &sess
	c.elevated = time.Now().Before(sess.AdminUntil)
	if created {
		s.Log.Emit(events.Event{Level: events.LevelInfo, Action: "session", Actor: c.String(), Target: tilde(cwd), Msg: "new " + agent.Name + " session"})
	}
	return c, nil
}

// agentAncestor names the agent (e.g. "claude") the requesting process runs
// under, or "" when it runs under none.
func (s *Server) agentAncestor(r *http.Request) (string, error) {
	pi, _ := r.Context().Value(peerKey{}).(peerInfo)
	if pi.err != nil || pi.pid == 0 {
		return "", fmt.Errorf("cannot identify peer process")
	}
	_, agent, err := s.findAgent(pi.pid)
	if errors.Is(err, peer.ErrNoAgent) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return agent.Name, nil
}

func (s *Server) checkMaster(pw string) error {
	s.masterMu.Lock()
	defer s.masterMu.Unlock()
	s.mu.Lock()
	now := time.Now()
	if now.Before(s.adminLock) {
		s.mu.Unlock()
		return errf(http.StatusTooManyRequests, api.ErrRateLimited, "too many wrong master passwords; try again after %s", s.adminLock.Format("15:04:05"))
	}
	kf, dek := s.kf, s.dek
	s.mu.Unlock()

	if kf.Verify(pw, dek) {
		// A correct password clears earlier failures (e.g. a stale
		// password from 1Password followed by the typed one).
		s.mu.Lock()
		s.adminFails = nil
		s.mu.Unlock()
		return nil
	}
	s.mu.Lock()
	s.adminFails = recent(append(s.adminFails, now), failWindow)
	locked := len(s.adminFails) >= adminMaxFails
	if locked {
		s.adminLock = now.Add(adminLockout)
		s.adminFails = nil
	}
	s.mu.Unlock()
	if locked {
		s.Log.Emit(events.Event{Level: events.LevelAlert, Action: "master-lockout", Msg: "too many wrong master passwords, locked for 5m"})
	} else {
		s.Log.Emit(events.Event{Level: events.LevelDeny, Action: "master-auth", Msg: "wrong master password"})
	}
	return errf(http.StatusUnauthorized, api.ErrWrongMaster, "wrong master password")
}

func recent(ts []time.Time, window time.Duration) []time.Time {
	cut := time.Now().Add(-window)
	out := ts[:0]
	for _, t := range ts {
		if t.After(cut) {
			out = append(out, t)
		}
	}
	return out
}

// ---- one-time codes ----

const codeAlphabet = "abcdefghjkmnpqrstuvwxyz23456789"

func newCode() string {
	b := make([]byte, 8)
	rand.Read(b)
	out := []byte("agp-xxxx-xxxx")
	j := 0
	for i := range out {
		if out[i] == 'x' {
			out[i] = codeAlphabet[int(b[j])%len(codeAlphabet)]
			j++
		}
	}
	return string(out)
}

func codeHash(code string) string {
	h := sha256.Sum256([]byte(code))
	return hex.EncodeToString(h[:])
}

func (s *Server) mintCode() api.MintResponse {
	code := newCode()
	exp := time.Now().Add(otpTTL)
	s.mu.Lock()
	for k, e := range s.otps {
		if time.Now().After(e) {
			delete(s.otps, k)
		}
	}
	s.otps[codeHash(code)] = exp
	s.mu.Unlock()
	return api.MintResponse{Code: code, ExpiresAt: exp}
}

// redeemCode consumes code and returns a func that puts it back, for when
// elevation fails after all. Repeated failures invalidate all
// outstanding codes.
func (s *Server) redeemCode(code string) (restore func(), err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := codeHash(code)
	exp, ok := s.otps[h]
	if ok {
		delete(s.otps, h)
		if time.Now().Before(exp) {
			return func() {
				s.mu.Lock()
				s.otps[h] = exp
				s.mu.Unlock()
			}, nil
		}
	}
	s.codeFails = recent(append(s.codeFails, time.Now()), failWindow)
	if len(s.codeFails) >= codeMaxFails {
		s.otps = map[string]time.Time{}
		s.codeFails = nil
		go s.Log.Emit(events.Event{Level: events.LevelAlert, Action: "code-lockout", Msg: "too many invalid admin codes; all outstanding codes revoked"})
	}
	return nil, errf(http.StatusUnauthorized, api.ErrForbidden, "invalid, expired or already used code")
}

// ---- helpers ----

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errf(http.StatusBadRequest, api.ErrBadRequest, "invalid request body: %v", err)
	}
	return nil
}

func randomID(prefix string) string {
	b := make([]byte, 8)
	rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

// ---- dashboard ----

// History returns the last n audit events from the store.
func (s *Server) History(n int) ([]events.Event, error) {
	s.mu.Lock()
	st := s.st
	s.mu.Unlock()
	if st == nil {
		return nil, nil
	}
	return st.RecentEvents(n)
}

// Status summarizes the vault for the dashboard header.
type Status struct {
	Folders, Items     int
	Sessions, LiveSess int
	AdminSess          int    // live sessions with unexpired admin access
	Gatekeeper         string // model, or "" when not configured
}

func (s *Server) Status() (Status, error) {
	s.mu.Lock()
	st := s.st
	s.mu.Unlock()
	out := Status{}
	if st == nil {
		return out, nil
	}
	c, err := st.Counts()
	if err != nil {
		return out, err
	}
	out.Folders, out.Items = c.Folders, c.Items
	sessions, err := st.Sessions()
	if err != nil {
		return out, err
	}
	out.Sessions = len(sessions)
	if key, model := s.gatekeeper(); key != "" {
		out.Gatekeeper = model
	}
	for _, sess := range sessions {
		if p, err := peer.Info(sess.PID); err == nil && p.StartUS == sess.StartUS {
			out.LiveSess++
			if time.Now().Before(sess.AdminUntil) {
				out.AdminSess++
			}
		}
	}
	return out, nil
}

// tilde shortens a path under the home directory for display.
func tilde(p string) string {
	if home, err := os.UserHomeDir(); err == nil && strings.HasPrefix(p, home+"/") {
		return "~" + p[len(home):]
	}
	return p
}
