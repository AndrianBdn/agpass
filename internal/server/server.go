// Package server is the agpass daemon: HTTP over a Unix socket.
//
// Callers are identified by the socket peer pid: the server walks up its
// ancestry to the nearest signed agent process (e.g. Claude Code). A session
// is bound to that process's (pid, start time) after it redeems a one-time
// code minted by the human. Humans authenticate per request with the master
// password (X-Agpass-Master).
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
	"sync"
	"time"

	"agpass/internal/api"
	"agpass/internal/events"
	"agpass/internal/peer"
	"agpass/internal/store"
	"agpass/internal/vault"
)

const (
	otpTTL          = 10 * time.Minute
	adminMaxFails   = 5
	adminLockout    = 5 * time.Minute
	connectMaxFails = 10
	failWindow      = 10 * time.Minute
)

type Server struct {
	Dir           string
	AllowRollback bool
	Log           *events.Log

	mu         sync.Mutex
	kf         *vault.KeyFile
	dek        []byte
	st         *store.Store
	otps       map[string]time.Time // sha256(code) -> expiry
	adminFails []time.Time
	adminLock  time.Time
	codeFails  []time.Time

	resolver *peer.Resolver
}

func New(dir string, log *events.Log) *Server {
	return &Server{Dir: dir, Log: log, otps: map[string]time.Time{}, resolver: peer.NewResolver()}
}

func SocketPath(dir string) string { return filepath.Join(dir, "agpass.sock") }
func KeyPath(dir string) string    { return filepath.Join(dir, "agpass.key") }
func EventsPath(dir string) string { return filepath.Join(dir, "events.jsonl") }

// Unlock opens the vault, creating it if no key file exists.
func (s *Server) Unlock(password string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st != nil {
		return nil
	}
	var dek []byte
	var err error
	created := false
	if !vault.Exists(KeyPath(s.Dir)) {
		if dek, err = vault.Create(KeyPath(s.Dir), password); err != nil {
			return err
		}
		created = true
	}
	kf, err := vault.Load(KeyPath(s.Dir))
	if err != nil {
		return err
	}
	if dek == nil {
		if dek, err = kf.Unwrap(password); err != nil {
			return err
		}
	}
	st, err := store.Open(s.Dir, dek, s.AllowRollback)
	if err != nil {
		return err
	}
	s.kf, s.dek, s.st = kf, dek, st
	msg := "vault unlocked"
	if created {
		msg = "new vault created"
	}
	s.Log.Emit(events.Event{Level: events.LevelOK, Action: "unlock", Actor: "human", Msg: msg})
	return nil
}

func (s *Server) Unlocked() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st != nil
}

// Serve listens on the Unix socket until ctx is cancelled.
func (s *Server) Serve(ctx context.Context) error {
	sock := SocketPath(s.Dir)
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
	srv := &http.Server{
		Handler:           s.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			pid, err := peer.PeerPID(c)
			return context.WithValue(ctx, peerKey{}, peerInfo{pid, err})
		},
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
	}()
	s.Log.Emit(events.Event{Level: events.LevelInfo, Action: "listen", Target: sock, Msg: "agpass " + api.Version})
	err = srv.Serve(ln)
	os.Remove(sock)
	if s.st != nil {
		s.st.Close()
	}
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
	admin   bool
	agent   peer.Proc
	name    string // agent name, e.g. claude
	session *store.Session
}

func (c *caller) String() string {
	if c.admin {
		return "human"
	}
	s := fmt.Sprintf("%s:%d", c.name, c.agent.PID)
	if c.session != nil {
		s += " " + c.session.ID
	}
	return s
}

type authMode int

const (
	authNone    authMode = iota // no identity needed
	authAdmin                   // master password required
	authAgent                   // agent process required, session optional
	authSession                 // admin or connected agent session
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
		return nil, errf(http.StatusServiceUnavailable, api.ErrLocked, "agpass is locked: run `agpass unlock`")
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
	proc, agent, err := s.resolver.FindAgent(pi.pid)
	if errors.Is(err, peer.ErrNoAgent) {
		return nil, errf(http.StatusUnauthorized, api.ErrNeedAdmin, "not running under a recognised agent; use the master password")
	}
	if err != nil {
		return nil, err
	}
	c := &caller{agent: proc, name: agent.Name}
	sess, err := s.st.SessionByProc(proc.PID, proc.StartUS)
	if err == nil {
		c.session = &sess
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	if mode == authSession && c.session == nil {
		return nil, errf(http.StatusUnauthorized, api.ErrNotConnected,
			"this %s session (pid %d) is not connected to agpass. Ask the user to run `agpass mint` and give you the code, then run `agpass connect <code>`.", agent.Name, proc.PID)
	}
	return c, nil
}

func (s *Server) checkMaster(pw string) error {
	s.mu.Lock()
	now := time.Now()
	if now.Before(s.adminLock) {
		s.mu.Unlock()
		return errf(http.StatusTooManyRequests, api.ErrRateLimited, "too many wrong master passwords; try again after %s", s.adminLock.Format("15:04:05"))
	}
	kf, dek := s.kf, s.dek
	s.mu.Unlock()

	if kf.Verify(pw, dek) {
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
	return errf(http.StatusUnauthorized, api.ErrForbidden, "wrong master password")
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

// redeemCode consumes code. Repeated failures invalidate all outstanding codes.
func (s *Server) redeemCode(code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := codeHash(code)
	exp, ok := s.otps[h]
	if ok {
		delete(s.otps, h)
		if time.Now().Before(exp) {
			return nil
		}
	}
	s.codeFails = recent(append(s.codeFails, time.Now()), failWindow)
	if len(s.codeFails) >= connectMaxFails {
		s.otps = map[string]time.Time{}
		s.codeFails = nil
		go s.Log.Emit(events.Event{Level: events.LevelAlert, Action: "code-lockout", Msg: "too many invalid connect codes; all outstanding codes revoked"})
	}
	return errf(http.StatusUnauthorized, api.ErrForbidden, "invalid, expired or already used code")
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
	b := make([]byte, 4)
	rand.Read(b)
	return prefix + hex.EncodeToString(b)
}
