//go:build darwin

// Package peer identifies the process on the other end of the Unix socket
// and finds the agent process (e.g. Claude Code) it runs under.
package peer

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

type Proc struct {
	PID     int
	PPID    int
	StartUS int64 // process start time, microseconds since epoch
	Exe     string
	Comm    string
}

// Agent is a recognised agent binary, identified by its code signature.
type Agent struct {
	Name   string
	TeamID string
}

// KnownAgents are matched by verifying the binary's Developer ID signature.
var KnownAgents = []Agent{
	{Name: "claude", TeamID: "Q6L2SF6YDW"}, // Anthropic PBC
}

var ErrNoAgent = errors.New("no agent process found among ancestors")

// PeerPID returns the pid of the process connected on c (LOCAL_PEERPID).
func PeerPID(c net.Conn) (int, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, fmt.Errorf("not a unix socket connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var pid int
	var serr error
	if err := raw.Control(func(fd uintptr) {
		pid, serr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	}); err != nil {
		return 0, err
	}
	return pid, serr
}

// Info returns pid, parent, start time and executable path of pid.
func Info(pid int) (Proc, error) {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return Proc{}, err
	}
	if int(kp.Proc.P_pid) != pid {
		return Proc{}, fmt.Errorf("process %d not found", pid)
	}
	p := Proc{
		PID:     pid,
		PPID:    int(kp.Eproc.Ppid),
		StartUS: kp.Proc.P_starttime.Sec*1_000_000 + int64(kp.Proc.P_starttime.Usec),
		Comm:    cstr(kp.Proc.P_comm[:]),
	}
	p.Exe, _ = exePath(pid)
	return p, nil
}

// exePath reads the executable path from kern.procargs2.
func exePath(pid int) (string, error) {
	buf, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil {
		return "", err
	}
	if len(buf) < 5 {
		return "", fmt.Errorf("short procargs")
	}
	rest := buf[4:]
	if i := bytes.IndexByte(rest, 0); i >= 0 {
		return string(rest[:i]), nil
	}
	return "", fmt.Errorf("bad procargs")
}

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// Resolver walks process ancestry and caches code-signature checks.
type Resolver struct {
	mu    sync.Mutex
	cache map[string]*Agent // key: resolved exe + size + mtime; nil = not an agent
}

func NewResolver() *Resolver { return &Resolver{cache: map[string]*Agent{}} }

// FindAgent walks from pid up through its ancestors and returns the nearest
// process whose binary carries a valid signature from a known agent team.
func (r *Resolver) FindAgent(pid int) (Proc, Agent, error) {
	for depth := 0; pid > 1 && depth < 64; depth++ {
		p, err := Info(pid)
		if err != nil {
			return Proc{}, Agent{}, err
		}
		if a := r.agentFor(p.Exe); a != nil {
			return p, *a, nil
		}
		pid = p.PPID
	}
	return Proc{}, Agent{}, ErrNoAgent
}

func (r *Resolver) agentFor(exe string) *Agent {
	if exe == "" {
		return nil
	}
	real, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return nil
	}
	st, err := os.Stat(real)
	if err != nil {
		return nil
	}
	key := fmt.Sprintf("%s|%d|%d", real, st.Size(), st.ModTime().UnixNano())
	r.mu.Lock()
	a, ok := r.cache[key]
	r.mu.Unlock()
	if ok {
		return a
	}
	a = verify(real)
	r.mu.Lock()
	r.cache[key] = a
	r.mu.Unlock()
	return a
}

// verify checks the signature of path: a quick TeamIdentifier read first
// (cheap rejection of shells, terminals, …), then full verification against
// a Developer ID requirement pinned to the team.
func verify(path string) *Agent {
	out, _ := exec.Command("/usr/bin/codesign", "-dv", "--verbose=2", path).CombinedOutput()
	team := ""
	for _, line := range strings.Split(string(out), "\n") {
		if v, ok := strings.CutPrefix(line, "TeamIdentifier="); ok {
			team = strings.TrimSpace(v)
		}
	}
	for _, a := range KnownAgents {
		if a.TeamID != team {
			continue
		}
		req := fmt.Sprintf(`=anchor apple generic and certificate leaf[subject.OU] = "%s"`, a.TeamID)
		if exec.Command("/usr/bin/codesign", "--verify", "-R", req, path).Run() == nil {
			return &a
		}
	}
	return nil
}
