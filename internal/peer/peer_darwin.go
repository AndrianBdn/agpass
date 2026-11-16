//go:build darwin

// Package peer identifies the process on the other end of the Unix socket
// and finds the agent process (e.g. Claude Code) it runs under.
package peer

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"unsafe"

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
	p.Exe, _ = ExePath(pid)
	return p, nil
}

const (
	procInfoCallPIDInfo  = 2  // PROC_INFO_CALL_PIDINFO
	procPIDVnodePathInfo = 9  // PROC_PIDVNODEPATHINFO
	procPIDPathInfo      = 11 // PROC_PIDPATHINFO
	maxPathLen           = 1024
	vnodeInfoSize        = 152 // sizeof(struct vnode_info)
	vnodePathInfoSize    = 2 * (vnodeInfoSize + maxPathLen)
	csOpsStatus          = 0 // CS_OPS_STATUS
	csOpsCDHash          = 5 // CS_OPS_CDHASH
	csValid              = 0x1
)

func procInfo(pid, flavor int, buf []byte) error {
	_, _, e := unix.Syscall6(unix.SYS_PROC_INFO, procInfoCallPIDInfo, uintptr(pid), uintptr(flavor), 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if e != 0 {
		return e
	}
	return nil
}

// ExePath is the kernel's path of the running executable (proc_pidpath).
// Unlike kern.procargs2, the process cannot rewrite it.
func ExePath(pid int) (string, error) {
	buf := make([]byte, 4*maxPathLen)
	if err := procInfo(pid, procPIDPathInfo, buf); err != nil {
		return "", err
	}
	return cstr(buf), nil
}

// Cwd is the current working directory of pid, read from the kernel.
func Cwd(pid int) (string, error) {
	buf := make([]byte, vnodePathInfoSize)
	if err := procInfo(pid, procPIDVnodePathInfo, buf); err != nil {
		return "", err
	}
	return cstr(buf[vnodeInfoSize : vnodeInfoSize+maxPathLen]), nil
}

func csops(pid, op int, buf []byte) error {
	_, _, e := unix.Syscall6(unix.SYS_CSOPS, uintptr(pid), uintptr(op),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0, 0)
	if e != 0 {
		return e
	}
	return nil
}

// runningCDHash returns the code directory hash of the code pid is actually
// running, as the kernel validated it. It fails unless the kernel still
// considers the process's signature valid.
func runningCDHash(pid int) (string, error) {
	st := make([]byte, 4)
	if err := csops(pid, csOpsStatus, st); err != nil {
		return "", err
	}
	if binary.NativeEndian.Uint32(st)&csValid == 0 {
		return "", fmt.Errorf("process %d has no valid code signature", pid)
	}
	cd := make([]byte, 20)
	if err := csops(pid, csOpsCDHash, cd); err != nil {
		return "", err
	}
	return hex.EncodeToString(cd), nil
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
	cache map[string]signed // key: exe + size + mtime
}

type signed struct {
	agent  *Agent // nil = not a known agent
	cdhash string
}

func NewResolver() *Resolver { return &Resolver{cache: map[string]signed{}} }

// FindAgent walks from pid up through its ancestors and returns the nearest
// process running a binary with a valid signature from a known agent team.
func (r *Resolver) FindAgent(pid int) (Proc, Agent, error) {
	for depth := 0; pid > 1 && depth < 64; depth++ {
		p, err := Info(pid)
		if err != nil {
			return Proc{}, Agent{}, err
		}
		if a := r.agentFor(p); a != nil {
			return p, *a, nil
		}
		pid = p.PPID
	}
	return Proc{}, Agent{}, ErrNoAgent
}

// agentFor reports whether p runs a known agent. The file at p.Exe must carry
// a valid signature from the agent's team, and the kernel's hash of the code
// p is running must equal that file's hash, so swapping the file after
// launch, or pointing at someone else's binary, doesn't pass.
func (r *Resolver) agentFor(p Proc) *Agent {
	if p.Exe == "" {
		return nil
	}
	st, err := os.Stat(p.Exe)
	if err != nil {
		return nil
	}
	key := fmt.Sprintf("%s|%d|%d", p.Exe, st.Size(), st.ModTime().UnixNano())
	r.mu.Lock()
	sg, ok := r.cache[key]
	r.mu.Unlock()
	if !ok {
		sg = verify(p.Exe)
		r.mu.Lock()
		if len(r.cache) > 1024 {
			clear(r.cache)
		}
		r.cache[key] = sg
		r.mu.Unlock()
	}
	if sg.agent == nil {
		return nil
	}
	running, err := runningCDHash(p.PID)
	if err != nil || running != sg.cdhash {
		return nil
	}
	return sg.agent
}

// verify checks the signature of the file at path: a quick read of its
// TeamIdentifier first (cheap rejection of shells, terminals, …), then full
// verification against a Developer ID requirement pinned to the team.
func verify(path string) signed {
	out, _ := exec.Command("/usr/bin/codesign", "-dv", "--verbose=4", path).CombinedOutput()
	var team, cdhash string
	for _, line := range strings.Split(string(out), "\n") {
		if v, ok := strings.CutPrefix(line, "TeamIdentifier="); ok {
			team = strings.TrimSpace(v)
		}
		if v, ok := strings.CutPrefix(line, "CDHash="); ok {
			cdhash = strings.ToLower(strings.TrimSpace(v))
		}
	}
	for _, a := range KnownAgents {
		if a.TeamID != team || cdhash == "" {
			continue
		}
		req := fmt.Sprintf(`=anchor apple generic and certificate leaf[subject.OU] = "%s"`, a.TeamID)
		if exec.Command("/usr/bin/codesign", "--verify", "-R", req, path).Run() == nil {
			return signed{agent: &a, cdhash: cdhash}
		}
	}
	return signed{}
}
