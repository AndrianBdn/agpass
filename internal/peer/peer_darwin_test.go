//go:build darwin

package peer

import (
	"os"
	"testing"
)

func TestSelf(t *testing.T) {
	exe, err := ExePath(os.Getpid())
	if err != nil || exe == "" {
		t.Fatalf("ExePath: %q %v", exe, err)
	}
	wd, _ := os.Getwd()
	cwd, err := Cwd(os.Getpid())
	if err != nil || cwd != wd {
		t.Fatalf("Cwd: %q %v, want %q", cwd, err, wd)
	}
}

// TestFindAgent passes when run from inside Claude Code (it finds Claude)
// and when run elsewhere (no agent), but never misidentifies a non-agent.
func TestFindAgent(t *testing.T) {
	p, a, err := NewResolver().FindAgent(os.Getpid())
	if err == ErrNoAgent {
		t.Skip("not running under a known agent")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("found %s pid %d exe %s", a.Name, p.PID, p.Exe)
	if a.Name != "claude" {
		t.Fatalf("unexpected agent %q", a.Name)
	}
}
