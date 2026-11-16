package dashboard

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"

	"agpass/internal/events"
)

func newTestModel(n int) *model {
	m := &model{src: Source{Title: "agpass 0.1.0 · ~/.local/share/agpass", Status: func() string { return "● serving" }}, status: "● serving · 1 live sessions (2 total) · 3 folders · 7 items"}
	day := time.Date(2026, 11, 15, 23, 59, 0, 0, time.Local)
	for i := range n {
		e := events.Event{Time: day.Add(time.Duration(i) * 20 * time.Second), Level: events.LevelOK, Action: "get", Actor: "claude:15148 s-1", Target: "crm/db", Msg: "redacted"}
		if i%4 == 1 {
			e.Level, e.Action, e.Msg = events.LevelDeny, "request-access", "fix\x1b[2K login"
		}
		if i%5 == 2 {
			e.Level, e.Action, e.Msg = events.LevelWarn, "reveal", "fields=url"
		}
		m.add(e)
	}
	m.w, m.h = 100, 16
	return m
}

func screen(m *model) string { return ansi.Strip(strings.Join(m.view(), "\n")) }

func TestViewLayout(t *testing.T) {
	m := newTestModel(30)
	v := screen(m)
	lines := strings.Split(v, "\n")
	if len(lines) != 16 {
		t.Fatalf("view has %d lines, want 16", len(lines))
	}
	for i, l := range lines {
		if w := ansi.StringWidth(l); w > 100 {
			t.Errorf("line %d is %d wide", i, w)
		}
	}
	if strings.Contains(m.frame(), "fix\x1b[2K") {
		t.Error("raw escape from event text reached the screen")
	}
	if os.Getenv("SHOW") != "" {
		t.Log("\n" + v)
	}

	// Scroll up, then a new event arrives: the view must not move.
	m.key("up")
	before := screen(m)
	m.onEvent(events.Event{Time: time.Now(), Level: events.LevelOK, Action: "set", Target: "crm/db"})
	if after := screen(m); stripFooter(after) != stripFooter(before) {
		t.Error("view moved while paused")
	}
	if !strings.Contains(screen(m), "1 new below") {
		t.Error("no 'new below' hint")
	}

	// Filter.
	m.key("/")
	for _, r := range "reveal" {
		m.key(string(r))
	}
	m.key("enter")
	for _, l := range strings.Split(screen(m), "\n")[3:14] {
		if strings.TrimSpace(l) != "" && !strings.Contains(l, "reveal") && !strings.Contains(l, "──") {
			t.Errorf("filtered view shows %q", l)
		}
	}
	if os.Getenv("SHOW") != "" {
		t.Log("\n" + screen(m))
	}

	// q once arms, another key disarms, q q quits.
	if m.key("q") || !strings.Contains(screen(m), "Press q again") {
		t.Error("first q should only arm")
	}
	m.key("down")
	if m.quitArmed {
		t.Error("other key should disarm")
	}
	m.key("q")
	if !m.key("ctrl+c") {
		t.Error("second q/ctrl+c should quit")
	}
}

func TestReadKeys(t *testing.T) {
	ch := make(chan string, 64)
	readKeys(strings.NewReader("\x1b[Aj\x1b[6~/ré\x7f\r\x03\x1b"), ch)
	var got []string
	for k := range ch {
		got = append(got, k)
	}
	want := "up j pgdown / r é backspace enter ctrl+c esc"
	if strings.Join(got, " ") != want {
		t.Errorf("got %q, want %q", strings.Join(got, " "), want)
	}
}

func stripFooter(s string) string {
	l := strings.Split(s, "\n")
	return strings.Join(l[:len(l)-1], "\n")
}
