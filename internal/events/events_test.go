package events

import (
	"strings"
	"testing"
	"time"
)

func TestClean(t *testing.T) {
	rlo := string(rune(0x202e)) // right-to-left override
	csi := string(rune(0x9b))   // C1 control
	bs := `\`
	cases := map[string]string{
		"plain text ✓":       "plain text ✓",
		"a\x1b[1A\x1b[2Kb":   `a\x1b[1A\x1b[2Kb`,
		"line1\nline2\rx":    `line1\x0aline2\x0dx`,
		"evil" + rlo + "gnp": "evil" + bs + "u202egnp",
		"c1" + csi + "csi":   "c1" + bs + "x9bcsi",
		"bad\xffutf8":        "bad" + bs + "ufffdutf8",
	}
	for in, want := range cases {
		if got := Clean(in); got != want {
			t.Errorf("Clean(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFormatHasNoRawControls(t *testing.T) {
	line := Format(Event{Time: time.Now(), Level: LevelOK, Action: "connect", Actor: "x", Target: "/tmp/\x1b[2K", Msg: "r\n✓ fake"}, false)
	if strings.ContainsAny(line, "\x1b\n\r") {
		t.Fatalf("raw control in %q", line)
	}
}

func TestLogAttachAndSubscribe(t *testing.T) {
	var stored []Event
	l := New(nil, false)
	l.Emit(Event{Level: LevelInfo, Action: "before-attach"})
	l.Attach(func(e Event) error { stored = append(stored, e); return nil })
	if len(stored) != 1 || stored[0].Action != "before-attach" {
		t.Fatalf("pending event not flushed on attach: %+v", stored)
	}
	past, ch, cancel, err := l.Subscribe(func() ([]Event, error) { return append([]Event(nil), stored...), nil })
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	l.Emit(Event{Level: LevelOK, Action: "live"})
	if len(past) != 1 {
		t.Fatalf("history: %+v", past)
	}
	if e := <-ch; e.Action != "live" {
		t.Fatalf("live event: %+v", e)
	}
	if len(stored) != 2 {
		t.Fatalf("live event not persisted: %+v", stored)
	}
	l.Detach()
	l.Emit(Event{Level: LevelOK, Action: "after-detach"})
	if len(stored) != 2 {
		t.Fatal("persisted after detach")
	}
}
