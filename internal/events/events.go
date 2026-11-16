// Package events is the audit/event log: JSON lines on disk, colored lines
// on the terminal. Events never contain secret values.
package events

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	LevelInfo  = "info"
	LevelOK    = "ok"
	LevelDeny  = "deny"
	LevelWarn  = "warn"
	LevelAlert = "alert"
)

type Event struct {
	Time   time.Time `json:"time"`
	Level  string    `json:"level"`
	Action string    `json:"action"`
	Actor  string    `json:"actor,omitempty"`
	Target string    `json:"target,omitempty"`
	Msg    string    `json:"msg,omitempty"`
}

// Log fans events out to the store (once the vault is open), an optional
// plain-text writer, and subscribers such as the dashboard. Events emitted
// before the store is attached are kept and written when it is.
type Log struct {
	mu      sync.Mutex
	persist func(Event) error
	pending []Event
	subs    map[chan Event]struct{}
	out     io.Writer
	color   bool
}

const maxPending = 1000

// New returns a log that also prints each event to out (nil: don't print).
func New(out io.Writer, color bool) *Log {
	return &Log{out: out, color: color, subs: map[chan Event]struct{}{}}
}

func (l *Log) Emit(e Event) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.persist == nil || l.persist(e) != nil {
		if len(l.pending) < maxPending {
			l.pending = append(l.pending, e)
		}
	}
	if l.out != nil {
		fmt.Fprintln(l.out, Format(e, l.color))
	}
	for ch := range l.subs {
		select {
		case ch <- e:
		default: // subscriber is behind; it still has the store for history
		}
	}
}

// Attach starts persisting events with persist, after writing the ones
// emitted so far.
func (l *Log) Attach(persist func(Event) error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	kept := l.pending[:0]
	for _, e := range l.pending {
		if persist(e) != nil {
			kept = append(kept, e)
		}
	}
	l.pending, l.persist = kept, persist
}

// Detach stops persisting (before the store closes).
func (l *Log) Detach() {
	l.mu.Lock()
	l.persist = nil
	l.mu.Unlock()
}

// SetOutput changes where events are printed (nil: nowhere).
func (l *Log) SetOutput(out io.Writer, color bool) {
	l.mu.Lock()
	l.out, l.color = out, color
	l.mu.Unlock()
}

// Subscribe returns history() and a channel of every event emitted after it,
// with nothing lost or repeated in between. cancel stops the subscription.
func (l *Log) Subscribe(history func() ([]Event, error)) (past []Event, ch <-chan Event, cancel func(), err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if past, err = history(); err != nil {
		return nil, nil, nil, err
	}
	c := make(chan Event, 4096)
	l.subs[c] = struct{}{}
	return past, c, func() {
		l.mu.Lock()
		delete(l.subs, c)
		l.mu.Unlock()
	}, nil
}

const (
	reset   = "\x1b[0m"
	bold    = "\x1b[1m"
	dim     = "\x1b[2m"
	red     = "\x1b[31m"
	green   = "\x1b[32m"
	yellow  = "\x1b[33m"
	blue    = "\x1b[34m"
	magenta = "\x1b[35m"
	cyan    = "\x1b[36m"
)

var levelStyle = map[string][2]string{
	LevelInfo:  {"•", cyan},
	LevelOK:    {"✓", green},
	LevelDeny:  {"✗", red},
	LevelWarn:  {"!", yellow},
	LevelAlert: {"‼", bold + red},
}

// Format renders one event as a single readable line. Fields are cleaned:
// they carry text written by agents.
func Format(e Event, color bool) string {
	e.Action, e.Actor, e.Target, e.Msg = Clean(e.Action), Clean(e.Actor), Clean(e.Target), Clean(e.Msg)
	st, ok := levelStyle[e.Level]
	if !ok {
		st = [2]string{"·", ""}
	}
	c := func(code, s string) string {
		if !color || code == "" {
			return s
		}
		return code + s + reset
	}
	var b strings.Builder
	b.WriteString(c(dim, e.Time.Local().Format("15:04:05")))
	b.WriteString("  ")
	b.WriteString(c(st[1], st[0]))
	b.WriteString(" ")
	b.WriteString(c(bold+st[1], fmt.Sprintf("%-14s", e.Action)))
	b.WriteString(" ")
	b.WriteString(c(magenta, fmt.Sprintf("%-22s", e.Target)))
	b.WriteString(" ")
	b.WriteString(c(blue, e.Actor))
	if e.Msg != "" {
		b.WriteString("  ")
		b.WriteString(c(dim, e.Msg))
	}
	return b.String()
}

// Clean makes text safe to print on a terminal: control characters
// (including ESC, CR and newlines) and bidirectional overrides are shown as
// escapes instead of being interpreted, so agent-written text can't move the
// cursor, recolor, erase or fake lines.
func Clean(s string) string {
	clean := true
	for _, r := range s {
		if unsafeRune(r) {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		if unsafeRune(r) {
			if r <= 0xff {
				fmt.Fprintf(&b, `\x%02x`, r)
			} else {
				fmt.Fprintf(&b, `\u%04x`, r)
			}
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func unsafeRune(r rune) bool {
	return unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) || r == utf8.RuneError
}
