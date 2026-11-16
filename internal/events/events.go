// Package events is the audit/event log: JSON lines on disk, colored lines
// on the terminal. Events never contain secret values.
package events

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
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

type Log struct {
	mu    sync.Mutex
	f     *os.File
	out   io.Writer
	color bool
}

func Open(path string, out io.Writer, color bool) (*Log, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &Log{f: f, out: out, color: color}, nil
}

func (l *Log) Emit(e Event) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	b, _ := json.Marshal(e)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.f.Write(append(b, '\n'))
	if l.out != nil {
		fmt.Fprintln(l.out, Format(e, l.color))
	}
}

func (l *Log) Close() error { return l.f.Close() }

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

// Format renders one event as a single readable line.
func Format(e Event, color bool) string {
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

// Tail prints the last n events of path, then keeps following if follow.
func Tail(path string, n int, follow bool, w io.Writer, color bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	r := bufio.NewReader(f)
	var lines []string
	var partial string
	for {
		line, err := r.ReadString('\n')
		if err == io.EOF {
			partial = line
			break
		}
		if err != nil {
			return err
		}
		lines = append(lines, line)
		if n > 0 && len(lines) > n {
			lines = lines[1:]
		}
	}
	print := func(line string) {
		var e Event
		if json.Unmarshal([]byte(line), &e) == nil {
			fmt.Fprintln(w, Format(e, color))
		}
	}
	for _, l := range lines {
		print(l)
	}
	if !follow {
		return nil
	}
	for {
		line, err := r.ReadString('\n')
		partial += line
		if err == io.EOF {
			time.Sleep(300 * time.Millisecond)
			continue
		}
		if err != nil {
			return err
		}
		print(partial)
		partial = ""
	}
}
