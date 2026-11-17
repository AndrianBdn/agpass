// Package dashboard is the `agpass serve` terminal UI: a live, scrollable
// view of the audit log with a status header.
//
// It is deliberately view-only. Agents may be able to type into the
// terminal (tmux send-keys) and read the screen, so no key here grants
// access or shows a secret. The worst a keypress can do is
// stop the server, and that takes q twice.
//
// It drives the terminal directly (raw mode + ANSI) instead of using a TUI
// framework: the CLI is one binary, and frameworks that probe the terminal
// at init would slow down every agpass command.
package dashboard

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/charmbracelet/x/ansi"
	"golang.org/x/term"

	"agpass/internal/events"
)

// Source is what the dashboard shows.
type Source struct {
	Title   string                         // e.g. "agpass 0.1.0 · ~/.local/share/agpass"
	Log     *events.Log                    // live events
	History func() ([]events.Event, error) // past events, oldest first
	Status  func() string                  // one-line summary, refreshed every 2s
}

const maxEvents = 20000

// Run shows the dashboard on the terminal until the user quits or ctx is
// cancelled.
func Run(ctx context.Context, src Source) error {
	past, ch, cancel, err := src.Log.Subscribe(src.History)
	if err != nil {
		return err
	}
	defer cancel()
	m := &model{src: src, status: src.Status()}
	for _, e := range past {
		m.add(e)
	}

	in, out := int(os.Stdin.Fd()), os.Stdout
	old, err := term.MakeRaw(in)
	if err != nil {
		return err
	}
	defer term.Restore(in, old)
	io.WriteString(out, "\x1b[?1049h\x1b[?25l") // alternate screen, hide cursor
	defer io.WriteString(out, "\x1b[?25h\x1b[?1049l")

	keys := make(chan string, 64)
	go readKeys(os.Stdin, keys)
	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	defer signal.Stop(winch)
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()

	resize := func() {
		if w, h, err := term.GetSize(int(out.Fd())); err == nil {
			m.w, m.h = w, h
		}
	}
	resize()
	for {
		io.WriteString(out, m.frame())
		select {
		case <-ctx.Done():
			return nil
		case e := <-ch:
			m.onEvent(e)
			for drained := false; !drained; { // batch bursts into one redraw
				select {
				case e := <-ch:
					m.onEvent(e)
				default:
					drained = true
				}
			}
		case k, ok := <-keys:
			if !ok || m.key(k) {
				return nil
			}
		case <-winch:
			resize()
		case <-tick.C:
			m.status = src.Status()
		}
	}
}

// readKeys turns raw terminal input into key names: "up", "down", "pgup",
// "pgdown", "home", "end", "enter", "esc", "backspace", "ctrl+c", "ctrl+u",
// "ctrl+d", or the typed text.
func readKeys(r io.Reader, out chan<- string) {
	defer close(out)
	buf := make([]byte, 256)
	seqs := map[string]string{
		"\x1b[A": "up", "\x1b[B": "down", "\x1bOA": "up", "\x1bOB": "down",
		"\x1b[5~": "pgup", "\x1b[6~": "pgdown",
		"\x1b[H": "home", "\x1b[1~": "home", "\x1bOH": "home",
		"\x1b[F": "end", "\x1b[4~": "end", "\x1bOF": "end",
	}
	for {
		n, err := r.Read(buf)
		if err != nil {
			return
		}
		s := string(buf[:n])
		for len(s) > 0 {
			if s[0] == 0x1b {
				if len(s) == 1 {
					out <- "esc"
					break
				}
				matched := false
				for seq, name := range seqs {
					if strings.HasPrefix(s, seq) {
						out <- name
						s = s[len(seq):]
						matched = true
						break
					}
				}
				if !matched { // unknown sequence: drop the rest of this read
					break
				}
				continue
			}
			switch c := s[0]; c {
			case '\r', '\n':
				out <- "enter"
			case 0x7f, 0x08:
				out <- "backspace"
			case 0x03:
				out <- "ctrl+c"
			case 0x15:
				out <- "ctrl+u"
			case 0x04:
				out <- "ctrl+d"
			default:
				if c >= 0x20 {
					r := []rune(s)
					out <- string(r[0])
					s = s[len(string(r[0])):]
					continue
				}
			}
			s = s[1:]
		}
	}
}

type model struct {
	src    Source
	all    []events.Event
	counts map[string]int // per level, over loaded events
	status string
	w, h   int

	scroll    int // rendered lines scrolled up from the bottom; 0 = follow
	unseen    int // events that arrived while scrolled up
	filtering bool
	filter    string
	quitArmed bool
}

func (m *model) add(e events.Event) {
	if m.counts == nil {
		m.counts = map[string]int{}
	}
	m.all = append(m.all, e)
	if len(m.all) > maxEvents {
		m.all = m.all[len(m.all)-maxEvents:]
	}
	m.counts[e.Level]++
	if e.Action == "reveal" {
		m.counts["reveal"]++
	}
}

func (m *model) onEvent(e events.Event) {
	m.add(e)
	if m.scroll > 0 && m.matches(e) {
		m.scroll++ // keep the view still while the user reads history
		m.unseen++
	}
}

// key handles one key and reports whether to quit.
func (m *model) key(k string) bool {
	if m.filtering {
		switch k {
		case "enter":
			m.filtering = false
		case "esc", "ctrl+c":
			m.filtering, m.filter = false, ""
		case "backspace":
			if r := []rune(m.filter); len(r) > 0 {
				m.filter = string(r[:len(r)-1])
			}
		default:
			if len([]rune(k)) == 1 {
				m.filter += k
			}
		}
		m.scroll, m.unseen = 0, 0
		return false
	}
	if k == "q" || k == "ctrl+c" {
		if m.quitArmed {
			return true
		}
		m.quitArmed = true
		return false
	}
	m.quitArmed = false
	page := max(m.rows()-1, 1)
	switch k {
	case "up", "k":
		m.scroll++
	case "down", "j":
		m.scroll--
	case "pgup", "b", "ctrl+u":
		m.scroll += page
	case "pgdown", " ", "ctrl+d":
		m.scroll -= page
	case "home", "g":
		m.scroll = 1 << 30
	case "end", "G":
		m.scroll = 0
	case "/":
		m.filtering = true
	case "esc":
		m.filter = ""
		m.scroll = 0
	}
	if m.scroll <= 0 {
		m.scroll, m.unseen = 0, 0
	}
	return false
}

func (m *model) matches(e events.Event) bool {
	if m.filter == "" {
		return true
	}
	return strings.Contains(strings.ToLower(events.Format(e, false)), strings.ToLower(m.filter))
}

// rows is the number of log lines that fit between header and footer.
func (m *model) rows() int { return max(m.h-5, 1) }

const (
	reset  = "\x1b[0m"
	bold   = "\x1b[1m"
	faint  = "\x1b[2m"
	red    = "\x1b[31m"
	yellow = "\x1b[1;33m"
	title  = "\x1b[1;30;46m" // bold black on cyan
)

func style(code, s string) string { return code + s + reset }

// frame renders the whole screen, ready to write to the terminal.
func (m *model) frame() string {
	var b strings.Builder
	b.WriteString("\x1b[H") // home; every line clears its rest, no flicker
	for i, l := range m.view() {
		if i > 0 {
			b.WriteString("\r\n")
		}
		b.WriteString(l)
		b.WriteString(reset + "\x1b[K")
	}
	return b.String()
}

// view returns the screen as m.h lines, each at most m.w cells wide.
func (m *model) view() []string {
	if m.w <= 0 || m.h <= 0 {
		return nil
	}
	rule := style(faint, strings.Repeat("─", m.w))
	out := []string{
		style(title, pad(" "+m.src.Title, m.w)),
		fit(m.statusLine(), m.w),
		rule,
	}
	lines := m.render()
	rows := m.rows()
	m.scroll = min(m.scroll, max(len(lines)-rows, 0))
	end := len(lines) - m.scroll
	shown := lines[max(end-rows, 0):end]
	for i := range rows {
		l := ""
		if i < len(shown) {
			l = fit(shown[i], m.w)
		}
		out = append(out, l)
	}
	out = append(out, rule, fit(m.footer(len(lines)), m.w))
	return out[:min(len(out), m.h)]
}

func (m *model) statusLine() string {
	s := " " + m.status
	if n := m.counts[events.LevelDeny]; n > 0 {
		s += " · " + style(red, fmt.Sprintf("%d denied", n))
	}
	if n := m.counts["reveal"]; n > 0 {
		s += " · " + style(yellow, fmt.Sprintf("%d reveals", n))
	}
	if n := m.counts[events.LevelAlert]; n > 0 {
		s += " · " + style(yellow, fmt.Sprintf("%d alerts", n))
	}
	return s
}

// render turns the matching events into lines, with a rule at each new day.
func (m *model) render() []string {
	var out []string
	var day string
	for _, e := range m.all {
		if !m.matches(e) {
			continue
		}
		if d := e.Time.Local().Format("Mon 2 Jan 2006"); d != day {
			day = d
			out = append(out, style(faint, "── "+d+" ──"))
		}
		out = append(out, events.Format(e, true))
	}
	return out
}

func (m *model) footer(total int) string {
	switch {
	case m.quitArmed:
		return style(yellow, " Press q again to stop the agpass server") + style(faint, " (any other key cancels)")
	case m.filtering:
		return " " + style(bold, "/") + " " + events.Clean(m.filter) + "▏" + style(faint, "  enter apply · esc clear")
	}
	help := style(faint, " ↑↓ scroll · g/G top/bottom · / filter · q quit")
	var tags []string
	if m.filter != "" {
		tags = append(tags, style(bold, "filter: ")+events.Clean(m.filter)+style(faint, " (esc clears)"))
	}
	if m.scroll > 0 {
		t := fmt.Sprintf("paused %d/%d", total-m.scroll, total)
		if m.unseen > 0 {
			t += fmt.Sprintf(" · %d new below", m.unseen)
		}
		tags = append(tags, style(yellow, t))
	}
	if len(tags) > 0 {
		return " " + strings.Join(tags, "  ") + "  " + help
	}
	return help
}

func fit(s string, w int) string { return ansi.Truncate(s, w, "…") }

func pad(s string, w int) string {
	s = ansi.Truncate(s, w, "…")
	if n := ansi.StringWidth(s); n < w {
		s += strings.Repeat(" ", w-n)
	}
	return s
}
