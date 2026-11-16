// Package cli implements the agpass command line.
package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/spf13/pflag"
	"golang.org/x/sys/unix"
	"golang.org/x/term"

	"agpass/internal/api"
	"agpass/internal/client"
	"agpass/internal/events"
	"agpass/internal/server"
	"agpass/internal/vault"
)

const usage = `agpass — local secrets broker for AI agents

Human:
  agpass serve                     run the server in a terminal tab (asks for the master password)
  agpass unlock                    unlock a server started without a terminal
  agpass mint                      create a one-time code that connects one agent session
  agpass log [-f] [-n 50]          show the event log
  Any command below also works for the human: it asks for the master password
  (or pass --admin).

Agent (run inside Claude Code):
  agpass connect <code>            bind this agent session using the code the user gave you
  agpass request-access --reason "what you work on and why you need secrets" [--repo R] [--folder F]
  agpass whoami                    show this session and its folders
  agpass list [folder]             list folders and items (no values)
  agpass get folder/item           show an item, secrets redacted as [REDACTED_AGPASS]
      --field KEY                  print one field's value only
      --reveal                     include secret values (logged)
      --json                       JSON output (works well with jq)
  agpass set folder/item key[:type]=value ... [--rm key]
                                   types: text (default), sensitive, password, url
                                   value "-" reads the value from the terminal/stdin
  agpass folder create NAME --project P [--desc D] [--repo github.com/org/repo]
  agpass folder edit NAME [--project P] [--desc D] [--repo R ...]

Environment: AGPASS_DIR (default ~/.agpass)
`

func Run(args []string) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Print(usage)
		return 0
	}
	cmd, rest := args[0], args[1:]
	if cmd == "folder" {
		if len(rest) == 0 {
			fmt.Fprint(os.Stderr, "usage: agpass folder create|edit NAME ...\n")
			return 2
		}
		cmd, rest = "folder "+rest[0], rest[1:]
	}
	fn, ok := commands[cmd]
	if !ok {
		fmt.Fprintf(os.Stderr, "agpass: unknown command %q (see agpass help)\n", cmd)
		return 2
	}
	if err := fn(rest); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			return 0
		}
		fmt.Fprintf(os.Stderr, "agpass: %v\n", err)
		return 1
	}
	return 0
}

var commands map[string]func([]string) error

func init() {
	commands = map[string]func([]string) error{
		"serve":          cmdServe,
		"unlock":         cmdUnlock,
		"mint":           cmdMint,
		"connect":        cmdConnect,
		"whoami":         cmdWhoami,
		"request-access": cmdRequestAccess,
		"list":           cmdList,
		"ls":             cmdList,
		"get":            cmdGet,
		"set":            cmdSet,
		"folder create":  cmdFolderCreate,
		"folder edit":    cmdFolderEdit,
		"log":            cmdLog,
		"version":        func([]string) error { fmt.Println("agpass", api.Version); return nil },
	}
}

// ---- shared helpers ----

func dataDir() string {
	if d := os.Getenv("AGPASS_DIR"); d != "" {
		return d
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".agpass")
}

func flags(name string) (*pflag.FlagSet, *bool) {
	fs := pflag.NewFlagSet(name, pflag.ContinueOnError)
	admin := fs.Bool("admin", false, "authenticate with the master password")
	return fs, admin
}

type conn struct {
	*client.Client
}

func newConn(admin bool) (*conn, error) {
	c := &conn{client.New(server.SocketPath(dataDir()))}
	if admin {
		pw, err := readPassword("Master password: ")
		if err != nil {
			return nil, err
		}
		c.Master = pw
	}
	return c, nil
}

// call retries once with the master password when the server says the
// caller is not an agent and we are talking to a human at a terminal.
func (c *conn) call(method, path string, q url.Values, body, out any) error {
	err := c.Do(method, path, q, body, out)
	var ae *api.Error
	if errors.As(err, &ae) && ae.Code == api.ErrNeedAdmin && c.Master == "" && isTTY(os.Stdin) {
		pw, perr := readPassword("Master password: ")
		if perr != nil {
			return perr
		}
		c.Master = pw
		return c.Do(method, path, q, body, out)
	}
	return err
}

func isTTY(f *os.File) bool { return term.IsTerminal(int(f.Fd())) }

// stdinLines is shared by every non-terminal read, so a value piped for one
// field doesn't get swallowed by the buffer of a previous read.
var stdinLines = bufio.NewReader(os.Stdin)

func readPassword(prompt string) (string, error) {
	if isTTY(os.Stdin) {
		fmt.Fprint(os.Stderr, prompt)
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		return string(b), err
	}
	line, err := stdinLines.ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("no password on stdin")
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func color() bool { return isTTY(os.Stdout) && os.Getenv("NO_COLOR") == "" }

func cwd() string { d, _ := os.Getwd(); return d }

// ---- serve / unlock / mint / log ----

func cmdServe(args []string) error {
	fs := pflag.NewFlagSet("serve", pflag.ContinueOnError)
	rollback := fs.Bool("accept-rollback", false, "open a database older than the last one seen")
	pwStdin := fs.Bool("password-stdin", false, "read the master password from stdin")
	if err := fs.Parse(args); err != nil {
		return err
	}
	unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}) // no core dumps of decrypted memory

	dir := dataDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	log, err := events.Open(server.EventsPath(dir), os.Stdout, color())
	if err != nil {
		return err
	}
	defer log.Close()
	srv := server.New(dir, log)
	srv.AllowRollback = *rollback

	fmt.Printf("agpass %s · %s\n", api.Version, dir)
	newVault := !vault.Exists(server.KeyPath(dir))
	switch {
	case isTTY(os.Stdin):
		if newVault {
			fmt.Println("No vault yet — choose a master password (it cannot be recovered).")
			pw, err := readPassword("New master password: ")
			if err != nil {
				return err
			}
			if len(pw) < 10 {
				return fmt.Errorf("use at least 10 characters")
			}
			again, err := readPassword("Repeat: ")
			if err != nil {
				return err
			}
			if pw != again {
				return fmt.Errorf("passwords do not match")
			}
			if err := srv.Unlock(pw); err != nil {
				return err
			}
			break
		}
		for tries := 0; ; tries++ {
			pw, err := readPassword("Master password: ")
			if err != nil {
				return err
			}
			err = srv.Unlock(pw)
			if err == nil {
				break
			}
			if !errors.Is(err, vault.ErrWrongPassword) || tries == 2 {
				return err
			}
			fmt.Println("Wrong password.")
		}
	case *pwStdin:
		pw, err := readPassword("")
		if err != nil {
			return err
		}
		if err := srv.Unlock(pw); err != nil {
			return err
		}
	default:
		fmt.Println("No terminal: starting locked — run `agpass unlock`.")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return srv.Serve(ctx)
}

func cmdUnlock(args []string) error {
	pw, err := readPassword("Master password: ")
	if err != nil {
		return err
	}
	c := client.New(server.SocketPath(dataDir()))
	if err := c.Do("POST", "/v1/unlock", nil, api.UnlockRequest{Password: pw}, nil); err != nil {
		return err
	}
	fmt.Println("Unlocked.")
	return nil
}

func cmdMint(args []string) error {
	fs := pflag.NewFlagSet("mint", pflag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := newConn(true)
	if err != nil {
		return err
	}
	var m api.MintResponse
	if err := c.call("POST", "/v1/mint", nil, struct{}{}, &m); err != nil {
		return err
	}
	fmt.Printf("Connect code: %s  (single use, valid until %s)\n\n", m.Code, m.ExpiresAt.Local().Format("15:04"))
	fmt.Printf("Tell your agent:\n  connect to agpass with `agpass connect %s`\n", m.Code)
	return nil
}

func cmdLog(args []string) error {
	fs := pflag.NewFlagSet("log", pflag.ContinueOnError)
	follow := fs.BoolP("follow", "f", false, "keep printing new events")
	n := fs.IntP("lines", "n", 50, "number of past events to show (0 = all)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return events.Tail(server.EventsPath(dataDir()), *n, *follow, os.Stdout, color())
}

// ---- agent session ----

func cmdConnect(args []string) error {
	fs := pflag.NewFlagSet("connect", pflag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: agpass connect <code>")
	}
	c := client.New(server.SocketPath(dataDir()))
	var info api.SessionInfo
	if err := c.Do("POST", "/v1/connect", nil, api.ConnectRequest{Code: fs.Arg(0), Cwd: cwd()}, &info); err != nil {
		return err
	}
	fmt.Printf("Connected: session %s (%s pid %d)\n", info.ID, info.Agent, info.PID)
	if len(info.Grants) == 0 {
		fmt.Println(`Next: agpass request-access --reason "<what you are working on and why you need secrets>"`)
	} else {
		printGrants(info.Grants)
	}
	return nil
}

func cmdWhoami(args []string) error {
	fs, admin := flags("whoami")
	asJSON := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := newConn(*admin)
	if err != nil {
		return err
	}
	var w api.WhoamiResponse
	if err := c.call("GET", "/v1/whoami", nil, nil, &w); err != nil {
		return err
	}
	if *asJSON {
		return printJSON(w)
	}
	if w.Admin {
		fmt.Println("human (master password): full access")
		return nil
	}
	s := w.Session
	fmt.Printf("session %s · %s pid %d · since %s\n", s.ID, s.Agent, s.PID, s.CreatedAt.Local().Format("2006-01-02 15:04"))
	if s.Repo != "" || s.Cwd != "" {
		fmt.Printf("repo %s · cwd %s\n", s.Repo, s.Cwd)
	}
	printGrants(s.Grants)
	return nil
}

func printGrants(gs []api.Grant) {
	if len(gs) == 0 {
		fmt.Println("No folders granted yet.")
		return
	}
	fmt.Println("Folders:")
	for _, g := range gs {
		fmt.Printf("  %-20s %s\n", g.Folder, g.By)
	}
}

func cmdRequestAccess(args []string) error {
	fs := pflag.NewFlagSet("request-access", pflag.ContinueOnError)
	reason := fs.String("reason", "", "what you are working on and why you need secrets (required)")
	repo := fs.String("repo", "", "repository (default: git remote origin of the current directory)")
	folders := fs.StringArray("folder", nil, "folder you think you need (repeatable)")
	asJSON := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *repo == "" {
		out, _ := exec.Command("git", "remote", "get-url", "origin").Output()
		*repo = strings.TrimSpace(string(out))
	}
	c := client.New(server.SocketPath(dataDir()))
	var resp api.AccessResponse
	err := c.Do("POST", "/v1/request-access", nil, api.AccessRequest{Repo: *repo, Reason: *reason, Folders: *folders, Cwd: cwd()}, &resp)
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(resp)
	}
	for _, g := range resp.Granted {
		fmt.Printf("granted  %-20s (%s)\n", g.Folder, g.By)
	}
	for _, d := range resp.Denied {
		fmt.Printf("denied   %s\n", d)
	}
	if len(resp.Granted) == 0 && len(resp.Denied) == 0 {
		fmt.Println("No new folders granted.")
	}
	if resp.Explanation != "" {
		fmt.Println("\n" + resp.Explanation)
	}
	fmt.Println()
	printGrants(resp.Session.Grants)
	return nil
}

// ---- data commands ----

func cmdList(args []string) error {
	fs, admin := flags("list")
	asJSON := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c, err := newConn(*admin)
	if err != nil {
		return err
	}
	q := url.Values{}
	if fs.NArg() > 0 {
		q.Set("folder", fs.Arg(0))
	}
	var resp api.ListResponse
	if err := c.call("GET", "/v1/list", q, nil, &resp); err != nil {
		return err
	}
	if *asJSON {
		return printJSON(resp)
	}
	for i, f := range resp.Folders {
		if i > 0 {
			fmt.Println()
		}
		fmt.Printf("%s  (project: %s)", f.Name, f.Project)
		if len(f.Repos) > 0 {
			fmt.Printf("  repos: %s", strings.Join(f.Repos, ", "))
		}
		fmt.Println()
		if f.Description != "" {
			fmt.Printf("  %s\n", f.Description)
		}
		if len(f.Items) == 0 {
			fmt.Println("  (no items)")
		}
		for _, it := range f.Items {
			var keys []string
			for _, fl := range it.Fields {
				k := fl.Key
				if fl.Type != api.TypeText {
					k += ":" + fl.Type
				}
				keys = append(keys, k)
			}
			fmt.Printf("  - %-24s %s\n", it.Name, strings.Join(keys, ", "))
		}
	}
	if len(resp.Others) > 0 {
		var names []string
		for _, o := range resp.Others {
			names = append(names, fmt.Sprintf("%s (%s)", o.Name, o.Project))
		}
		fmt.Printf("\nOther folders (use request-access): %s\n", strings.Join(names, ", "))
	}
	return nil
}

func cmdGet(args []string) error {
	fs, admin := flags("get")
	reveal := fs.Bool("reveal", false, "include secret values (logged)")
	field := fs.String("field", "", "print only this field's value")
	asJSON := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: agpass get folder/item [--field KEY] [--reveal] [--json]")
	}
	c, err := newConn(*admin)
	if err != nil {
		return err
	}
	q := url.Values{"path": {fs.Arg(0)}}
	if *reveal {
		q.Set("reveal", "1")
	}
	var it api.Item
	if err := c.call("GET", "/v1/item", q, nil, &it); err != nil {
		return err
	}
	if *field != "" {
		for _, f := range it.Fields {
			if f.Key == *field {
				if *asJSON {
					return printJSON(f)
				}
				fmt.Println(f.Value)
				return nil
			}
		}
		return fmt.Errorf("item %s has no field %q", fs.Arg(0), *field)
	}
	if *asJSON {
		return printJSON(it)
	}
	fmt.Printf("%s/%s  v%d · updated %s by %s\n", it.Folder, it.Name, it.Version, it.UpdatedAt.Local().Format("2006-01-02 15:04"), it.UpdatedBy)
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	for _, f := range it.Fields {
		fmt.Fprintf(tw, "  %s\t%s\t%s\n", f.Key, f.Type, f.Value)
	}
	return tw.Flush()
}

func cmdSet(args []string) error {
	fs, admin := flags("set")
	remove := fs.StringArray("rm", nil, "remove a field (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("usage: agpass set folder/item key[:type]=value ... [--rm key]")
	}
	req := api.SetItemRequest{Path: fs.Arg(0), Remove: *remove}
	for _, a := range fs.Args()[1:] {
		kt, val, ok := strings.Cut(a, "=")
		if !ok {
			return fmt.Errorf("bad field %q: use key[:type]=value", a)
		}
		key, typ, _ := strings.Cut(kt, ":")
		if typ == "" {
			typ = api.TypeText
		}
		if val == "-" {
			v, err := readPassword(fmt.Sprintf("Value for %s: ", key))
			if err != nil {
				return err
			}
			val = v
		}
		req.Fields = append(req.Fields, api.Field{Key: key, Type: typ, Value: val})
	}
	c, err := newConn(*admin)
	if err != nil {
		return err
	}
	var it api.Item
	if err := c.call("POST", "/v1/item", nil, req, &it); err != nil {
		return err
	}
	fmt.Printf("saved %s/%s v%d\n", it.Folder, it.Name, it.Version)
	return nil
}

func cmdFolderCreate(args []string) error {
	fs, admin := flags("folder create")
	project := fs.String("project", "", "project this folder is for (required)")
	desc := fs.String("desc", "", "description: what these secrets are and who should use them")
	repos := fs.StringArray("repo", nil, "repository that gets this folder automatically (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: agpass folder create NAME --project P [--desc D] [--repo R]")
	}
	req := api.FolderRequest{Name: fs.Arg(0), Project: project, Description: desc, Repos: repos}
	c, err := newConn(*admin)
	if err != nil {
		return err
	}
	var f api.Folder
	if err := c.call("POST", "/v1/folder", nil, req, &f); err != nil {
		return err
	}
	fmt.Printf("created folder %s (project %s)\n", f.Name, f.Project)
	return nil
}

func cmdFolderEdit(args []string) error {
	fs, admin := flags("folder edit")
	project := fs.String("project", "", "project")
	desc := fs.String("desc", "", "description")
	repos := fs.StringArray("repo", nil, "repositories (replaces the list; repeatable; --repo '' clears)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: agpass folder edit NAME [--project P] [--desc D] [--repo R ...]")
	}
	req := api.FolderRequest{Name: fs.Arg(0)}
	if fs.Changed("project") {
		req.Project = project
	}
	if fs.Changed("desc") {
		req.Description = desc
	}
	if fs.Changed("repo") {
		rs := []string{}
		for _, r := range *repos {
			if r != "" {
				rs = append(rs, r)
			}
		}
		req.Repos = &rs
	}
	if req.Project == nil && req.Description == nil && req.Repos == nil {
		return fmt.Errorf("nothing to change")
	}
	c, err := newConn(*admin)
	if err != nil {
		return err
	}
	var f api.Folder
	if err := c.call("PATCH", "/v1/folder", nil, req, &f); err != nil {
		return err
	}
	fmt.Printf("updated folder %s\n", f.Name)
	return nil
}
