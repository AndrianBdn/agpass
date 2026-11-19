// Package cli implements the agpass command line.
package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	stdlog "log"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/spf13/pflag"
	"golang.org/x/sys/unix"
	"golang.org/x/term"

	"agpass/internal/api"
	"agpass/internal/client"
	"agpass/internal/config"
	"agpass/internal/dashboard"
	"agpass/internal/events"
	"agpass/internal/server"
	"agpass/internal/vault"
)

const usage = `agpass — local secrets broker for AI agents

Human:
  agpass setup                     create the vault and configure the LLM gatekeeper (interactive)
  agpass serve                     run the server in a terminal tab: asks for the master
                                   password (or reads it from 1Password, see Config), then
                                   shows the live event log
  agpass mint                      one-time code that gives one Claude session admin access
                                   (all folders incl. SYSTEM) for 1 hour
  Any command below also works for the human: it asks for the master password
  (or pass --admin). With 1Password in the config, agpass reads it from there;
  --manual types it instead.

Agent (run inside Claude Code; each Claude process gets its own session automatically):
  agpass connect --reason "what you work on and why you need secrets"
                                   get the folders of this repository (and others the gatekeeper allows)
      --create [--name N] [--desc D]   no folder for this repository yet? create one and get it
      --folder F                   a folder you think you need (repeatable)
  agpass elevate <code>            admin access for this session, with a code the user minted
  agpass whoami                    show this session and its folders
  agpass list [folder]             list folders and items (no values)
  agpass get folder/item           show an item, secrets redacted as [REDACTED_AGPASS]
      --field KEY                  print one field's value only
      --reveal                     include secret values (logged)
      --json                       JSON output (works well with jq)
  agpass set folder/item key[:type]=value ... [--rm key]
                                   types: text (default), sensitive, password, url
                                   value "-" reads the value from the terminal/stdin
  agpass folder create NAME --project P [--desc D] [--repo R ...]
                                   --repo: repositories whose sessions get the folder
                                   (agents: always their own repository)
  agpass folder edit NAME [--project P] [--desc D] [--repo R ...] [--rm-repo R ...]
                                   --repo links one more repository, --rm-repo unlinks one;
                                   the other links stay (agents: only their own repository)

SSH agent (one shared key, used through agpass; see agpass ssh help):
  agpass ssh keygen | import FILE  create or import the key (human)
  agpass ssh key                   public key to add on GitHub or servers
  agpass ssh allow --host H --reason R   let this session use the key for host H
  agpass ssh unpin HOST            forget a host's pinned keys after it changed them (human)
  GIT_SSH_COMMAND="$(agpass ssh command)" git push

Data: $AGPASS_DIR, else $XDG_DATA_HOME/agpass, else ~/.local/share/agpass
Config: $AGPASS_DIR/config.toml, else $XDG_CONFIG_HOME/agpass/config.toml,
        else ~/.config/agpass/config.toml (optional; see README)
`

func Run(args []string) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Print(usage)
		return 0
	}
	cmd, rest := args[0], args[1:]
	if cmd == "folder" || cmd == "ssh" {
		if len(rest) == 0 || rest[0] == "help" || rest[0] == "-h" || rest[0] == "--help" {
			if cmd == "ssh" {
				fmt.Print(sshUsage)
				return 0
			}
			fmt.Fprint(os.Stderr, "usage: agpass folder create|edit NAME ...\n")
			return 2
		}
		cmd, rest = cmd+" "+rest[0], rest[1:]
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
		"serve":         cmdServe,
		"setup":         cmdSetup,
		"ssh keygen":    cmdSSHKeygen,
		"ssh import":    cmdSSHImport,
		"ssh key":       cmdSSHKey,
		"ssh allow":     cmdSSHAllow,
		"ssh unpin":     cmdSSHUnpin,
		"ssh command":   cmdSSHCommand,
		"mint":          cmdMint,
		"elevate":       cmdElevate,
		"connect":       cmdConnect,
		"whoami":        cmdWhoami,
		"list":          cmdList,
		"ls":            cmdList,
		"get":           cmdGet,
		"set":           cmdSet,
		"folder create": cmdFolderCreate,
		"folder edit":   cmdFolderEdit,
		"version":       func([]string) error { fmt.Println("agpass", api.Version); return nil },
	}
}

// ---- shared helpers ----

// dataDir is $AGPASS_DIR, else $XDG_DATA_HOME/agpass, else
// ~/.local/share/agpass.
func dataDir() string {
	if d := os.Getenv("AGPASS_DIR"); d != "" {
		return d
	}
	if d := os.Getenv("XDG_DATA_HOME"); filepath.IsAbs(d) {
		return filepath.Join(d, "agpass")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "share", "agpass")
}

func flags(name string) (*pflag.FlagSet, *bool) {
	fs := pflag.NewFlagSet(name, pflag.ContinueOnError)
	admin := fs.Bool("admin", false, "authenticate with the master password")
	addManualFlag(fs)
	return fs, admin
}

type conn struct {
	*client.Client
	login bool // send the master password from the first request on (--admin)
}

func newConn(admin bool) (*conn, error) {
	return &conn{Client: client.New(server.SocketPath(dataDir())), login: admin}, nil
}

// call sends a request, with the master password when the command asked for
// it (--admin, mint, ...). A request refused for not being an agent is
// retried with the master password only for a human at a terminal, not for
// a detached process.
func (c *conn) call(method, path string, q url.Values, body, out any) error {
	do := func() error { return c.Do(method, path, q, body, out) }
	if c.login && c.Master == "" {
		return c.withLogin(do)
	}
	err := do()
	if c.Master == "" && apiCode(err) == api.ErrNeedAdmin && isTTY(os.Stdin) {
		return c.withLogin(do)
	}
	return err
}

// withLogin gets the master password (1Password or typed) and runs do with
// it, retrying while the server says it is wrong.
func (c *conn) withLogin(do func() error) error {
	var last error
	err := withMasterPassword(func(pw string) (bool, error) {
		c.Master = pw
		last = do()
		return apiCode(last) == api.ErrWrongMaster, last
	})
	if err != nil {
		c.Master = ""
	}
	return err
}

func apiCode(err error) string {
	var ae *api.Error
	if errors.As(err, &ae) {
		return ae.Code
	}
	return ""
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

// clean escapes control characters in text that may come from agents.
// Raw output (--field, --json) is left untouched for pipes.
func clean(s string) string { return events.Clean(s) }

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func color() bool { return isTTY(os.Stdout) && os.Getenv("NO_COLOR") == "" }

func cwd() string { d, _ := os.Getwd(); return d }

// ---- serve ----

func cmdServe(args []string) error {
	fs := pflag.NewFlagSet("serve", pflag.ContinueOnError)
	rollback := fs.Bool("accept-rollback", false, "open a database older than the last one seen")
	pwStdin := fs.Bool("password-stdin", false, "read the master password from stdin (no dashboard; log lines on stdout)")
	addManualFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}) // no core dumps of decrypted memory
	// Libraries (net/http, the SSH agent) report errors through the standard
	// logger; agpass reports through its event log, and stray lines would
	// draw over the dashboard.
	stdlog.SetOutput(io.Discard)

	dir := dataDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	interactive := !*pwStdin && isTTY(os.Stdin) && isTTY(os.Stdout)
	onePassword := false
	if !*pwStdin { // --password-stdin doesn't use the config
		// A broken config only matters without a terminal: at one,
		// masterPassword reports it and asks for the password.
		op, err := onePasswordConfig()
		if err != nil && !interactive {
			return err
		}
		onePassword = err == nil && op.MasterPassword != ""
	}
	if isTTY(os.Stdout) {
		// Push the current title on the xterm title stack and set ours. On
		// exit, clear it first (terminals without a title stack, like
		// Ghostty, then fall back to their default title), then pop (where
		// supported, this restores the exact previous title).
		fmt.Print("\x1b[22;0t\x1b]0;" + serveTitle + "\x07")
		defer fmt.Print("\x1b]0;\x07\x1b[23;0t")
	}
	if !interactive && manualPassword && !*pwStdin {
		return fmt.Errorf("--manual needs a terminal to type the password in (or pass --password-stdin)")
	}
	if !interactive && !*pwStdin && !onePassword {
		return fmt.Errorf("run `agpass serve` in a terminal, pass --password-stdin, or set [onepassword] in %s", tildePath(config.Path()))
	}
	// The dashboard shows events itself; without it, print them as lines.
	log := events.New(nil, false)
	if !interactive {
		log.SetOutput(os.Stdout, color())
	}
	srv := server.New(dir, log)
	srv.AllowRollback = *rollback

	fmt.Printf("agpass %s · %s\n", api.Version, tildePath(dir))
	newVault := !vault.Exists(server.KeyPath(dir))
	switch {
	case newVault:
		return fmt.Errorf("no vault in %s yet: run `agpass setup` first", tildePath(dir))
	case interactive || onePassword:
		if err := unlockServer(srv); err != nil {
			return err
		}
	default:
		pw, err := readPassword("")
		if err != nil {
			return err
		}
		if err := srv.Unlock(pw); err != nil {
			return err
		}
	}
	if err := srv.Listen(); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if !interactive {
		return srv.Serve(ctx)
	}

	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- srv.Serve(sctx) }()
	derr := dashboard.Run(sctx, dashboard.Source{
		Title:   fmt.Sprintf("agpass %s · %s", api.Version, tildePath(dir)),
		Log:     log,
		History: func() ([]events.Event, error) { return srv.History(5000) },
		Status:  func() string { return statusLine(srv) },
	})
	// Back on the normal screen: show the shutdown as plain lines.
	log.SetOutput(os.Stdout, color())
	cancel()
	serr := <-served
	if derr != nil {
		return derr
	}
	return serr
}

// unlockServer unlocks the vault with the master password from 1Password or
// typed, up to three tries.
func unlockServer(srv *server.Server) error {
	return withMasterPassword(func(pw string) (bool, error) {
		err := srv.Unlock(pw)
		return errors.Is(err, vault.ErrWrongPassword), err
	})
}

// serveTitle is the terminal tab/window title while `agpass serve` runs.
const serveTitle = "🔐 AgPass Serve"

func statusLine(srv *server.Server) string {
	st, err := srv.Status()
	if err != nil {
		return "status unavailable: " + err.Error()
	}
	s := fmt.Sprintf("● serving · %d live sessions (%d total) · %d folders · %d items", st.LiveSess, st.Sessions, st.Folders, st.Items)
	if st.AdminSess > 0 {
		s += fmt.Sprintf(" · ‼ %d admin", st.AdminSess)
	}
	if st.Gatekeeper != "" {
		s += " · gatekeeper " + st.Gatekeeper
	} else {
		s += " · gatekeeper off (agpass setup)"
	}
	return s
}

func tildePath(p string) string {
	if home, err := os.UserHomeDir(); err == nil && strings.HasPrefix(p, home+"/") {
		return "~" + p[len(home):]
	}
	return p
}

// ---- agent session ----

func cmdConnect(args []string) error {
	fs := pflag.NewFlagSet("connect", pflag.ContinueOnError)
	reason := fs.String("reason", "", "what you are working on and why you need secrets (required)")
	folders := fs.StringArray("folder", nil, "folder you think you need (repeatable)")
	create := fs.Bool("create", false, "create a folder for this repository if it has none")
	name := fs.String("name", "", "name of the folder --create makes (default: repository name)")
	desc := fs.String("desc", "", "description of the folder --create makes: what secrets it holds")
	repo := fs.String("repo", "", "repository you work on, if not the one in the current directory (informational)")
	asJSON := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("connect takes no arguments (codes are no longer needed); use --reason")
	}
	c := client.New(server.SocketPath(dataDir()))
	var resp api.AccessResponse
	req := api.AccessRequest{Repo: *repo, Reason: *reason, Folders: *folders, Create: *create, Name: *name, Description: *desc}
	if err := c.Do("POST", "/v1/connect", nil, req, &resp); err != nil {
		return err
	}
	if *asJSON {
		return printJSON(resp)
	}
	s := resp.Session
	fmt.Printf("Connected: session %s (%s pid %d) · repo %s\n", s.ID, s.Agent, s.PID, orDash(clean(s.Repo)))
	if resp.Created != "" {
		fmt.Printf("created  %s for this repository\n", clean(resp.Created))
	}
	for _, g := range resp.Granted {
		fmt.Printf("granted  %-20s (%s)\n", clean(g.Folder), clean(g.By))
	}
	for _, d := range resp.Denied {
		fmt.Printf("denied   %s\n", clean(d))
	}
	if resp.Explanation != "" {
		fmt.Println("\n" + clean(strings.TrimSpace(resp.Explanation)))
	}
	fmt.Println()
	printGrants(s.Grants)
	if len(s.Grants) == 0 && !*create {
		fmt.Println(`No folder for this repository yet? Run again with --create --desc "<what secrets it will hold>".`)
	}
	return nil
}

func cmdMint(args []string) error {
	fs := pflag.NewFlagSet("mint", pflag.ContinueOnError)
	addManualFlag(fs)
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
	fmt.Printf("Admin code: %s  (single use, redeem by %s)\n\n", m.Code, m.ExpiresAt.Local().Format("15:04"))
	fmt.Printf("It gives one Claude session access to every folder, SYSTEM included, for %s.\n", server.ElevateDuration)
	fmt.Printf("Tell Claude:\n  run `agpass elevate %s`\n", m.Code)
	return nil
}

func cmdElevate(args []string) error {
	fs := pflag.NewFlagSet("elevate", pflag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: agpass elevate <code>   (the user creates the code with `agpass mint`)")
	}
	c := client.New(server.SocketPath(dataDir()))
	var info api.SessionInfo
	if err := c.Do("POST", "/v1/elevate", nil, api.ElevateRequest{Code: fs.Arg(0)}, &info); err != nil {
		return err
	}
	until := "?"
	if info.AdminUntil != nil {
		until = info.AdminUntil.Local().Format("15:04")
	}
	fmt.Printf("Admin access for session %s (%s pid %d) until %s: every folder, SYSTEM included.\n", info.ID, info.Agent, info.PID, until)
	fmt.Println("Every action is logged on the user's dashboard. Use it only for what the user asked.")
	return nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
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
	if s.AdminUntil != nil {
		fmt.Printf("ADMIN until %s: every folder, SYSTEM included\n", s.AdminUntil.Local().Format("15:04"))
	}
	if s.Repo != "" || s.Cwd != "" {
		fmt.Printf("repo %s · cwd %s\n", orDash(clean(s.Repo)), clean(s.Cwd))
	}
	printGrants(s.Grants)
	if len(s.SSHHosts) > 0 {
		fmt.Println("SSH:")
		for _, g := range s.SSHHosts {
			fmt.Printf("  %-20s %s\n", clean(g.Host), clean(g.By))
		}
	}
	return nil
}

func printGrants(gs []api.Grant) {
	if len(gs) == 0 {
		fmt.Println("No folders granted yet.")
		return
	}
	fmt.Println("Folders:")
	for _, g := range gs {
		fmt.Printf("  %-20s %s\n", clean(g.Folder), clean(g.By))
	}
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
		fmt.Printf("%s  (project: %s)", clean(f.Name), clean(f.Project))
		if len(f.Repos) > 0 {
			fmt.Printf("  repos: %s", clean(strings.Join(f.Repos, ", ")))
		}
		fmt.Println()
		if f.Description != "" {
			fmt.Printf("  %s\n", clean(f.Description))
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
			names = append(names, fmt.Sprintf("%s (%s)", clean(o.Name), clean(o.Project)))
		}
		fmt.Printf("\nOther folders (agpass connect --folder NAME): %s\n", strings.Join(names, ", "))
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
	fmt.Printf("%s/%s  v%d · updated %s by %s\n", it.Folder, it.Name, it.Version, it.UpdatedAt.Local().Format("2006-01-02 15:04"), clean(it.UpdatedBy))
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	for _, f := range it.Fields {
		fmt.Fprintf(tw, "  %s\t%s\t%s\n", f.Key, clean(f.Type), clean(f.Value))
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
	repos := fs.StringArray("repo", nil, "repository whose sessions get this folder automatically (repeatable)")
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
	repos := fs.StringArray("repo", nil, "link a repository: its sessions get this folder (repeatable; other links stay)")
	rmRepos := fs.StringArray("rm-repo", nil, "unlink a repository (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: agpass folder edit NAME [--project P] [--desc D] [--repo R ...] [--rm-repo R ...]")
	}
	for _, r := range slices.Concat(*repos, *rmRepos) {
		if strings.TrimSpace(r) == "" {
			return fmt.Errorf("empty repository: --repo links one repository and --rm-repo unlinks one (--repo '' no longer clears the list)")
		}
	}
	req := api.FolderRequest{Name: fs.Arg(0), AddRepos: *repos, RemoveRepos: *rmRepos}
	if fs.Changed("project") {
		req.Project = project
	}
	if fs.Changed("desc") {
		req.Description = desc
	}
	if req.Project == nil && req.Description == nil && len(req.AddRepos)+len(req.RemoveRepos) == 0 {
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
	fmt.Printf("updated folder %s", f.Name)
	if len(req.AddRepos)+len(req.RemoveRepos) > 0 {
		fmt.Printf(" · repos: %s", orDash(clean(strings.Join(f.Repos, ", "))))
	}
	fmt.Println()
	return nil
}
