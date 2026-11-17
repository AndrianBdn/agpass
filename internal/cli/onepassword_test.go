package cli

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"agpass/internal/api"
	"agpass/internal/config"
	"agpass/internal/events"
	"agpass/internal/server"
	"agpass/internal/vault"
)

func TestUnquote(t *testing.T) {
	for in, want := range map[string]string{
		`"op://Private/Agpass Master/password"`: "op://Private/Agpass Master/password",
		` 'op://P/I/f' `:                        "op://P/I/f",
		"“AgPass master”":                       "AgPass master",
		"op://P/I/f":                            "op://P/I/f",
	} {
		if got := unquote(in); got != want {
			t.Errorf("unquote(%q) = %q", in, got)
		}
	}
	if got := opArgs(config.OnePassword{MasterPassword: `"op://P/I/f"`}); got[len(got)-1] != "op://P/I/f" {
		t.Errorf("opArgs kept quotes: %q", got)
	}
}

func TestOpArgs(t *testing.T) {
	got := opArgs(config.OnePassword{MasterPassword: "op://Private/AgPass/password", Account: "my.1password.com"})
	want := []string{"read", "--no-newline", "--account", "my.1password.com", "--", "op://Private/AgPass/password"}
	if !slices.Equal(got, want) {
		t.Errorf("reference: %q", got)
	}
	got = opArgs(config.OnePassword{MasterPassword: "-AgPass master"})
	want = []string{"item", "get", "--fields", "label=password", "--reveal", "--format", "json", "--", "-AgPass master"}
	if !slices.Equal(got, want) {
		t.Errorf("item: %q", got)
	}
}

// fakeOp installs an op that records its arguments and prints out.
func fakeOp(t *testing.T, out string, exit int) (argsFile string) {
	t.Helper()
	dir := t.TempDir()
	argsFile = filepath.Join(dir, "args")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > '" + argsFile + "'\nprintf '%s' '" + out + "'\nexit " + string(rune('0'+exit)) + "\n"
	p := filepath.Join(dir, "op")
	if err := os.WriteFile(p, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	old := opCommand
	opCommand = p
	t.Cleanup(func() { opCommand = old })
	return argsFile
}

// opVault makes a vault in a short temp dir (unix socket paths are limited)
// with a config pointing at a 1Password item, and points agpass at it.
func opVault(t *testing.T) (dir string) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "agp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if _, err := vault.Create(server.KeyPath(dir), testPW); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "config.toml"), []byte("[onepassword]\nmaster_password = \"op://Private/AgPass/password\"\n"), 0o600)
	t.Setenv("AGPASS_DIR", dir)
	manualPassword = false
	resetOPConfig(t)
	asAgent(t, "") // a human's terminal; the tests themselves run under Claude
	return dir
}

const testPW = "correct-horse-1"

// Tests run without a terminal, so every 1Password failure is an error
// here; at a terminal the same paths ask for the password instead.
func TestUnlockServerOnePassword(t *testing.T) {
	dir := opVault(t)

	fakeOp(t, "nope\n", 0)
	if err := unlockServer(server.New(dir, events.New(nil, false))); err == nil || !strings.Contains(err.Error(), "not the master password") {
		t.Fatalf("wrong password: %v", err)
	}
	fakeOp(t, "", 1)
	if err := unlockServer(server.New(dir, events.New(nil, false))); err == nil || !strings.Contains(err.Error(), "1Password: op failed") {
		t.Fatalf("op failure: %v", err)
	}
	opCommand = filepath.Join(dir, "no-such-op")
	if err := unlockServer(server.New(dir, events.New(nil, false))); err == nil || !strings.Contains(err.Error(), "not installed") {
		t.Fatalf("missing op: %v", err)
	}

	argsFile := fakeOp(t, testPW+"\n", 0) // op item get prints a newline
	srv := server.New(dir, events.New(nil, false))
	if err := unlockServer(srv); err != nil {
		t.Fatal(err)
	}
	if !srv.Unlocked() {
		t.Fatal("not unlocked")
	}
	if b, _ := os.ReadFile(argsFile); string(b) != "read\n--no-newline\n--\nop://Private/AgPass/password\n" {
		t.Errorf("op called with %q", b)
	}
}

// Client commands (mint, --admin) send the password from 1Password.
func TestAdminCommandOnePassword(t *testing.T) {
	dir := opVault(t)
	srv := server.New(dir, events.New(nil, false))
	if err := srv.Unlock(testPW); err != nil {
		t.Fatal(err)
	}
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()
	defer func() { cancel(); <-done }()

	// An admin command (list --admin); mint itself is refused for this
	// test process by the server, since it runs under Claude.
	mint := func() error {
		c, err := newConn(true)
		if err != nil {
			return err
		}
		var l api.ListResponse
		return c.call("GET", "/v1/list", nil, nil, &l)
	}
	fakeOp(t, testPW, 0)
	if err := mint(); err != nil {
		t.Fatalf("mint with the password from 1Password: %v", err)
	}
	fakeOp(t, "nope", 0)
	if err := mint(); err == nil || !strings.Contains(err.Error(), "not the master password") {
		t.Fatalf("mint with a wrong password from 1Password: %v", err)
	}

	// --manual: op is not run; without a terminal the password comes from stdin.
	argsFile := fakeOp(t, testPW, 0)
	manualPassword = true
	defer func() { manualPassword = false }()
	r, w, _ := os.Pipe()
	w.WriteString(testPW + "\n")
	w.Close()
	oldStdin := stdinLines
	stdinLines = bufio.NewReader(r)
	defer func() { stdinLines = oldStdin }()
	if err := mint(); err != nil {
		t.Fatalf("mint --manual: %v", err)
	}
	if _, err := os.Stat(argsFile); err == nil {
		t.Error("op ran with --manual")
	}
}

// fakeOpScript installs an op that answers account list with two accounts
// and read/item get with out.
func fakeOpScript(t *testing.T, out string) {
	t.Helper()
	dir := t.TempDir()
	script := `#!/bin/sh
case "$1" in
account) echo '[{"url":"a.1password.com","email":"a@x"},{"url":"b.1password.com","email":"b@x"}]' ;;
*) echo "$@" >> '` + dir + `/calls'; printf '%s' '` + out + `' ;;
esac
`
	p := filepath.Join(dir, "op")
	if err := os.WriteFile(p, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	old := opCommand
	opCommand = p
	t.Cleanup(func() { opCommand = old })
}

func withStdin(t *testing.T, s string) {
	t.Helper()
	old := stdinLines
	stdinLines = bufio.NewReader(strings.NewReader(s))
	t.Cleanup(func() { stdinLines = old })
}

func TestSetupOnePassword(t *testing.T) {
	dir := opVault(t)
	path := filepath.Join(dir, "config.toml")
	os.Remove(path)

	// Wrong item: nothing saved.
	fakeOpScript(t, "nope")
	withStdin(t, "y\n2\nop://P/Wrong/password\nn\n")
	if err := setupOnePassword(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("config saved for a wrong item")
	}

	// Right item in the second account, pasted the way 1Password copies it
	// (quoted): saved unquoted, with that account.
	fakeOpScript(t, testPW)
	withStdin(t, "y\n2\n\"op://P/AgPass/password\"\n")
	if err := setupOnePassword(dir); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := (config.OnePassword{MasterPassword: "op://P/AgPass/password", Account: "b.1password.com"}); cfg.OnePassword != want {
		t.Fatalf("saved %+v", cfg.OnePassword)
	}

	// Run again: it checks the saved item and keeps it.
	withStdin(t, "n\n")
	if err := setupOnePassword(dir); err != nil {
		t.Fatal(err)
	}
	if cfg2, _ := config.Load(path); cfg2 != cfg {
		t.Fatalf("changed to %+v", cfg2)
	}
}

func TestDescribeOPEscapes(t *testing.T) {
	got := describeOP(config.OnePassword{MasterPassword: "op://P/\x1b[2J/password", Account: "a\x07"})
	if strings.ContainsAny(got, "\x1b\x07") {
		t.Fatalf("not escaped: %q", got)
	}
}

// resetOPConfig forgets the cached config (tests switch AGPASS_DIR).
func resetOPConfig(t *testing.T) {
	opConfig.once = sync.Once{}
	t.Cleanup(func() { opConfig.once = sync.Once{} })
}

// An item name is read as JSON, so a password with quotes and commas (which
// op would CSV-quote in plain output) comes through intact.
func TestOpItemJSON(t *testing.T) {
	const pw = `ab"c,d 12345`
	dir := t.TempDir()
	p := filepath.Join(dir, "op")
	script := "#!/bin/sh\ncat <<'EOF'\n{\"id\":\"password\",\"type\":\"CONCEALED\",\"label\":\"password\",\"value\":\"ab\\\"c,d 12345\"}\nEOF\n"
	os.WriteFile(p, []byte(script), 0o700)
	old := opCommand
	opCommand = p
	defer func() { opCommand = old }()
	got, err := opMasterPassword(context.Background(), config.OnePassword{MasterPassword: "AgPass master"})
	if err != nil || got != pw {
		t.Fatalf("got %q %v", got, err)
	}
}

// A broken config (agents can write it) doesn't block setup: it offers to
// replace it.
func TestSetupOnePasswordBrokenConfig(t *testing.T) {
	dir := opVault(t)
	path := filepath.Join(dir, "config.toml")
	os.WriteFile(path, []byte("[onepassword]\nfoo = 1\n"), 0o600)
	fakeOpScript(t, testPW)
	withStdin(t, "y\n1\nop://P/AgPass/password\n")
	if err := setupOnePassword(dir); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil || cfg.OnePassword.MasterPassword != "op://P/AgPass/password" {
		t.Fatalf("got %+v %v", cfg, err)
	}
}

// asAgent makes agentAncestor report name ("" = no agent).
func asAgent(t *testing.T, name string) {
	old := agentAncestor
	agentAncestor = func() (string, error) { return name, nil }
	t.Cleanup(func() { agentAncestor = old })
}

// Under an agent, op is never run: approving its prompt would unlock
// 1Password in the agent's session.
func TestNoOpUnderAgent(t *testing.T) {
	opVault(t)
	argsFile := fakeOp(t, testPW, 0)
	asAgent(t, "claude")
	_, _, err := masterPassword()
	if err == nil || !strings.Contains(err.Error(), "not used for commands run under claude") {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Stat(argsFile); err == nil {
		t.Fatal("op ran under an agent")
	}
}
