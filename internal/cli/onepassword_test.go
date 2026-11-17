package cli

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"agpass/internal/api"
	"agpass/internal/config"
	"agpass/internal/events"
	"agpass/internal/server"
	"agpass/internal/vault"
)

func TestOpArgs(t *testing.T) {
	got := opArgs(config.OnePassword{MasterPassword: "op://Private/AgPass/password", Account: "my.1password.com"})
	want := []string{"read", "--no-newline", "op://Private/AgPass/password", "--account", "my.1password.com"}
	if !slices.Equal(got, want) {
		t.Errorf("reference: %q", got)
	}
	got = opArgs(config.OnePassword{MasterPassword: "AgPass master"})
	want = []string{"item", "get", "AgPass master", "--fields", "label=password", "--reveal"}
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
	if b, _ := os.ReadFile(argsFile); string(b) != "read\n--no-newline\nop://Private/AgPass/password\n" {
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

	mint := func() error {
		c, err := newConn(true)
		if err != nil {
			return err
		}
		var m api.MintResponse
		return c.call("POST", "/v1/mint", nil, struct{}{}, &m)
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

	// Right item in the second account: saved with that account.
	fakeOpScript(t, testPW)
	withStdin(t, "y\n2\nop://P/AgPass/password\n")
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
