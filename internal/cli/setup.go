package cli

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"agpass/internal/api"
	"agpass/internal/client"
	"agpass/internal/events"
	"agpass/internal/llm"
	"agpass/internal/server"
	"agpass/internal/store"
	"agpass/internal/vault"
)

// cmdSetup is the interactive first-run and reconfiguration wizard:
// master password (creating the vault if needed), then the OpenAI key for
// the LLM gatekeeper, verified online before it is saved.
//
// When the server is running, setup talks to it with the master password;
// otherwise it opens the vault files directly.
func cmdSetup(args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("usage: agpass setup")
	}
	if !isTTY(os.Stdin) {
		return fmt.Errorf("agpass setup is interactive: run it in a terminal")
	}
	dir := dataDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	fmt.Printf("%s · %s\n\n", ui.bold("agpass setup"), tildePath(dir))

	fmt.Println(ui.bold("1. Master password"))
	v, err := openSetupVault(dir)
	if err != nil {
		return err
	}
	defer v.close()

	fmt.Println()
	fmt.Println(ui.bold("2. LLM gatekeeper"))
	fmt.Println(ui.dim(wrap(fmt.Sprintf("When an agent's repository doesn't match a folder, an LLM decides from your folder "+
		"descriptions and the agent's reason which folders to grant. agpass uses OpenAI %s for this: folder names, "+
		"projects, descriptions and the agent's reason are sent to OpenAI (store=false). Without a key, only "+
		"repository matches are granted.", llm.DefaultModel), 78)))
	fmt.Println()
	set, err := v.gatekeeperSet()
	if err != nil {
		return err
	}
	configure := false
	if set {
		configure = askYesNo("An OpenAI key is already stored. Replace it?", false)
	} else {
		configure = askYesNo("Set an OpenAI API key now?", true)
	}
	changed := false
	if configure {
		if changed, err = setupGatekeeper(v); err != nil {
			return err
		}
	} else if !set {
		fmt.Println(ui.dim("Skipped. Run `agpass setup` again to add it later."))
	}

	fmt.Println()
	if v.remote() {
		msg := ui.ok("Done.")
		if changed {
			msg += " The running server uses the new key right away."
		}
		fmt.Println(msg)
	} else {
		fmt.Println(ui.ok("Done.") + " Next: start the server in a terminal tab with " + ui.bold("agpass serve") +
			". Agents then connect on their own.")
	}
	return nil
}

// setupGatekeeper asks for a key, checks it online and saves it. It reports
// whether a key was saved.
func setupGatekeeper(v setupVault) (bool, error) {
	for tries := 0; ; tries++ {
		key, err := readPassword("OpenAI API key (input hidden): ")
		if err != nil {
			return false, err
		}
		key = strings.TrimSpace(key)
		if key == "" {
			fmt.Println(ui.dim("No key entered; skipped."))
			return false, nil
		}
		fmt.Printf("Checking the key with OpenAI (%s)… ", llm.DefaultModel)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err = llm.Check(ctx, key, llm.DefaultModel)
		cancel()
		if err == nil {
			fmt.Println(ui.ok("works"))
			if err := v.setGatekeeper(key); err != nil {
				return false, err
			}
			fmt.Println(ui.ok("Saved") + " to " + api.SystemFolder + "/" + server.GatekeeperItem + " (agents can never read SYSTEM).")
			return true, nil
		}
		fmt.Println(ui.bad("failed"))
		fmt.Println("  " + err.Error())
		if tries == 2 || !askYesNo("Try another key?", true) {
			fmt.Println(ui.dim("Gatekeeper not configured. Run `agpass setup` again to add it later."))
			return false, nil
		}
	}
}

// setupVault is the vault as setup needs it: through the running server, or
// opened directly from disk.
type setupVault interface {
	gatekeeperSet() (bool, error)
	setGatekeeper(key string) error
	remote() bool
	close()
}

func openSetupVault(dir string) (setupVault, error) {
	sock := server.SocketPath(dir)
	if client.New(sock).Do("GET", "/v1/status", nil, nil, nil) == nil {
		fmt.Println(ui.dim("The server is running; setup will go through it."))
		return openRemoteVault(sock)
	}
	keyPath := server.KeyPath(dir)
	if !vault.Exists(keyPath) {
		return createLocalVault(dir)
	}
	return openLocalVault(dir)
}

// ---- through the running server ----

type remoteVault struct{ c *client.Client }

func openRemoteVault(sock string) (setupVault, error) {
	for tries := 0; ; tries++ {
		pw, err := readPassword("Master password: ")
		if err != nil {
			return nil, err
		}
		v := &remoteVault{c: client.New(sock)}
		v.c.Master = pw
		_, err = v.gatekeeperSet() // also checks the password
		if err == nil {
			fmt.Println(ui.ok("Unlocked."))
			return v, nil
		}
		var ae *api.Error
		if !errors.As(err, &ae) || ae.Code != api.ErrForbidden || tries == 2 {
			return nil, err
		}
		fmt.Println("Wrong password.")
	}
}

func (v *remoteVault) gatekeeperSet() (bool, error) {
	var it api.Item
	err := v.c.Do("GET", "/v1/item", url.Values{"path": {api.SystemFolder + "/" + server.GatekeeperItem}}, nil, &it)
	var ae *api.Error
	if errors.As(err, &ae) && ae.Code == api.ErrNotFound {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return hasField(it.Fields, "api_key"), nil
}

func (v *remoteVault) setGatekeeper(key string) error {
	req := api.SetItemRequest{
		Path:   api.SystemFolder + "/" + server.GatekeeperItem,
		Fields: []api.Field{{Key: "api_key", Type: api.TypeSensitive, Value: key}},
	}
	return v.c.Do("POST", "/v1/item", nil, req, nil)
}

func (v *remoteVault) remote() bool { return true }
func (v *remoteVault) close()       {}

// ---- directly on disk (server not running) ----

type localVault struct{ st *store.Store }

func createLocalVault(dir string) (setupVault, error) {
	fmt.Println("No vault yet. Choose a master password: it protects every secret and cannot be recovered.")
	var pw string
	for {
		p, err := readPassword("New master password: ")
		if err != nil {
			return nil, err
		}
		if len(p) < vault.MinPasswordLen {
			fmt.Printf("Use at least %d characters.\n", vault.MinPasswordLen)
			continue
		}
		again, err := readPassword("Repeat: ")
		if err != nil {
			return nil, err
		}
		if p != again {
			fmt.Println("Passwords do not match.")
			continue
		}
		pw = p
		break
	}
	dek, err := vault.Create(server.KeyPath(dir), pw)
	if err != nil {
		return nil, err
	}
	st, err := store.Open(dir, dek, false)
	if err != nil {
		return nil, err
	}
	st.AddEvent(events.Event{Time: time.Now(), Level: events.LevelOK, Action: "setup", Actor: "human", Msg: "new vault created"})
	fmt.Println(ui.ok("Vault created."))
	return &localVault{st: st}, nil
}

func openLocalVault(dir string) (setupVault, error) {
	kf, err := vault.Load(server.KeyPath(dir))
	if err != nil {
		return nil, err
	}
	for tries := 0; ; tries++ {
		pw, err := readPassword("Master password: ")
		if err != nil {
			return nil, err
		}
		dek, err := kf.Unwrap(pw)
		if errors.Is(err, vault.ErrWrongPassword) && tries < 2 {
			fmt.Println("Wrong password.")
			continue
		}
		if err != nil {
			return nil, err
		}
		st, err := store.Open(dir, dek, false)
		if err != nil {
			return nil, err
		}
		fmt.Println(ui.ok("Unlocked."))
		return &localVault{st: st}, nil
	}
}

func (v *localVault) gatekeeperSet() (bool, error) {
	it, err := v.st.GetItem(api.SystemFolder, server.GatekeeperItem)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return hasField(it.Fields, "api_key"), nil
}

func (v *localVault) setGatekeeper(key string) error {
	f := []api.Field{{Key: "api_key", Type: api.TypeSensitive, Value: key}}
	it, err := v.st.SetItem(api.SystemFolder, server.GatekeeperItem, f, nil, "human")
	if err != nil {
		return err
	}
	v.st.AddEvent(events.Event{Time: time.Now(), Level: events.LevelOK, Action: "set", Actor: "human",
		Target: api.SystemFolder + "/" + server.GatekeeperItem, Msg: fmt.Sprintf("v%d set=api_key (setup)", it.Version)})
	return nil
}

func (v *localVault) remote() bool { return false }
func (v *localVault) close()       { v.st.Close() }

// ---- helpers ----

func hasField(fs []api.Field, key string) bool {
	for _, f := range fs {
		if f.Key == key && f.Value != "" {
			return true
		}
	}
	return false
}

func askYesNo(q string, def bool) bool {
	hint := " [y/N] "
	if def {
		hint = " [Y/n] "
	}
	fmt.Print(q + hint)
	line, err := stdinLines.ReadString('\n')
	if err != nil && line == "" {
		fmt.Println()
		return def
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	case "n", "no":
		return false
	}
	return def
}

// wrap breaks text into lines of at most width runes.
func wrap(s string, width int) string {
	var b strings.Builder
	n := 0
	for i, w := range strings.Fields(s) {
		if i > 0 && n+1+len([]rune(w)) > width {
			b.WriteString("\n")
			n = 0
		} else if i > 0 {
			b.WriteString(" ")
			n++
		}
		b.WriteString(w)
		n += len([]rune(w))
	}
	return b.String()
}

// ui styles setup output when stdout is a color terminal.
var ui = uiStyle{}

type uiStyle struct{}

func (uiStyle) wrap(code, s string) string {
	if !color() {
		return s
	}
	return code + s + "\x1b[0m"
}
func (u uiStyle) bold(s string) string { return u.wrap("\x1b[1m", s) }
func (u uiStyle) dim(s string) string  { return u.wrap("\x1b[2m", s) }
func (u uiStyle) ok(s string) string   { return u.wrap("\x1b[32m", "✓ "+s) }
func (u uiStyle) bad(s string) string  { return u.wrap("\x1b[31m", "✗ "+s) }
