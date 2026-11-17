package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/pflag"

	"agpass/internal/config"
	"agpass/internal/server"
	"agpass/internal/vault"
)

// manualPassword is --manual: type the master password even when 1Password
// is configured.
var manualPassword bool

func addManualFlag(fs *pflag.FlagSet) {
	fs.BoolVar(&manualPassword, "manual", false, "type the master password instead of reading it from 1Password")
}

// onePasswordConfig is the [onepassword] config, empty with --manual.
func onePasswordConfig() (config.OnePassword, error) {
	if manualPassword {
		return config.OnePassword{}, nil
	}
	cfg, err := config.Load(config.Path())
	return cfg.OnePassword, err
}

func onePasswordSet() bool {
	c, err := onePasswordConfig()
	return err == nil && c.MasterPassword != ""
}

// masterPassword gets the master password: from 1Password when configured
// (unless --manual), else typed. If op fails and there is a terminal, it
// asks instead. fromOP says where the password came from.
func masterPassword() (pw string, fromOP bool, err error) {
	op, err := onePasswordConfig()
	if err != nil {
		return "", false, err
	}
	if op.MasterPassword != "" {
		fmt.Fprintf(os.Stderr, "Reading the master password from 1Password (%s)…\n", op.MasterPassword)
		pw, err := opMasterPassword(context.Background(), op)
		if err == nil {
			return pw, true, nil
		}
		if !isTTY(os.Stdin) {
			return "", false, fmt.Errorf("1Password: %w", err)
		}
		fmt.Fprintf(os.Stderr, "1Password: %v\nType the master password instead.\n", err)
	}
	pw, err = readPassword("Master password: ")
	return pw, false, err
}

// nextMasterPassword is masterPassword for the first try and typed after.
func nextMasterPassword(try int) (string, bool, error) {
	if try == 0 {
		return masterPassword()
	}
	pw, err := readPassword("Master password: ")
	return pw, false, err
}

// wrongPassword reports a rejected master password before the next try. A
// rejected one from 1Password is an error without a terminal to type in.
func wrongPassword(fromOP bool) error {
	if !fromOP {
		fmt.Fprintln(os.Stderr, "Wrong password.")
		return nil
	}
	op, _ := onePasswordConfig()
	if !isTTY(os.Stdin) {
		return fmt.Errorf("1Password: the password in %s is not the master password", op.MasterPassword)
	}
	fmt.Fprintf(os.Stderr, "1Password: the password in %s is not the master password. Type it instead.\n", op.MasterPassword)
	return nil
}

// opCommand is the 1Password CLI; tests replace it.
var opCommand = "op"

// opArgs builds the op command line: `op read` for a secret reference,
// `op item get` (password field) for an item name or ID.
func opArgs(c config.OnePassword) []string {
	var args []string
	if strings.HasPrefix(c.MasterPassword, "op://") {
		args = []string{"read", "--no-newline", c.MasterPassword}
	} else {
		args = []string{"item", "get", c.MasterPassword, "--fields", "label=password", "--reveal"}
	}
	if c.Account != "" {
		args = append(args, "--account", c.Account)
	}
	return args
}

// opMasterPassword reads the master password with the 1Password CLI. op may
// ask to be unlocked (Touch ID through the desktop app, or its own prompt on
// this terminal), so it gets the terminal's stdin and stderr.
func opMasterPassword(ctx context.Context, c config.OnePassword) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute) // time to approve
	defer cancel()
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, opCommand, opArgs(c)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, &out, os.Stderr
	if err := cmd.Run(); err != nil {
		if errors.Is(err, exec.ErrNotFound) || errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("the 1Password CLI (op) is not installed or not on PATH")
		}
		return "", fmt.Errorf("op failed: %w", err)
	}
	pw := strings.TrimSuffix(strings.TrimSuffix(out.String(), "\n"), "\r")
	if pw == "" {
		return "", fmt.Errorf("op returned an empty password for %q", c.MasterPassword)
	}
	return pw, nil
}

// checkOnePassword reads the password from 1Password and checks it against
// the vault's key file (not the server, so a wrong one doesn't count toward
// its lockout).
func checkOnePassword(dir string, c config.OnePassword) error {
	pw, err := opMasterPassword(context.Background(), c)
	if err != nil {
		return err
	}
	kf, err := vault.Load(server.KeyPath(dir))
	if err != nil {
		return err
	}
	if _, err := kf.Unwrap(pw); errors.Is(err, vault.ErrWrongPassword) {
		return fmt.Errorf("the password in %s is not the master password of this vault", c.MasterPassword)
	} else if err != nil {
		return err
	}
	return nil
}

type opAccount struct {
	URL   string `json:"url"`
	Email string `json:"email"`
}

func opAccounts() ([]opAccount, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, opCommand, "account", "list", "--format", "json")
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("op account list: %w", err)
	}
	var accts []opAccount
	if err := json.Unmarshal(out, &accts); err != nil {
		return nil, fmt.Errorf("op account list: %w", err)
	}
	return accts, nil
}

// setupOnePassword is the setup step that sets [onepassword] in the config,
// after checking that the item holds this vault's master password.
func setupOnePassword(dir string) error {
	path := config.Path()
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	cur := cfg.OnePassword
	if cur.MasterPassword != "" {
		fmt.Printf("Configured in %s: %s\n", tildePath(path), describeOP(cur))
		fmt.Println("Checking (1Password may ask you to approve)…")
		if err := checkOnePassword(dir, cur); err != nil {
			fmt.Println(ui.bad("does not work") + "\n  " + err.Error())
			if !askYesNo("Change it?", true) {
				return nil
			}
		} else {
			fmt.Println(ui.ok("works: it unlocks this vault"))
			if !askYesNo("Change it?", false) {
				return nil
			}
		}
	} else {
		if _, err := exec.LookPath(opCommand); err != nil {
			fmt.Println(ui.dim("The 1Password CLI (op) is not installed; skipped."))
			return nil
		}
		if !askYesNo("Read the master password from 1Password?", false) {
			fmt.Println(ui.dim("Skipped. Run `agpass setup` again to set it up later."))
			return nil
		}
	}

	accts, err := opAccounts()
	if err != nil {
		fmt.Println(ui.bad("failed") + "\n  " + err.Error())
		return nil
	}
	account := ""
	switch len(accts) {
	case 0:
		fmt.Println(ui.bad("op has no accounts") + ": sign in with `op signin`, or turn on the 1Password app's CLI integration.")
		return nil
	case 1:
	default:
		def := 1
		fmt.Println("op is signed in to several 1Password accounts:")
		for i, a := range accts {
			fmt.Printf("  %d) %s  %s\n", i+1, a.URL, ui.dim(a.Email))
			if a.URL == cur.Account {
				def = i + 1
			}
		}
		for {
			line, err := readLine(fmt.Sprintf("Which one has the item? [%d] ", def))
			if err != nil {
				return err
			}
			n := def
			if line != "" {
				if n, err = strconv.Atoi(line); err != nil || n < 1 || n > len(accts) {
					continue
				}
			}
			account = accts[n-1].URL
			break
		}
	}

	fmt.Println(ui.dim("The item: a secret reference (in 1Password: the field's ▾ menu → Copy Secret Reference),\n" +
		"e.g. op://Private/AgPass/password, or an item name, whose \"password\" field is used."))
	for tries := 0; ; tries++ {
		ref, err := readLine("1Password item: ")
		if err != nil {
			return err
		}
		if ref == "" {
			fmt.Println(ui.dim("Nothing entered; the config is unchanged."))
			return nil
		}
		c := config.OnePassword{MasterPassword: ref, Account: account}
		fmt.Println("Checking (1Password may ask you to approve)…")
		if err := checkOnePassword(dir, c); err != nil {
			fmt.Println(ui.bad("does not work") + "\n  " + err.Error())
			if tries == 2 || !askYesNo("Try another item?", true) {
				fmt.Println(ui.dim("The config is unchanged."))
				return nil
			}
			continue
		}
		fmt.Println(ui.ok("works: it unlocks this vault"))
		cfg.OnePassword = c
		if err := config.Save(path, cfg); err != nil {
			return err
		}
		fmt.Println(ui.ok("Saved") + " to " + tildePath(path) + ". agpass now reads the master password from 1Password (--manual types it).")
		return nil
	}
}

func describeOP(c config.OnePassword) string {
	if c.Account != "" {
		return c.MasterPassword + " (account " + c.Account + ")"
	}
	return c.MasterPassword
}

// readLine reads one line from the terminal or stdin, trimmed.
func readLine(prompt string) (string, error) {
	fmt.Print(prompt)
	line, err := stdinLines.ReadString('\n')
	if err != nil && line == "" {
		fmt.Println()
		return "", err
	}
	return strings.TrimSpace(line), nil
}
