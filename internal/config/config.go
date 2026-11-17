// Package config reads the optional agpass config file (TOML). It holds
// settings for the agpass command on this machine; vault settings live in
// the encrypted database.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

// Config is the config file.
type Config struct {
	OnePassword OnePassword `toml:"onepassword"`
}

// OnePassword lets `agpass serve` read the master password from 1Password.
type OnePassword struct {
	// MasterPassword is a secret reference (op://vault/item/field) or an
	// item name or ID, whose "password" field is used.
	MasterPassword string `toml:"master_password"`
	// Account picks the 1Password account (sign-in address, e.g.
	// my.1password.com, or account ID) when op is signed in to several.
	Account string `toml:"account,omitempty"`
}

// Path is $AGPASS_DIR/config.toml when AGPASS_DIR is set (so a separate
// vault gets its own config), else $XDG_CONFIG_HOME/agpass/config.toml,
// else ~/.config/agpass/config.toml.
func Path() string {
	if d := os.Getenv("AGPASS_DIR"); d != "" {
		return filepath.Join(d, "config.toml")
	}
	if d := os.Getenv("XDG_CONFIG_HOME"); filepath.IsAbs(d) {
		return filepath.Join(d, "agpass", "config.toml")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "agpass", "config.toml")
}

// Load reads the config file at path. A missing file is an empty config.
// Unknown keys are an error, so a typo doesn't silently do nothing.
func Load(path string) (Config, error) {
	var c Config
	md, err := toml.DecodeFile(path, &c)
	if errors.Is(err, fs.ErrNotExist) {
		return Config{}, nil
	}
	if err != nil {
		return Config{}, fmt.Errorf("config %s: %w", path, err)
	}
	if un := md.Undecoded(); len(un) > 0 {
		keys := make([]string, len(un))
		for i, k := range un {
			keys[i] = k.String()
		}
		return Config{}, fmt.Errorf("config %s: unknown keys: %s", path, strings.Join(keys, ", "))
	}
	return c, nil
}

// Save writes c to path (mode 0600), replacing the file.
func Save(path string, c Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString("# agpass config (see README: Master password from 1Password).\n\n")
	enc := toml.NewEncoder(&b)
	enc.Indent = ""
	if err := enc.Encode(c); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".config-*.toml")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name()) // no-op after the rename
	if _, err := f.WriteString(b.String()); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
