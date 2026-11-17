package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	c, err := Load(filepath.Join(dir, "missing.toml"))
	if err != nil || c.OnePassword.MasterPassword != "" {
		t.Fatalf("missing file: %+v, %v", c, err)
	}

	p := filepath.Join(dir, "config.toml")
	os.WriteFile(p, []byte("[onepassword]\nmaster_password = \"op://Private/AgPass/password\"\naccount = \"my.1password.com\"\n"), 0o600)
	c, err = Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.OnePassword.MasterPassword != "op://Private/AgPass/password" || c.OnePassword.Account != "my.1password.com" {
		t.Fatalf("got %+v", c)
	}

	os.WriteFile(p, []byte("[onepassword]\nmaster_pasword = \"x\"\n"), 0o600)
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "master_pasword") {
		t.Fatalf("typo not reported: %v", err)
	}
}

func TestSaveLoad(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "config.toml")
	want := Config{OnePassword: OnePassword{MasterPassword: "op://Private/AgPass \"x\"/password", Account: "my.1password.com"}}
	if err := Save(p, want); err != nil {
		t.Fatal(err)
	}
	got, err := Load(p)
	if err != nil || got != want {
		t.Fatalf("got %+v, %v", got, err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode())
	}
}
