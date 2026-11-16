package server

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeRepo(t *testing.T) {
	cases := map[string]string{
		"git@github.com:Acme/CRM.git":             "github.com/acme/crm",
		"https://github.com/acme/crm":             "github.com/acme/crm",
		"https://github.com/acme/crm.git/":        "github.com/acme/crm",
		"https://x-access-token:t@github.com/a/b": "github.com/a/b",
		"ssh://git@github.com/acme/crm.git":       "github.com/acme/crm",
		"github.com/acme/crm":                     "github.com/acme/crm",
		"":                                        "",
	}
	for in, want := range cases {
		if got := NormalizeRepo(in); got != want {
			t.Errorf("NormalizeRepo(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGitOrigin(t *testing.T) {
	root := t.TempDir()
	repo := filepath.Join(root, "crm")
	sub := filepath.Join(repo, "src", "pkg")
	must(t, os.MkdirAll(sub, 0o755))
	must(t, os.MkdirAll(filepath.Join(repo, ".git"), 0o755))
	must(t, os.WriteFile(filepath.Join(repo, ".git", "config"), []byte(`[core]
	bare = false
[remote "upstream"]
	url = git@github.com:other/crm.git
[remote "origin"]
	url = git@github.com:acme/crm.git
	fetch = +refs/heads/*:refs/remotes/origin/*
`), 0o644))
	if got := GitOrigin(sub); got != "git@github.com:acme/crm.git" {
		t.Errorf("subdir: got %q", got)
	}

	// Linked worktree: .git is a file pointing at .git/worktrees/x, whose
	// commondir leads back to the main .git with the config.
	wt := filepath.Join(root, "crm-wt")
	wtGit := filepath.Join(repo, ".git", "worktrees", "wt")
	must(t, os.MkdirAll(wt, 0o755))
	must(t, os.MkdirAll(wtGit, 0o755))
	must(t, os.WriteFile(filepath.Join(wt, ".git"), []byte("gitdir: "+wtGit+"\n"), 0o644))
	must(t, os.WriteFile(filepath.Join(wtGit, "commondir"), []byte("../..\n"), 0o644))
	if got := GitOrigin(wt); got != "git@github.com:acme/crm.git" {
		t.Errorf("worktree: got %q", got)
	}

	if got := GitOrigin(root); got != "" {
		t.Errorf("no repo: got %q", got)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
