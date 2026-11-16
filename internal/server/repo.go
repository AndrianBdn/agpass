package server

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// NormalizeRepo turns git remotes into host/owner/repo:
// git@github.com:x/crm.git, https://github.com/x/crm → github.com/x/crm.
func NormalizeRepo(r string) string {
	r = strings.ToLower(strings.TrimSpace(r))
	if r == "" {
		return ""
	}
	if i := strings.Index(r, "://"); i >= 0 {
		r = r[i+3:]
	} else if c := strings.IndexByte(r, ':'); c >= 0 && (strings.IndexByte(r, '/') < 0 || c < strings.IndexByte(r, '/')) {
		r = r[:c] + "/" + r[c+1:] // scp-like syntax
	}
	hostEnd := strings.IndexByte(r, '/')
	if hostEnd < 0 {
		hostEnd = len(r)
	}
	if at := strings.LastIndexByte(r[:hostEnd], '@'); at >= 0 {
		r = r[at+1:]
	}
	r = strings.TrimSuffix(r, "/")
	r = strings.TrimSuffix(r, ".git")
	return r
}

// GitOrigin finds the git repository containing dir and returns its
// remote.origin.url. It reads the config files directly instead of running
// git, so a repository's config (hooks, fsmonitor, …) never executes code in
// the server.
func GitOrigin(dir string) string {
	gitDir := ""
	for d := dir; ; d = filepath.Dir(d) {
		p := filepath.Join(d, ".git")
		if st, err := os.Stat(p); err == nil {
			if st.IsDir() {
				gitDir = p
			} else if b, err := os.ReadFile(p); err == nil { // worktree or submodule: "gitdir: <path>"
				if v, ok := strings.CutPrefix(strings.TrimSpace(string(b)), "gitdir:"); ok {
					gitDir = strings.TrimSpace(v)
					if !filepath.IsAbs(gitDir) {
						gitDir = filepath.Join(d, gitDir)
					}
				}
			}
			break
		}
		if d == filepath.Dir(d) {
			return ""
		}
	}
	if gitDir == "" {
		return ""
	}
	if b, err := os.ReadFile(filepath.Join(gitDir, "commondir")); err == nil {
		c := strings.TrimSpace(string(b))
		if !filepath.IsAbs(c) {
			c = filepath.Join(gitDir, c)
		}
		gitDir = c
	}
	f, err := os.Open(filepath.Join(gitDir, "config"))
	if err != nil {
		return ""
	}
	defer f.Close()
	inOrigin := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "[") {
			inOrigin = strings.EqualFold(strings.Join(strings.Fields(line), " "), `[remote "origin"]`)
			continue
		}
		if !inOrigin {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if ok && strings.EqualFold(strings.TrimSpace(k), "url") {
			return strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	return ""
}
