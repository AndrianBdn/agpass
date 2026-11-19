package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"unicode/utf8"

	"agpass/internal/api"
	"agpass/internal/client"
	"agpass/internal/events"
	"agpass/internal/llm"
	"agpass/internal/peer"
	"agpass/internal/sshagent"
	"agpass/internal/vault"
)

// testEnv is a running server with two clients: the human (master password)
// and an agent session. The agent is this test process, sitting in a
// repository whose origin is the one given to newTestEnv.
type testEnv struct {
	s            *Server
	dir          string
	admin, agent *client.Client
	llmCalls     atomic.Int32
}

// newTestEnv starts the server. gatekeeperGrants is what the fake LLM
// gatekeeper grants on every call.
func newTestEnv(t *testing.T, origin string, gatekeeperGrants ...string) *testEnv {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "agp") // short: unix socket paths are limited
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	const pw = "correct-horse-1"
	if _, err := vault.Create(KeyPath(dir), pw); err != nil {
		t.Fatal(err)
	}
	e := &testEnv{s: New(dir, events.New(nil, false)), dir: dir}
	if err := e.s.Unlock(pw); err != nil {
		t.Fatal(err)
	}
	if err := e.s.Listen(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.s.Serve(ctx) }()
	t.Cleanup(func() { cancel(); <-done })

	repo := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(repo, ".git"), 0o755))
	must(t, os.WriteFile(filepath.Join(repo, ".git", "config"), []byte("[remote \"origin\"]\n\turl = "+origin+"\n"), 0o644))
	t.Chdir(repo)
	me, err := peer.Info(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	e.s.findAgent = func(int) (peer.Proc, peer.Agent, error) { return me, peer.Agent{Name: "claude"}, nil }

	gk := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.llmCalls.Add(1)
		text, _ := json.Marshal(llm.Decision{Grant: gatekeeperGrants, Explanation: "test gatekeeper"})
		json.NewEncoder(w).Encode(map[string]any{"status": "completed", "output": []any{
			map[string]any{"type": "message", "content": []any{map[string]any{"type": "output_text", "text": string(text)}}},
		}})
	}))
	oldURL := llm.BaseURL
	llm.BaseURL = gk.URL
	t.Cleanup(func() { llm.BaseURL = oldURL; gk.Close() })

	e.admin, e.agent = client.New(SocketPath(dir)), client.New(SocketPath(dir))
	e.admin.Master = pw
	must(t, e.admin.Do("POST", "/v1/item", nil, api.SetItemRequest{
		Path:   api.SystemFolder + "/" + GatekeeperItem,
		Fields: []api.Field{{Key: "api_key", Type: api.TypeSensitive, Value: "sk-test"}},
	}, nil))
	return e
}

func (e *testEnv) folder(t *testing.T, name string, repos ...string) {
	t.Helper()
	project, desc := name, "secrets of "+name
	must(t, e.admin.Do("POST", "/v1/folder", nil, api.FolderRequest{Name: name, Project: &project, Description: &desc, Repos: &repos}, nil))
}

func (e *testEnv) connect(t *testing.T, folders ...string) api.AccessResponse {
	t.Helper()
	var resp api.AccessResponse
	must(t, e.agent.Do("POST", "/v1/connect", nil, api.AccessRequest{Reason: "fix the crm login bug", Folders: folders}, &resp))
	return resp
}

func grantNames(gs []api.Grant) []string {
	out := []string{}
	for _, g := range gs {
		out = append(out, g.Folder+":"+g.By)
	}
	return out
}

func apiErrCode(err error) string {
	var ae *api.Error
	if errors.As(err, &ae) {
		return ae.Code
	}
	return ""
}

// A session that has its repository's folders and connects again asks for
// nothing new: the gatekeeper must not be consulted, or it could hand out
// folders nobody asked for. Asking for one with --folder does consult it.
func TestConnectAgainAsksNoGatekeeper(t *testing.T) {
	e := newTestEnv(t, "git@github.com:acme/crm.git", "billing")
	e.folder(t, "crm", "github.com/acme/crm")
	e.folder(t, "billing", "github.com/acme/billing")

	for i := 1; i <= 2; i++ {
		resp := e.connect(t)
		if got := grantNames(resp.Session.Grants); !slices.Equal(got, []string{"crm:repo-match"}) {
			t.Fatalf("connect #%d: session has %v, want only crm", i, got)
		}
		if n := e.llmCalls.Load(); n != 0 {
			t.Fatalf("connect #%d: gatekeeper called %d times, want 0", i, n)
		}
	}

	resp := e.connect(t, "billing")
	if e.llmCalls.Load() != 1 || !slices.Equal(grantNames(resp.Granted), []string{"billing:llm"}) {
		t.Fatalf("connect --folder billing: granted %v after %d gatekeeper calls", grantNames(resp.Granted), e.llmCalls.Load())
	}
}

// With no folder for its repository, the session has nothing, so the
// gatekeeper decides, on every connect until it has a folder.
func TestConnectWithoutFolderAsksGatekeeper(t *testing.T) {
	e := newTestEnv(t, "git@github.com:acme/other.git") // gatekeeper grants nothing
	e.folder(t, "crm", "github.com/acme/crm")
	for i := 1; i <= 2; i++ {
		if resp := e.connect(t); len(resp.Session.Grants) != 0 || int(e.llmCalls.Load()) != i {
			t.Fatalf("connect #%d: grants %v, %d gatekeeper calls", i, grantNames(resp.Session.Grants), e.llmCalls.Load())
		}
	}
}

// folder edit links and unlinks single repositories and leaves the others.
// An agent may do that only with its own repository.
func TestFolderEditRepos(t *testing.T) {
	e := newTestEnv(t, "git@github.com:acme/crm.git")
	// Stored as written before 0.3.0: not normalized.
	must(t, e.s.st.CreateFolder(api.FolderRequest{Name: "crm", Repos: &[]string{"git@github.com:acme/crm-web.git"}}, "human"))
	e.folder(t, "billing", "https://github.com/Acme/Billing.git")
	if f, _ := e.s.st.GetFolder("billing"); !slices.Equal(f.Repos, []string{"github.com/acme/billing"}) {
		t.Fatalf("new folder repos not normalized: %v", f.Repos)
	}

	edit := func(c *client.Client, req api.FolderRequest) ([]string, error) {
		var f api.Folder
		err := c.Do("PATCH", "/v1/folder", nil, req, &f)
		return f.Repos, err
	}

	// The human links the agent's repository: the existing link stays.
	repos, err := edit(e.admin, api.FolderRequest{Name: "crm", AddRepos: []string{"https://github.com/acme/crm"}})
	if err != nil || !slices.Equal(repos, []string{"git@github.com:acme/crm-web.git", "github.com/acme/crm"}) {
		t.Fatalf("human links a repository: %v, %v", repos, err)
	}
	e.connect(t) // the agent session gets crm by repository match

	// The agent can't touch another repository's link, in either direction.
	for _, req := range []api.FolderRequest{
		{Name: "crm", RemoveRepos: []string{"github.com/acme/crm-web"}},
		{Name: "crm", AddRepos: []string{"github.com/acme/billing"}},
		{Name: "crm", AddRepos: []string{"github.com/acme/crm", "github.com/acme/billing"}},
	} {
		if _, err := edit(e.agent, req); apiErrCode(err) != api.ErrForbidden {
			t.Fatalf("agent edit %+v: %v, want forbidden", req, err)
		}
	}
	// Linking its own repository again changes nothing; unlinking it keeps
	// the other one.
	if repos, err = edit(e.agent, api.FolderRequest{Name: "crm", AddRepos: []string{"git@github.com:acme/crm.git"}}); err != nil || len(repos) != 2 {
		t.Fatalf("agent links its own repository again: %v, %v", repos, err)
	}
	if repos, err = edit(e.agent, api.FolderRequest{Name: "crm", RemoveRepos: []string{"github.com/acme/crm"}}); err != nil || !slices.Equal(repos, []string{"git@github.com:acme/crm-web.git"}) {
		t.Fatalf("agent unlinks its own repository: %v, %v", repos, err)
	}

	// The human unlinks by any spelling of the repository.
	if repos, err = edit(e.admin, api.FolderRequest{Name: "crm", RemoveRepos: []string{"https://github.com/acme/crm-web"}}); err != nil || len(repos) != 0 {
		t.Fatalf("human unlinks a repository: %v, %v", repos, err)
	}
	// Replacing the list (clients before 0.3.0) is refused, not half-applied.
	if _, err := edit(e.admin, api.FolderRequest{Name: "billing", Repos: &[]string{"github.com/acme/x"}}); apiErrCode(err) != api.ErrBadRequest {
		t.Fatalf("replacing the list: %v, want bad_request", err)
	}
	if _, err := edit(e.admin, api.FolderRequest{Name: "billing", AddRepos: []string{"github.com/a/b"}, RemoveRepos: []string{"git@github.com:a/b"}}); apiErrCode(err) != api.ErrBadRequest {
		t.Fatalf("linking and unlinking the same repository: %v, want bad_request", err)
	}
}

// A host that changed its keys stays refused until the human unpins it; the
// next allow then pins the keys it serves now.
func TestSSHUnpin(t *testing.T) {
	e := newTestEnv(t, "git@github.com:acme/crm.git")
	_, current, err := sshagent.Generate("")
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := sshagent.Signer(func() []byte { p, _, _ := sshagent.Generate(""); return p }())
	host := testSSHServer(t, signer.PublicKey()) // serves its own, new host key
	_, old, _ := sshagent.Generate("")
	must(t, e.s.st.PinHostKeys(host, []string{old}))
	must(t, e.s.st.PinHostKeys("other.example.com", []string{current}))

	knownHosts := func() string {
		b, err := os.ReadFile(KnownHostsPath(e.dir))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	admin := &caller{admin: true}
	if _, err := e.s.pinHost(context.Background(), admin, host); err != nil {
		t.Fatal(err)
	}
	if keys, _ := e.s.st.HostKeys(host); !slices.Equal(keys, []string{old}) {
		t.Fatalf("a pinned host was scanned again: %v", keys)
	}

	unpin := func(c *client.Client, h string) (api.SSHUnpinResponse, error) {
		var resp api.SSHUnpinResponse
		err := c.Do("POST", "/v1/ssh/unpin", nil, api.SSHUnpinRequest{Host: h}, &resp)
		return resp, err
	}
	if _, err := unpin(e.agent, host); apiErrCode(err) != api.ErrNeedAdmin {
		t.Fatalf("unpin by an agent session: %v, want need_admin", err)
	}
	resp, err := unpin(e.admin, "ssh://deploy@"+host+"/")
	if err != nil || resp.Host != host || resp.Removed != 1 {
		t.Fatalf("unpin: %+v, %v", resp, err)
	}
	if kh := knownHosts(); strings.Contains(kh, old) || !strings.Contains(kh, "other.example.com "+current) {
		t.Fatalf("known_hosts after unpin:\n%s", kh)
	}
	if _, err := unpin(e.admin, host); apiErrCode(err) != api.ErrNotFound {
		t.Fatalf("second unpin: %v, want not_found", err)
	}

	if _, err := e.s.pinHost(context.Background(), admin, host); err != nil {
		t.Fatal(err)
	}
	keys, _ := e.s.st.HostKeys(host)
	if len(keys) != 1 || keys[0] == old || !strings.Contains(knownHosts(), keys[0]) {
		t.Fatalf("host not pinned again with its current key: %v", keys)
	}
}

func TestTruncateKeepsCharacters(t *testing.T) {
	for _, s := range []string{"чиню логин в CRM, нужен dev Postgres", "naïve café déjà vu", "plain ascii reason here"} {
		for n := 2; n < len(s); n++ {
			got := truncate(s, n)
			if !utf8.ValidString(got) || !strings.HasSuffix(got, "…") || len(got) > n+len("…") {
				t.Fatalf("truncate(%q, %d) = %q", s, n, got)
			}
		}
		if got := truncate(s, len(s)); got != s {
			t.Fatalf("truncate(%q, len) = %q", s, got)
		}
	}
}
