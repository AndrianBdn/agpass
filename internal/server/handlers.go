package server

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"agpass/internal/api"
	"agpass/internal/events"
	"agpass/internal/llm"
	"agpass/internal/peer"
	"agpass/internal/redact"
	"agpass/internal/store"
)

var nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", s.handle(authNone, s.status))
	mux.HandleFunc("POST /v1/mint", s.handle(authAdmin, s.mint))
	mux.HandleFunc("POST /v1/elevate", s.handle(authSession, s.elevate))
	mux.HandleFunc("POST /v1/connect", s.handle(authSession, s.connect))
	mux.HandleFunc("POST /v1/ssh/keygen", s.handle(authAdmin, s.sshKeygen))
	mux.HandleFunc("POST /v1/ssh/import", s.handle(authAdmin, s.sshImport))
	mux.HandleFunc("GET /v1/ssh/key", s.handle(authSession, s.sshPubkey))
	mux.HandleFunc("POST /v1/ssh/allow", s.handle(authSession, s.sshAllow))
	mux.HandleFunc("POST /v1/ssh/unpin", s.handle(authAdmin, s.sshUnpin))
	mux.HandleFunc("GET /v1/whoami", s.handle(authSession, s.whoami))
	mux.HandleFunc("GET /v1/list", s.handle(authSession, s.list))
	mux.HandleFunc("GET /v1/item", s.handle(authSession, s.getItem))
	mux.HandleFunc("POST /v1/item", s.handle(authSession, s.setItem))
	mux.HandleFunc("POST /v1/folder", s.handle(authSession, s.createFolder))
	mux.HandleFunc("PATCH /v1/folder", s.handle(authSession, s.editFolder))
	return mux
}

func (s *Server) status(r *http.Request, c *caller) (any, error) {
	return api.StatusResponse{Version: api.Version, Unlocked: s.Unlocked()}, nil
}

// mint creates a one-time code that gives one agent session admin access.
func (s *Server) mint(r *http.Request, c *caller) (any, error) {
	// Codes come from the user's own terminal. Run inside an agent, even
	// with the master password, mint would let the agent elevate itself.
	if name, err := s.agentAncestor(r); err != nil || name != "" {
		msg := "admin codes can only be minted in your own terminal, not by a process running under " + name
		if err != nil {
			msg = "cannot check which process asked for an admin code: " + err.Error()
		}
		s.Log.Emit(events.Event{Level: events.LevelDeny, Action: "mint", Actor: c.String(), Msg: msg})
		return nil, errf(http.StatusForbidden, api.ErrForbidden, "%s", msg)
	}
	m := s.mintCode()
	s.Log.Emit(events.Event{Level: events.LevelWarn, Action: "mint", Actor: c.String(),
		Msg: fmt.Sprintf("admin code valid until %s", m.ExpiresAt.Format("15:04:05"))})
	return m, nil
}

// elevate redeems an admin code: the calling agent session gets access to
// every folder, SYSTEM included, for ElevateDuration.
func (s *Server) elevate(r *http.Request, c *caller) (any, error) {
	if c.admin {
		return nil, errf(http.StatusBadRequest, api.ErrBadRequest, "elevate is for agent sessions; the master password already has full access")
	}
	var req api.ElevateRequest
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	restore, err := s.redeemCode(strings.TrimSpace(req.Code))
	if err != nil {
		s.Log.Emit(events.Event{Level: events.LevelDeny, Action: "elevate", Actor: c.String(), Msg: err.Error()})
		return nil, err
	}
	until := time.Now().Add(ElevateDuration)
	if err := s.st.SetSessionAdmin(c.session.ID, until); err != nil {
		restore()
		return nil, err
	}
	c.session.AdminUntil, c.elevated = until, true
	s.Log.Emit(events.Event{Level: events.LevelAlert, Action: "elevate", Actor: c.String(), Target: "all folders",
		Msg: "admin access incl. SYSTEM until " + until.Format("15:04")})
	return s.sessionInfo(c.session)
}

func (s *Server) whoami(r *http.Request, c *caller) (any, error) {
	if c.admin {
		return api.WhoamiResponse{Admin: true}, nil
	}
	info, err := s.sessionInfo(c.session)
	if err != nil {
		return nil, err
	}
	return api.WhoamiResponse{Session: &info}, nil
}

func (s *Server) sessionInfo(sess *store.Session) (api.SessionInfo, error) {
	grants, err := s.st.Grants(sess.ID)
	if err != nil {
		return api.SessionInfo{}, err
	}
	info := api.SessionInfo{
		ID: sess.ID, Agent: sess.Agent, PID: sess.PID, Exe: sess.Exe, Cwd: sess.Cwd,
		Repo: sess.Repo, Reason: sess.Reason, CreatedAt: sess.CreatedAt, Grants: grants,
	}
	if time.Now().Before(sess.AdminUntil) {
		until := sess.AdminUntil
		info.AdminUntil = &until
	}
	if info.SSHHosts, err = s.st.SSHGrants(sess.ID); err != nil {
		return api.SessionInfo{}, err
	}
	return info, nil
}

// connect records what the session works on and grants folders: those
// listing its repository, a new folder for the repository (create), and
// whatever the gatekeeper approves.
func (s *Server) connect(r *http.Request, c *caller) (any, error) {
	if c.admin {
		return nil, errf(http.StatusBadRequest, api.ErrBadRequest, "connect is for agent sessions; the master password already has access to everything")
	}
	var req api.AccessRequest
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.Reason) == "" {
		return nil, errf(http.StatusBadRequest, api.ErrBadRequest, "a reason is required: say what you are working on and why you need secrets")
	}
	// The repository is worked out from the agent process's own working
	// directory. What the client says (--repo) is only a claim: the LLM sees
	// it, repository matching never uses it.
	cwd, repo, err := s.sessionRepo(c)
	if err != nil {
		return nil, err
	}
	claimed := NormalizeRepo(req.Repo)
	if claimed == repo {
		claimed = ""
	}
	if err := s.st.UpdateSessionClaims(c.session.ID, cwd, repo, req.Reason); err != nil {
		return nil, err
	}
	c.session.Cwd, c.session.Repo, c.session.Reason = cwd, repo, req.Reason

	have, err := s.grantSet(c)
	if err != nil {
		return nil, err
	}
	folders, err := s.st.ListFolders()
	if err != nil {
		return nil, err
	}
	resp := api.AccessResponse{}
	grant := func(folder, by, why string) error {
		g, err := s.st.Grant(c.session.ID, folder, by, why)
		if err != nil {
			return err
		}
		have[folder] = true
		resp.Granted = append(resp.Granted, g)
		s.Log.Emit(events.Event{Level: events.LevelOK, Action: "grant", Actor: c.String(), Target: folder, Msg: by + ": " + truncate(req.Reason, 80)})
		return nil
	}

	// 1. Deterministic: folders whose repos list contains the session's repo.
	var candidates []llm.FolderInfo
	repoHasFolder := false
	for _, f := range folders {
		listsRepo := repo != "" && slices.ContainsFunc(f.Repos, func(r string) bool { return NormalizeRepo(r) == repo })
		repoHasFolder = repoHasFolder || listsRepo
		if f.Name == api.SystemFolder || have[f.Name] {
			continue
		}
		if listsRepo {
			if err := grant(f.Name, "repo-match", "repository "+repo+" is listed on the folder"); err != nil {
				return nil, err
			}
			continue
		}
		// Folders created or last edited by an agent session are untrusted.
		candidates = append(candidates, llm.FolderInfo{Name: f.Name, Project: f.Project, Description: f.Description, Repos: f.Repos, WrittenBy: writtenBy(f)})
	}

	// 2. A folder of its own for a repository that has none yet.
	if req.Create && !repoHasFolder {
		f, err := s.createOwnFolder(c, repo, req)
		if err != nil {
			return nil, err
		}
		g, err := s.st.Grant(c.session.ID, f.Name, "created", "folder created by this session for "+repo)
		if err != nil {
			return nil, err
		}
		have[f.Name] = true
		resp.Granted = append(resp.Granted, g)
		resp.Created = f.Name
	} else if req.Create {
		resp.Explanation = "this repository already has a folder; no new folder created. "
	}

	// 3. LLM: when the session has no folder at all, or the agent asked for
	// folders it doesn't have yet. A session that already has its folders
	// and connects again asks for nothing new, so nothing is judged.
	pending := slices.DeleteFunc(slices.Clone(req.Folders), func(f string) bool { return have[f] })
	if len(candidates) > 0 && (len(have) == 0 || len(pending) > 0) {
		key, model := s.gatekeeper()
		if key == "" {
			resp.Explanation += "LLM gatekeeper not configured (the user can set it up with `agpass setup`); only repository matches are granted"
		} else {
			d, err := llm.Decide(r.Context(), key, model, llm.Request{Repo: repo, ClaimedRepo: claimed, Cwd: cwd, Reason: req.Reason, Requested: req.Folders, Folders: candidates})
			if err != nil {
				s.Log.Emit(events.Event{Level: events.LevelWarn, Action: "llm", Actor: c.String(), Msg: err.Error()})
				resp.Explanation += "LLM gatekeeper failed: " + err.Error()
			} else {
				resp.Explanation += d.Explanation
				for _, name := range d.Grant {
					if slices.ContainsFunc(candidates, func(f llm.FolderInfo) bool { return f.Name == name }) && !have[name] {
						if err := grant(name, "llm", d.Explanation); err != nil {
							return nil, err
						}
					}
				}
				if len(d.Grant) == 0 {
					s.Log.Emit(events.Event{Level: events.LevelDeny, Action: "llm", Actor: c.String(), Msg: truncate(d.Explanation, 120)})
				}
			}
		}
	}
	for _, f := range req.Folders {
		if !have[f] {
			resp.Denied = append(resp.Denied, f)
		}
	}
	if len(resp.Denied) > 0 {
		s.Log.Emit(events.Event{Level: events.LevelDeny, Action: "connect", Actor: c.String(), Target: strings.Join(resp.Denied, ","), Msg: truncate(req.Reason, 80)})
	}
	if resp.Session, err = s.sessionInfo(c.session); err != nil {
		return nil, err
	}
	if resp.Granted == nil {
		resp.Granted = []api.Grant{}
	}
	return resp, nil
}

// GatekeeperItem holds the gatekeeper's OpenAI settings: field api_key,
// optional field model.
const GatekeeperItem = "openai"

// gatekeeper returns the OpenAI key and model from SYSTEM/openai; key is ""
// when not configured.
func (s *Server) gatekeeper() (key, model string) {
	it, err := s.st.GetItem(api.SystemFolder, GatekeeperItem)
	if err != nil {
		return "", ""
	}
	for _, f := range it.Fields {
		switch f.Key {
		case "api_key":
			key = strings.TrimSpace(f.Value)
		case "model":
			model = strings.TrimSpace(f.Value)
		}
	}
	if model == "" {
		model = llm.DefaultModel
	}
	return key, model
}

// sessionRepo reads the agent process's working directory from the kernel
// and the git origin of the repository there.
func (s *Server) sessionRepo(c *caller) (cwd, repo string, err error) {
	cwd, err = peer.Cwd(c.agent.PID)
	if err != nil {
		return "", "", fmt.Errorf("read working directory of %s pid %d: %w", c.name, c.agent.PID, err)
	}
	return cwd, NormalizeRepo(GitOrigin(cwd)), nil
}

// normalizeRepos normalizes a repository list, dropping empty and repeated
// entries.
func normalizeRepos(in []string) []string {
	out := []string{}
	for _, r := range in {
		if n := NormalizeRepo(r); n != "" && !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out
}

// editRepos unlinks rm from repos and links add, leaving the other entries
// as they are. add and rm are normalized; entries are compared normalized.
func editRepos(repos, add, rm []string) []string {
	out := slices.DeleteFunc(slices.Clone(repos), func(r string) bool { return slices.Contains(rm, NormalizeRepo(r)) })
	for _, a := range add {
		if !slices.ContainsFunc(out, func(r string) bool { return NormalizeRepo(r) == a }) {
			out = append(out, a)
		}
	}
	return out
}

// agentRepos checks the repositories an agent wants on a new folder: only its
// own session's repository is allowed, so a folder can't be pushed onto another
// project's sessions. nil means "this session's repository".
func (s *Server) agentRepos(c *caller, want *[]string) ([]string, error) {
	_, repo, err := s.sessionRepo(c)
	if err != nil {
		return nil, err
	}
	if want == nil {
		if repo == "" {
			return []string{}, nil
		}
		return []string{repo}, nil
	}
	out := []string{}
	for _, r := range *want {
		n := NormalizeRepo(r)
		if n == "" {
			continue
		}
		if n != repo {
			return nil, errf(http.StatusForbidden, api.ErrForbidden,
				"agents can only link a folder to their own repository (%s); ask the user to add %s", orNone(repo), n)
		}
		if !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out, nil
}

func orNone(repo string) string {
	if repo == "" {
		return "none: not in a git repository with an origin remote"
	}
	return repo
}

// createOwnFolder creates the folder for the session's repository during
// connect --create, named after the repository unless req.Name is given.
func (s *Server) createOwnFolder(c *caller, repo string, req api.AccessRequest) (api.Folder, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		if repo == "" {
			return api.Folder{}, errf(http.StatusBadRequest, api.ErrBadRequest,
				"not in a git repository with an origin remote: pass --name for the new folder")
		}
		name = folderNameFor(repo)
	}
	if !nameRe.MatchString(name) || strings.EqualFold(name, api.SystemFolder) {
		return api.Folder{}, errf(http.StatusBadRequest, api.ErrBadRequest, "invalid folder name %q", name)
	}
	desc := strings.TrimSpace(req.Description)
	if desc == "" {
		desc = "Secrets for " + orNone(repo) + " (folder created by an agent)"
	}
	repos := []string{}
	if repo != "" {
		repos = []string{repo}
	}
	project := name
	err := s.st.CreateFolder(api.FolderRequest{Name: name, Project: &project, Description: &desc, Repos: &repos}, c.String())
	if errors.Is(err, store.ErrExists) {
		return api.Folder{}, errf(http.StatusConflict, api.ErrConflict,
			"a folder named %q already exists for another project: pass --name to choose another name", name)
	}
	if err != nil {
		return api.Folder{}, err
	}
	s.Log.Emit(events.Event{Level: events.LevelOK, Action: "folder-create", Actor: c.String(), Target: name, Msg: "for " + orNone(repo)})
	return s.st.GetFolder(name)
}

// folderNameFor turns github.com/acme/My.App into "my.app".
func folderNameFor(repo string) string {
	base := repo[strings.LastIndexByte(repo, '/')+1:]
	var b strings.Builder
	for _, r := range strings.ToLower(base) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	name := strings.TrimLeft(b.String(), "._-")
	if len(name) > 64 {
		name = name[:64]
	}
	return name
}

func (s *Server) grantSet(c *caller) (map[string]bool, error) {
	out := map[string]bool{}
	if c.session == nil {
		return out, nil
	}
	grants, err := s.st.Grants(c.session.ID)
	for _, g := range grants {
		out[g.Folder] = true
	}
	return out, err
}

// sshKeyGuard keeps SYSTEM/ssh away from every session, elevated ones
// included: the private key is only ever used through the agent socket.
func sshKeyGuard(c *caller, folder, name string) error {
	if !c.admin && folder == api.SystemFolder && name == SSHItem {
		return errf(http.StatusForbidden, api.ErrForbidden, "%s/%s can only be used through the SSH agent (agpass ssh), never read or replaced by a session", api.SystemFolder, SSHItem)
	}
	return nil
}

func (s *Server) checkAccess(c *caller, folder string) error {
	if c.full() {
		return nil
	}
	if folder == api.SystemFolder {
		return errf(http.StatusForbidden, api.ErrForbidden, "%s is not available to agent sessions", api.SystemFolder)
	}
	have, err := s.grantSet(c)
	if err != nil {
		return err
	}
	if !have[folder] {
		return errf(http.StatusForbidden, api.ErrForbidden, "this session has no access to folder %q; run `agpass connect --reason ...`", folder)
	}
	return nil
}

func (s *Server) list(r *http.Request, c *caller) (any, error) {
	only := r.URL.Query().Get("folder")
	folders, err := s.st.ListFolders()
	if err != nil {
		return nil, err
	}
	have, err := s.grantSet(c)
	if err != nil {
		return nil, err
	}
	resp := api.ListResponse{Folders: []api.Folder{}}
	for _, f := range folders {
		if only != "" && f.Name != only {
			continue
		}
		if c.full() || have[f.Name] {
			if f.Items, err = s.st.ListItems(f.Name); err != nil {
				return nil, err
			}
			resp.Folders = append(resp.Folders, f)
		} else if f.Name != api.SystemFolder {
			resp.Others = append(resp.Others, api.FolderRef{Name: f.Name, Project: f.Project})
		}
	}
	if only != "" && len(resp.Folders) == 0 {
		if err := s.checkAccess(c, only); err != nil {
			return nil, err
		}
		return nil, errf(http.StatusNotFound, api.ErrNotFound, "folder %q not found", only)
	}
	s.Log.Emit(events.Event{Level: events.LevelInfo, Action: "list", Actor: c.String(), Target: only})
	return resp, nil
}

func splitPath(p string) (string, string, error) {
	folder, name, ok := strings.Cut(p, "/")
	if !ok || !nameRe.MatchString(folder) || !nameRe.MatchString(name) {
		return "", "", errf(http.StatusBadRequest, api.ErrBadRequest, "item path must be folder/name (letters, digits, . _ -)")
	}
	return folder, name, nil
}

func (s *Server) getItem(r *http.Request, c *caller) (any, error) {
	path := r.URL.Query().Get("path")
	reveal := r.URL.Query().Get("reveal") == "1"
	folder, name, err := splitPath(path)
	if err != nil {
		return nil, err
	}
	if err := s.checkAccess(c, folder); err != nil {
		s.Log.Emit(events.Event{Level: events.LevelDeny, Action: "get", Actor: c.String(), Target: path})
		return nil, err
	}
	if err := sshKeyGuard(c, folder, name); err != nil {
		s.Log.Emit(events.Event{Level: events.LevelDeny, Action: "get", Actor: c.String(), Target: path})
		return nil, err
	}
	it, err := s.st.GetItem(folder, name)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errf(http.StatusNotFound, api.ErrNotFound, "item %q not found", path)
	}
	if err != nil {
		return nil, err
	}
	keys := fieldKeys(it.Fields)
	if reveal {
		s.Log.Emit(events.Event{Level: events.LevelWarn, Action: "reveal", Actor: c.String(), Target: path, Msg: "fields=" + keys})
	} else {
		it.Fields = redact.Fields(it.Fields)
		it.Redacted = true
		s.Log.Emit(events.Event{Level: events.LevelOK, Action: "get", Actor: c.String(), Target: path, Msg: "redacted"})
	}
	return it, nil
}

func (s *Server) setItem(r *http.Request, c *caller) (any, error) {
	var req api.SetItemRequest
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	folder, name, err := splitPath(req.Path)
	if err != nil {
		return nil, err
	}
	if err := s.checkAccess(c, folder); err != nil {
		s.Log.Emit(events.Event{Level: events.LevelDeny, Action: "set", Actor: c.String(), Target: req.Path})
		return nil, err
	}
	if err := sshKeyGuard(c, folder, name); err != nil {
		s.Log.Emit(events.Event{Level: events.LevelDeny, Action: "set", Actor: c.String(), Target: req.Path})
		return nil, err
	}
	if len(req.Fields) == 0 && len(req.Remove) == 0 {
		return nil, errf(http.StatusBadRequest, api.ErrBadRequest, "nothing to set")
	}
	removing := map[string]bool{}
	for _, k := range req.Remove {
		if !nameRe.MatchString(k) {
			return nil, errf(http.StatusBadRequest, api.ErrBadRequest, "invalid field key %q", k)
		}
		removing[k] = true
	}
	seen := map[string]bool{}
	for i, f := range req.Fields {
		if removing[f.Key] {
			return nil, errf(http.StatusBadRequest, api.ErrBadRequest, "field %q is both set and removed", f.Key)
		}
		if f.Type == "" {
			req.Fields[i].Type = api.TypeText
		}
		if !nameRe.MatchString(f.Key) || seen[f.Key] {
			return nil, errf(http.StatusBadRequest, api.ErrBadRequest, "invalid or duplicate field key %q", f.Key)
		}
		if !api.ValidType(req.Fields[i].Type) {
			return nil, errf(http.StatusBadRequest, api.ErrBadRequest, "invalid field type %q (text, sensitive, password, url)", f.Type)
		}
		seen[f.Key] = true
	}
	it, err := s.st.SetItem(folder, name, req.Fields, req.Remove, c.String())
	if errors.Is(err, store.ErrNotFound) {
		return nil, errf(http.StatusNotFound, api.ErrNotFound, "%v", err)
	}
	if err != nil {
		return nil, err
	}
	msg := fmt.Sprintf("v%d", it.Version)
	if len(req.Fields) > 0 {
		msg += " set=" + fieldKeys(req.Fields)
	}
	if len(req.Remove) > 0 {
		msg += " rm=" + strings.Join(req.Remove, ",")
	}
	s.Log.Emit(events.Event{Level: events.LevelOK, Action: "set", Actor: c.String(), Target: req.Path, Msg: msg})
	it.Fields = redact.Fields(it.Fields)
	it.Redacted = true
	return it, nil
}

func (s *Server) createFolder(r *http.Request, c *caller) (any, error) {
	var req api.FolderRequest
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	if !nameRe.MatchString(req.Name) {
		return nil, errf(http.StatusBadRequest, api.ErrBadRequest, "invalid folder name %q", req.Name)
	}
	if strings.EqualFold(req.Name, api.SystemFolder) {
		return nil, errf(http.StatusForbidden, api.ErrForbidden, "%s is reserved", api.SystemFolder)
	}
	if req.Project == nil || strings.TrimSpace(*req.Project) == "" {
		return nil, errf(http.StatusBadRequest, api.ErrBadRequest, "--project is required: say which project this folder is for")
	}
	if !c.full() {
		repos, err := s.agentRepos(c, req.Repos)
		if err != nil {
			s.Log.Emit(events.Event{Level: events.LevelDeny, Action: "folder-create", Actor: c.String(), Target: req.Name, Msg: err.Error()})
			return nil, err
		}
		req.Repos = &repos
	} else if req.Repos != nil {
		repos := normalizeRepos(*req.Repos)
		req.Repos = &repos
	}
	err := s.st.CreateFolder(req, c.String())
	if errors.Is(err, store.ErrExists) {
		return nil, errf(http.StatusConflict, api.ErrConflict, "folder %q already exists", req.Name)
	}
	if err != nil {
		return nil, err
	}
	if c.session != nil {
		if _, err := s.st.Grant(c.session.ID, req.Name, "created", "folder created by this session"); err != nil {
			return nil, err
		}
	}
	s.Log.Emit(events.Event{Level: events.LevelOK, Action: "folder-create", Actor: c.String(), Target: req.Name, Msg: "project=" + *req.Project})
	return s.st.GetFolder(req.Name)
}

func (s *Server) editFolder(r *http.Request, c *caller) (any, error) {
	var req api.FolderRequest
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	if err := s.checkAccess(c, req.Name); err != nil {
		s.Log.Emit(events.Event{Level: events.LevelDeny, Action: "folder-edit", Actor: c.String(), Target: req.Name})
		return nil, err
	}
	// An edit links and unlinks single repositories. Replacing the whole list
	// (what "repos" did before 0.3.0) silently dropped the other links.
	if req.Repos != nil {
		return nil, errf(http.StatusBadRequest, api.ErrBadRequest,
			"folder edit no longer replaces the repository list: use --repo to link and --rm-repo to unlink (update the agpass client)")
	}
	add, rm := normalizeRepos(req.AddRepos), normalizeRepos(req.RemoveRepos)
	for _, a := range add {
		if slices.Contains(rm, a) {
			return nil, errf(http.StatusBadRequest, api.ErrBadRequest, "repository %s is both linked and unlinked", a)
		}
	}
	if !c.full() && len(add)+len(rm) > 0 {
		// Agents link and unlink only their own repository, so a folder can't
		// be pushed onto, or taken from, another project's sessions.
		_, repo, err := s.sessionRepo(c)
		if err != nil {
			return nil, err
		}
		for _, n := range slices.Concat(add, rm) {
			if n != repo {
				err := errf(http.StatusForbidden, api.ErrForbidden,
					"agents can only link or unlink their own repository (%s); ask the user to change %s", orNone(repo), n)
				s.Log.Emit(events.Event{Level: events.LevelDeny, Action: "folder-edit", Actor: c.String(), Target: req.Name, Msg: err.Error()})
				return nil, err
			}
		}
	}
	f, err := s.st.UpdateFolder(req.Name, c.String(), func(f *api.Folder) {
		if req.Project != nil {
			f.Project = *req.Project
		}
		if req.Description != nil {
			f.Description = *req.Description
		}
		f.Repos = editRepos(f.Repos, add, rm)
	})
	if errors.Is(err, store.ErrNotFound) {
		return nil, errf(http.StatusNotFound, api.ErrNotFound, "folder %q not found", req.Name)
	}
	if err != nil {
		return nil, err
	}
	var changed []string
	if req.Project != nil {
		changed = append(changed, "project")
	}
	if req.Description != nil {
		changed = append(changed, "description")
	}
	for _, a := range add {
		changed = append(changed, "repo+"+a)
	}
	for _, r := range rm {
		changed = append(changed, "repo-"+r)
	}
	s.Log.Emit(events.Event{Level: events.LevelOK, Action: "folder-edit", Actor: c.String(), Target: req.Name, Msg: strings.Join(changed, " ")})
	return f, nil
}

func fieldKeys(fs []api.Field) string {
	keys := make([]string, len(fs))
	for i, f := range fs {
		keys[i] = f.Key
	}
	return strings.Join(keys, ",")
}

func truncate(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	cut := n - 1
	for cut > 0 && !utf8.RuneStart(s[cut]) { // don't cut inside a character
		cut--
	}
	return s[:cut] + "…"
}
