package server

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"

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
	mux.HandleFunc("POST /v1/connect", s.handle(authAgent, s.connect))
	mux.HandleFunc("GET /v1/whoami", s.handle(authSession, s.whoami))
	mux.HandleFunc("POST /v1/request-access", s.handle(authSession, s.requestAccess))
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

func (s *Server) mint(r *http.Request, c *caller) (any, error) {
	m := s.mintCode()
	s.Log.Emit(events.Event{Level: events.LevelOK, Action: "mint", Actor: c.String(), Msg: "connect code valid until " + m.ExpiresAt.Format("15:04:05")})
	return m, nil
}

func (s *Server) connect(r *http.Request, c *caller) (any, error) {
	if c.admin {
		return nil, errf(http.StatusBadRequest, api.ErrBadRequest, "connect is for agent sessions")
	}
	var req api.ConnectRequest
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	if c.session != nil { // already connected: keep the code for another session
		s.Log.Emit(events.Event{Level: events.LevelInfo, Action: "connect", Actor: c.String(), Msg: "already connected; code not used"})
		return s.sessionInfo(c.session)
	}
	restore, err := s.redeemCode(strings.TrimSpace(req.Code))
	if err != nil {
		s.Log.Emit(events.Event{Level: events.LevelDeny, Action: "connect", Actor: c.String(), Msg: err.Error()})
		return nil, err
	}
	cwd, _ := peer.Cwd(c.agent.PID) // the agent's own cwd, not what the client claims
	sess, err := s.st.UpsertSession(store.Session{
		ID: randomID("s-"), PID: c.agent.PID, StartUS: c.agent.StartUS,
		Agent: c.name, Exe: c.agent.Exe, Cwd: cwd,
	})
	if err != nil {
		restore()
		return nil, err
	}
	c.session = &sess
	s.Log.Emit(events.Event{Level: events.LevelOK, Action: "connect", Actor: c.String(), Target: cwd, Msg: "session bound to " + c.agent.Exe})
	return s.sessionInfo(&sess)
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
	return api.SessionInfo{
		ID: sess.ID, Agent: sess.Agent, PID: sess.PID, Exe: sess.Exe, Cwd: sess.Cwd,
		Repo: sess.Repo, Reason: sess.Reason, CreatedAt: sess.CreatedAt, Grants: grants,
	}, nil
}

func (s *Server) requestAccess(r *http.Request, c *caller) (any, error) {
	if c.admin {
		return nil, errf(http.StatusBadRequest, api.ErrBadRequest, "the master password already has access to everything")
	}
	var req api.AccessRequest
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.Reason) == "" {
		return nil, errf(http.StatusBadRequest, api.ErrBadRequest, "a reason is required: say what you are working on and why you need secrets")
	}
	// The repository is worked out from the agent process's own working
	// directory. What the client says (--repo, its cwd) is only a claim: the
	// LLM sees it, repository matching never uses it.
	cwd, err := peer.Cwd(c.agent.PID)
	if err != nil {
		return nil, fmt.Errorf("read working directory of %s pid %d: %w", c.name, c.agent.PID, err)
	}
	repo := NormalizeRepo(GitOrigin(cwd))
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
	for _, f := range folders {
		if f.Name == api.SystemFolder || have[f.Name] {
			continue
		}
		if repo != "" && slices.ContainsFunc(f.Repos, func(r string) bool { return NormalizeRepo(r) == repo }) {
			if err := grant(f.Name, "repo-match", "repository "+repo+" is listed on the folder"); err != nil {
				return nil, err
			}
			continue
		}
		writtenBy := "agent" // created or last edited by an agent session: untrusted
		if f.UpdatedBy == "human" || f.UpdatedBy == "server" {
			writtenBy = "owner"
		}
		candidates = append(candidates, llm.FolderInfo{Name: f.Name, Project: f.Project, Description: f.Description, Repos: f.Repos, WrittenBy: writtenBy})
	}

	// 2. LLM: when nothing matched, or the agent asked for folders it doesn't have yet.
	pending := slices.DeleteFunc(slices.Clone(req.Folders), func(f string) bool { return have[f] })
	if len(candidates) > 0 && (len(resp.Granted) == 0 || len(pending) > 0) {
		key := s.llmKey()
		if key == "" {
			resp.Explanation = "LLM gatekeeper not configured (store the API key as SYSTEM/anthropic field api_key); only repository matches are granted"
		} else {
			d, err := llm.Decide(r.Context(), key, llm.Request{Repo: repo, ClaimedRepo: claimed, Cwd: cwd, Reason: req.Reason, Requested: req.Folders, Folders: candidates})
			if err != nil {
				s.Log.Emit(events.Event{Level: events.LevelWarn, Action: "llm", Actor: c.String(), Msg: err.Error()})
				resp.Explanation = "LLM gatekeeper failed: " + err.Error()
			} else {
				resp.Explanation = d.Explanation
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
		s.Log.Emit(events.Event{Level: events.LevelDeny, Action: "request-access", Actor: c.String(), Target: strings.Join(resp.Denied, ","), Msg: truncate(req.Reason, 80)})
	}
	if resp.Session, err = s.sessionInfo(c.session); err != nil {
		return nil, err
	}
	if resp.Granted == nil {
		resp.Granted = []api.Grant{}
	}
	return resp, nil
}

func (s *Server) llmKey() string {
	it, err := s.st.GetItem(api.SystemFolder, "anthropic")
	if err != nil {
		return ""
	}
	for _, f := range it.Fields {
		if f.Key == "api_key" {
			return f.Value
		}
	}
	return ""
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

func (s *Server) checkAccess(c *caller, folder string) error {
	if c.admin {
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
		return errf(http.StatusForbidden, api.ErrForbidden, "this session has no access to folder %q; run `agpass request-access --reason ...`", folder)
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
		if c.admin || have[f.Name] {
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
	f, err := s.st.UpdateFolder(req, c.String())
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
	if req.Repos != nil {
		changed = append(changed, "repos="+strings.Join(*req.Repos, ","))
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
	return s[:n-1] + "…"
}
