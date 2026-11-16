// Package api holds the wire types shared by the agpass server and client.
package api

import "time"

const Version = "0.1.0"

const (
	HeaderVersion = "X-Agpass-Version"
	HeaderMaster  = "X-Agpass-Master"
)

// SystemFolder holds agpass's own secrets (LLM key, SSH key). It is never
// granted to agent sessions and never shown to the LLM gatekeeper.
const SystemFolder = "SYSTEM"

// Redacted replaces secret material in redacted responses.
const Redacted = "[REDACTED_AGPASS]"

// Field types.
const (
	TypeText      = "text"
	TypeSensitive = "sensitive"
	TypePassword  = "password"
	TypeURL       = "url"
)

func ValidType(t string) bool {
	switch t {
	case TypeText, TypeSensitive, TypePassword, TypeURL:
		return true
	}
	return false
}

// Error codes.
const (
	ErrNeedAdmin    = "need_admin"
	ErrNotConnected = "not_connected"
	ErrForbidden    = "forbidden"
	ErrNotFound     = "not_found"
	ErrBadRequest   = "bad_request"
	ErrLocked       = "locked"
	ErrRateLimited  = "rate_limited"
	ErrConflict     = "conflict"
	ErrInternal     = "internal"
)

type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return e.Message }

type Field struct {
	Key   string `json:"key"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Meta is maintained by the server; clients cannot set it.
type Meta struct {
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
	UpdatedAt time.Time `json:"updated_at"`
	UpdatedBy string    `json:"updated_by"`
}

type Item struct {
	Folder   string  `json:"folder"`
	Name     string  `json:"name"`
	Fields   []Field `json:"fields"`
	Version  int     `json:"version"`
	Redacted bool    `json:"redacted"`
	Meta
}

type FieldSummary struct {
	Key  string `json:"key"`
	Type string `json:"type"`
}

type ItemSummary struct {
	Name      string         `json:"name"`
	Fields    []FieldSummary `json:"fields"`
	Version   int            `json:"version"`
	UpdatedAt time.Time      `json:"updated_at"`
}

type Folder struct {
	Name        string        `json:"name"`
	Project     string        `json:"project"`
	Description string        `json:"description"`
	Repos       []string      `json:"repos"`
	Items       []ItemSummary `json:"items,omitempty"`
	Meta
}

// FolderRef is what a session sees of folders it has not been granted.
type FolderRef struct {
	Name    string `json:"name"`
	Project string `json:"project"`
}

type Grant struct {
	Folder      string    `json:"folder"`
	By          string    `json:"by"` // repo-match | llm | created
	Explanation string    `json:"explanation,omitempty"`
	At          time.Time `json:"at"`
}

type SessionInfo struct {
	ID        string    `json:"id"`
	Agent     string    `json:"agent"`
	PID       int       `json:"pid"`
	Exe       string    `json:"exe"`
	Cwd       string    `json:"cwd"`
	Repo      string    `json:"repo"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"created_at"`
	Grants    []Grant   `json:"grants"`
}

type WhoamiResponse struct {
	Admin   bool         `json:"admin"`
	Session *SessionInfo `json:"session,omitempty"`
}

type UnlockRequest struct {
	Password string `json:"password"`
}

type StatusResponse struct {
	Version  string `json:"version"`
	Unlocked bool   `json:"unlocked"`
}

type MintResponse struct {
	Code      string    `json:"code"`
	ExpiresAt time.Time `json:"expires_at"`
}

type ConnectRequest struct {
	Code string `json:"code"`
	Cwd  string `json:"cwd"`
}

type AccessRequest struct {
	Repo    string   `json:"repo"`
	Reason  string   `json:"reason"`
	Folders []string `json:"folders,omitempty"`
	Cwd     string   `json:"cwd"`
}

type AccessResponse struct {
	Granted     []Grant     `json:"granted"`
	Denied      []string    `json:"denied,omitempty"`
	Explanation string      `json:"explanation,omitempty"`
	Session     SessionInfo `json:"session"`
}

type ListResponse struct {
	Folders []Folder    `json:"folders"`
	Others  []FolderRef `json:"others,omitempty"`
}

type SetItemRequest struct {
	Path   string   `json:"path"`
	Fields []Field  `json:"fields"`
	Remove []string `json:"remove,omitempty"`
}

// FolderRequest creates (all fields) or edits (nil = unchanged) a folder.
type FolderRequest struct {
	Name        string    `json:"name"`
	Project     *string   `json:"project,omitempty"`
	Description *string   `json:"description,omitempty"`
	Repos       *[]string `json:"repos,omitempty"`
}
