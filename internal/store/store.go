// Package store is the encrypted SQLite store (ncruces/go-sqlite3 with the
// Adiantum VFS: the whole file — pages, journal, temp files — is encrypted).
package store

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ncruces/go-sqlite3"
	"github.com/ncruces/go-sqlite3/driver"
	_ "github.com/ncruces/go-sqlite3/vfs/adiantum"

	"agpass/internal/api"
)

var ErrNotFound = errors.New("not found")
var ErrExists = errors.New("already exists")

const schema = `
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
INSERT OR IGNORE INTO meta (k, v) VALUES ('generation', '0'), ('schema', '1');

CREATE TABLE IF NOT EXISTS folders (
	name        TEXT PRIMARY KEY,
	project     TEXT NOT NULL DEFAULT '',
	description TEXT NOT NULL DEFAULT '',
	repos       TEXT NOT NULL DEFAULT '[]',
	created_at  TEXT NOT NULL,
	created_by  TEXT NOT NULL,
	updated_at  TEXT NOT NULL,
	updated_by  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS items (
	folder     TEXT NOT NULL REFERENCES folders(name),
	name       TEXT NOT NULL,
	fields     TEXT NOT NULL,
	version    INTEGER NOT NULL,
	created_at TEXT NOT NULL,
	created_by TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	updated_by TEXT NOT NULL,
	PRIMARY KEY (folder, name)
);

CREATE TABLE IF NOT EXISTS item_history (
	folder     TEXT NOT NULL,
	name       TEXT NOT NULL,
	version    INTEGER NOT NULL,
	fields     TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	updated_by TEXT NOT NULL,
	PRIMARY KEY (folder, name, version)
);

CREATE TABLE IF NOT EXISTS sessions (
	id         TEXT PRIMARY KEY,
	pid        INTEGER NOT NULL,
	start_us   INTEGER NOT NULL,
	agent      TEXT NOT NULL,
	exe        TEXT NOT NULL,
	cwd        TEXT NOT NULL DEFAULT '',
	repo       TEXT NOT NULL DEFAULT '',
	reason     TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	UNIQUE (pid, start_us)
);

CREATE TABLE IF NOT EXISTS grants (
	session_id  TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
	folder      TEXT NOT NULL REFERENCES folders(name),
	granted_by  TEXT NOT NULL,
	explanation TEXT NOT NULL DEFAULT '',
	at          TEXT NOT NULL,
	PRIMARY KEY (session_id, folder)
);
`

type Store struct {
	db      *sql.DB
	genPath string
	// wmu serializes write transactions together with publishing their
	// generation, so the generation file only ever moves forward.
	wmu sync.Mutex
}

// queryer is satisfied by *sql.DB and *sql.Tx. Reads that feed a write must
// use the write's tx: with one connection, s.db inside a tx would deadlock.
type queryer interface {
	QueryRow(query string, args ...any) *sql.Row
}

type Session struct {
	ID        string
	PID       int
	StartUS   int64
	Agent     string
	Exe       string
	Cwd       string
	Repo      string
	Reason    string
	CreatedAt time.Time
}

// Open opens (or creates) the database at dir/agpass.db with dek.
// It refuses to open a database whose generation counter is older than the
// last one recorded in dir/generation (a swapped-in old copy), unless
// allowRollback is set.
func Open(dir string, dek []byte, allowRollback bool) (*Store, error) {
	path := filepath.Join(dir, "agpass.db")
	pragmas := fmt.Sprintf("PRAGMA hexkey='%s'; PRAGMA temp_store=memory; PRAGMA foreign_keys=on; PRAGMA busy_timeout=5000;", hex.EncodeToString(dek))
	db, err := driver.Open("file:"+path+"?vfs=adiantum", func(c *sqlite3.Conn) error {
		return c.Exec(pragmas)
	})
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		if strings.Contains(err.Error(), "not a database") {
			return nil, fmt.Errorf("cannot decrypt %s (wrong key or corrupted file)", path)
		}
		return nil, fmt.Errorf("init schema: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		db.Close()
		return nil, err
	}
	s := &Store{db: db, genPath: filepath.Join(dir, "generation")}
	dbGen, err := s.generation()
	if err != nil {
		db.Close()
		return nil, err
	}
	if b, err := os.ReadFile(s.genPath); err == nil {
		fileGen, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
		if dbGen < fileGen && !allowRollback {
			db.Close()
			return nil, fmt.Errorf("database generation %d is older than last seen %d: the database file may have been replaced with an older copy (start with --accept-rollback if this is intended)", dbGen, fileGen)
		}
	}
	if err := s.writeGen(dbGen); err != nil {
		db.Close()
		return nil, err
	}
	if err := s.ensureSystemFolder(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) generation() (int64, error) {
	var v string
	if err := s.db.QueryRow(`SELECT v FROM meta WHERE k='generation'`).Scan(&v); err != nil {
		return 0, err
	}
	return strconv.ParseInt(v, 10, 64)
}

// writeGen atomically replaces the generation file (unique temp file,
// fsync, rename).
func (s *Store) writeGen(gen int64) error {
	f, err := os.CreateTemp(filepath.Dir(s.genPath), ".generation-*")
	if err != nil {
		return fmt.Errorf("record generation: %w", err)
	}
	tmp := f.Name()
	_, err = f.WriteString(strconv.FormatInt(gen, 10) + "\n")
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, s.genPath)
	}
	if err != nil {
		os.Remove(tmp)
		return fmt.Errorf("record generation: %w", err)
	}
	return nil
}

// write runs fn in a transaction, bumps the generation counter and publishes
// it. The whole sequence holds wmu, so writes are serialized and the
// generation file is never overwritten with an older value.
func (s *Store) write(fn func(tx *sql.Tx) error) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	var gen int64
	if err := tx.QueryRow(`UPDATE meta SET v = CAST(v AS INTEGER) + 1 WHERE k='generation' RETURNING CAST(v AS INTEGER)`).Scan(&gen); err != nil {
		tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if err := s.writeGen(gen); err != nil {
		return fmt.Errorf("change saved, but %w", err)
	}
	return nil
}

func (s *Store) ensureSystemFolder() error {
	if _, err := s.GetFolder(api.SystemFolder); err == nil {
		return nil
	}
	desc := "agpass internal secrets (LLM API key, SSH keys). Never granted to agents."
	return s.CreateFolder(api.FolderRequest{Name: api.SystemFolder, Project: ptr("agpass"), Description: &desc}, "server")
}

// ---- folders ----

func (s *Store) CreateFolder(req api.FolderRequest, actor string) error {
	now := ts(time.Now())
	repos, _ := json.Marshal(deref(req.Repos))
	return s.write(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO folders (name, project, description, repos, created_at, created_by, updated_at, updated_by)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			req.Name, deref(req.Project), deref(req.Description), string(repos), now, actor, now, actor)
		if err != nil && strings.Contains(err.Error(), "UNIQUE") {
			return ErrExists
		}
		return err
	})
}

func (s *Store) UpdateFolder(req api.FolderRequest, actor string) (api.Folder, error) {
	var f api.Folder
	err := s.write(func(tx *sql.Tx) error {
		var err error
		if f, err = getFolder(tx, req.Name); err != nil {
			return err
		}
		if req.Project != nil {
			f.Project = *req.Project
		}
		if req.Description != nil {
			f.Description = *req.Description
		}
		if req.Repos != nil {
			f.Repos = *req.Repos
		}
		repos, _ := json.Marshal(f.Repos)
		now := time.Now()
		f.UpdatedAt, f.UpdatedBy = now, actor
		_, err = tx.Exec(`UPDATE folders SET project=?, description=?, repos=?, updated_at=?, updated_by=? WHERE name=?`,
			f.Project, f.Description, string(repos), ts(now), actor, f.Name)
		return err
	})
	return f, err
}

const folderCols = `name, project, description, repos, created_at, created_by, updated_at, updated_by`

func scanFolder(sc interface{ Scan(...any) error }) (api.Folder, error) {
	var f api.Folder
	var repos, ca, ua string
	if err := sc.Scan(&f.Name, &f.Project, &f.Description, &repos, &ca, &f.CreatedBy, &ua, &f.UpdatedBy); err != nil {
		return f, err
	}
	json.Unmarshal([]byte(repos), &f.Repos)
	if f.Repos == nil {
		f.Repos = []string{}
	}
	f.CreatedAt, f.UpdatedAt = parseTS(ca), parseTS(ua)
	return f, nil
}

func (s *Store) GetFolder(name string) (api.Folder, error) { return getFolder(s.db, name) }

func getFolder(q queryer, name string) (api.Folder, error) {
	f, err := scanFolder(q.QueryRow(`SELECT `+folderCols+` FROM folders WHERE name=?`, name))
	if errors.Is(err, sql.ErrNoRows) {
		return f, ErrNotFound
	}
	return f, err
}

func (s *Store) ListFolders() ([]api.Folder, error) {
	rows, err := s.db.Query(`SELECT ` + folderCols + ` FROM folders ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []api.Folder
	for rows.Next() {
		f, err := scanFolder(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// ---- items ----

func (s *Store) ListItems(folder string) ([]api.ItemSummary, error) {
	rows, err := s.db.Query(`SELECT name, fields, version, updated_at FROM items WHERE folder=? ORDER BY name`, folder)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []api.ItemSummary{}
	for rows.Next() {
		var it api.ItemSummary
		var fields, ua string
		if err := rows.Scan(&it.Name, &fields, &it.Version, &ua); err != nil {
			return nil, err
		}
		var fs []api.Field
		json.Unmarshal([]byte(fields), &fs)
		for _, f := range fs {
			it.Fields = append(it.Fields, api.FieldSummary{Key: f.Key, Type: f.Type})
		}
		it.UpdatedAt = parseTS(ua)
		out = append(out, it)
	}
	return out, rows.Err()
}

func (s *Store) GetItem(folder, name string) (api.Item, error) { return getItem(s.db, folder, name) }

func getItem(q queryer, folder, name string) (api.Item, error) {
	it := api.Item{Folder: folder, Name: name}
	var fields, ca, ua string
	err := q.QueryRow(`SELECT fields, version, created_at, created_by, updated_at, updated_by FROM items WHERE folder=? AND name=?`, folder, name).
		Scan(&fields, &it.Version, &ca, &it.CreatedBy, &ua, &it.UpdatedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return it, ErrNotFound
	}
	if err != nil {
		return it, err
	}
	if err := json.Unmarshal([]byte(fields), &it.Fields); err != nil {
		return it, err
	}
	it.CreatedAt, it.UpdatedAt = parseTS(ca), parseTS(ua)
	return it, nil
}

// SetItem upserts fields by key (existing keys not mentioned are kept),
// removes the keys in remove, and records the previous version in history.
func (s *Store) SetItem(folder, name string, fields []api.Field, remove []string, actor string) (api.Item, error) {
	var out api.Item
	err := s.write(func(tx *sql.Tx) error {
		if _, err := getFolder(tx, folder); err != nil {
			return err
		}
		// Read, merge and write in one transaction so concurrent updates to
		// the same item apply one after the other instead of colliding.
		cur, err := getItem(tx, folder, name)
		exists := err == nil
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		merged := slices.Clone(cur.Fields)
		for _, f := range fields {
			if i := slices.IndexFunc(merged, func(m api.Field) bool { return m.Key == f.Key }); i >= 0 {
				merged[i] = f
			} else {
				merged = append(merged, f)
			}
		}
		merged = slices.DeleteFunc(merged, func(m api.Field) bool { return slices.Contains(remove, m.Key) })
		if merged == nil {
			merged = []api.Field{}
		}
		b, _ := json.Marshal(merged)
		now := ts(time.Now())
		if !exists {
			if _, err := tx.Exec(`INSERT INTO items (folder, name, fields, version, created_at, created_by, updated_at, updated_by)
				VALUES (?, ?, ?, 1, ?, ?, ?, ?)`, folder, name, string(b), now, actor, now, actor); err != nil {
				return err
			}
		} else {
			old, _ := json.Marshal(cur.Fields)
			if _, err := tx.Exec(`INSERT INTO item_history (folder, name, version, fields, updated_at, updated_by) VALUES (?, ?, ?, ?, ?, ?)`,
				folder, name, cur.Version, string(old), ts(cur.UpdatedAt), cur.UpdatedBy); err != nil {
				return err
			}
			if _, err := tx.Exec(`UPDATE items SET fields=?, version=version+1, updated_at=?, updated_by=? WHERE folder=? AND name=?`,
				string(b), now, actor, folder, name); err != nil {
				return err
			}
		}
		out, err = getItem(tx, folder, name)
		return err
	})
	return out, err
}

// ---- sessions ----

func (s *Store) UpsertSession(sess Session) (Session, error) {
	if existing, err := s.SessionByProc(sess.PID, sess.StartUS); err == nil {
		return existing, nil // fast path, no write
	}
	out := sess
	err := s.write(func(tx *sql.Tx) error {
		// Re-check inside the transaction: a concurrent connect for the same
		// process may have inserted it since.
		existing, err := sessionByProc(tx, sess.PID, sess.StartUS)
		if err == nil {
			out = existing
			return nil
		}
		if !errors.Is(err, ErrNotFound) {
			return err
		}
		out.CreatedAt = time.Now()
		_, err = tx.Exec(`INSERT INTO sessions (id, pid, start_us, agent, exe, cwd, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			out.ID, out.PID, out.StartUS, out.Agent, out.Exe, out.Cwd, ts(out.CreatedAt))
		return err
	})
	return out, err
}

func (s *Store) SessionByProc(pid int, startUS int64) (Session, error) {
	return sessionByProc(s.db, pid, startUS)
}

func sessionByProc(q queryer, pid int, startUS int64) (Session, error) {
	var sess Session
	var ca string
	err := q.QueryRow(`SELECT id, pid, start_us, agent, exe, cwd, repo, reason, created_at FROM sessions WHERE pid=? AND start_us=?`, pid, startUS).
		Scan(&sess.ID, &sess.PID, &sess.StartUS, &sess.Agent, &sess.Exe, &sess.Cwd, &sess.Repo, &sess.Reason, &ca)
	if errors.Is(err, sql.ErrNoRows) {
		return sess, ErrNotFound
	}
	sess.CreatedAt = parseTS(ca)
	return sess, err
}

func (s *Store) UpdateSessionClaims(id, cwd, repo, reason string) error {
	return s.write(func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE sessions SET cwd=?, repo=?, reason=? WHERE id=?`, cwd, repo, reason, id)
		return err
	})
}

func (s *Store) Grants(sessionID string) ([]api.Grant, error) {
	rows, err := s.db.Query(`SELECT folder, granted_by, explanation, at FROM grants WHERE session_id=? ORDER BY folder`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []api.Grant{}
	for rows.Next() {
		var g api.Grant
		var at string
		if err := rows.Scan(&g.Folder, &g.By, &g.Explanation, &at); err != nil {
			return nil, err
		}
		g.At = parseTS(at)
		out = append(out, g)
	}
	return out, rows.Err()
}

func (s *Store) Grant(sessionID, folder, by, explanation string) (api.Grant, error) {
	g := api.Grant{Folder: folder, By: by, Explanation: explanation, At: time.Now()}
	err := s.write(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT OR IGNORE INTO grants (session_id, folder, granted_by, explanation, at) VALUES (?, ?, ?, ?, ?)`,
			sessionID, folder, by, explanation, ts(g.At))
		return err
	})
	return g, err
}

// ---- helpers ----

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func parseTS(s string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t
}

func ptr[T any](v T) *T { return &v }

func deref[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}
