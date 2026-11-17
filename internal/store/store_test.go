package store

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"agpass/internal/api"
	"agpass/internal/events"
)

func openTest(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	dek := make([]byte, 32)
	rand.Read(dek)
	s, err := Open(dir, dek, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, dir
}

func TestConcurrentSetItem(t *testing.T) {
	s, dir := openTest(t)
	if err := s.CreateFolder(api.FolderRequest{Name: "crm"}, "test"); err != nil {
		t.Fatal(err)
	}
	const n = 25
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f := api.Field{Key: fmt.Sprintf("k%d", i), Type: api.TypeText, Value: "v"}
			if _, err := s.SetItem("crm", "db", []api.Field{f}, nil, "test"); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	it, err := s.GetItem("crm", "db")
	if err != nil {
		t.Fatal(err)
	}
	if len(it.Fields) != n || it.Version != n {
		t.Fatalf("got %d fields, version %d; want %d, %d", len(it.Fields), it.Version, n, n)
	}

	// The generation file matches the database after concurrent writes.
	dbGen, _ := s.generation()
	b, err := os.ReadFile(filepath.Join(dir, "generation"))
	if err != nil {
		t.Fatal(err)
	}
	fileGen, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if fileGen != dbGen {
		t.Fatalf("generation file %d, database %d", fileGen, dbGen)
	}
	if m, _ := filepath.Glob(filepath.Join(dir, ".generation-*")); len(m) > 0 {
		t.Fatalf("leftover temp files: %v", m)
	}
}

func TestConcurrentUpsertSession(t *testing.T) {
	s, _ := openTest(t)
	var wg sync.WaitGroup
	ids := make(chan string, 10)
	for i := range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sess, _, err := s.UpsertSession(Session{ID: fmt.Sprintf("s%d", i), PID: 42, StartUS: 7, Agent: "claude", Exe: "/x"})
			if err != nil {
				t.Error(err)
				return
			}
			ids <- sess.ID
		}()
	}
	wg.Wait()
	close(ids)
	first := ""
	for id := range ids {
		if first == "" {
			first = id
		} else if id != first {
			t.Fatalf("same process got two sessions: %s and %s", first, id)
		}
	}
}

func TestSetItemRemove(t *testing.T) {
	s, _ := openTest(t)
	if err := s.CreateFolder(api.FolderRequest{Name: "crm"}, "test"); err != nil {
		t.Fatal(err)
	}
	// Remove-only on a missing item must not create it.
	_, err := s.SetItem("crm", "typo", nil, []string{"x"}, "test")
	if !errors.Is(err, ErrNotFound) || err.Error() != "item crm/typo not found" {
		t.Fatalf("remove on missing item: %v", err)
	}
	if _, err := s.GetItem("crm", "typo"); !errors.Is(err, ErrNotFound) {
		t.Fatal("remove-only created the item")
	}
	if _, err := s.SetItem("nope", "x", []api.Field{{Key: "a", Value: "1"}}, nil, "test"); err == nil || err.Error() != `folder "nope" not found` {
		t.Fatalf("missing folder: %v", err)
	}
	if _, err := s.SetItem("crm", "db", []api.Field{{Key: "a", Type: api.TypeText, Value: "1"}}, nil, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetItem("crm", "db", nil, []string{"b"}, "test"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("remove missing field: %v", err)
	}
	it, err := s.SetItem("crm", "db", nil, []string{"a"}, "test")
	if err != nil || len(it.Fields) != 0 || it.Version != 2 {
		t.Fatalf("remove field: %+v %v", it, err)
	}
}

func TestEvents(t *testing.T) {
	s, _ := openTest(t)
	base := time.Now()
	for i := range 5 {
		if err := s.AddEvent(events.Event{Time: base.Add(time.Duration(i) * time.Second), Level: "ok", Action: fmt.Sprintf("a%d", i)}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.RecentEvents(3)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].Action != "a2" || got[2].Action != "a4" {
		t.Fatalf("want a2..a4 oldest first, got %+v", got)
	}
}

// A vault created before admin_until existed gets the column on open.
func TestMigrateAddsAdminUntil(t *testing.T) {
	dir := t.TempDir()
	dek := make([]byte, 32)
	rand.Read(dek)
	s, err := Open(dir, dek, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.UpsertSession(Session{ID: "s1", PID: 1, StartUS: 2, Agent: "claude", Exe: "/x"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`ALTER TABLE sessions DROP COLUMN admin_until`); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(dir, dek, false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	until := time.Now().Add(time.Hour).Truncate(time.Microsecond)
	if err := s.SetSessionAdmin("s1", until); err != nil {
		t.Fatal(err)
	}
	got, err := s.SessionByProc(1, 2)
	if err != nil || !got.AdminUntil.Equal(until) {
		t.Fatalf("got %v %v, want %v", got.AdminUntil, err, until)
	}
}
