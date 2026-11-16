package store

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"agpass/internal/api"
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
			sess, err := s.UpsertSession(Session{ID: fmt.Sprintf("s%d", i), PID: 42, StartUS: 7, Agent: "claude", Exe: "/x"})
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
