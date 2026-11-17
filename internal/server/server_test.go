package server

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"agpass/internal/api"
	"agpass/internal/events"
	"agpass/internal/vault"
)

// A client that sends headers but never the body must not keep the server
// from stopping.
func TestShutdownWithStalledRequest(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "agp") // short: unix socket paths are limited
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	const pw = "correct-horse-1"
	if _, err := vault.Create(KeyPath(dir), pw); err != nil {
		t.Fatal(err)
	}
	s := New(dir, events.New(nil, false))
	if err := s.Unlock(pw); err != nil {
		t.Fatal(err)
	}
	if err := s.Listen(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- s.Serve(ctx) }()

	c, err := net.Dial("unix", SocketPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Authenticated request whose body never completes: the handler blocks
	// reading it.
	fmt.Fprintf(c, "POST /v1/item HTTP/1.1\r\nHost: agpass\r\n%s: %s\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{\"path\":", api.HeaderMaster, pw)
	time.Sleep(time.Second) // let the master-password check finish and the handler start reading

	start := time.Now()
	cancel()
	select {
	case err := <-served:
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("stopped after %s", time.Since(start).Round(time.Millisecond))
	case <-time.After(2*shutdownGrace + 5*time.Second):
		t.Fatal("server did not stop")
	}
}
