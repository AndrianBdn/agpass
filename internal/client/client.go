// Package client talks to the agpass server over its Unix socket.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"syscall"
	"time"

	"agpass/internal/api"
)

type Client struct {
	Master string // master password, sent as X-Agpass-Master when set
	sock   string
	http   *http.Client
	warned bool
}

func New(sock string) *Client {
	return &Client{
		sock: sock,
		http: &http.Client{
			Timeout: 3 * time.Minute, // connect may wait on the LLM
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", sock)
				},
			},
		},
	}
}

var ErrNotRunning = errors.New("agpass server is not running (start it with `agpass serve` in a terminal tab)")

// Do sends a JSON request. API errors are returned as *api.Error.
func (c *Client) Do(method, path string, query url.Values, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	u := "http://agpass" + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequest(method, u, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(api.HeaderVersion, api.Version)
	if c.Master != "" {
		req.Header.Set(api.HeaderMaster, c.Master)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED) {
			return ErrNotRunning
		}
		return err
	}
	defer resp.Body.Close()
	if v := resp.Header.Get(api.HeaderVersion); v != "" && v != api.Version && !c.warned {
		c.warned = true
		fmt.Fprintf(os.Stderr, "agpass: warning: server is version %s, client is %s — restart `agpass serve`\n", v, api.Version)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		apiErr := &api.Error{}
		if json.Unmarshal(data, apiErr) != nil || apiErr.Code == "" {
			return fmt.Errorf("server returned %s", resp.Status)
		}
		return apiErr
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}
