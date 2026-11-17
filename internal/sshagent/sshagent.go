// Package sshagent holds the SSH pieces of agpass that don't depend on the
// server: key generation and import, the session-bind@openssh.com message
// that tells an agent which server a signature is for, and host key scans.
package sshagent

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Generate creates an Ed25519 key. It returns the private key in OpenSSH PEM
// form and the public key in authorized_keys form.
func Generate(comment string) (privPEM []byte, authorized string, err error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", err
	}
	return encode(priv, comment)
}

// Normalize parses a private key (any format ssh-keygen writes, optionally
// passphrase-protected) and returns it unencrypted in OpenSSH PEM form, with
// its public key. The vault's encryption protects it at rest.
func Normalize(pemBytes, passphrase []byte, comment string) (privPEM []byte, authorized string, err error) {
	var key any
	if len(passphrase) > 0 {
		key, err = ssh.ParseRawPrivateKeyWithPassphrase(pemBytes, passphrase)
	} else {
		key, err = ssh.ParseRawPrivateKey(pemBytes)
	}
	if err != nil {
		return nil, "", err
	}
	switch k := key.(type) {
	case *ed25519.PrivateKey:
		key = *k
	case ed25519.PrivateKey, *rsa.PrivateKey, *ecdsa.PrivateKey:
	default:
		return nil, "", fmt.Errorf("unsupported key type %T (use ed25519, ecdsa or rsa)", key)
	}
	return encode(key.(crypto.PrivateKey), comment)
}

// IsPassphraseError reports whether err means the key needs a passphrase.
func IsPassphraseError(err error) bool {
	var e *ssh.PassphraseMissingError
	return errors.As(err, &e)
}

func encode(key crypto.PrivateKey, comment string) ([]byte, string, error) {
	block, err := ssh.MarshalPrivateKey(key, comment)
	if err != nil {
		return nil, "", err
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, "", err
	}
	auth := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	if comment != "" {
		auth += " " + comment
	}
	return pem.EncodeToMemory(block), auth, nil
}

// Signer loads a private key stored by Generate or Normalize.
func Signer(privPEM []byte) (ssh.Signer, error) {
	return ssh.ParsePrivateKey(privPEM)
}

// SignWithFlags signs data like an agent: RSA keys honour the rsa-sha2-256/512
// flags, other keys sign with their only algorithm.
func SignWithFlags(s ssh.Signer, data []byte, rsaSHA256, rsaSHA512 bool) (*ssh.Signature, error) {
	if as, ok := s.(ssh.AlgorithmSigner); ok && s.PublicKey().Type() == ssh.KeyAlgoRSA {
		switch {
		case rsaSHA512:
			return as.SignWithAlgorithm(rand.Reader, data, ssh.KeyAlgoRSASHA512)
		case rsaSHA256:
			return as.SignWithAlgorithm(rand.Reader, data, ssh.KeyAlgoRSASHA256)
		}
	}
	return s.Sign(rand.Reader, data)
}

// Bind is a verified session-bind@openssh.com message: the client proves
// which server (host key) it is talking to in which session.
type Bind struct {
	HostKey    ssh.PublicKey
	SessionID  []byte
	Forwarding bool
}

// ParseSessionBind parses and verifies the extension contents: the server's
// signature over the session ID must check out with the host key, so the
// client can't name a server it isn't connected to.
func ParseSessionBind(contents []byte) (Bind, error) {
	var m struct {
		HostKey    []byte
		SessionID  []byte
		Signature  []byte
		Forwarding bool
	}
	if err := ssh.Unmarshal(contents, &m); err != nil {
		return Bind{}, fmt.Errorf("parse session-bind: %w", err)
	}
	hk, err := ssh.ParsePublicKey(m.HostKey)
	if err != nil {
		return Bind{}, fmt.Errorf("parse session-bind host key: %w", err)
	}
	var sig ssh.Signature
	if err := ssh.Unmarshal(m.Signature, &sig); err != nil {
		return Bind{}, fmt.Errorf("parse session-bind signature: %w", err)
	}
	if err := hk.Verify(m.SessionID, &sig); err != nil {
		return Bind{}, fmt.Errorf("session-bind signature does not verify: %w", err)
	}
	return Bind{HostKey: hk, SessionID: m.SessionID, Forwarding: m.Forwarding}, nil
}

// UserAuthSessionID returns the session ID inside data, which must be an SSH
// "publickey" user authentication request (RFC 4252 section 7) — the only
// thing agpass signs.
func UserAuthSessionID(data []byte) ([]byte, error) {
	var m struct {
		SessionID []byte
		Type      byte
		User      string
		Service   string
		Method    string
		Rest      []byte `ssh:"rest"`
	}
	if err := ssh.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("not an SSH user authentication request: %w", err)
	}
	const msgUserAuthRequest = 50
	if m.Type != msgUserAuthRequest || m.Method != "publickey" {
		return nil, fmt.Errorf("not an SSH publickey authentication request")
	}
	return m.SessionID, nil
}

// SameKey reports whether a and b are the same public key.
func SameKey(a, b ssh.PublicKey) bool {
	return a != nil && b != nil && bytes.Equal(a.Marshal(), b.Marshal())
}

// NormalizeHost turns "github.com", "git@github.com", "ssh://h:2222" or
// "h:22" into "github.com" or "h:2222" (port only when not 22).
func NormalizeHost(h string) (string, error) {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimPrefix(h, "ssh://")
	if i := strings.LastIndexByte(h, '@'); i >= 0 {
		h = h[i+1:]
	}
	h = strings.TrimSuffix(h, "/")
	host, port := h, "22"
	if hh, pp, err := net.SplitHostPort(h); err == nil {
		host, port = hh, pp
	}
	if host == "" || strings.ContainsAny(host, "/ ") {
		return "", fmt.Errorf("invalid host %q", h)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("invalid port in %q", h)
	}
	if port == "22" {
		return host, nil
	}
	return net.JoinHostPort(host, port), nil
}

// HostPort is the dial address for a normalized host.
func HostPort(host string) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(host, "22")
}

// ScanHostKeys connects to host and collects its host keys (one handshake
// per key type), like ssh-keyscan.
func ScanHostKeys(ctx context.Context, host string) ([]ssh.PublicKey, error) {
	algos := []string{ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoRSASHA512}
	var keys []ssh.PublicKey
	var lastErr error
	for _, algo := range algos {
		k, err := scanOne(ctx, HostPort(host), algo)
		if err != nil {
			lastErr = err
			continue
		}
		if !containsKey(keys, k) {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no host keys from %s: %v", host, lastErr)
	}
	return keys, nil
}

var errGotKey = errors.New("got host key")

func scanOne(ctx context.Context, addr, algo string) (ssh.PublicKey, error) {
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	var got ssh.PublicKey
	cfg := &ssh.ClientConfig{
		User:              "agpass-keyscan",
		HostKeyAlgorithms: []string{algo},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			got = key
			return errGotKey // stop after the key exchange
		},
	}
	_, _, _, err = ssh.NewClientConn(conn, addr, cfg)
	if got != nil {
		return got, nil
	}
	return nil, err
}

func containsKey(keys []ssh.PublicKey, k ssh.PublicKey) bool {
	for _, x := range keys {
		if SameKey(x, k) {
			return true
		}
	}
	return false
}
