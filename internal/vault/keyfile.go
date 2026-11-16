// Package vault manages agpass.key: a random data key (DEK) wrapped with a
// key derived from the master password (Argon2id + XChaCha20-Poly1305).
// Changing the master password only re-wraps the DEK.
package vault

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

var ErrWrongPassword = errors.New("wrong master password")

const aad = "agpass-keyfile-v1"

type KeyFile struct {
	Version   int    `json:"version"`
	KDF       string `json:"kdf"`
	Salt      []byte `json:"salt"`
	Time      uint32 `json:"time"`
	MemoryKiB uint32 `json:"memory_kib"`
	Threads   uint8  `json:"threads"`
	Nonce     []byte `json:"nonce"`
	Wrapped   []byte `json:"wrapped"`
}

func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Create generates a new DEK, wraps it with password and writes path.
func Create(path, password string) ([]byte, error) {
	if Exists(path) {
		return nil, fmt.Errorf("%s already exists", path)
	}
	kf := &KeyFile{Version: 1, KDF: "argon2id", Time: 3, MemoryKiB: 128 * 1024, Threads: 4}
	kf.Salt = random(16)
	kf.Nonce = random(chacha20poly1305.NonceSizeX)
	dek := random(32)
	aead, err := chacha20poly1305.NewX(kf.kek(password))
	if err != nil {
		return nil, err
	}
	kf.Wrapped = aead.Seal(nil, kf.Nonce, dek, []byte(aad))
	b, err := json.MarshalIndent(kf, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return nil, err
	}
	return dek, nil
}

func Load(path string) (*KeyFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	kf := &KeyFile{}
	if err := json.Unmarshal(b, kf); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if kf.Version != 1 || kf.KDF != "argon2id" {
		return nil, fmt.Errorf("unsupported key file version %d/%s", kf.Version, kf.KDF)
	}
	return kf, nil
}

// Unwrap derives the KEK from password and returns the DEK.
func (kf *KeyFile) Unwrap(password string) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(kf.kek(password))
	if err != nil {
		return nil, err
	}
	dek, err := aead.Open(nil, kf.Nonce, kf.Wrapped, []byte(aad))
	if err != nil {
		return nil, ErrWrongPassword
	}
	return dek, nil
}

// Verify reports whether password unwraps to the expected DEK.
func (kf *KeyFile) Verify(password string, dek []byte) bool {
	got, err := kf.Unwrap(password)
	return err == nil && subtle.ConstantTimeCompare(got, dek) == 1
}

func (kf *KeyFile) kek(password string) []byte {
	return argon2.IDKey([]byte(password), kf.Salt, kf.Time, kf.MemoryKiB, kf.Threads, 32)
}

func random(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}
