// Package vault is the user-owned credential store (AW-HLD-P2-CRED §3.2). It holds
// secrets encrypted at rest (AES-256-GCM under a passphrase-derived key) and is the
// ONLY component that can turn an alias into a plaintext secret. Nothing on any
// agent-reachable surface imports it; the broker calls Resolve at the egress
// boundary and immediately redacts the value from everything the agent can see.
//
// Reference scope (honest): correct + demonstrable, not a KMS/HSM. Hardware keys,
// rotation, and multi-tenant isolation belong to the closed PEA engine.
//
// Zero external dependencies (ADR-0002): stdlib crypto only. Key derivation uses
// crypto/pbkdf2 (Go 1.24+ stdlib).
//
// Licensed under the Apache License 2.0.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/aiegis/agentwarden/pkg/awspec"
)

const (
	fileMagic = "AWV1"  // 4-byte format tag, also used as GCM additional data
	saltLen   = 16      // pbkdf2 salt
	nonceLen  = 12      // GCM standard nonce
	keyLen    = 32      // AES-256
	pbkdfIter = 200_000 // pbkdf2 iterations
)

// Binding constrains what an entry may be used for (AW-HLD-P2-CRED §2). A secret
// may only be injected for an action on Substrate whose destination matches one of
// Dests (exact host or a host suffix like ".github.com").
type Binding struct {
	Substrate awspec.Substrate `json:"substrate"`
	Dests     []string         `json:"dests"`
}

// Allows reports whether (sub, dest) is permitted by the binding (exact or suffix).
func (b Binding) Allows(sub awspec.Substrate, dest string) bool {
	if b.Substrate != "" && b.Substrate != sub {
		return false
	}
	for _, d := range b.Dests {
		if d == dest {
			return true
		}
		// suffix rule: a binding of ".github.com" allows "api.github.com"
		if len(d) > 0 && d[0] == '.' && len(dest) >= len(d) && dest[len(dest)-len(d):] == d {
			return true
		}
	}
	return false
}

type entry struct {
	Alias   string  `json:"alias"`
	Value   string  `json:"value"`
	Binding Binding `json:"binding"`
}

// Vault is an opened (unsealed) credential store held in memory by the broker.
type Vault struct {
	path    string
	key     []byte
	salt    []byte
	entries map[string]entry
}

// ErrNotFound is returned by Resolve for an unknown alias.
var ErrNotFound = errors.New("vault: alias not found")

// Open unseals the vault at path with passphrase, creating an empty one (with a
// fresh salt) if the file does not exist. The derived key is held until Close.
func Open(path, passphrase string) (*Vault, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		salt := make([]byte, saltLen)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return nil, err
		}
		key, err := deriveKey(passphrase, salt)
		if err != nil {
			return nil, err
		}
		return &Vault{path: path, key: key, salt: salt, entries: map[string]entry{}}, nil
	}
	if err != nil {
		return nil, err
	}
	return openBytes(path, raw, passphrase)
}

func openBytes(path string, raw []byte, passphrase string) (*Vault, error) {
	if len(raw) < len(fileMagic)+saltLen+nonceLen {
		return nil, errors.New("vault: file too short / corrupt")
	}
	if string(raw[:len(fileMagic)]) != fileMagic {
		return nil, errors.New("vault: bad magic (not an AW vault file)")
	}
	off := len(fileMagic)
	salt := append([]byte(nil), raw[off:off+saltLen]...)
	off += saltLen
	nonce := raw[off : off+nonceLen]
	off += nonceLen
	ciphertext := raw[off:]

	key, err := deriveKey(passphrase, salt)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, []byte(fileMagic))
	if err != nil {
		return nil, fmt.Errorf("vault: unseal failed (wrong passphrase or tampered file): %w", err)
	}
	entries := map[string]entry{}
	if err := json.Unmarshal(plain, &entries); err != nil {
		return nil, fmt.Errorf("vault: corrupt contents: %w", err)
	}
	return &Vault{path: path, key: key, salt: salt, entries: entries}, nil
}

// Put adds or replaces a secret. Call Seal to persist.
func (v *Vault) Put(alias, value string, b Binding) {
	v.entries[alias] = entry{Alias: alias, Value: value, Binding: b}
}

// Resolve returns the plaintext secret and its binding for alias. BROKER-ONLY:
// the result must be injected at the egress boundary and never surfaced to the
// agent, the result payload, or the ledger (AW-HLD-P2-CRED §5).
func (v *Vault) Resolve(alias string) (string, Binding, error) {
	e, ok := v.entries[alias]
	if !ok {
		return "", Binding{}, ErrNotFound
	}
	return e.Value, e.Binding, nil
}

// Aliases lists the stored aliases (names only — never values).
func (v *Vault) Aliases() []string {
	out := make([]string, 0, len(v.entries))
	for a := range v.entries {
		out = append(out, a)
	}
	return out
}

// Seal writes the encrypted vault to disk atomically (0600).
func (v *Vault) Seal() error {
	plain, err := json.Marshal(v.entries)
	if err != nil {
		return err
	}
	gcm, err := newGCM(v.key)
	if err != nil {
		return err
	}
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	ciphertext := gcm.Seal(nil, nonce, plain, []byte(fileMagic))

	buf := make([]byte, 0, len(fileMagic)+len(v.salt)+len(nonce)+len(ciphertext))
	buf = append(buf, []byte(fileMagic)...)
	buf = append(buf, v.salt...)
	buf = append(buf, nonce...)
	buf = append(buf, ciphertext...)

	tmp := v.path + ".tmp"
	if err := os.WriteFile(tmp, buf, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, v.path)
}

// Close zeroes the in-memory key and secret values (best-effort).
func (v *Vault) Close() {
	for i := range v.key {
		v.key[i] = 0
	}
	for a, e := range v.entries {
		e.Value = ""
		v.entries[a] = e
	}
	v.entries = map[string]entry{}
}

func deriveKey(passphrase string, salt []byte) ([]byte, error) {
	return pbkdf2.Key(sha256.New, passphrase, salt, pbkdfIter, keyLen)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
