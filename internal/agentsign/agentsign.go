// Package agentsign signs and verifies agent releases with Ed25519.
//
// The private key stays with the operator, away from the server: the server
// only distributes binaries and their signatures, so a compromised server
// cannot hand agents that pinned a public key a binary of its own.
//
// A signature covers a statement naming the version, the platform and the
// SHA-256 of the binary (Message), so a signed binary cannot be offered as
// another version or for another platform. Formats:
//
//	public key   standard base64 of the 32-byte Ed25519 public key
//	private key  file with one line "npsk1:<base64 of the 32-byte seed>"
//	signature    "<key id>:<base64 of the 64-byte signature>", also the
//	             content of "<binary>.sig" next to the binary
//	key id       first 16 hex digits of the SHA-256 of the public key
package agentsign

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

// MaxKeys bounds the public keys an agent trusts at once (key rotation).
const MaxKeys = 8

const privatePrefix = "npsk1:"

// ErrInvalidKey is returned for keys that are not Ed25519 keys in the
// expected encoding.
var ErrInvalidKey = errors.New("invalid key")

// ParsePublicKey decodes a base64 Ed25519 public key.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, ErrInvalidKey
	}
	return ed25519.PublicKey(b), nil
}

// EncodePublicKey returns the base64 form of a public key.
func EncodePublicKey(pub ed25519.PublicKey) string { return base64.StdEncoding.EncodeToString(pub) }

// KeyID identifies a public key in signatures and on the dashboard.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// ParsePublicKeys reads public keys separated by commas, spaces or new
// lines. It returns the keys in canonical form without duplicates, and an
// error naming the first invalid key or when there are more than MaxKeys.
func ParsePublicKeys(s string) ([]string, error) {
	out := []string{}
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t' }) {
		pub, err := ParsePublicKey(f)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrInvalidKey, f)
		}
		if k := EncodePublicKey(pub); !contains(out, k) {
			out = append(out, k)
		}
	}
	if len(out) > MaxKeys {
		return nil, fmt.Errorf("%w: more than %d keys", ErrInvalidKey, MaxKeys)
	}
	return out, nil
}

// CleanPublicKeys keeps the valid, distinct keys (at most MaxKeys); used for
// what agents report.
func CleanPublicKeys(keys []string) []string {
	out := []string{}
	for _, k := range keys {
		pub, err := ParsePublicKey(k)
		if err != nil {
			continue
		}
		if c := EncodePublicKey(pub); !contains(out, c) && len(out) < MaxKeys {
			out = append(out, c)
		}
	}
	return out
}

// KeyIDs returns the ids of base64 public keys (invalid ones are skipped).
func KeyIDs(keys []string) []string {
	out := []string{}
	for _, k := range keys {
		if pub, err := ParsePublicKey(k); err == nil {
			out = append(out, KeyID(pub))
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// Message is the statement a release signature covers.
func Message(version, goos, arch, sha256Hex string) []byte {
	return []byte("netio.patchman agent release v1\nversion=" + version + "\nplatform=" + goos + "/" + arch +
		"\nsha256=" + strings.ToLower(sha256Hex) + "\n")
}

// GenerateKey creates a new key pair.
func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// EncodePrivateKey returns the private key file content.
func EncodePrivateKey(priv ed25519.PrivateKey) string {
	return privatePrefix + base64.StdEncoding.EncodeToString(priv.Seed()) + "\n"
}

// ParsePrivateKey decodes the private key file content.
func ParsePrivateKey(s string) (ed25519.PrivateKey, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, privatePrefix) {
		return nil, ErrInvalidKey
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, privatePrefix))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, ErrInvalidKey
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// WritePrivateKey writes a new private key file readable by its owner only.
// It never overwrites an existing file.
func WritePrivateKey(path string, priv ed25519.PrivateKey) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(EncodePrivateKey(priv)); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	return f.Close()
}

// ReadPrivateKey reads a private key file.
func ReadPrivateKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePrivateKey(string(b))
}

// Sign signs a release statement.
func Sign(priv ed25519.PrivateKey, version, goos, arch, sha256Hex string) string {
	pub := priv.Public().(ed25519.PublicKey)
	sig := ed25519.Sign(priv, Message(version, goos, arch, sha256Hex))
	return KeyID(pub) + ":" + base64.StdEncoding.EncodeToString(sig)
}

// SignatureKeyID returns the key id a signature names ("" if malformed).
func SignatureKeyID(sig string) string {
	id, _, ok := splitSignature(sig)
	if !ok {
		return ""
	}
	return id
}

func splitSignature(sig string) (string, []byte, bool) {
	id, b64, ok := strings.Cut(strings.TrimSpace(sig), ":")
	if !ok || len(id) != 16 {
		return "", nil, false
	}
	if _, err := hex.DecodeString(id); err != nil {
		return "", nil, false
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) != ed25519.SignatureSize {
		return "", nil, false
	}
	return strings.ToLower(id), raw, true
}

// Verify checks a release signature against trusted base64 public keys and
// returns the id of the key that verified it.
func Verify(sig string, keys []string, version, goos, arch, sha256Hex string) (string, bool) {
	id, raw, ok := splitSignature(sig)
	if !ok {
		return "", false
	}
	msg := Message(version, goos, arch, sha256Hex)
	for _, k := range keys {
		pub, err := ParsePublicKey(k)
		if err != nil || KeyID(pub) != id {
			continue
		}
		if ed25519.Verify(pub, msg, raw) {
			return id, true
		}
	}
	return "", false
}
