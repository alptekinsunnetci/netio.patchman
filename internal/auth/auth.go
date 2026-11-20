// Package auth provides password hashing, random tokens and login throttling.
package auth

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// PBKDF2 parameters (OWASP 2023 recommendation for PBKDF2-HMAC-SHA256).
const (
	pbkdf2Iterations = 600_000
	saltBytes        = 16
	keyBytes         = 32
	// MinPasswordLength is the minimum accepted password length in characters.
	MinPasswordLength = 10
)

// HashPassword returns "pbkdf2-sha256$<iter>$<salt>$<hash>".
func HashPassword(password string) (string, error) {
	salt := make([]byte, saltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, pbkdf2Iterations, keyBytes)
	if err != nil {
		return "", err
	}
	enc := base64.RawStdEncoding
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", pbkdf2Iterations, enc.EncodeToString(salt), enc.EncodeToString(key)), nil
}

// VerifyPassword checks a password against a stored hash in constant time.
func VerifyPassword(stored, password string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1000 || iter > 10_000_000 {
		return false
	}
	enc := base64.RawStdEncoding
	salt, err1 := enc.DecodeString(parts[2])
	want, err2 := enc.DecodeString(parts[3])
	if err1 != nil || err2 != nil || len(want) == 0 {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, iter, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

// dummyHash is used to equalize timing when the user does not exist.
var dummyHash, _ = HashPassword("netio.patchman-timing-equalizer")

// VerifyDummy burns the same time as a real verification.
func VerifyDummy(password string) { VerifyPassword(dummyHash, password) }

// ErrWeakPassword is returned for passwords shorter than MinPasswordLength.
var ErrWeakPassword = errors.New("auth: password too short")

// CheckPasswordPolicy validates a new password.
func CheckPasswordPolicy(p string) error {
	if utf8.RuneCountInString(p) < MinPasswordLength {
		return ErrWeakPassword
	}
	return nil
}

// RandomToken returns a URL-safe random token with n bytes of entropy.
func RandomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// HashToken returns the SHA-256 hex digest used to store tokens at rest.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// RandomPassword returns a readable random password.
func RandomPassword() string {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	out := make([]byte, len(b))
	for i, v := range b {
		out[i] = alphabet[int(v)%len(alphabet)]
	}
	return string(out)
}

// Limiter throttles repeated failures per key (IP or email).
type Limiter struct {
	mu      sync.Mutex
	max     int
	window  time.Duration
	entries map[string]*limitEntry
}

type limitEntry struct {
	failures int
	first    time.Time
}

// NewLimiter allows max failures per window per key.
func NewLimiter(max int, window time.Duration) *Limiter {
	return &Limiter{max: max, window: window, entries: map[string]*limitEntry{}}
}

// Blocked reports whether key has exceeded the limit.
func (l *Limiter) Blocked(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[key]
	if !ok {
		return false
	}
	if time.Since(e.first) > l.window {
		delete(l.entries, key)
		return false
	}
	return e.failures >= l.max
}

// Fail records a failure.
func (l *Limiter) Fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[key]
	if !ok || time.Since(e.first) > l.window {
		e = &limitEntry{first: time.Now()}
		l.entries[key] = e
	}
	e.failures++
	if len(l.entries) > 10000 { // bound memory
		for k, v := range l.entries {
			if time.Since(v.first) > l.window {
				delete(l.entries, k)
			}
		}
	}
}

// Reset clears failures for key.
func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}
