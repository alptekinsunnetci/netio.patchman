package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 default; authenticator apps expect HMAC-SHA1
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP parameters understood by every common authenticator app.
const (
	TOTPDigits = 6
	TOTPPeriod = 30 // seconds
	// TOTPSkew accepts one step before and after the current one (clock drift).
	TOTPSkew = 1
	// RecoveryCodeCount codes are issued when two-factor sign-in is enabled.
	RecoveryCodeCount = 10
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns a random 160-bit key, base32 encoded.
func NewTOTPSecret() string {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b32.EncodeToString(b)
}

// FormatSecret groups a base32 key in blocks of four for manual entry.
func FormatSecret(secret string) string {
	var parts []string
	for len(secret) > 4 {
		parts = append(parts, secret[:4])
		secret = secret[4:]
	}
	return strings.Join(append(parts, secret), " ")
}

// TOTPURI returns the otpauth:// URI that authenticator apps import.
func TOTPURI(issuer, account, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{"secret": {secret}, "issuer": {issuer}, "algorithm": {"SHA1"}, "digits": {fmt.Sprint(TOTPDigits)}, "period": {fmt.Sprint(TOTPPeriod)}}
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// hotp computes an RFC 4226 code with the given number of digits.
func hotp(key []byte, counter uint64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, v%mod)
}

// TOTPStep returns the time step of t.
func TOTPStep(t time.Time) int64 { return t.Unix() / TOTPPeriod }

// TOTPCode returns the code of a step (exported for tests and setup checks).
func TOTPCode(secret string, step int64) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(strings.ReplaceAll(secret, " ", "")))
	if err != nil || len(key) == 0 {
		return "", fmt.Errorf("auth: invalid TOTP secret")
	}
	return hotp(key, uint64(step), TOTPDigits), nil
}

// VerifyTOTP checks a code against the steps around t and returns the
// matching step. Callers must reject steps that were already used.
func VerifyTOTP(secret, code string, t time.Time) (int64, bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != TOTPDigits {
		return 0, false
	}
	now := TOTPStep(t)
	matched, found := int64(0), false
	for d := int64(-TOTPSkew); d <= TOTPSkew; d++ {
		want, err := TOTPCode(secret, now+d)
		if err != nil {
			return 0, false
		}
		// Compare every candidate so timing does not reveal which step matched.
		if hmac.Equal([]byte(want), []byte(code)) && !found {
			matched, found = now+d, true
		}
	}
	return matched, found
}

// NewRecoveryCodes returns single-use codes like "k7m2-9xq4-p3vd".
func NewRecoveryCodes() []string {
	const alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
	out := make([]string, RecoveryCodeCount)
	b := make([]byte, 12)
	for i := range out {
		if _, err := rand.Read(b); err != nil {
			panic(err)
		}
		c := make([]byte, 0, 14)
		for j, v := range b {
			if j == 4 || j == 8 {
				c = append(c, '-')
			}
			c = append(c, alphabet[int(v)%len(alphabet)])
		}
		out[i] = string(c)
	}
	return out
}

// NormalizeRecoveryCode lowercases a typed code and restores its dashes.
func NormalizeRecoveryCode(s string) string {
	s = strings.ToLower(strings.NewReplacer(" ", "", "-", "").Replace(strings.TrimSpace(s)))
	if len(s) != 12 {
		return s
	}
	return s[:4] + "-" + s[4:8] + "-" + s[8:]
}
