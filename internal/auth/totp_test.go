package auth

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

// RFC 6238 appendix B, SHA-1 key "12345678901234567890", 8 digits.
func TestHOTPRFC6238Vectors(t *testing.T) {
	key := []byte("12345678901234567890")
	for _, tc := range []struct {
		unix int64
		want string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	} {
		if got := hotp(key, uint64(tc.unix/TOTPPeriod), 8); got != tc.want {
			t.Errorf("t=%d: got %s, want %s", tc.unix, got, tc.want)
		}
	}
}

func TestVerifyTOTP(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	at := time.Unix(1111111111, 0)
	// 6-digit code is the last six digits of the 8-digit vector.
	step, ok := VerifyTOTP(secret, "050471", at)
	if !ok || step != 1111111111/TOTPPeriod {
		t.Fatalf("valid code rejected: %d %v", step, ok)
	}
	// One step of clock drift is accepted, two are not.
	if _, ok := VerifyTOTP(secret, "050471", at.Add(30*time.Second)); !ok {
		t.Error("previous step rejected")
	}
	if _, ok := VerifyTOTP(secret, "050471", at.Add(90*time.Second)); ok {
		t.Error("code two steps old accepted")
	}
	for _, bad := range []string{"", "12345", "1234567", "abcdef", "000000"} {
		if _, ok := VerifyTOTP(secret, bad, at); ok {
			t.Errorf("bad code %q accepted", bad)
		}
	}
	if _, ok := VerifyTOTP("not base32!", "050471", at); ok {
		t.Error("invalid secret accepted")
	}
}

func TestSecretAndURI(t *testing.T) {
	s := NewTOTPSecret()
	if len(s) != 32 || s == NewTOTPSecret() {
		t.Fatalf("secret %q", s)
	}
	if got := FormatSecret("ABCDEFGHIJ"); got != "ABCD EFGH IJ" {
		t.Errorf("format: %q", got)
	}
	uri := TOTPURI("netio.patchman", "ayse@example.test", s)
	for _, want := range []string{"otpauth://totp/netio.patchman:ayse@example.test?", "secret=" + s, "issuer=netio.patchman", "digits=6", "period=30"} {
		if !strings.Contains(uri, want) {
			t.Errorf("uri %q missing %q", uri, want)
		}
	}
}

func TestRecoveryCodes(t *testing.T) {
	codes := NewRecoveryCodes()
	if len(codes) != RecoveryCodeCount {
		t.Fatalf("got %d codes", len(codes))
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if len(c) != 14 || c[4] != '-' || c[9] != '-' || seen[c] {
			t.Errorf("bad code %q", c)
		}
		seen[c] = true
		if NormalizeRecoveryCode(" "+strings.ToUpper(strings.ReplaceAll(c, "-", ""))+" ") != c {
			t.Errorf("normalize %q", c)
		}
	}
}
