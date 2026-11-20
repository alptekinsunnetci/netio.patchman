package auth

import (
	"strings"
	"testing"
	"time"
)

func TestPasswordHashing(t *testing.T) {
	h, err := HashPassword("güçlü-parola-İı-123")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "pbkdf2-sha256$600000$") {
		t.Errorf("unexpected hash format: %s", h)
	}
	if !VerifyPassword(h, "güçlü-parola-İı-123") {
		t.Error("correct password rejected")
	}
	if VerifyPassword(h, "güçlü-parola-Iı-123") || VerifyPassword(h, "") || VerifyPassword("garbage", "x") {
		t.Error("wrong password accepted")
	}
	h2, _ := HashPassword("güçlü-parola-İı-123")
	if h == h2 {
		t.Error("salt not random")
	}
}

func TestPasswordPolicy(t *testing.T) {
	if CheckPasswordPolicy("çok-kısa") == nil {
		t.Error("short password accepted")
	}
	// Ten Turkish characters count as ten, not by bytes.
	if CheckPasswordPolicy("ğüşıöçĞÜŞİ") != nil {
		t.Error("rune count not used")
	}
}

func TestTokens(t *testing.T) {
	a, b := RandomToken(32), RandomToken(32)
	if a == b || len(a) < 40 {
		t.Errorf("weak tokens: %q %q", a, b)
	}
	if HashToken(a) == HashToken(b) || len(HashToken(a)) != 64 {
		t.Error("token hash")
	}
	if p := RandomPassword(); len(p) != 16 {
		t.Errorf("random password length %d", len(p))
	}
}

func TestLimiter(t *testing.T) {
	l := NewLimiter(3, time.Minute)
	for range 3 {
		if l.Blocked("ip") {
			t.Fatal("blocked too early")
		}
		l.Fail("ip")
	}
	if !l.Blocked("ip") {
		t.Error("not blocked after max failures")
	}
	l.Reset("ip")
	if l.Blocked("ip") {
		t.Error("reset did not clear")
	}
}
