package agentsign

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestSignVerify(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	otherPub, _, _ := GenerateKey()
	key, other := EncodePublicKey(pub), EncodePublicKey(otherPub)
	sig := Sign(priv, "1.2.0", "linux", "amd64", sum)
	if SignatureKeyID(sig) != KeyID(pub) {
		t.Fatalf("key id %q", SignatureKeyID(sig))
	}
	if id, ok := Verify(sig, []string{other, key}, "1.2.0", "linux", "amd64", strings.ToUpper(sum)); !ok || id != KeyID(pub) {
		t.Fatalf("valid signature rejected: %q %v", id, ok)
	}
	for name, c := range map[string]struct {
		keys                     []string
		version, goos, arch, sum string
	}{
		"untrusted key":  {[]string{other}, "1.2.0", "linux", "amd64", sum},
		"no keys":        {nil, "1.2.0", "linux", "amd64", sum},
		"other version":  {[]string{key}, "1.1.0", "linux", "amd64", sum},
		"other platform": {[]string{key}, "1.2.0", "linux", "arm64", sum},
		"other os":       {[]string{key}, "1.2.0", "windows", "amd64", sum},
		"other binary":   {[]string{key}, "1.2.0", "linux", "amd64", strings.Repeat("0", 64)},
	} {
		if _, ok := Verify(sig, c.keys, c.version, c.goos, c.arch, c.sum); ok {
			t.Errorf("%s: accepted", name)
		}
	}
	for _, bad := range []string{"", "x", sig[:20], strings.Replace(sig, ":", "", 1), "zzzzzzzzzzzzzzzz" + sig[16:]} {
		if _, ok := Verify(bad, []string{key}, "1.2.0", "linux", "amd64", sum); ok {
			t.Errorf("malformed signature %q accepted", bad)
		}
	}
	// A signature claiming the trusted key's id but made with another key.
	_, otherPriv, _ := GenerateKey()
	forged := KeyID(pub) + Sign(otherPriv, "1.2.0", "linux", "amd64", sum)[16:]
	if _, ok := Verify(forged, []string{key}, "1.2.0", "linux", "amd64", sum); ok {
		t.Error("forged signature accepted")
	}
}

func TestKeys(t *testing.T) {
	pub, priv, _ := GenerateKey()
	pub2, _, _ := GenerateKey()
	a, b := EncodePublicKey(pub), EncodePublicKey(pub2)
	got, err := ParsePublicKeys(" " + a + ",\n" + b + "  " + a + "\r\n")
	if err != nil || len(got) != 2 || got[0] != a || got[1] != b {
		t.Fatalf("parse: %v %v", got, err)
	}
	if got, err := ParsePublicKeys(""); err != nil || len(got) != 0 {
		t.Fatalf("empty: %v %v", got, err)
	}
	if _, err := ParsePublicKeys(a + " bm90LWEta2V5"); err == nil {
		t.Error("invalid key accepted")
	}
	if got := CleanPublicKeys([]string{a, "junk", a, b}); len(got) != 2 {
		t.Errorf("clean: %v", got)
	}
	if ids := KeyIDs([]string{a, "junk"}); len(ids) != 1 || ids[0] != KeyID(pub) || len(ids[0]) != 16 {
		t.Errorf("ids: %v", ids)
	}

	path := filepath.Join(t.TempDir(), "agent-signing.key")
	if err := WritePrivateKey(path, priv); err != nil {
		t.Fatal(err)
	}
	if err := WritePrivateKey(path, priv); err == nil {
		t.Error("existing key file overwritten")
	}
	back, err := ReadPrivateKey(path)
	if err != nil || !back.Equal(priv) {
		t.Fatalf("read back: %v", err)
	}
	if st, _ := os.Stat(path); st != nil && st.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		t.Errorf("key file mode %v", st.Mode().Perm())
	}
	if _, err := ParsePrivateKey(a); err == nil {
		t.Error("public key accepted as private key")
	}
}
