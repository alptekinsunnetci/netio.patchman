package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"netio.patchman/internal/agentsign"
	"netio.patchman/internal/i18n"
	"netio.patchman/internal/release"
)

// agent-key and agent-sign produce a release the server distributes with
// signatures that agents trusting the key accept.
func TestAgentKeyAndSign(t *testing.T) {
	l := i18n.MustLoad().Localizer(i18n.DefaultLocale)
	dir := t.TempDir()
	keyFile := filepath.Join(t.TempDir(), "agent-signing.key")
	if agentKey(l, keyFile) != 0 || agentKey(l, keyFile) == 0 {
		t.Fatal("agent-key: created twice or not at all")
	}
	priv, err := agentsign.ReadPrivateKey(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	pub := agentsign.EncodePublicKey(priv.Public().(ed25519.PublicKey))
	if agentSign(l, keyFile, dir) == 0 {
		t.Error("signed a directory without a version file")
	}
	for name, content := range map[string]string{"version": "1.2.0\n", "netio-patchman-agent-linux-amd64": "linux agent", "netio-patchman-agent-windows-amd64.exe": "windows agent"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// A .sha256 file that disagrees with the binary is refused.
	if err := os.WriteFile(filepath.Join(dir, "netio-patchman-agent-linux-amd64.sha256"), []byte(strings.Repeat("0", 64)+"  netio-patchman-agent-linux-amd64\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if agentSign(l, keyFile, dir) == 0 {
		t.Error("signed despite a wrong .sha256 file")
	}
	os.Remove(filepath.Join(dir, "netio-patchman-agent-linux-amd64.sha256"))
	if code := agentSign(l, keyFile, dir); code != 0 {
		t.Fatalf("agent-sign: %d", code)
	}
	rel := release.Load(dir, "0.0.0")
	if rel.Unsigned() || len(rel.Signers()) != 1 {
		t.Fatalf("release signatures: %+v", rel.Binaries)
	}
	for _, osID := range []string{"debian", "windows"} {
		if !rel.Installable("1.1.0", osID, "amd64", []string{pub}) {
			t.Errorf("%s: signed release not installable", osID)
		}
	}
	if rel.Installable("1.2.0", "debian", "amd64", []string{pub}) || rel.Installable("1.3.0", "debian", "amd64", []string{pub}) {
		t.Error("same or older version installable for an agent with keys")
	}
	other, _, _ := agentsign.GenerateKey()
	if rel.Installable("1.1.0", "debian", "amd64", []string{agentsign.EncodePublicKey(other)}) {
		t.Error("installable with an untrusted key")
	}
	if !rel.Installable("1.3.0", "debian", "amd64", nil) {
		t.Error("agents without keys take any release")
	}
	if p, _ := rel.JobParams("debian", "amd64"); p["signature"] == "" {
		t.Errorf("job params without signature: %v", p)
	}
}
