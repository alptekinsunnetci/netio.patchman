package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"netio.patchman/internal/agentsign"
	"netio.patchman/internal/i18n"
	"netio.patchman/internal/protocol"
)

// With trusted keys the agent installs only signed, newer versions.
func TestSelfUpdateSigned(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	sum := hex.EncodeToString(digest[:])
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(payload) }))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	client, _ := NewClient(Config{ServerURL: u})
	l := i18n.MustLoad().Localizer(i18n.DefaultLocale)

	pub, priv, _ := agentsign.GenerateKey()
	otherPub, otherPriv, _ := agentsign.GenerateKey()
	keys := []string{agentsign.EncodePublicKey(otherPub), agentsign.EncodePublicKey(pub)}
	job := func(version, sig string) protocol.Job {
		p := map[string]string{protocol.ParamVersion: version, protocol.ParamSHA256: sum,
			protocol.ParamPath: protocol.AgentDownloadPrefix + "netio-patchman-agent-linux-amd64"}
		if sig != "" {
			p[protocol.ParamSignature] = sig
		}
		return protocol.Job{ID: 1, Type: protocol.JobAgentUpdate, Params: p}
	}
	run := func(t *testing.T, keys []string, j protocol.Job) (string, string, error) {
		t.Helper()
		t.Setenv("NP_FAKE_AGENT_VERSION", j.Params[protocol.ParamVersion])
		exe := filepath.Join(t.TempDir(), "netio-patchman-agent")
		if err := os.WriteFile(exe, []byte("old-binary"), 0o755); err != nil {
			t.Fatal(err)
		}
		msg, _, err := SelfUpdater{L: l, Client: client, Enabled: true, Executable: exe, Keys: keys}.Update(context.Background(), j)
		got, _ := os.ReadFile(exe)
		return msg, string(got), err
	}
	sign := func(version string) string { return agentsign.Sign(priv, version, runtime.GOOS, runtime.GOARCH, sum) }

	t.Run("installs a signed newer version", func(t *testing.T) {
		msg, got, err := run(t, keys, job("9.9.9", sign("9.9.9")))
		if err != nil || got == "old-binary" || !strings.Contains(msg, agentsign.KeyID(pub)) {
			t.Fatalf("signed update: %q %v", msg, err)
		}
	})
	for name, c := range map[string]struct {
		keys []string
		job  protocol.Job
		want string
	}{
		"missing signature":            {keys, job("9.9.9", ""), "imza yok"},
		"untrusted key":                {keys[1:], job("9.9.9", agentsign.Sign(otherPriv, "9.9.9", runtime.GOOS, runtime.GOARCH, sum)), "doğrulanamadı"},
		"signature of another version": {keys, job("9.9.9", sign("9.9.8")), "doğrulanamadı"},
		"other platform":               {keys, job("9.9.9", agentsign.Sign(priv, "9.9.9", "plan9", runtime.GOARCH, sum)), "doğrulanamadı"},
		"downgrade":                    {keys, job("0.0.9", sign("0.0.9")), "eski sürüme dönülmez"},
	} {
		t.Run("refuses "+name, func(t *testing.T) {
			_, got, err := run(t, c.keys, c.job)
			if err == nil || !strings.Contains(err.Error(), c.want) || got != "old-binary" {
				t.Fatalf("accepted or wrong error: %v (binary %q)", err, got)
			}
		})
	}
	t.Run("without keys SHA-256 is enough", func(t *testing.T) {
		if _, got, err := run(t, nil, job("9.9.9", "")); err != nil || got == "old-binary" {
			t.Fatalf("unsigned update without keys: %v", err)
		}
	})
}

func TestUpdateKeysPinning(t *testing.T) {
	l := i18n.MustLoad().Localizer(i18n.DefaultLocale)
	pub, _, _ := agentsign.GenerateKey()
	pub2, _, _ := agentsign.GenerateKey()
	key, key2 := agentsign.EncodePublicKey(pub), agentsign.EncodePublicKey(pub2)
	dir := t.TempDir()
	cfg := Config{ServerURL: mustParse(t, "https://patchman.example.test"), StateDir: dir}

	r, err := NewRunner(cfg, l, discardLogger())
	if err != nil || len(r.updater.Keys) != 0 {
		t.Fatalf("fresh agent: %v %v", r, err)
	}
	r.pinUpdateKeys([]string{"junk"})
	if len(r.updater.Keys) != 0 {
		t.Fatal("invalid key pinned")
	}
	r.pinUpdateKeys([]string{key})
	if len(r.updater.Keys) != 1 || r.hostInfo().UpdateKeys[0] != key {
		t.Fatalf("pinned: %v", r.updater.Keys)
	}
	// Pinned keys never change from the server, also after a restart.
	r.pinUpdateKeys([]string{key2})
	r, err = NewRunner(cfg, l, discardLogger())
	if err != nil || len(r.updater.Keys) != 1 || r.updater.Keys[0] != key {
		t.Fatalf("after restart: %v %v", r.updater.Keys, err)
	}
	// Keys in the configuration win over pinned ones.
	cfg.UpdateKeys = []string{key2}
	if r, err = NewRunner(cfg, l, discardLogger()); err != nil || r.updater.Keys[0] != key2 {
		t.Fatalf("configured keys: %v %v", r.updater.Keys, err)
	}
	// A damaged pin file stops the agent instead of allowing unsigned updates.
	cfg.UpdateKeys = nil
	if err := os.WriteFile(filepath.Join(dir, pinnedKeysFile), []byte("damaged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRunner(cfg, l, discardLogger()); err == nil || !strings.Contains(err.Error(), "okunamadı") {
		t.Fatalf("damaged pin file: %v", err)
	}
}

func TestLoadConfigUpdateKeys(t *testing.T) {
	l := i18n.MustLoad().Localizer(i18n.DefaultLocale)
	pub, _, _ := agentsign.GenerateKey()
	key := agentsign.EncodePublicKey(pub)
	env := func(keys string) func(string) string {
		return func(k string) string {
			switch k {
			case "PATCHMAN_SERVER_URL":
				return "https://patchman.example.test"
			case "PATCHMAN_UPDATE_KEYS":
				return keys
			}
			return ""
		}
	}
	missing := filepath.Join(t.TempDir(), "missing.env")
	if cfg, err := LoadConfig(l, missing, env(key+", "+key)); err != nil || len(cfg.UpdateKeys) != 1 {
		t.Fatalf("keys: %v %v", cfg.UpdateKeys, err)
	}
	if _, err := LoadConfig(l, missing, env("bm90LWEta2V5")); err == nil || !strings.Contains(err.Error(), "PATCHMAN_UPDATE_KEYS") {
		t.Fatalf("invalid key accepted: %v", err)
	}
}

func mustParse(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }
