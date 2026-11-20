package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"netio.patchman/internal/i18n"
	"netio.patchman/internal/protocol"
)

// When started with NP_FAKE_AGENT_VERSION set, the test binary behaves like
// an agent printing its version, so it can stand in for a downloaded agent.
func TestMain(m *testing.M) {
	if v := os.Getenv("NP_FAKE_AGENT_VERSION"); v != "" {
		fmt.Printf("netio-patchman-agent %s (netio.patchman)\n", v)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestSelfUpdate(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	goodSum := hex.EncodeToString(sum[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != protocol.AgentDownloadPrefix+"netio-patchman-agent-linux-amd64" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(payload)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	client, _ := NewClient(Config{ServerURL: u})
	l := i18n.MustLoad().Localizer(i18n.DefaultLocale)

	setup := func(t *testing.T) string {
		dir := t.TempDir()
		exe := filepath.Join(dir, "netio-patchman-agent")
		if err := os.WriteFile(exe, []byte("old-binary"), 0o755); err != nil {
			t.Fatal(err)
		}
		return exe
	}
	job := func(version, sum string) protocol.Job {
		return protocol.Job{ID: 1, Type: protocol.JobAgentUpdate, Params: map[string]string{
			protocol.ParamVersion: version, protocol.ParamSHA256: sum,
			protocol.ParamPath: protocol.AgentDownloadPrefix + "netio-patchman-agent-linux-amd64",
		}}
	}

	t.Run("installs verified binary", func(t *testing.T) {
		t.Setenv("NP_FAKE_AGENT_VERSION", "9.9.9")
		exe := setup(t)
		msg, restart, err := SelfUpdater{L: l, Client: client, Enabled: true, Executable: exe}.Update(context.Background(), job("9.9.9", goodSum))
		if err != nil || !restart || !strings.Contains(msg, "9.9.9") {
			t.Fatalf("update: %q %v %v", msg, restart, err)
		}
		got, _ := os.ReadFile(exe)
		if len(got) != len(payload) {
			t.Error("binary not replaced")
		}
		prev, _ := os.ReadFile(exe + ".previous")
		if string(prev) != "old-binary" {
			t.Errorf("previous binary not kept: %q", prev)
		}
	})

	t.Run("rejects checksum mismatch", func(t *testing.T) {
		t.Setenv("NP_FAKE_AGENT_VERSION", "9.9.9")
		exe := setup(t)
		_, restart, err := SelfUpdater{L: l, Client: client, Enabled: true, Executable: exe}.Update(context.Background(), job("9.9.9", strings.Repeat("0", 64)))
		if err == nil || restart || !strings.Contains(err.Error(), "SHA-256") {
			t.Fatalf("mismatch accepted: %v", err)
		}
		if got, _ := os.ReadFile(exe); string(got) != "old-binary" {
			t.Error("binary changed after failed update")
		}
	})

	t.Run("rejects binary reporting another version", func(t *testing.T) {
		t.Setenv("NP_FAKE_AGENT_VERSION", "1.0.0")
		exe := setup(t)
		_, _, err := SelfUpdater{L: l, Client: client, Enabled: true, Executable: exe}.Update(context.Background(), job("9.9.9", goodSum))
		if err == nil || !strings.Contains(err.Error(), "doğrulanamadı") {
			t.Fatalf("wrong version accepted: %v", err)
		}
		if got, _ := os.ReadFile(exe); string(got) != "old-binary" {
			t.Error("binary changed after failed verification")
		}
	})

	t.Run("rejects unsafe parameters and disabled updates", func(t *testing.T) {
		exe := setup(t)
		bad := job("9.9.9", goodSum)
		bad.Params[protocol.ParamPath] = "/downloads/agent/../../etc/passwd"
		if _, _, err := (SelfUpdater{L: l, Client: client, Enabled: true, Executable: exe}).Update(context.Background(), bad); err == nil {
			t.Error("path traversal accepted")
		}
		bad = job("9.9.9; rm -rf /", goodSum)
		if _, _, err := (SelfUpdater{L: l, Client: client, Enabled: true, Executable: exe}).Update(context.Background(), bad); err == nil {
			t.Error("invalid version accepted")
		}
		if _, _, err := (SelfUpdater{L: l, Client: client, Enabled: false, Executable: exe}).Update(context.Background(), job("9.9.9", goodSum)); err == nil || !strings.Contains(err.Error(), "kapalı") {
			t.Errorf("disabled updater ran: %v", err)
		}
	})
}
