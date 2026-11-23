package notify

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"netio.patchman/internal/store"
)

func TestEventOf(t *testing.T) {
	for _, c := range []struct {
		kind   string
		params map[string]string
		want   string
	}{
		{"vuln_detected", map[string]string{"severity": "critical", "kev": "0"}, "critical_cve"},
		{"vuln_detected", map[string]string{"severity": "low", "kev": "1"}, "kev"},
		{"vulns_detected", map[string]string{"severity": "critical", "kev": "2"}, "kev"},
		{"vulns_detected", map[string]string{"severity": "high", "kev": "0"}, "vuln"},
		{"job_started", nil, "update_started"},
		{"job_succeeded", nil, "update_succeeded"},
		{"job_partial", nil, "update_failed"},
		{"job_failed", nil, "update_failed"},
		{"rollback_done", nil, "rollback"},
		{"reboot_required", nil, "reboot_required"},
		{"health_regressed", nil, "health_failed"},
		{"eol_approaching", nil, "eol"},
		{"agent_offline", nil, "host_offline"},
		{"drift_detected", nil, "drift"},
		{"rollout_paused", nil, "rollout"},
		{"score_below", nil, "score_below"},
		{"sla_overdue", nil, "sla_overdue"},
		{"software_changed", nil, "software_changed"},
		{"backup_failed", nil, "other"},
	} {
		if got := EventOf(store.Notification{Kind: c.kind, Params: c.params}); got != c.want {
			t.Errorf("%s %v: %s, want %s", c.kind, c.params, got, c.want)
		}
		if !slices.Contains(Events, c.want) {
			t.Errorf("%s is not in Events", c.want)
		}
	}
}

func TestChannelAccepts(t *testing.T) {
	c := store.Channel{Enabled: true, MinLevel: store.LevelWarning}
	if c.Accepts(store.LevelInfo, "update_started") || !c.Accepts(store.LevelWarning, "drift") {
		t.Error("level filter")
	}
	c.Events = []string{"kev"}
	if c.Accepts(store.LevelCritical, "critical_cve") || !c.Accepts(store.LevelCritical, "kev") || !c.Accepts(store.LevelInfo, "kev") {
		// Chosen events decide on their own (an info-level job start can be subscribed to).
		t.Error("event filter")
	}
	c.Enabled = false
	if c.Accepts(store.LevelCritical, "kev") {
		t.Error("disabled channel accepts")
	}
}

// TestEventsHaveLabels keeps notify.Events and the channel.event.* catalog
// keys (and the i18n test family) in step.
func TestEventsHaveLabels(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "i18n", "locales", "tr-TR.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cat map[string]string
	if err := json.Unmarshal(b, &cat); err != nil {
		t.Fatal(err)
	}
	for _, e := range Events {
		if cat["channel.event."+e] == "" {
			t.Errorf("no label for event %s", e)
		}
	}
	for k := range cat {
		if len(k) > 14 && k[:14] == "channel.event." && !slices.Contains(Events, k[14:]) {
			t.Errorf("label for unknown event %s", k)
		}
	}
}
