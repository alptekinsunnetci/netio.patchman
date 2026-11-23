package web_test

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"netio.patchman/internal/i18n"
	"netio.patchman/internal/notify"
	"netio.patchman/internal/protocol"
	"netio.patchman/internal/settings"
	"netio.patchman/internal/store"
	"netio.patchman/internal/timeutil"
)

func settingsValues(t *testing.T, e *env) settings.Values {
	t.Helper()
	v, err := settings.Load(context.Background(), e.st)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func countKind(t *testing.T, e *env, kind string) int {
	t.Helper()
	list, _, _ := e.st.ListNotifications(context.Background(), false, store.Page{Number: 1, Size: 200})
	n := 0
	for _, x := range list {
		if x.Kind == kind {
			n++
		}
	}
	return n
}

func TestContinuousMonitoring(t *testing.T) {
	e, admin, oldID := fleetEnv(t)
	ctx := context.Background()
	info := protocol.HostInfo{Hostname: "web-21", MachineID: "mon1", OSID: "debian", OSVersionID: "12", Arch: "amd64", PackageManager: "apt",
		AgentVersion: "1.0.1", RemoteUpdates: true, Capabilities: []string{protocol.CapServices, protocol.CapHealth, protocol.CapHealthMonitor}}
	client, id := e.agentFor(info)
	if err := client.Report(ctx, protocol.Report{Host: info, CollectedAt: timeutil.Now()}); err != nil {
		t.Fatal(err)
	}
	hostURL := "/servers/" + strconv.FormatInt(id, 10)

	// A monitored check, and one that only runs with updates.
	for _, f := range []url.Values{
		{"name": {"Web sitesi"}, "type": {"http"}, "target": {"https://127.0.0.1/health"}, "scope": {"all"}, "with_updates": {"1"}, "monitor": {"1"}, "enabled": {"1"}},
		{"name": {"Yalnız güncellemede"}, "type": {"tcp"}, "target": {"127.0.0.1:5432"}, "scope": {"all"}, "with_updates": {"1"}, "enabled": {"1"}},
	} {
		f.Set("_csrf", e.csrf(admin))
		if status, body, _ := e.do(admin, "POST", "/settings/health", f); status != 303 {
			t.Fatalf("create check: %d %s", status, body)
		}
	}
	checks, _ := e.st.ListHealthChecks(ctx)
	var web int64
	for _, c := range checks {
		if c.Name == "Web sitesi" {
			web = c.ID
		}
	}

	// The check-in carries the schedule with the monitored check only; an
	// agent without the capability gets none.
	resp, err := client.Checkin(ctx, info)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Health == nil || resp.Health.IntervalSeconds != 300 || len(resp.Health.Checks) != 1 || resp.Health.Checks[0].ID != web {
		t.Fatalf("schedule: %+v", resp.Health)
	}
	old := info
	old.MachineID, old.Hostname, old.Capabilities = "mon-old", "web-22", []string{protocol.CapHealth}
	oldClient, _ := e.agentFor(old)
	if r, _ := oldClient.Checkin(ctx, old); r.Health != nil {
		t.Errorf("schedule sent to an agent without monitoring: %+v", r.Health)
	}

	const gib = int64(1) << 30
	round := func(ok bool, rootUsed int64, extra ...protocol.HealthResult) {
		t.Helper()
		st := protocol.HealthStatus{CheckedAt: timeutil.Now(),
			Results: append([]protocol.HealthResult{{ID: web, Name: "Web sitesi", Type: "http", OK: ok, Value: "HTTP 200", Message: map[bool]string{true: "", false: "HTTP 502"}[ok]}}, extra...),
			Resources: &protocol.Resources{CPUs: 4, Load: []float64{0.52, 0.4, 0.3}, MemoryTotal: 8 * gib, MemoryAvailable: 6 * gib, SwapTotal: 2 * gib, SwapFree: 2 * gib,
				Disks: []protocol.DiskUsage{{Path: "/", Total: 100 * gib, Used: rootUsed, Available: 100*gib - rootUsed}, {Path: "/var/lib/mysql", Total: 50 * gib, Used: 10 * gib, Available: 40 * gib}}}}
		if err := client.Health(ctx, st); err != nil {
			t.Fatal(err)
		}
	}
	// Round 1: check fails, root disk at 95%; results of unknown checks are ignored.
	round(false, 95*gib, protocol.HealthResult{ID: 999999, Name: "uydurma", Type: "http", OK: false})
	states, _ := e.st.HostHealthStates(ctx, id)
	failing := 0
	for _, st := range states {
		if st.Name == "uydurma" {
			t.Errorf("unknown check stored")
		}
		if !st.OK {
			failing++
		}
	}
	if failing != 2 || len(states) != 4 { // check, disk /, disk /var/lib/mysql, memory
		t.Fatalf("states after round 1: %+v", states)
	}
	if countKind(t, e, "health_down")+countKind(t, e, "resource_high") != 0 {
		t.Error("notified after one failed round")
	}
	// Round 2: still failing -> notified once.
	round(false, 95*gib)
	waitNotification(t, e, "health_down", "web-21")
	n := waitNotification(t, e, "resource_high", "web-21")
	if n.Params["resource"] != "disk" || n.Params["target"] != "/" || n.Params["value"] != "95%" || n.Params["limit"] != "90" {
		t.Errorf("resource notification: %+v", n.Params)
	}
	if text := notify.Text(i18n.MustLoad().Localizer(i18n.DefaultLocale), n); text != "web-21: Disk (/) kullanımı 95% (sınır %90)." {
		t.Errorf("text: %q", text)
	}
	round(false, 95*gib)
	if countKind(t, e, "health_down") != 1 || countKind(t, e, "resource_high") != 1 {
		t.Error("failure notified more than once")
	}

	// Pages while failing.
	status, body, _ := e.do(admin, "GET", hostURL+"?tab=health", nil)
	expect(t, "health tab", status, 200, body, "Anlık durum", "/var/lib/mysql", "95%", "Disk (/)", "HTTP 502", "Otomatik sınır", "usage--bad", "0,52 · 0,40 · 0,30")
	status, body, _ = e.do(admin, "GET", "/servers?status=health", nil)
	expect(t, "health filter", status, 200, body, "web-21", "Sağlık sorunu: 2")
	if strings.Contains(body, "db-01") {
		t.Error("healthy host in the health filter")
	}
	key := e.createAPIKey(admin, "mon", false)
	status, body = e.apiDo(key, "GET", "/api/v1/hosts/"+strconv.FormatInt(id, 10)+"/health", "")
	var api struct {
		Failing   int
		Checks    []struct{ Key string }
		Resources *protocol.Resources
	}
	if err := json.Unmarshal([]byte(body), &api); status != 200 || err != nil || api.Failing != 2 || len(api.Checks) != 4 || api.Resources == nil || len(api.Resources.Disks) != 2 {
		t.Errorf("api: %d %v %s", status, err, body)
	}
	status, body = e.apiDo(key, "GET", "/metrics", "")
	expect(t, "metrics", status, 200, body, `netio_patchman_host_health_failing{host="web-21",os="debian"} 2`,
		`netio_patchman_host_disk_used_percent{host="web-21",os="debian",path="/"} 95.0`, `netio_patchman_host_memory_used_percent{host="web-21",os="debian"} 25.0`,
		`netio_patchman_host_load_per_cpu_percent{host="web-21",os="debian"} 13.0`)

	// Recovery is notified; the history keeps the changes only.
	round(true, 40*gib)
	waitNotification(t, e, "health_up", "web-21")
	waitNotification(t, e, "resource_ok", "web-21")
	hist, _, _ := e.st.HostHealth(ctx, id, store.Page{Number: 1, Size: 50})
	monitorRows := 0
	for _, h := range hist {
		if h.Phase == store.HealthMonitor {
			monitorRows++
		}
	}
	if monitorRows != 4 { // check and disk / failed, then recovered
		t.Errorf("monitor history rows: %d %+v", monitorRows, hist)
	}
	if failing, _ := e.st.FailingHealth(ctx); failing[id] != 0 {
		t.Errorf("still failing: %v", failing)
	}

	// Settings: interval 0 stops the schedule; limits are saved.
	form := url.Values{"_csrf": {e.csrf(admin)}, "email_min_severity": {"high"}, "email_digest_threshold": {"5"}, "agent_offline_minutes": {"10"},
		"agent_checkin_seconds": {"60"}, "agent_report_minutes": {"60"}, "retention_days": {"90"}, "scan_enabled": {"1"},
		"monitor_section": {"1"}, "health_monitor": {"0"}, "health_disk_warn": {"80"}, "health_memory_warn": {"0"}, "health_cpu_warn": {"150"}}
	if status, _, _ := e.do(admin, "POST", "/settings", form); status != 303 {
		t.Fatalf("settings: %d", status)
	}
	if r, _ := client.Checkin(ctx, info); r.Health != nil {
		t.Errorf("schedule with monitoring off: %+v", r.Health)
	}
	form.Set("health_disk_warn", "101")
	e.do(admin, "POST", "/settings", form) // refused: the stored values stay
	if cfg := settingsValues(t, e); cfg.HealthDiskWarn != 80 || cfg.HealthMemoryWarn != 0 || cfg.HealthCPUWarn != 150 || cfg.HealthMonitor != 0 {
		t.Errorf("saved limits: %+v", cfg)
	}
	// Memory limit off: the memory state goes away with the next round.
	round(true, 40*gib)
	states, _ = e.st.HostHealthStates(ctx, id)
	for _, st := range states {
		if st.Key == store.MonitorMemory {
			t.Errorf("memory state with the limit off")
		}
	}
	// Removing the host drops its states.
	_ = oldID
}
