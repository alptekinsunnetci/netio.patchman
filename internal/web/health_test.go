package web_test

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"netio.patchman/internal/protocol"
	"netio.patchman/internal/store"
	"netio.patchman/internal/timeutil"
)

func TestHealthChecksEndToEnd(t *testing.T) {
	e, admin, oldID := fleetEnv(t)
	ctx := context.Background()
	info := protocol.HostInfo{Hostname: "web-09", MachineID: "hc1", OSID: "debian", OSVersionID: "12", Arch: "amd64", PackageManager: "apt",
		AgentVersion: "0.10.0", RemoteUpdates: true, Capabilities: []string{protocol.CapServices, protocol.CapHealth}}
	client, id := e.agentFor(info)
	if err := client.Report(ctx, protocol.Report{Host: info, CollectedAt: timeutil.Now()}); err != nil {
		t.Fatal(err)
	}
	hostURL := "/servers/" + strconv.FormatInt(id, 10)

	// Definitions.
	form := url.Values{"_csrf": {e.csrf(admin)}, "name": {"Web sitesi"}, "type": {"http"}, "target": {"file:///etc/passwd"}, "scope": {"all"},
		"with_updates": {"1"}, "enabled": {"1"}, "timeout_seconds": {"5"}}
	status, body, _ := e.do(admin, "POST", "/settings/health", form)
	expect(t, "invalid target", status, 400, body, "HTTP/HTTPS kontrolü için hedef geçersiz.")
	form.Set("target", "https://127.0.0.1/health")
	if status, _, _ := e.do(admin, "POST", "/settings/health", form); status != 303 {
		t.Fatalf("create: %d", status)
	}
	form = url.Values{"_csrf": {e.csrf(admin)}, "name": {"Disk"}, "type": {"resources"}, "disk": {"90"}, "scope": {"host"}, "host_id": {strconv.FormatInt(id, 10)},
		"enabled": {"1"}}
	if status, _, _ := e.do(admin, "POST", "/settings/health", form); status != 303 {
		t.Fatalf("create resources check: %d", status)
	}
	checks, _ := e.st.ListHealthChecks(ctx)
	if len(checks) != 2 {
		t.Fatalf("checks: %+v", checks)
	}
	status, body, _ = e.do(admin, "GET", "/settings/health", nil)
	expect(t, "checks page", status, 200, body, "Web sitesi", "https://127.0.0.1/health", "Disk", "web-09")

	// An update job carries only the checks marked for updates; the manual
	// check gets every check of the host.
	if status, _, _ := e.do(admin, "POST", hostURL+"/jobs", url.Values{"_csrf": {e.csrf(admin)}, "type": {"upgrade_all"}}); status != 303 {
		t.Fatalf("queue update: %d", status)
	}
	if status, _, _ := e.do(admin, "POST", hostURL+"/jobs", url.Values{"_csrf": {e.csrf(admin)}, "type": {"health_check"}}); status != 303 {
		t.Fatalf("queue health check: %d", status)
	}
	resp, err := client.Checkin(ctx, info)
	if err != nil {
		t.Fatal(err)
	}
	var upd, hc protocol.Job
	for _, j := range resp.Jobs {
		switch j.Type {
		case protocol.JobUpgradeAll:
			upd = j
		case protocol.JobHealthCheck:
			hc = j
		}
	}
	var updChecks, allChecks []protocol.HealthCheck
	_ = json.Unmarshal([]byte(upd.Params[protocol.ParamHealth]), &updChecks)
	_ = json.Unmarshal([]byte(hc.Params[protocol.ParamHealth]), &allChecks)
	if len(updChecks) != 1 || updChecks[0].Name != "Web sitesi" || upd.Params[protocol.ParamHealthDelay] != "15" || upd.Params[protocol.ParamHealthPolicy] != "" {
		t.Errorf("update job checks: %+v %v", updChecks, upd.Params)
	}
	if len(allChecks) != 2 {
		t.Errorf("health_check job checks: %+v", allChecks)
	}

	// The agent reports: the web check passed before and failed after.
	web := updChecks[0]
	res := protocol.JobResult{Succeeded: true, Output: "ok", StartedAt: timeutil.Now(), FinishedAt: timeutil.Now(), Health: &protocol.HealthReport{
		Before: []protocol.HealthResult{{ID: web.ID, Name: web.Name, Type: "http", OK: true, Value: "HTTP 200"}},
		After:  []protocol.HealthResult{{ID: web.ID, Name: web.Name, Type: "http", OK: false, Value: "HTTP 502", Message: "HTTP 502 döndü"}},
	}}
	if err := client.JobResult(ctx, upd.ID, res); err != nil {
		t.Fatal(err)
	}
	status, body, _ = e.do(admin, "GET", "/jobs/"+strconv.FormatInt(upd.ID, 10), nil)
	expect(t, "job health", status, 200, body, "Güncellemeden sonra bozuldu", "Güncelleme öncesi", "HTTP 502")
	waitNotification(t, e, "health_regressed", "web-09")

	hcRes := protocol.JobResult{Succeeded: true, StartedAt: timeutil.Now(), FinishedAt: timeutil.Now(), Health: &protocol.HealthReport{
		Checks: []protocol.HealthResult{{ID: allChecks[0].ID, Name: allChecks[0].Name, OK: true, Value: "/ 40%"}, {ID: allChecks[1].ID, Name: allChecks[1].Name, OK: true, Value: "HTTP 200"}},
	}}
	if err := client.JobResult(ctx, hc.ID, hcRes); err != nil {
		t.Fatal(err)
	}
	status, body, _ = e.do(admin, "GET", hostURL+"?tab=health", nil)
	expect(t, "host health tab", status, 200, body, "Ek kontroller (isteğe bağlı)", "Şimdi kontrol et", "/ 40%", "Sonuç geçmişi", "HTTP 502")
	hist, total, _ := e.st.HostHealth(ctx, id, store.Page{Number: 1, Size: 50})
	if total != 4 || len(hist) != 4 {
		t.Errorf("history: %d", total)
	}

	// An agent without the capability gets neither the checks nor the job.
	_, body, _ = e.do(admin, "GET", "/servers/"+strconv.FormatInt(oldID, 10)+"?tab=health", nil)
	if !strings.Contains(body, "sağlık kontrolü desteklemiyor") || strings.Contains(body, "Şimdi kontrol et") {
		t.Errorf("old agent health tab")
	}
	_, _, hdr := e.do(admin, "POST", "/servers/"+strconv.FormatInt(oldID, 10)+"/jobs", url.Values{"_csrf": {e.csrf(admin)}, "type": {"health_check"}})
	if loc := hdr.Get("Location"); strings.HasPrefix(loc, "/jobs/") {
		t.Errorf("health_check queued on an old agent: %s", loc)
	}

	// Edit and delete.
	form = url.Values{"_csrf": {e.csrf(admin)}, "name": {"Web sitesi 2"}, "type": {"tcp"}, "target": {"127.0.0.1:443"}, "scope": {"all"}, "enabled": {"1"}}
	if status, _, _ := e.do(admin, "POST", "/settings/health/"+strconv.FormatInt(web.ID, 10), form); status != 303 {
		t.Fatalf("update: %d", status)
	}
	c, _ := e.st.HealthCheckByID(ctx, web.ID)
	if c.Name != "Web sitesi 2" || c.Type != "tcp" || c.WithUpdates {
		t.Errorf("updated: %+v", c)
	}
	if status, _, _ := e.do(admin, "POST", "/settings/health/"+strconv.FormatInt(web.ID, 10)+"/delete", url.Values{"_csrf": {e.csrf(admin)}}); status != 303 {
		t.Fatalf("delete: %d", status)
	}
	if list, _ := e.st.ListHealthChecks(ctx); len(list) != 1 {
		t.Errorf("after delete: %d", len(list))
	}
}

// waitNotification waits for an asynchronous notification of kind about host.
func waitNotification(t *testing.T, e *env, kind, host string) store.Notification {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		list, _, _ := e.st.ListNotifications(context.Background(), false, store.Page{Number: 1, Size: 100})
		for _, n := range list {
			if n.Kind == kind && (host == "" || n.Params["hostname"] == host) {
				return n
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("notification %s for %s missing", kind, host)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
