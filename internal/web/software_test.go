package web_test

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"netio.patchman/internal/agent"
	"netio.patchman/internal/auth"
	"netio.patchman/internal/protocol"
	"netio.patchman/internal/store"
	"netio.patchman/internal/timeutil"
)

// agentFor registers a host directly in the store and returns an agent
// client that authenticates as it.
func (e *env) agentFor(info protocol.HostInfo) (*agent.Client, int64) {
	e.t.Helper()
	ctx := context.Background()
	tok := "tok-" + info.MachineID
	if _, err := e.st.CreateEnrollmentToken(ctx, tok, tok, "p", 0, time.Time{}, 0); err != nil {
		e.t.Fatal(err)
	}
	secret := "secret-" + info.MachineID
	id, _, err := e.st.RegisterHost(ctx, tok, info, "", auth.HashToken(secret))
	if err != nil {
		e.t.Fatal(err)
	}
	c, err := agent.NewClient(agent.Config{ServerURL: mustURL(e.srv.URL)})
	if err != nil {
		e.t.Fatal(err)
	}
	c.SetSecret(secret)
	return c, id
}

func TestSoftwareInventoryPages(t *testing.T) {
	e, admin, dbID := fleetEnv(t)
	ctx := context.Background()
	info := protocol.HostInfo{Hostname: "web-07", MachineID: "sw1", OSID: "debian", OSVersionID: "12", OSName: "Debian GNU/Linux 12 (bookworm)",
		Arch: "amd64", PackageManager: "apt", AgentVersion: "0.10.0", Capabilities: []string{protocol.CapServices}}
	client, id := e.agentFor(info)
	hostURL := "/servers/" + strconv.FormatInt(id, 10)
	report := func(pkgs []protocol.Package, svcs []protocol.Service) {
		t.Helper()
		if err := client.Report(ctx, protocol.Report{Host: info, CollectedAt: timeutil.Now(), Packages: pkgs, Services: svcs}); err != nil {
			t.Fatal(err)
		}
	}
	nginx := protocol.Package{Name: "nginx", Version: "1.22.1-9", Arch: "amd64", SourceName: "nginx", SourceVersion: "1.22.1-9"}
	php := protocol.Package{Name: "php8.2-fpm", Version: "8.2.26-1~deb12u1", Arch: "amd64", SourceName: "php8.2", SourceVersion: "8.2.26-1~deb12u1"}
	report([]protocol.Package{nginx, php}, []protocol.Service{{Name: "nginx", State: "running", Enabled: true}, {Name: "php8.2-fpm", State: "failed"}, {Name: "cron", State: "stopped"}})

	status, body, _ := e.do(admin, "GET", hostURL+"?tab=software", nil)
	expect(t, "host software tab", status, 200, body, "Nginx", "PHP-FPM", "1.22.1", "Çalışıyor", "php8.2-fpm", "Hatalı", "Durdurulmuş 1 servisi de göster")
	if strings.Contains(body, ">cron<") {
		t.Errorf("stopped service shown by default")
	}
	status, body, _ = e.do(admin, "GET", hostURL+"?tab=software&services=all", nil)
	expect(t, "all services", status, 200, body, ">cron<")

	status, body, _ = e.do(admin, "GET", "/software", nil)
	expect(t, "software list", status, 200, body, "Yazılım Envanteri", `href="/software/nginx"`, "Nginx", "1.22")
	status, body, _ = e.do(admin, "GET", "/software?category=database", nil)
	if status != 200 || strings.Contains(body, `href="/software/nginx"`) {
		t.Errorf("category filter: %d", status)
	}
	status, body, _ = e.do(admin, "GET", "/software/nginx?cycle=1.22", nil)
	expect(t, "software detail", status, 200, body, "web-07", "1.22.1-9", "nginx")
	status, _, _ = e.do(admin, "GET", "/software/unknown-thing", nil)
	if status != 404 {
		t.Errorf("unknown software: %d", status)
	}

	// Second report: nginx upgraded, PHP-FPM removed, Redis installed.
	nginx.Version = "1.22.1-9+deb12u1"
	report([]protocol.Package{nginx, {Name: "redis-server", Version: "5:7.0.15-1~deb12u1", Arch: "amd64", SourceName: "redis"}},
		[]protocol.Service{{Name: "nginx", State: "running"}, {Name: "redis-server", State: "running"}})
	status, body, _ = e.do(admin, "GET", "/software?tab=changes&host="+strconv.FormatInt(id, 10), nil)
	expect(t, "change history", status, 200, body, "Yükseltildi", "Kaldırıldı", "Kuruldu", "deb12u1", "Redis")
	// The notification is added asynchronously.
	deadline := time.Now().Add(3 * time.Second)
	for {
		list, _, _ := e.st.ListNotifications(ctx, false, store.Page{Number: 1, Size: 50})
		found := false
		for _, n := range list {
			if n.Kind == "software_changed" && n.Params["hostname"] == "web-07" && strings.Contains(n.Params["added"], "Redis 7.0") &&
				strings.Contains(n.Params["removed"], "PHP-FPM 8.2") {
				found = true
			}
		}
		if found {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("software_changed notification missing")
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Comparison with the fleetEnv host (no recognized software).
	status, body, _ = e.do(admin, "GET", "/software?tab=compare&a="+strconv.FormatInt(id, 10)+"&b="+strconv.FormatInt(dbID, 10), nil)
	expect(t, "compare", status, 200, body, "Yalnızca birinde", "Kurulu değil")

	// REST API.
	key := e.createAPIKey(admin, "inventory", false)
	code, out := e.apiDo(key, "GET", "/api/v1/hosts/"+strconv.FormatInt(id, 10)+"/software", "")
	if code != 200 || !strings.Contains(out, `"software": "nginx"`) || !strings.Contains(out, `"running": true`) || !strings.Contains(out, `"services_known": true`) {
		t.Errorf("api host software: %d %s", code, out)
	}
	code, out = e.apiDo(key, "GET", "/api/v1/software?software=redis", "")
	if code != 200 || !strings.Contains(out, `"hostname": "web-07"`) || strings.Contains(out, `"nginx"`) {
		t.Errorf("api software: %d %s", code, out)
	}
	if code, _ := e.apiDo(key, "GET", "/api/v1/software?software=nope", ""); code != 400 {
		t.Errorf("api unknown software: %d", code)
	}
}
