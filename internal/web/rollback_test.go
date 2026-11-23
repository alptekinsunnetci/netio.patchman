package web_test

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"netio.patchman/internal/protocol"
	"netio.patchman/internal/timeutil"
)

func TestRollbackFlow(t *testing.T) {
	e, admin, _ := fleetEnv(t)
	ctx := context.Background()
	info := protocol.HostInfo{Hostname: "db-07", MachineID: "rb1", OSID: "debian", OSVersionID: "12", Arch: "amd64", PackageManager: "apt",
		AgentVersion: "0.10.0", RemoteUpdates: true, Capabilities: []string{protocol.CapRollback}}
	client, id := e.agentFor(info)
	report := func(version string) {
		t.Helper()
		if err := client.Report(ctx, protocol.Report{Host: info, CollectedAt: timeutil.Now(),
			Packages: []protocol.Package{{Name: "openssl", Arch: "amd64", Version: version, SourceName: "openssl"}, {Name: "bash", Arch: "amd64", Version: "5.2.15-2+b7"}}}); err != nil {
			t.Fatal(err)
		}
	}
	report("3.0.11-1~deb12u2")
	hostURL := "/servers/" + strconv.FormatInt(id, 10)
	jobFromLoc := func(loc string) int64 {
		n, _ := strconv.ParseInt(strings.TrimPrefix(loc, "/jobs/"), 10, 64)
		return n
	}
	dispatch := func() protocol.Job {
		t.Helper()
		resp, err := client.Checkin(ctx, info)
		if err != nil || len(resp.Jobs) != 1 {
			t.Fatalf("dispatch: %+v %v", resp, err)
		}
		return resp.Jobs[0]
	}

	// The update; the agent reports what it changed.
	_, _, hdr := e.do(admin, "POST", hostURL+"/jobs", url.Values{"_csrf": {e.csrf(admin)}, "type": {"upgrade_packages"}, "packages": {"openssl"}})
	updID := jobFromLoc(hdr.Get("Location"))
	upd := dispatch()
	if upd.ID != updID {
		t.Fatalf("dispatched %d, queued %d", upd.ID, updID)
	}
	if inv, err := e.st.JobInventory(ctx, updID); err != nil || len(inv) != 2 {
		t.Fatalf("inventory snapshot: %v %v", inv, err)
	}
	change := protocol.PackageChange{Name: "openssl", Arch: "amd64", From: "3.0.11-1~deb12u2", To: "3.0.15-1~deb12u1"}
	if err := client.JobResult(ctx, updID, protocol.JobResult{Succeeded: true, Changes: []protocol.PackageChange{change}}); err != nil {
		t.Fatal(err)
	}
	report("3.0.15-1~deb12u1")
	status, body, _ := e.do(admin, "GET", "/jobs/"+strconv.FormatInt(updID, 10), nil)
	expect(t, "update job changes", status, 200, body, "Paket değişiklikleri", "Ajan bildirdi", "Seçilenlerin geri alınabilirliğini kontrol et")

	// Check: nothing changes, the agent reports availability and the plan.
	_, _, hdr = e.do(admin, "POST", "/jobs/"+strconv.FormatInt(updID, 10)+"/rollback-check", url.Values{"_csrf": {e.csrf(admin)}, "pkg": {"0"}})
	checkID := jobFromLoc(hdr.Get("Location"))
	chk := dispatch()
	var targets []protocol.PackageChange
	_ = json.Unmarshal([]byte(chk.Params[protocol.ParamRollbackTargets]), &targets)
	if chk.Type != protocol.JobRollback || chk.Params[protocol.ParamRollbackMode] != protocol.RollbackCheck || len(targets) != 1 || targets[0].To != "3.0.11-1~deb12u2" {
		t.Fatalf("check job: %+v %+v", chk, targets)
	}
	if err := client.JobResult(ctx, checkID, protocol.JobResult{Succeeded: true,
		Rollback: []protocol.RollbackItem{{Name: "openssl", Arch: "amd64", From: "3.0.15-1~deb12u1", To: "3.0.11-1~deb12u2", Status: protocol.RollbackAvailable}},
		Preview:  &protocol.Preview{PackageManager: "apt", DownloadBytes: -1, DiskBytes: -1, FreeBytes: -1, Downgrades: []protocol.PackageChange{{Name: "openssl", From: "3.0.15-1~deb12u1", To: "3.0.11-1~deb12u2"}}}}); err != nil {
		t.Fatal(err)
	}
	status, body, _ = e.do(admin, "GET", "/jobs/"+strconv.FormatInt(checkID, 10), nil)
	expect(t, "check page", status, 200, body, "Geri dönüş kontrolü", "Geri alınabilir", "Onayla ve geri al", "Geri dönüş planı", "Sürümü düşürülecek paketler")

	// Apply once, with hold.
	_, _, hdr = e.do(admin, "POST", "/jobs/"+strconv.FormatInt(checkID, 10)+"/rollback-apply", url.Values{"_csrf": {e.csrf(admin)}, "pkg": {"0"}, "hold": {"1"}})
	applyID := jobFromLoc(hdr.Get("Location"))
	_, _, hdr = e.do(admin, "POST", "/jobs/"+strconv.FormatInt(checkID, 10)+"/rollback-apply", url.Values{"_csrf": {e.csrf(admin)}, "pkg": {"0"}})
	if jobFromLoc(hdr.Get("Location")) != checkID {
		t.Errorf("second apply allowed: %s", hdr.Get("Location"))
	}
	app := dispatch()
	if app.ID != applyID || app.Params[protocol.ParamRollbackMode] != protocol.RollbackApply || app.Params["hold"] != "1" {
		t.Fatalf("apply job: %+v", app)
	}
	if err := client.JobResult(ctx, applyID, protocol.JobResult{Succeeded: true,
		Rollback: []protocol.RollbackItem{{Name: "openssl", Arch: "amd64", From: "3.0.15-1~deb12u1", To: "3.0.11-1~deb12u2", Status: protocol.RollbackDone}},
		Changes:  []protocol.PackageChange{{Name: "openssl", Arch: "amd64", From: "3.0.15-1~deb12u1", To: "3.0.11-1~deb12u2"}}}); err != nil {
		t.Fatal(err)
	}
	status, body, _ = e.do(admin, "GET", "/jobs/"+strconv.FormatInt(applyID, 10), nil)
	expect(t, "apply page", status, 200, body, "Geri dönüş sonucu", "Geri alındı", "Bu geri dönüş şu işin değişikliklerini hedefliyor")
	h, _ := e.st.HostByID(ctx, id)
	if !strings.Contains(h.Exclude, "openssl") {
		t.Errorf("hold: exclusions %q", h.Exclude)
	}
	waitNotification(t, e, "rollback_done", "db-07")
	_, body, _ = e.do(admin, "GET", "/jobs/"+strconv.FormatInt(checkID, 10), nil)
	if !strings.Contains(body, "Bu kontrol onaylandı") || strings.Contains(body, "Onayla ve geri al") {
		t.Errorf("check page after apply")
	}

	// An agent that reports no changes: the inventory at dispatch is compared.
	_, _, hdr = e.do(admin, "POST", hostURL+"/jobs", url.Values{"_csrf": {e.csrf(admin)}, "type": {"upgrade_all"}})
	oldStyle := jobFromLoc(hdr.Get("Location"))
	dispatch()
	if err := client.JobResult(ctx, oldStyle, protocol.JobResult{Succeeded: true}); err != nil {
		t.Fatal(err)
	}
	report("3.0.17-1~deb12u1")
	status, body, _ = e.do(admin, "GET", "/jobs/"+strconv.FormatInt(oldStyle, 10), nil)
	expect(t, "inventory changes", status, 200, body, "Envanter karşılaştırması", "3.0.17-1~deb12u1")
}
