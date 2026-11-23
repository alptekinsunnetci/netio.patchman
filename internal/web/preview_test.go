package web_test

import (
	"context"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"netio.patchman/internal/protocol"
	"netio.patchman/internal/settings"
	"netio.patchman/internal/timeutil"
)

func TestPreviewApproval(t *testing.T) {
	e, admin, oldID := fleetEnv(t)
	ctx := context.Background()
	info := protocol.HostInfo{Hostname: "app-05", MachineID: "pv1", OSID: "debian", OSVersionID: "12", Arch: "amd64", PackageManager: "apt",
		AgentVersion: "0.10.0", RemoteUpdates: true, Capabilities: []string{protocol.CapPreview}}
	client, id := e.agentFor(info)
	if err := client.Report(ctx, protocol.Report{Host: info, CollectedAt: timeutil.Now(),
		Updates: []protocol.Update{{Name: "openssl", CurrentVersion: "3.0.11-1~deb12u2", AvailableVersion: "3.0.15-1~deb12u1", Security: true}}}); err != nil {
		t.Fatal(err)
	}
	hostURL := "/servers/" + strconv.FormatInt(id, 10)

	// An update started on the server page becomes a preview first.
	_, _, hdr := e.do(admin, "POST", hostURL+"/jobs", url.Values{"_csrf": {e.csrf(admin)}, "type": {"upgrade_security"}})
	loc := hdr.Get("Location")
	if !strings.HasPrefix(loc, "/jobs/") {
		t.Fatalf("redirect: %s", loc)
	}
	pvID, _ := strconv.ParseInt(strings.TrimPrefix(loc, "/jobs/"), 10, 64)
	pv, _ := e.st.JobByID(ctx, pvID)
	if pv.Type != protocol.JobPreview || pv.Params[protocol.ParamPreviewType] != protocol.JobUpgradeSecurity {
		t.Fatalf("preview job: %+v", pv)
	}
	status, body, _ := e.do(admin, "GET", loc, nil)
	expect(t, "queued preview", status, 200, body, "Güncelleme önizlemesi")
	if strings.Contains(body, "Onayla ve güncellemeyi başlat") {
		t.Errorf("approve offered before the plan exists")
	}
	resp, err := client.Checkin(ctx, info)
	if err != nil || len(resp.Jobs) != 1 || resp.Jobs[0].Type != protocol.JobPreview {
		t.Fatalf("dispatch: %+v %v", resp, err)
	}
	plan := &protocol.Preview{PackageManager: "apt", DownloadBytes: 2_500_000, DiskBytes: 120_000, FreeBytes: 9_000_000_000, Kernel: false, Reboot: false,
		Upgrades: []protocol.PackageChange{{Name: "openssl", Arch: "amd64", From: "3.0.11-1~deb12u2", To: "3.0.15-1~deb12u1"}},
		Installs: []protocol.PackageChange{{Name: "libnew1", To: "1.0-1"}}}
	if err := client.JobResult(ctx, pvID, protocol.JobResult{Succeeded: true, Output: "plan", StartedAt: timeutil.Now(), FinishedAt: timeutil.Now(), Preview: plan}); err != nil {
		t.Fatal(err)
	}
	status, body, _ = e.do(admin, "GET", loc, nil)
	expect(t, "plan page", status, 200, body, "Güncelleme planı", "Yükseltilecek paketler", "Kurulacak yeni paketler", "libnew1", "Onayla ve güncellemeyi başlat", "Yeniden başlatma beklenmiyor")

	// Approve: the previewed job is queued, once.
	_, _, hdr = e.do(admin, "POST", loc+"/approve", url.Values{"_csrf": {e.csrf(admin)}})
	newLoc := hdr.Get("Location")
	newID, _ := strconv.ParseInt(strings.TrimPrefix(newLoc, "/jobs/"), 10, 64)
	job, err := e.st.JobByID(ctx, newID)
	if err != nil || job.Type != protocol.JobUpgradeSecurity || job.Params["preview_job"] != strconv.FormatInt(pvID, 10) {
		t.Fatalf("approved job: %+v %v", job, err)
	}
	status, body, _ = e.do(admin, "GET", newLoc, nil)
	expect(t, "approved job", status, 200, body, "önizleme onaylanarak başlatıldı")
	_, _, hdr = e.do(admin, "POST", loc+"/approve", url.Values{"_csrf": {e.csrf(admin)}})
	if hdr.Get("Location") != loc {
		t.Errorf("second approval: %s", hdr.Get("Location"))
	}
	_, body, _ = e.do(admin, "GET", loc, nil)
	if strings.Contains(body, "Onayla ve güncellemeyi başlat") {
		t.Errorf("approve still offered")
	}

	// A plan with conflicts cannot be approved.
	_, _, hdr = e.do(admin, "POST", hostURL+"/preview", url.Values{"_csrf": {e.csrf(admin)}, "type": {"upgrade_packages"}, "packages": {"openssl"}})
	id2, _ := strconv.ParseInt(strings.TrimPrefix(hdr.Get("Location"), "/jobs/"), 10, 64)
	if _, err := client.Checkin(ctx, info); err != nil {
		t.Fatal(err)
	}
	bad := &protocol.Preview{PackageManager: "apt", DownloadBytes: -1, DiskBytes: -1, FreeBytes: -1, Conflicts: []string{"E: Unable to correct problems, you have held broken packages."}}
	if err := client.JobResult(ctx, id2, protocol.JobResult{Succeeded: true, Preview: bad}); err != nil {
		t.Fatal(err)
	}
	status, body, _ = e.do(admin, "GET", "/jobs/"+strconv.FormatInt(id2, 10), nil)
	expect(t, "conflicting plan", status, 200, body, "held broken packages", "Plan sorun içeriyor")
	_, _, hdr = e.do(admin, "POST", "/jobs/"+strconv.FormatInt(id2, 10)+"/approve", url.Values{"_csrf": {e.csrf(admin)}})
	if !strings.HasSuffix(hdr.Get("Location"), "/jobs/"+strconv.FormatInt(id2, 10)) {
		t.Errorf("conflicting plan approved: %s", hdr.Get("Location"))
	}

	// Agents without preview support and the setting turned off run at once.
	_, _, hdr = e.do(admin, "POST", "/servers/"+strconv.FormatInt(oldID, 10)+"/jobs", url.Values{"_csrf": {e.csrf(admin)}, "type": {"upgrade_security"}})
	oldJobID, _ := strconv.ParseInt(strings.TrimPrefix(hdr.Get("Location"), "/jobs/"), 10, 64)
	if j, _ := e.st.JobByID(ctx, oldJobID); j.Type != protocol.JobUpgradeSecurity {
		t.Errorf("old agent job: %+v", j)
	}
	if err := e.st.SaveSettings(ctx, map[string]string{settings.KeyRequirePreview: "false"}); err != nil {
		t.Fatal(err)
	}
	_, _, hdr = e.do(admin, "POST", hostURL+"/jobs", url.Values{"_csrf": {e.csrf(admin)}, "type": {"upgrade_all"}})
	directID, _ := strconv.ParseInt(strings.TrimPrefix(hdr.Get("Location"), "/jobs/"), 10, 64)
	if j, _ := e.st.JobByID(ctx, directID); j.Type != protocol.JobUpgradeAll {
		t.Errorf("job with previews off: %+v", j)
	}
}
