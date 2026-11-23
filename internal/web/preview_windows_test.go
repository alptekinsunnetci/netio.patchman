package web_test

import (
	"context"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"netio.patchman/internal/protocol"
	"netio.patchman/internal/store"
	"netio.patchman/internal/timeutil"
)

// Agents up to 1.0.3 declared CapPreview and CapRollback on Windows, where
// neither works: an update started on the server page must run directly
// instead of becoming a preview that fails.
func TestWindowsUpdateSkipsPreview(t *testing.T) {
	e, admin, _ := fleetEnv(t)
	ctx := context.Background()
	info := protocol.HostInfo{Hostname: "WIN-LO3UPJJM4L7", MachineID: "win-pv", OSID: "windows", OSVersionID: "10.0.20348", Arch: "amd64",
		PackageManager: protocol.PMWindowsUpdate, AgentVersion: "1.0.3", RemoteUpdates: true,
		Capabilities: []string{protocol.CapServices, protocol.CapHealth, protocol.CapPreview, protocol.CapRollback, protocol.CapHealthMonitor}}
	client, id := e.agentFor(info)
	if err := client.Report(ctx, protocol.Report{Host: info, CollectedAt: timeutil.Now(), Updates: []protocol.Update{
		{Name: "KB5122882", AvailableVersion: "KB5122882", Security: true, Title: "2026-11 Cumulative Update"},
		{Name: "KB890830", AvailableVersion: "KB890830", Title: "Windows Malicious Software Removal Tool"},
	}}); err != nil {
		t.Fatal(err)
	}
	h, _ := e.st.HostByID(ctx, id)
	if h.CanPreview() || h.CanRollback() {
		t.Fatalf("windows host can preview %v / roll back %v", h.CanPreview(), h.CanRollback())
	}
	hostURL := "/servers/" + strconv.FormatInt(id, 10)

	_, _, hdr := e.do(admin, "POST", hostURL+"/jobs", url.Values{"_csrf": {e.csrf(admin)}, "type": {"upgrade_packages"}, "packages": {"KB5122882", "KB890830"}})
	jobs, _, _ := e.st.ListJobs(ctx, storeJobFilter(id), storePage())
	if len(jobs) != 1 || jobs[0].Type != protocol.JobUpgradePackages || strings.Join(jobs[0].Packages, ",") != "KB5122882,KB890830" {
		t.Fatalf("jobs (redirect %s): %+v", hdr.Get("Location"), jobs)
	}
	_, body, _ := e.do(admin, "GET", hostURL+"?tab=updates", nil)
	if strings.Contains(body, "/servers/"+strconv.FormatInt(id, 10)+"/preview") {
		t.Error("preview button offered on a windows host")
	}
	// A direct preview request is refused.
	_, _, hdr = e.do(admin, "POST", hostURL+"/preview", url.Values{"_csrf": {e.csrf(admin)}, "type": {"upgrade_security"}})
	if jobs, _, _ := e.st.ListJobs(ctx, storeJobFilter(id), storePage()); len(jobs) != 1 {
		t.Errorf("preview queued on windows: %+v", jobs)
	}

	// A preview that already failed (queued before this fix) is retried as
	// the update itself.
	pvID, err := e.st.CreateJob(ctx, id, protocol.JobPreview, []string{"KB5122882"}, map[string]string{protocol.ParamPreviewType: protocol.JobUpgradePackages}, 0)
	if err != nil {
		t.Fatal(err)
	}
	resp, _ := client.Checkin(ctx, info)
	for _, j := range resp.Jobs {
		res := protocol.JobResult{ExitCode: -1, Output: "[netio.patchman] Bu paket yöneticisi için güncelleme önizlemesi desteklenmiyor.", StartedAt: timeutil.Now(), FinishedAt: timeutil.Now()}
		if err := client.JobResult(ctx, j.ID, res); err != nil {
			t.Fatal(err)
		}
	}
	_, _, hdr = e.do(admin, "POST", "/jobs/"+strconv.FormatInt(pvID, 10)+"/retry", url.Values{"_csrf": {e.csrf(admin)}})
	newID, _ := strconv.ParseInt(strings.TrimPrefix(hdr.Get("Location"), "/jobs/"), 10, 64)
	retried, err := e.st.JobByID(ctx, newID)
	if err != nil || retried.Type != protocol.JobUpgradePackages || strings.Join(retried.Packages, ",") != "KB5122882" {
		t.Fatalf("retry of the failed preview: %s %+v %v", hdr.Get("Location"), retried, err)
	}
}

func storeJobFilter(hostID int64) store.JobFilter { return store.JobFilter{HostID: hostID} }

func storePage() store.Page { return store.Page{Number: 1, Size: 50} }
