package web_test

import (
	"context"
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"netio.patchman/internal/agent"
	"netio.patchman/internal/auth"
	"netio.patchman/internal/protocol"
	"netio.patchman/internal/settings"
	"netio.patchman/internal/store"
	"netio.patchman/internal/timeutil"
)

// apiDo sends a REST API request with an optional bearer key.
func (e *env) apiDo(key, method, path, body string) (int, string) {
	e.t.Helper()
	req, _ := http.NewRequest(method, e.srv.URL+path, strings.NewReader(body))
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

var newKeyRE = regexp.MustCompile(`value="(npat_[^"]+)" readonly id="new-api-token"`)

func (e *env) createAPIKey(c *http.Client, name string, write bool) string {
	e.t.Helper()
	form := url.Values{"_csrf": {e.csrf(c)}, "name": {name}, "valid_days": {"30"}}
	if write {
		form.Set("write", "1")
	}
	_, body, _ := e.do(c, "POST", "/profile/api-tokens", form)
	m := newKeyRE.FindStringSubmatch(body)
	if m == nil {
		e.t.Fatalf("API key not shown")
	}
	return html.UnescapeString(m[1])
}

func TestOperationsFeatures(t *testing.T) {
	e, admin, hostID := fleetEnv(t)
	ctx := context.Background()
	hostURL := "/servers/" + strconv.FormatInt(hostID, 10)

	// A second host in group "Web" for the group limit.
	if _, err := e.st.CreateEnrollmentToken(ctx, "t2", "tok2", "p", 0, time.Time{}, 0); err != nil {
		t.Fatal(err)
	}
	webInfo := protocol.HostInfo{Hostname: "web-01", MachineID: "m2", OSID: "ubuntu", OSVersionID: "24.04", OSName: "Ubuntu 24.04", Kernel: "6.8.0-45-generic",
		Arch: "amd64", PackageManager: "apt", RemoteUpdates: true}
	webID, _, err := e.st.RegisterHost(ctx, "tok2", webInfo, "", "secret2")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.st.SaveReport(ctx, webID, protocol.Report{Host: webInfo, Updates: []protocol.Update{{Name: "nginx", CurrentVersion: "1.24.0-2", AvailableVersion: "1.24.0-3", Security: true}}}, ""); err != nil {
		t.Fatal(err)
	}
	gid, err := e.st.CreateGroup(ctx, "Web", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.AddHostsToGroup(ctx, gid, []int64{webID}); err != nil {
		t.Fatal(err)
	}

	// ---- Exclusions: fleet list (setting) + host list reach the agent.
	if err := e.st.SaveSettings(ctx, map[string]string{settings.KeyUpdateExclude: "linux-*"}); err != nil {
		t.Fatal(err)
	}
	if status, _, _ := e.do(admin, "POST", hostURL+"/exclude", url.Values{"_csrf": {e.csrf(admin)}, "exclude": {"openssl, mysql-*"}}); status != http.StatusSeeOther {
		t.Fatalf("host exclude: %d", status)
	}
	if status, body, _ := e.do(admin, "POST", hostURL+"/exclude", url.Values{"_csrf": {e.csrf(admin)}, "exclude": {"../x"}}); status != http.StatusSeeOther || strings.Contains(body, "../x") {
		t.Errorf("invalid pattern accepted: %d", status)
	}
	status, body, _ := e.do(admin, "GET", hostURL+"?tab=updates", nil)
	expect(t, "excluded update", status, 200, body, "Dışlandı", "linux-*, openssl, mysql-*")
	client, _ := agent.NewClient(agent.Config{ServerURL: mustURL(e.srv.URL)})
	reg, _ := e.st.HostByID(ctx, hostID)
	info := reg.HostInfo()
	info.RemoteUpdates, info.AgentVersion = true, "0.3.0"
	// fleetEnv's agent secret is not kept; rotate it to talk as the agent.
	secret := "test-secret-1"
	if _, _, err := e.st.RegisterHost(ctx, "tok2", info, "Debian:12", auth.HashToken(secret)); err != nil {
		t.Fatal(err)
	}
	client.SetSecret(secret)
	if status, _, _ := e.do(admin, "POST", hostURL+"/jobs", url.Values{"_csrf": {e.csrf(admin)}, "type": {"upgrade_security"}}); status != http.StatusSeeOther {
		t.Fatalf("job: %d", status)
	}
	resp, err := client.Checkin(ctx, info)
	if err != nil {
		t.Fatal(err)
	}
	var secJob *protocol.Job
	for i := range resp.Jobs {
		if resp.Jobs[i].Type == protocol.JobUpgradeSecurity {
			secJob = &resp.Jobs[i]
		}
	}
	if secJob == nil || secJob.Params[protocol.ParamExclude] != "linux-*,openssl,mysql-*" {
		t.Fatalf("exclusions not sent: %+v", resp.Jobs)
	}
	_ = client.JobResult(ctx, secJob.ID, protocol.JobResult{Succeeded: true, StartedAt: timeutil.Now(), FinishedAt: timeutil.Now()})

	// ---- EPSS and SLA.
	if err := e.st.ReplaceEPSS(ctx, []store.EPSSEntry{{CVEID: "CVE-2026-0001", Score: 0.97512, Percentile: 0.99931}}); err != nil {
		t.Fatal(err)
	}
	status, body, _ = e.do(admin, "GET", "/vulnerabilities?sort=epss", nil)
	expect(t, "epss list", status, 200, body, "%97,5", "İstismar olasılığına göre")
	status, body, _ = e.do(admin, "GET", "/vulnerabilities/CVE-2026-0001", nil)
	expect(t, "epss detail", status, 200, body, "EPSS (istismar olasılığı)", "%97,5", "%99,9")
	if _, err := e.st.DB().ExecContext(ctx, `UPDATE findings SET first_detected_at = ?`, time.Now().Add(-40*24*time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	status, body, _ = e.do(admin, "GET", "/dashboard", nil)
	expect(t, "overdue card", status, 200, body, "Süresi geçen bulgular")
	status, body, _ = e.do(admin, "GET", "/vulnerabilities?overdue=1", nil)
	expect(t, "overdue list", status, 200, body, "CVE-2026-0001", "Süresi geçti")
	e.notifier.SLAOverdue(ctx)
	e.notifier.SLAOverdue(ctx)
	notes, _, _ := e.st.ListNotifications(ctx, false, store.Page{Number: 1, Size: 100})
	n := 0
	for _, x := range notes {
		if x.Kind == "sla_overdue" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("sla_overdue notifications: %d", n)
	}

	// ---- Group-limited operator.
	pw := "kisitli-parola-1"
	e.do(admin, "POST", "/users", url.Values{"_csrf": {e.csrf(admin)}, "name": {"Web Ekibi"}, "email": {"web@example.test"}, "role": {"operator"},
		"password": {pw}, "password_confirm": {pw}})
	u, err := e.st.UserByEmail(ctx, "web@example.test")
	if err != nil {
		t.Fatal(err)
	}
	if status, _, _ := e.do(admin, "POST", "/users/"+strconv.FormatInt(u.ID, 10), url.Values{"_csrf": {e.csrf(admin)}, "name": {"Web Ekibi"}, "role": {"operator"},
		"scope": {"groups"}, "group_ids": {strconv.FormatInt(gid, 10)}}); status != http.StatusSeeOther {
		t.Fatalf("user scope: %d", status)
	}
	op := newClient()
	e.do(op, "POST", "/login", url.Values{"email": {"web@example.test"}, "password": {pw}})
	status, body, _ = e.do(op, "GET", "/servers", nil)
	expect(t, "limited servers", status, 200, body, "web-01")
	if strings.Contains(body, "db-01") {
		t.Error("limited user sees a host outside its groups")
	}
	if status, _, _ := e.do(op, "GET", hostURL, nil); status != http.StatusNotFound {
		t.Errorf("limited user opened another host: %d", status)
	}
	status, body, _ = e.do(op, "GET", "/vulnerabilities", nil)
	if status != 200 || strings.Contains(body, "CVE-2026-0001") {
		t.Errorf("limited user sees CVEs of other hosts: %d", status)
	}
	for _, p := range []string{"/schedules", "/agents"} {
		if status, _, _ := e.do(op, "GET", p, nil); status != http.StatusForbidden {
			t.Errorf("limited user %s: %d", p, status)
		}
	}
	status, body, _ = e.do(op, "GET", "/dashboard", nil)
	if status != 200 || strings.Contains(body, `href="/schedules"`) {
		t.Errorf("limited navigation: %d", status)
	}
	if status, _, _ := e.do(op, "POST", hostURL+"/jobs", url.Values{"_csrf": {e.csrf(op)}, "type": {"refresh"}}); status != http.StatusNotFound {
		t.Errorf("limited user queued a job on another host: %d", status)
	}
	status, body, _ = e.do(op, "GET", "/notifications", nil)
	if status != 200 || strings.Contains(body, "db-01") {
		t.Errorf("limited user sees notifications of other hosts: %d", status)
	}

	// ---- REST API and metrics.
	readKey := e.createAPIKey(admin, "grafana", false)
	writeKey := e.createAPIKey(admin, "ansible", true)
	opKey := e.createAPIKey(op, "web-team", true)
	if status, _ := e.apiDo("", "GET", "/api/v1/hosts", ""); status != http.StatusUnauthorized {
		t.Errorf("no key: %d", status)
	}
	if status, _ := e.apiDo("npat_wrong", "GET", "/api/v1/hosts", ""); status != http.StatusUnauthorized {
		t.Errorf("bad key: %d", status)
	}
	status, body = e.apiDo(readKey, "GET", "/api/v1/hosts", "")
	var hosts struct {
		Hosts []struct {
			ID       int64  `json:"id"`
			Hostname string `json:"hostname"`
		} `json:"hosts"`
		Pagination struct{ Total int } `json:"pagination"`
	}
	if status != 200 || json.Unmarshal([]byte(body), &hosts) != nil || hosts.Pagination.Total != 2 {
		t.Fatalf("hosts: %d %s", status, body)
	}
	status, body = e.apiDo(readKey, "GET", "/api/v1/hosts/"+strconv.FormatInt(hostID, 10)+"/findings", "")
	expect(t, "api findings", status, 200, body, `"cve": "CVE-2026-0001"`, `"epss": 0.97512`, `"overdue": true`)
	status, body = e.apiDo(readKey, "GET", "/api/v1/vulnerabilities?sort=epss", "")
	expect(t, "api vulns", status, 200, body, `"known_exploited": true`)
	if status, _ := e.apiDo(readKey, "POST", "/api/v1/hosts/"+strconv.FormatInt(hostID, 10)+"/jobs", `{"type":"refresh"}`); status != http.StatusForbidden {
		t.Errorf("read-only key queued a job: %d", status)
	}
	status, body = e.apiDo(writeKey, "POST", "/api/v1/hosts/"+strconv.FormatInt(hostID, 10)+"/jobs", `{"type":"upgrade_packages","packages":["openssl"]}`)
	expect(t, "api job", status, http.StatusCreated, body, `"type": "upgrade_packages"`)
	audit, _, _ := e.st.ListAudit(ctx, store.Page{Number: 1, Size: 5})
	if len(audit) == 0 || !strings.Contains(audit[0].Details, "api_token=ansible") {
		t.Errorf("api audit: %+v", audit)
	}
	// The limited operator's key sees only its group.
	status, body = e.apiDo(opKey, "GET", "/api/v1/hosts", "")
	if status != 200 || !strings.Contains(body, "web-01") || strings.Contains(body, "db-01") {
		t.Errorf("limited key hosts: %d %s", status, body)
	}
	if status, _ := e.apiDo(opKey, "GET", "/api/v1/hosts/"+strconv.FormatInt(hostID, 10), ""); status != http.StatusNotFound {
		t.Errorf("limited key opened another host: %d", status)
	}
	if status, _ := e.apiDo(opKey, "GET", "/api/v1/vulnerabilities/CVE-2026-0001", ""); status != http.StatusNotFound {
		t.Errorf("limited key read a CVE of another host: %d", status)
	}
	// Cookies do not authenticate the API.
	if status, _, _ := e.do(admin, "GET", "/api/v1/hosts", nil); status != http.StatusUnauthorized {
		t.Errorf("cookie on API: %d", status)
	}
	status, body = e.apiDo(readKey, "GET", "/metrics", "")
	expect(t, "metrics", status, 200, body, `netio_patchman_hosts{state="online"}`, `netio_patchman_vulnerabilities{severity="critical"} 1`,
		`netio_patchman_findings_overdue 1`, `netio_patchman_host_vulnerabilities{host="db-01",os="debian",severity="critical"} 1`)
	status, body = e.apiDo(opKey, "GET", "/metrics", "")
	if status != 200 || strings.Contains(body, `host="db-01"`) {
		t.Errorf("limited metrics: %d", status)
	}

	// ---- Schedule reboot option.
	scID, err := e.st.CreateSchedule(ctx, store.Schedule{Name: "Gece", Enabled: true, JobType: protocol.JobUpgradeSecurity, Days: 127, Minute: 0,
		WindowMinutes: 120, Target: store.TargetHosts, HostIDs: []int64{hostID}, Reboot: true}, 0)
	if err != nil {
		t.Fatal(err)
	}
	jobID, err := e.st.CreateScheduledJob(ctx, hostID, protocol.JobUpgradeSecurity, scID, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	resp, _ = client.Checkin(ctx, info)
	for _, j := range resp.Jobs {
		_ = client.JobResult(ctx, j.ID, protocol.JobResult{Succeeded: true, StartedAt: timeutil.Now(), FinishedAt: timeutil.Now()})
	}
	report := protocol.Report{Host: info, CollectedAt: timeutil.Now(), RebootRequired: true,
		KernelPatch: &protocol.KernelPatch{Provider: protocol.KernelCare, EffectiveKernel: "6.1.0-27-amd64"}}
	for range 2 {
		if err := client.Report(ctx, report); err != nil {
			t.Fatal(err)
		}
	}
	jobs, _, _ := e.st.ListJobs(ctx, store.JobFilter{HostID: hostID, Status: "queued"}, store.Page{Number: 1, Size: 50})
	reboots := 0
	for _, j := range jobs {
		if j.Type == protocol.JobReboot && j.ScheduleID == scID {
			reboots++
		}
	}
	if reboots != 1 {
		t.Errorf("scheduled reboots after job %d: %d (%+v)", jobID, reboots, jobs)
	}
	status, body, _ = e.do(admin, "GET", hostURL+"?tab=info", nil)
	expect(t, "kernelcare", status, 200, body, "KernelCare", "6.1.0-27-amd64")
}
