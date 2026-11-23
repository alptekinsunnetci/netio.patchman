package web_test

import (
	"context"
	"html"
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
	"netio.patchman/internal/store"
	"netio.patchman/internal/timeutil"
)

// fleetEnv sets up an admin and one scanned, vulnerable VMware host.
func fleetEnv(t *testing.T) (*env, *http.Client, int64) {
	t.Helper()
	e := newEnv(t)
	ctx := context.Background()
	admin := e.client
	pw := "çok-güçlü-parola-1"
	if status, _, _ := e.do(admin, "POST", "/setup", url.Values{"name": {"Alptekin Sünnetci"}, "email": {"ayse@example.test"}, "password": {pw}, "password_confirm": {pw}}); status != http.StatusSeeOther {
		t.Fatalf("setup: %d", status)
	}
	token := e.csrf(admin)
	_, body, _ := e.do(admin, "POST", "/agents/tokens", url.Values{"_csrf": {token}, "name": {"t"}, "valid_days": {"7"}, "max_uses": {"0"}})
	m := regexp.MustCompile(`value="([^"]+)" readonly id="new-token"`).FindStringSubmatch(body)
	if m == nil {
		t.Fatal("token not shown")
	}
	client, err := agent.NewClient(agent.Config{ServerURL: mustURL(e.srv.URL)})
	if err != nil {
		t.Fatal(err)
	}
	info := protocol.HostInfo{Hostname: "db-01", MachineID: "m1", OSID: "debian", OSVersionID: "12", OSVersion: "12 (bookworm)",
		OSName: "Debian GNU/Linux 12 (bookworm)", Kernel: "6.1.0-25-amd64", Arch: "amd64", PackageManager: "apt", AgentVersion: "0.3.0",
		RemoteUpdates: true, Virtualization: "vmware"}
	reg, err := client.Register(ctx, html.UnescapeString(m[1]), info)
	if err != nil {
		t.Fatal(err)
	}
	client.SetSecret(reg.AgentSecret)
	if err := client.Report(ctx, protocol.Report{Host: info, CollectedAt: timeutil.Now(), RebootRequired: true,
		Packages: []protocol.Package{{Name: "openssl", Version: "3.0.11-1~deb12u2", Arch: "amd64", SourceName: "openssl", SourceVersion: "3.0.11-1~deb12u2"}},
		Updates:  []protocol.Update{{Name: "openssl", CurrentVersion: "3.0.11-1~deb12u2", AvailableVersion: "3.0.17-1~deb12u1", Security: true}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.scan.RefreshKEV(ctx); err != nil {
		t.Fatal(err)
	}
	if err := e.scan.ScanHost(ctx, reg.HostID); err != nil {
		t.Fatal(err)
	}
	return e, admin, reg.HostID
}

func TestGroupsPlatformAndSchedules(t *testing.T) {
	e, admin, hostID := fleetEnv(t)
	ctx := context.Background()
	id := strconv.FormatInt(hostID, 10)

	token := e.csrf(admin)
	status, _, hdr := e.do(admin, "POST", "/groups", url.Values{"_csrf": {token}, "name": {"Üretim"}, "description": {"Canlı sistemler"}})
	if status != http.StatusSeeOther || !strings.HasPrefix(hdr.Get("Location"), "/groups/") {
		t.Fatalf("create group: %d %s", status, hdr.Get("Location"))
	}
	groupPath := hdr.Get("Location")
	gid := strings.TrimPrefix(groupPath, "/groups/")
	status, body, _ := e.do(admin, "POST", "/groups", url.Values{"_csrf": {token}, "name": {"üretim"}})
	expect(t, "duplicate group", status, 409, body, "adlı bir grup zaten var")

	// Bulk add from the inventory; the server shows its group and platform.
	if status, _, _ = e.do(admin, "POST", "/servers/bulk-groups", url.Values{"_csrf": {token}, "group_id": {gid}, "op": {"add"}, "host_ids": {id}}); status != http.StatusSeeOther {
		t.Fatalf("bulk add: %d", status)
	}
	status, body, _ = e.do(admin, "GET", "/servers?group="+gid, nil)
	expect(t, "group filter", status, 200, body, "db-01", `class="tag"`, "Üretim", "VMware sanal makine")
	status, body, _ = e.do(admin, "GET", "/servers?platform=physical", nil)
	expect(t, "physical filter", status, 200, body)
	if strings.Contains(body, ">db-01<") {
		t.Error("VMware host listed as physical")
	}
	status, body, _ = e.do(admin, "GET", "/servers/"+id+"?tab=info", nil)
	expect(t, "server info", status, 200, body, "Platform", "VMware sanal makine", "(vmware)", "Bekleme başlangıcı:", `name="group_ids" value="`+gid+`" checked`)
	status, body, _ = e.do(admin, "GET", groupPath, nil)
	expect(t, "group page", status, 200, body, "Canlı sistemler", "1 sunucu", "db-01")

	// A schedule targeting the group.
	status, _, hdr = e.do(admin, "POST", "/schedules", url.Values{"_csrf": {token}, "name": {"Üretim gecesi"}, "enabled": {"1"}, "job_type": {"upgrade_security"},
		"days": {"0"}, "time": {"03:00"}, "window_minutes": {"60"}, "target": {"group"}, "group_id": {gid}})
	if status != http.StatusSeeOther {
		t.Fatalf("schedule create: %d", status)
	}
	schedID, _ := strconv.ParseInt(strings.TrimPrefix(hdr.Get("Location"), "/schedules/"), 10, 64)
	sc, err := e.st.ScheduleByID(ctx, schedID)
	if err != nil || sc.Target != store.TargetGroup || sc.GroupName != "Üretim" {
		t.Fatalf("schedule: %+v %v", sc, err)
	}
	if targets, _ := e.st.ScheduleTargets(ctx, sc); len(targets) != 1 || targets[0].Hostname != "db-01" {
		t.Errorf("group targets: %v", targets)
	}
	status, body, _ = e.do(admin, "GET", "/schedules", nil)
	expect(t, "schedules list", status, 200, body, "“Üretim” grubu")
	status, body, _ = e.do(admin, "POST", "/schedules", url.Values{"_csrf": {token}, "name": {"x"}, "job_type": {"upgrade_security"},
		"days": {"0"}, "time": {"03:00"}, "window_minutes": {"60"}, "target": {"group"}})
	expect(t, "schedule without group", status, 400, body, "Hedef grup seçin.")

	// Removing the host and deleting the group; the schedule never falls back to every host.
	if status, _, _ = e.do(admin, "POST", "/servers/"+id+"/groups", url.Values{"_csrf": {token}}); status != http.StatusSeeOther {
		t.Fatalf("clear host groups: %d", status)
	}
	if targets, _ := e.st.ScheduleTargets(ctx, sc); len(targets) != 0 {
		t.Errorf("host still targeted after leaving the group")
	}
	if status, _, _ = e.do(admin, "POST", groupPath+"/delete", url.Values{"_csrf": {token}}); status != http.StatusSeeOther {
		t.Fatalf("delete group: %d", status)
	}
	sc, _ = e.st.ScheduleByID(ctx, schedID)
	if sc.Enabled || sc.Target != store.TargetHosts || sc.GroupID != 0 {
		t.Errorf("schedule after group delete: %+v", sc)
	}
	if targets, _ := e.st.ScheduleTargets(ctx, sc); len(targets) != 0 {
		t.Errorf("deleted group schedule targets %d hosts", len(targets))
	}

	// Viewers see groups but cannot create them.
	viewer := newClient()
	_, _, _ = e.do(admin, "POST", "/users", url.Values{"_csrf": {token}, "name": {"İzleyici"}, "email": {"izleyici@example.test"}, "role": {"viewer"},
		"password": {"izleyici-parola-1"}, "password_confirm": {"izleyici-parola-1"}})
	e.do(viewer, "POST", "/login", url.Values{"email": {"izleyici@example.test"}, "password": {"izleyici-parola-1"}})
	status, _, _ = e.do(viewer, "GET", "/groups", nil)
	if status != http.StatusOK {
		t.Errorf("viewer groups page: %d", status)
	}
	status, _, _ = e.do(viewer, "POST", "/groups", url.Values{"_csrf": {e.csrf(viewer)}, "name": {"x"}})
	if status != http.StatusForbidden {
		t.Errorf("viewer created a group: %d", status)
	}
}

func TestAcceptedRiskExpires(t *testing.T) {
	e, admin, hostID := fleetEnv(t)
	ctx := context.Background()
	token := e.csrf(admin)

	status, _, _ := e.do(admin, "POST", "/vulnerabilities/CVE-2026-0001/status", url.Values{"_csrf": {token}, "status": {"accepted_risk"}, "note": {"iç ağ"}, "risk_days": {"9999"}})
	if status != http.StatusSeeOther {
		t.Fatalf("status: %d", status)
	}
	rows, _, _ := e.st.ListFindings(ctx, store.FindingFilter{HostID: hostID, Status: "all"}, store.Page{Number: 1})
	if rows[0].Status != store.StatusOpen {
		t.Fatalf("term above the maximum accepted: %s", rows[0].Status)
	}
	status, _, _ = e.do(admin, "POST", "/vulnerabilities/CVE-2026-0001/status", url.Values{"_csrf": {token}, "status": {"accepted_risk"}, "note": {"iç ağ"}, "risk_days": {"30"}})
	if status != http.StatusSeeOther {
		t.Fatalf("accept risk: %d", status)
	}
	rows, _, _ = e.st.ListFindings(ctx, store.FindingFilter{HostID: hostID, Status: "all"}, store.Page{Number: 1})
	r := rows[0]
	if r.Status != store.StatusAcceptedRisk || r.StatusChangedBy != "Alptekin Sünnetci" {
		t.Fatalf("finding: %+v", r)
	}
	if d := time.Until(r.StatusExpiresAt); d < 29*24*time.Hour || d > 31*24*time.Hour {
		t.Errorf("expiry in %v, want about 30 days", d)
	}
	_, body, _ := e.do(admin, "GET", "/vulnerabilities/CVE-2026-0001?status=all", nil)
	if !strings.Contains(body, "tarihine kadar") || !strings.Contains(body, "— Alptekin Sünnetci") {
		t.Error("expiry or accepting user not shown")
	}

	// Not yet due: nothing changes.
	if exp, _ := e.st.ExpireAcceptedRisks(ctx, timeutil.Now()); len(exp) != 0 {
		t.Fatalf("expired early: %v", exp)
	}
	exp, err := e.st.ExpireAcceptedRisks(ctx, r.StatusExpiresAt.Add(time.Second))
	if err != nil || len(exp) != 1 || exp[0].CVEID != "CVE-2026-0001" || exp[0].Hostname != "db-01" {
		t.Fatalf("expire: %v %v", exp, err)
	}
	e.notifier.RisksExpired(ctx, exp)
	rows, _, _ = e.st.ListFindings(ctx, store.FindingFilter{HostID: hostID, Status: "all"}, store.Page{Number: 1})
	if rows[0].Status != store.StatusOpen || !rows[0].StatusExpiresAt.IsZero() || rows[0].StatusNote != "" {
		t.Errorf("finding after expiry: %+v", rows[0])
	}
	_, body, _ = e.do(admin, "GET", "/notifications", nil)
	if !strings.Contains(body, "CVE-2026-0001 için risk kabulünün süresi doldu; 1 sunucuda bulgu yeniden açık: db-01") {
		t.Error("expiry notification missing")
	}
	last := e.sender.msgs[len(e.sender.msgs)-1]
	if last.Subject != "netio.patchman: 1 risk kabulünün süresi doldu" && !strings.Contains(last.Subject, "risk kabulünün süresi doldu") {
		t.Errorf("expiry email: %q", last.Subject)
	}
}

func TestTrendsAndReport(t *testing.T) {
	e, admin, _ := fleetEnv(t)
	ctx := context.Background()

	_, body, _ := e.do(admin, "GET", "/dashboard", nil)
	expect(t, "dashboard before data", 200, 200, body, "Eğilim verisi birikiyor", "Yeniden Başlatma Bekleyen", "/servers?status=reboot")
	now := timeutil.Now()
	if err := e.st.TakeSnapshot(ctx, now.AddDate(0, 0, -3)); err != nil {
		t.Fatal(err)
	}
	if err := e.st.TakeSnapshot(ctx, now); err != nil {
		t.Fatal(err)
	}
	if err := e.st.TakeSnapshot(ctx, now); err != nil { // same day replaces
		t.Fatal(err)
	}
	snaps, _ := e.st.Snapshots(ctx, now.AddDate(0, 0, -30), now)
	if len(snaps) != 2 || snaps[1].Sev.Critical != 1 || snaps[1].KEV != 1 || snaps[1].RebootRequired != 1 {
		t.Fatalf("snapshots: %+v", snaps)
	}
	_, body, _ = e.do(admin, "GET", "/dashboard", nil)
	expect(t, "dashboard trend", 200, 200, body, `class="trend__plot"`, `data-values="`, ",,1,,,1\"", `class="trend__line" d="M`, "Kritik ve yüksek açık (CVE)", "Günlük değerleri tablo olarak göster")

	// The compliance report moved into Compliance & audit.
	status, _, hdr := e.do(admin, "GET", "/reports", nil)
	if status != http.StatusMovedPermanently || hdr.Get("Location") != "/compliance/reports" {
		t.Errorf("old report address: %d %s", status, hdr.Get("Location"))
	}
}

func TestTwoFactorLogin(t *testing.T) {
	e, admin, _ := fleetEnv(t)
	ctx := context.Background()
	pw := "çok-güçlü-parola-1"
	token := e.csrf(admin)

	_, body, _ := e.do(admin, "POST", "/profile/mfa/setup", url.Values{"_csrf": {token}})
	m := regexp.MustCompile(`name="secret" value="([A-Z2-7]{32})"`).FindStringSubmatch(body)
	if m == nil || !strings.Contains(body, "otpauth://totp/netio.patchman:ayse@example.test?") {
		t.Fatal("setup secret not shown")
	}
	secret := m[1]
	step := auth.TOTPStep(timeutil.Now())
	wrong, _ := auth.TOTPCode(secret, step+5)
	status, body, _ := e.do(admin, "POST", "/profile/mfa/enable", url.Values{"_csrf": {token}, "secret": {secret}, "code": {wrong}, "current_password": {pw}})
	expect(t, "wrong setup code", status, 400, body, "Doğrulama kodu geçersiz")
	code, _ := auth.TOTPCode(secret, step)
	status, body, _ = e.do(admin, "POST", "/profile/mfa/enable", url.Values{"_csrf": {token}, "secret": {secret}, "code": {code}, "current_password": {pw}})
	expect(t, "enable", status, 200, body, "İki adımlı doğrulama açıldı", "yalnızca şimdi gösterilir", "10 yedek kod kaldı")
	codes := regexp.MustCompile(`<span>([a-z2-9]{4}-[a-z2-9]{4}-[a-z2-9]{4})</span>`).FindAllStringSubmatch(body, -1)
	if len(codes) != auth.RecoveryCodeCount {
		t.Fatalf("recovery codes shown: %d", len(codes))
	}

	// Password alone no longer signs in.
	c := newClient()
	status, _, hdr := e.do(c, "POST", "/login", url.Values{"email": {"ayse@example.test"}, "password": {pw}, "next": {"/reports"}})
	if status != http.StatusSeeOther || hdr.Get("Location") != "/login/mfa" {
		t.Fatalf("login step 1: %d %s", status, hdr.Get("Location"))
	}
	if status, _, hdr = e.do(c, "GET", "/dashboard", nil); status != http.StatusFound || !strings.HasPrefix(hdr.Get("Location"), "/login") {
		t.Errorf("signed in without second factor: %d", status)
	}
	status, body, _ = e.do(c, "POST", "/login/mfa", url.Values{"code": {wrong}})
	expect(t, "wrong login code", status, 401, body, "Kod geçersiz")
	// The enrollment step was used; its code is rejected (replay).
	status, _, _ = e.do(c, "POST", "/login/mfa", url.Values{"code": {code}})
	if status != http.StatusUnauthorized {
		t.Errorf("replayed code accepted: %d", status)
	}
	next, _ := auth.TOTPCode(secret, step+1)
	status, _, hdr = e.do(c, "POST", "/login/mfa", url.Values{"code": {next}})
	if status != http.StatusSeeOther || hdr.Get("Location") != "/reports" {
		t.Fatalf("login step 2: %d %s", status, hdr.Get("Location"))
	}
	if status, _, _ = e.do(c, "GET", "/dashboard", nil); status != http.StatusOK {
		t.Errorf("dashboard after MFA: %d", status)
	}

	// A recovery code works once.
	rc := codes[0][1]
	for i, want := range []int{http.StatusSeeOther, http.StatusUnauthorized} {
		c2 := newClient()
		e.do(c2, "POST", "/login", url.Values{"email": {"ayse@example.test"}, "password": {pw}})
		status, _, _ = e.do(c2, "POST", "/login/mfa", url.Values{"code": {strings.ToUpper(rc)}})
		if status != want {
			t.Errorf("recovery use %d: %d, want %d", i+1, status, want)
		}
	}
	if n, _ := e.st.RecoveryCodesLeft(ctx, 1); n != auth.RecoveryCodeCount-1 {
		t.Errorf("recovery codes left: %d", n)
	}

	// Too many wrong codes end the challenge.
	c3 := newClient()
	e.do(c3, "POST", "/login", url.Values{"email": {"ayse@example.test"}, "password": {pw}})
	for i := 0; i < 4; i++ {
		e.do(c3, "POST", "/login/mfa", url.Values{"code": {"000000"}})
	}
	if status, _, hdr = e.do(c3, "POST", "/login/mfa", url.Values{"code": {"000000"}}); status != http.StatusSeeOther || hdr.Get("Location") != "/login" {
		t.Errorf("challenge not ended: %d %s", status, hdr.Get("Location"))
	}

	// Required for everyone: a user without an authenticator only reaches the profile.
	token = e.csrf(c)
	e.do(c, "POST", "/users", url.Values{"_csrf": {token}, "name": {"Operatör"}, "email": {"op@example.test"}, "role": {"operator"},
		"password": {"operator-parola-1"}, "password_confirm": {"operator-parola-1"}})
	status, _, _ = e.do(c, "POST", "/settings", url.Values{"_csrf": {token}, "email_enabled": {"1"}, "email_min_severity": {"high"},
		"email_digest_threshold": {"5"}, "agent_offline_minutes": {"10"}, "agent_checkin_seconds": {"60"}, "agent_report_minutes": {"60"},
		"retention_days": {"90"}, "scan_enabled": {"1"}, "risk_max_days": {"365"}, "auth_require_mfa": {"1"}})
	if status != http.StatusSeeOther {
		t.Fatalf("settings: %d", status)
	}
	op := newClient()
	e.do(op, "POST", "/login", url.Values{"email": {"op@example.test"}, "password": {"operator-parola-1"}})
	if status, _, hdr = e.do(op, "GET", "/servers", nil); status != http.StatusSeeOther || hdr.Get("Location") != "/profile#mfa" {
		t.Errorf("operator without MFA reached servers: %d %s", status, hdr.Get("Location"))
	}
	status, body, _ = e.do(op, "GET", "/profile", nil)
	expect(t, "profile when required", status, 200, body, "iki adımlı doğrulama zorunludur", "Doğrulayıcı uygulaması tanımla")

	// The admin can remove a lost authenticator; disabling is refused while required.
	token = e.csrf(c)
	now, _ := auth.TOTPCode(secret, step+2)
	status, _, hdr = e.do(c, "POST", "/profile/mfa/disable", url.Values{"_csrf": {token}, "current_password": {pw}, "code": {now}})
	if status != http.StatusSeeOther {
		t.Fatalf("disable while required: %d", status)
	}
	if u, _ := e.st.UserByID(ctx, 1); !u.MFAEnabled() {
		t.Error("MFA disabled although required")
	}
	if status, _, _ = e.do(c, "POST", "/users/1/reset-mfa", url.Values{"_csrf": {token}}); status != http.StatusSeeOther {
		t.Fatalf("reset mfa: %d", status)
	}
	if u, _ := e.st.UserByID(ctx, 1); u.MFAEnabled() {
		t.Error("reset did not remove MFA")
	}
}
