package web_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"netio.patchman/internal/compliance"
	"netio.patchman/internal/i18n"
	"netio.patchman/internal/protocol"
	"netio.patchman/internal/store"
	"netio.patchman/internal/timeutil"
	"netio.patchman/internal/web"
)

var reportURLRE = regexp.MustCompile(`^/compliance/reports/(\d+)\?v=(\d+)$`)

// TestComplianceAudit covers the Compliance & Audit area end to end: one
// engine, the shared evidence repository, separate assessments per
// framework, versions, reviews, exports and access rules.
func TestComplianceAudit(t *testing.T) {
	e, admin, hostID := fleetEnv(t)
	ctx := context.Background()

	// A Windows server and a Windows 11 client next to the Debian host.
	_, winID := e.agentFor(protocol.HostInfo{Hostname: "WIN-SRV-01", MachineID: "win-1", OSID: "windows", OSVersionID: "10.0.20348",
		OSName: "Windows Server 2022 Standard", PackageManager: protocol.PMWindowsUpdate, AgentVersion: "1.0.5"})
	_, _ = e.agentFor(protocol.HostInfo{Hostname: "PC-11", MachineID: "win-2", OSID: "windows", OSVersionID: "10.0.22631",
		OSName: "Windows 11 Pro", PackageManager: protocol.PMWindowsUpdate, AgentVersion: "1.0.5"})

	// A successful Windows security update: one fact for several frameworks.
	jobID, err := e.st.CreateJob(ctx, winID, protocol.JobUpgradePackages, []string{"KB5044281"}, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.DispatchJobs(ctx, winID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.CompleteJob(ctx, winID, jobID, protocol.JobResult{Succeeded: true, Output: "ok", StartedAt: timeutil.Now(), FinishedAt: timeutil.Now()}); err != nil {
		t.Fatal(err)
	}
	col := &compliance.Collector{Store: e.st, EOL: e.eol.Data, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), L: i18n.MustLoad().Localizer(i18n.DefaultLocale)}
	if err := col.Snapshot(ctx, timeutil.Now()); err != nil {
		t.Fatal(err)
	}
	col.Collect(ctx)

	// Menu: one Compliance & Audit area, no separate framework menus.
	status, body, _ := e.do(admin, "GET", "/compliance", nil)
	expect(t, "overview", status, 200, body, "Uyum ve Denetim", `href="/compliance/reports"`, `href="/compliance/evidence"`, `href="/compliance/history"`,
		`href="/compliance/policies"`, "sertifika veya uygunluk beyanı değildir")
	if strings.Contains(body, `href="/standards"`) || strings.Contains(body, `href="/reports"`) {
		t.Error("old menu entries still in the sidebar")
	}

	// One report for all four frameworks.
	form := url.Values{"_csrf": {e.csrf(admin)}, "title": {"Yıllık denetim 2026"}, "preset": {"30d"},
		"profiles": {"isms@1", "baseline@1", "itsm@1", "general@1"}}
	status, _, hdr := e.do(admin, "POST", "/compliance/reports", form)
	m := reportURLRE.FindStringSubmatch(hdr.Get("Location"))
	if status != http.StatusSeeOther || m == nil {
		t.Fatalf("create report: %d %s", status, hdr.Get("Location"))
	}
	repID, _ := strconv.ParseInt(m[1], 10, 64)
	repURL := "/compliance/reports/" + m[1]
	status, body, _ = e.do(admin, "GET", repURL, nil)
	expect(t, "report", status, 200, body, "Yıllık denetim 2026", "Yönetici özeti", "Bilgi Güvenliği Yönetimi Denetimleri", "BT Temel Koruma Denetimleri",
		"BT Hizmet Yönetimi Değerlendirmeleri", "Genel Güvenlik ve Yama Uyumu", "ISMS-02", "BASE-04", "ITSM-01", "GEN-04", "Windows Server", "Windows 11",
		"db-01", "Tanımlı sunucu standardı yok.", "Manuel kanıt gerekli", "Eksik kanıtlar ve iyileştirme önerileri", "sertifika veya uygunluk beyanı değildir")
	for _, claim := range []string{"sertifikalıdır", "uyumludur", "certified"} {
		if strings.Contains(body, claim) {
			t.Errorf("report claims conformity: %q", claim)
		}
	}
	rep, err := e.st.ComplianceReportByID(ctx, repID)
	if err != nil {
		t.Fatal(err)
	}
	v1, err := e.st.ReportVersionByNumber(ctx, repID, 1)
	if err != nil {
		t.Fatal(err)
	}
	assessments, _ := e.st.ControlAssessments(ctx, v1.ID)
	total := 0
	for _, p := range compliance.Profiles() {
		total += len(p.Controls)
	}
	if len(assessments) != total {
		t.Errorf("assessments: %d, want one per control (%d)", len(assessments), total)
	}
	// The Windows update is one evidence item mapped to controls of every framework.
	uses, _ := e.st.VersionEvidenceControls(ctx, v1.ID)
	items, _ := e.st.EvidenceItems(ctx, store.EvidenceFilter{Kinds: []string{store.EvidenceUpdateJob}})
	if len(items) != 1 || items[0].Platform != store.PlatformWindowsServer {
		t.Fatalf("update evidence: %+v", items)
	}
	got := strings.Join(uses[items[0].ID], ",")
	for _, ctl := range []string{"isms:ISMS-02", "baseline:BASE-01", "itsm:ITSM-01", "general:GEN-04"} {
		if !strings.Contains(got, ctl) {
			t.Errorf("update evidence not mapped to %s: %s", ctl, got)
		}
	}
	content, err := compliance.Decode(v1.Content)
	if err != nil {
		t.Fatal(err)
	}
	outcome := func(c compliance.Report, profile, control string) compliance.ControlAssessment {
		for _, pa := range c.Controls {
			if pa.Profile == profile {
				for _, ca := range pa.Controls {
					if ca.ID == control {
						return ca
					}
				}
			}
		}
		t.Fatalf("no %s:%s", profile, control)
		return compliance.ControlAssessment{}
	}
	if o := outcome(content, "general", "GEN-04").Outcome; o != compliance.OutcomeSufficient {
		t.Errorf("GEN-04 (update success): %s", o)
	}
	// The KEV entry of the fake catalog is due in 30 days: open, not overdue.
	if o := outcome(content, "general", "GEN-02").Outcome; o != compliance.OutcomeSufficient {
		t.Errorf("GEN-02 (KEV not yet due): %s", o)
	}
	if k := content.Vulnerabilities.KEVOpen; len(k) != 1 || k[0].CVE != "CVE-2026-0001" || k[0].Hosts != 1 {
		t.Errorf("open KEV: %+v", k)
	}
	if o := outcome(content, "isms", "ISMS-12").Outcome; o != compliance.OutcomeManualRequired {
		t.Errorf("ISMS-12 without a policy document: %s", o)
	}
	if content.Summary.ByPlatform[store.PlatformLinux] != 1 || content.Summary.ByPlatform[store.PlatformWindows11] != 1 {
		t.Errorf("platforms: %v", content.Summary.ByPlatform)
	}

	// A Linux-only report: the Windows controls do not apply.
	form = url.Values{"_csrf": {e.csrf(admin)}, "title": {"Linux"}, "preset": {"30d"}, "profiles": {"baseline@1"}, "platforms": {"linux"}}
	_, _, hdr = e.do(admin, "POST", "/compliance/reports", form)
	lm := reportURLRE.FindStringSubmatch(hdr.Get("Location"))
	if lm == nil {
		t.Fatalf("linux report: %s", hdr.Get("Location"))
	}
	lid, _ := strconv.ParseInt(lm[1], 10, 64)
	lv, _ := e.st.ReportVersionByNumber(ctx, lid, 1)
	lc, _ := compliance.Decode(lv.Content)
	if o := outcome(lc, "baseline", "BASE-04").Outcome; o != compliance.OutcomeNotApplicable {
		t.Errorf("BASE-04 in a Linux report: %s", o)
	}
	if o := outcome(lc, "baseline", "BASE-03").Outcome; o == compliance.OutcomeNotApplicable {
		t.Errorf("BASE-03 in a Linux report: %s", o)
	}

	// Manual review, kept when a new version does not change the outcome.
	review := url.Values{"_csrf": {e.csrf(admin)}, "profile": {"general"}, "control": {"GEN-04"}, "status": {"accepted"}, "note": {"Örnekleme ile doğrulandı"}}
	if status, _, _ := e.do(admin, "POST", repURL+"/versions/1/review", review); status != http.StatusSeeOther {
		t.Fatalf("review: %d", status)
	}
	// Manual evidence for the policy control.
	ev := url.Values{"_csrf": {e.csrf(admin)}, "title": {"Bilgi güvenliği politikası v4"}, "reference": {"DMS-2026-114"}, "date": {""},
		"controls": {"isms:ISMS-12", "baseline:BASE-12"}}
	if status, _, _ := e.do(admin, "POST", "/compliance/evidence", ev); status != http.StatusSeeOther {
		t.Fatalf("manual evidence: %d", status)
	}
	status, _, hdr = e.do(admin, "POST", repURL+"/regenerate", url.Values{"_csrf": {e.csrf(admin)}})
	if status != http.StatusSeeOther || !strings.HasSuffix(hdr.Get("Location"), "?v=2") {
		t.Fatalf("regenerate: %d %s", status, hdr.Get("Location"))
	}
	v2, _ := e.st.ReportVersionByNumber(ctx, repID, 2)
	c2, _ := compliance.Decode(v2.Content)
	if o := outcome(c2, "isms", "ISMS-12").Outcome; o != compliance.OutcomeManualEvidence {
		t.Errorf("ISMS-12 with a policy document: %s", o)
	}
	a2, _ := e.st.ControlAssessments(ctx, v2.ID)
	for _, a := range a2 {
		if a.Profile == "general" && a.Control == "GEN-04" && (a.ReviewStatus != store.ReviewAccepted || a.ReviewNote != "Örnekleme ile doğrulandı") {
			t.Errorf("review not carried over: %+v", a)
		}
	}
	if v1, _ := e.st.ReportVersionByNumber(ctx, repID, 1); v1.SHA256 == "" || v1.Content == "" {
		t.Error("version 1 lost")
	}

	// Exports from the stored version.
	export := func(format string) (string, http.Header) {
		status, body, hdr := e.do(admin, "GET", repURL+"/versions/2/export?format="+format, nil)
		if status != 200 {
			t.Fatalf("export %s: %d", format, status)
		}
		return body, hdr
	}
	jsonBody, hdr := export("json")
	var exp struct {
		Schema  string `json:"schema"`
		Version struct {
			SHA256 string `json:"sha256"`
		} `json:"version"`
		Report      compliance.Report `json:"report"`
		Assessments []struct {
			Profile      string `json:"profile"`
			Control      string `json:"control"`
			ReviewStatus string `json:"review_status"`
		} `json:"assessments"`
		Evidence []struct {
			ID       int64    `json:"id"`
			SHA256   string   `json:"sha256"`
			Controls []string `json:"controls"`
		} `json:"evidence"`
	}
	if err := json.Unmarshal([]byte(jsonBody), &exp); err != nil || exp.Schema != compliance.ExportSchema || exp.Version.SHA256 != v2.SHA256 ||
		len(exp.Evidence) == 0 || exp.Report.Schema != compliance.Schema || len(exp.Assessments) != total {
		t.Fatalf("json export (%s): %v %+v", hdr.Get("Content-Type"), err, exp.Version)
	}
	again, _ := export("json")
	if again != jsonBody {
		t.Error("the same version exported twice differs")
	}
	zipBody, _ := export("csv")
	zr, err := zip.NewReader(bytes.NewReader([]byte(zipBody)), int64(len(zipBody)))
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, f := range zr.File {
		names[f.Name] = true
		if f.Name == "controls.csv" {
			rc, _ := f.Open()
			b, _ := io.ReadAll(rc)
			rc.Close()
			if !strings.Contains(string(b), "GEN-04") || !strings.Contains(string(b), "Örnekleme ile doğrulandı") || !strings.Contains(string(b), ";") {
				t.Errorf("controls.csv: %.300s", b)
			}
		}
	}
	for _, n := range []string{"summary.csv", "controls.csv", "checks.csv", "gaps.csv", "assets.csv", "evidence.csv"} {
		if !names[n] {
			t.Errorf("csv archive misses %s: %v", n, names)
		}
	}
	pdf, hdr := export("pdf")
	if !strings.HasPrefix(pdf, "%PDF-") || len(pdf) < 20000 || hdr.Get("Content-Type") != "application/pdf" {
		t.Errorf("pdf: %d bytes, %s", len(pdf), hdr.Get("Content-Type"))
	}

	// Finalize: the version and its reviews no longer change.
	if status, _, _ := e.do(admin, "POST", repURL+"/versions/2/finalize", url.Values{"_csrf": {e.csrf(admin)}}); status != http.StatusSeeOther {
		t.Fatalf("finalize: %d", status)
	}
	v2, _ = e.st.ReportVersionByNumber(ctx, repID, 2)
	if !v2.Final() || v2.FinalSHA256 == "" || v2.FinalSHA256 != compliance.FinalDigest(v2.SHA256, a2) {
		t.Errorf("final version: %+v", v2)
	}
	review.Set("_csrf", e.csrf(admin))
	review.Set("status", "gap")
	_, _, hdr = e.do(admin, "POST", repURL+"/versions/2/review", review)
	if a, _ := e.st.ControlAssessments(ctx, v2.ID); a[0].ReviewStatus == store.ReviewGap && a[0].Control == "GEN-04" {
		t.Error("review changed on a final version")
	}
	if status, _, _ := e.do(admin, "POST", repURL+"/delete", url.Values{"_csrf": {e.csrf(admin)}}); status != http.StatusSeeOther {
		t.Errorf("delete: %d", status)
	}
	if _, err := e.st.ComplianceReportByID(ctx, rep.ID); err != nil {
		t.Errorf("a report with a final version was deleted: %v", err)
	}

	// Evidence repository, history and integrity.
	status, body, _ = e.do(admin, "GET", "/compliance/evidence?kind=update_job", nil)
	expect(t, "evidence", status, 200, body, "WIN-SRV-01", "Seçili paket güncellemesi")
	status, body, _ = e.do(admin, "GET", "/compliance/evidence/"+strconv.FormatInt(items[0].ID, 10), nil)
	expect(t, "evidence item", status, 200, body, items[0].SHA256, "Yıllık denetim 2026", "ISMS-02", "Destekleyici", "BASE-01")
	status, body, _ = e.do(admin, "GET", "/compliance/history", nil)
	expect(t, "history", status, 200, body, "Yıllık denetim 2026", "Kesinleşti")
	status, body, _ = e.do(admin, "GET", "/compliance/history?tab=integrity", nil)
	expect(t, "integrity", status, 200, body, "Kanıt zinciri doğrulandı")

	// Policies: a control excluded needs a reason, which reports then show.
	pol := url.Values{"_csrf": {e.csrf(admin)}, "profile": {"itsm"}}
	for _, c := range []string{"ITSM-01", "ITSM-02", "ITSM-03", "ITSM-04", "ITSM-05", "ITSM-06", "ITSM-07"} {
		pol.Set("applicable_"+c, "1")
	}
	_, _, _ = e.do(admin, "POST", "/compliance/policies/controls", pol)
	if s, _ := e.st.ControlSettings(ctx); len(s) != 0 {
		t.Errorf("excluded without a reason: %+v", s)
	}
	pol.Set("justification_ITSM-08", "Olay yönetimi dış hizmet sağlayıcıda")
	_, _, _ = e.do(admin, "POST", "/compliance/policies/controls", pol)
	if s, _ := e.st.ControlSettings(ctx); s["itsm:ITSM-08"].Applicable || len(s) != 1 {
		t.Errorf("applicability: %+v", s)
	}
	_, _, hdr = e.do(admin, "POST", repURL+"/regenerate", url.Values{"_csrf": {e.csrf(admin)}})
	v3, _ := e.st.ReportVersionByNumber(ctx, repID, 3)
	c3, _ := compliance.Decode(v3.Content)
	if ca := outcome(c3, "itsm", "ITSM-08"); ca.Outcome != compliance.OutcomeNotApplicable || ca.Justification != "Olay yönetimi dış hizmet sağlayıcıda" {
		t.Errorf("ITSM-08 excluded: %+v", ca)
	}
	status, body, _ = e.do(admin, "GET", "/compliance/policies", nil)
	expect(t, "policies", status, 200, body, "Otomatik kontrol eşikleri", "Kanıt saklama süresi", `href="/standards"`)
	thresholds := url.Values{"_csrf": {e.csrf(admin)}, "profiles": {"general"}, "compliance_coverage_min": {"90"}, "compliance_patch_failure_max": {"5"},
		"compliance_currency_min": {"80"}, "compliance_sla_min": {"85"}, "compliance_reboot_max_days": {"3"}, "compliance_evidence_days": {"100"}}
	_, _, _ = e.do(admin, "POST", "/compliance/policies", thresholds)
	if v, _ := e.st.Settings(ctx); v["compliance.evidence_days"] != "" {
		t.Error("evidence retention below the minimum was saved")
	}
	thresholds.Set("compliance_evidence_days", "730")
	_, _, _ = e.do(admin, "POST", "/compliance/policies", thresholds)
	if v, _ := e.st.Settings(ctx); v["compliance.evidence_days"] != "730" || v["compliance.profiles"] != "general" {
		t.Errorf("policies saved: %v", v)
	}
	status, body, _ = e.do(admin, "GET", "/compliance/reports", nil)
	if status != 200 || strings.Contains(body, `value="isms@1"`) || !strings.Contains(body, `value="general@1"`) {
		t.Error("disabled frameworks offered for new reports")
	}

	// A group-limited operator sees and creates only reports of its groups.
	gid, err := e.st.CreateGroup(ctx, "Web", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.AddHostsToGroup(ctx, gid, []int64{hostID}); err != nil {
		t.Fatal(err)
	}
	pw := "kisitli-parola-1"
	e.do(admin, "POST", "/users", url.Values{"_csrf": {e.csrf(admin)}, "name": {"Web Ekibi"}, "email": {"web@example.test"}, "role": {"operator"},
		"password": {pw}, "password_confirm": {pw}})
	u, _ := e.st.UserByEmail(ctx, "web@example.test")
	e.do(admin, "POST", "/users/"+strconv.FormatInt(u.ID, 10), url.Values{"_csrf": {e.csrf(admin)}, "name": {"Web Ekibi"}, "role": {"operator"},
		"scope": {"groups"}, "group_ids": {strconv.FormatInt(gid, 10)}})
	op := newClient()
	e.do(op, "POST", "/login", url.Values{"email": {"web@example.test"}, "password": {pw}})
	if status, _, _ := e.do(op, "GET", repURL, nil); status != http.StatusNotFound {
		t.Errorf("limited user opened a fleet report: %d", status)
	}
	_, _, hdr = e.do(op, "POST", "/compliance/reports", url.Values{"_csrf": {e.csrf(op)}, "title": {"Filo"}, "preset": {"30d"}, "profiles": {"general@1"}})
	if reportURLRE.MatchString(hdr.Get("Location")) {
		t.Error("limited user created a fleet-wide report")
	}
	_, _, hdr = e.do(op, "POST", "/compliance/reports", url.Values{"_csrf": {e.csrf(op)}, "title": {"Web"}, "preset": {"30d"}, "profiles": {"general@1"},
		"group": {strconv.FormatInt(gid, 10)}})
	gm := reportURLRE.FindStringSubmatch(hdr.Get("Location"))
	if gm == nil {
		t.Fatalf("limited user group report: %s", hdr.Get("Location"))
	}
	status, body, _ = e.do(op, "GET", "/compliance/reports/"+gm[1], nil)
	expect(t, "group report", status, 200, body, "db-01")
	if strings.Contains(body, "WIN-SRV-01") {
		t.Error("group report shows hosts outside the group")
	}
	status, body, _ = e.do(op, "GET", "/compliance/evidence", nil)
	if status != 200 || strings.Contains(body, "WIN-SRV-01") || strings.Contains(body, "Bilgi güvenliği politikası v4") {
		t.Errorf("limited user sees evidence outside its groups: %d", status)
	}
	if status, _, _ := e.do(op, "GET", "/compliance/history?tab=audit", nil); status != 200 {
		t.Errorf("history: %d", status)
	}

	// REST API.
	key := e.createAPIKey(admin, "denetim", false)
	status, body = e.apiDo(key, "GET", "/api/v1/compliance/reports", "")
	if status != 200 || !strings.Contains(body, `"title": "Yıllık denetim 2026"`) {
		t.Errorf("api reports: %d %.200s", status, body)
	}
	status, body = e.apiDo(key, "GET", "/api/v1/compliance/reports/"+m[1]+"/versions/2", "")
	if status != 200 || !strings.Contains(body, compliance.ExportSchema) || !strings.Contains(body, v2.FinalSHA256) {
		t.Errorf("api version: %d %.200s", status, body)
	}
	status, body = e.apiDo(key, "GET", "/api/v1/compliance/evidence?kind=update_job", "")
	if status != 200 || !strings.Contains(body, items[0].SHA256) {
		t.Errorf("api evidence: %d %.200s", status, body)
	}
}

// TestComplianceBackgroundGeneration: a version that is not ready within the
// wait time is finished in the background; the list shows it as being
// generated and the report appears when it is stored.
func TestComplianceBackgroundGeneration(t *testing.T) {
	e := newEnvOpts(t, true, func(o *web.Options) { o.ComplianceWait = -1 })
	admin := e.client
	pw := "çok-güçlü-parola-1"
	if status, _, _ := e.do(admin, "POST", "/setup", url.Values{"name": {"Admin"}, "email": {"admin@example.test"}, "password": {pw}, "password_confirm": {pw}}); status != http.StatusSeeOther {
		t.Fatalf("setup: %d", status)
	}
	form := url.Values{"_csrf": {e.csrf(admin)}, "title": {"Arka plan raporu"}, "preset": {"30d"}, "profiles": {"general@1"}}
	status, _, hdr := e.do(admin, "POST", "/compliance/reports", form)
	if status != http.StatusSeeOther || hdr.Get("Location") != "/compliance/reports" {
		t.Fatalf("create: %d %s", status, hdr.Get("Location"))
	}
	ctx := context.Background()
	var rep store.ComplianceReport
	waitFor(t, func() bool {
		list, _ := e.st.ListComplianceReports(ctx)
		if len(list) == 1 {
			rep = list[0]
		}
		return len(list) == 1 && list[0].LatestVersion == 1
	})
	status, body, _ := e.do(admin, "GET", "/compliance/reports/"+strconv.FormatInt(rep.ID, 10), nil)
	expect(t, "report", status, 200, body, "Arka plan raporu", "Genel Güvenlik ve Yama Uyumu")
	if strings.Contains(body, "Yeni bir sürüm oluşturuluyor") {
		t.Error("finished report still shown as being generated")
	}
	// The audit entry is written when the version is stored.
	waitFor(t, func() bool {
		entries, _, _ := e.st.ListAudit(ctx, store.Page{Number: 1, Size: 50})
		for _, a := range entries {
			if a.Action == "compliance.report_create" {
				return a.UserEmail == "admin@example.test" && strings.Contains(a.Details, "profiles=general@1")
			}
		}
		return false
	})
	// A new version in the background, then the regenerated version 2.
	status, _, hdr = e.do(admin, "POST", "/compliance/reports/"+strconv.FormatInt(rep.ID, 10)+"/regenerate", url.Values{"_csrf": {e.csrf(admin)}})
	if status != http.StatusSeeOther || !strings.HasPrefix(hdr.Get("Location"), "/compliance/reports/"+strconv.FormatInt(rep.ID, 10)) {
		t.Fatalf("regenerate: %d %s", status, hdr.Get("Location"))
	}
	waitFor(t, func() bool {
		r, _ := e.st.ComplianceReportByID(ctx, rep.ID)
		return r.LatestVersion == 2
	})
}
