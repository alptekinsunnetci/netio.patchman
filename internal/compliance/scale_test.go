package compliance

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"netio.patchman/internal/i18n"
	"netio.patchman/internal/store"
	"netio.patchman/internal/timeutil"
)

// Fleet size of the scale benchmark: 500 hosts over 12 months with the
// evidence a busy fleet produces (weekly updates, monthly changes, resolved
// findings, audit events, daily inventory and backups).
const (
	scaleHosts = 500
	scaleDays  = 365
)

// BenchmarkGenerateLargeFleet measures one report version (all four
// frameworks, 12 months, 500 hosts): generation and storing the version with
// its evidence mapping, as the request handler does. Run it with
//
//	go test -run '^$' -bench GenerateLargeFleet -benchtime 3x ./internal/compliance/
//
// and against PostgreSQL with PATCHMAN_TEST_DATABASE_URL set.
func BenchmarkGenerateLargeFleet(b *testing.B) {
	ctx := context.Background()
	st := openScaleStore(b)
	now := time.Now().UTC()
	from := store.DayStart(now.AddDate(0, 0, -scaleDays))
	items := seedScale(b, ctx, st, from, now)
	repID, err := st.CreateComplianceReport(ctx, store.ComplianceReport{Title: "scale", Profiles: []string{"isms@1", "baseline@1", "itsm@1", "general@1"},
		From: from, To: now})
	if err != nil {
		b.Fatal(err)
	}
	rep, err := st.ComplianceReportByID(ctx, repID)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	var gen, save, export time.Duration
	var mapping, size int
	l := i18n.MustLoad().Localizer("en-US")
	r := Renderer{L: l, F: timeutil.NewFormatter(time.UTC, l)}
	for b.Loop() {
		t0 := time.Now()
		res, err := Generate(st, Request{Report: rep, GeneratedBy: "bench", Now: now})
		if err != nil {
			b.Fatal(err)
		}
		t1 := time.Now()
		if _, _, err := st.AddReportVersion(ctx, store.ReportVersion{ReportID: repID, GeneratedAt: now, GeneratedBy: "bench", Engine: EngineVersion,
			Content: res.Content, SHA256: res.SHA256}, res.Assessments, res.Mapping); err != nil {
			b.Fatal(err)
		}
		t2 := time.Now()
		// A PDF export of the new version, loaded as the export handler does.
		vers, err := st.ReportVersions(ctx, repID)
		if err != nil || len(vers) == 0 {
			b.Fatal(err)
		}
		v, err := st.ReportVersionByNumber(ctx, repID, vers[0].Version)
		if err != nil {
			b.Fatal(err)
		}
		bundle := Bundle{Report: rep, Version: v, Content: res.Report, Assessments: res.Assessments}
		if bundle.Evidence, err = st.EvidenceItems(ctx, store.EvidenceFilter{VersionID: v.ID}); err != nil {
			b.Fatal(err)
		}
		if bundle.Controls, err = st.VersionEvidenceControls(ctx, v.ID); err != nil {
			b.Fatal(err)
		}
		if err := WritePDF(io.Discard, bundle, r); err != nil {
			b.Fatal(err)
		}
		gen += t1.Sub(t0)
		save += t2.Sub(t1)
		export += time.Since(t2)
		mapping, size = len(res.Mapping), len(res.Content)
	}
	n := float64(b.N)
	b.ReportMetric(gen.Seconds()/n, "generate_s/op")
	b.ReportMetric(save.Seconds()/n, "store_s/op")
	b.ReportMetric(export.Seconds()/n, "pdf_export_s/op")
	b.ReportMetric(float64(mapping), "mapping_rows")
	b.ReportMetric(float64(size)/1e6, "content_MB")
	b.ReportMetric(float64(items), "evidence_items")
}

func openScaleStore(b *testing.B) *store.Store {
	b.Helper()
	// store.Open maps the path to its own PostgreSQL schema when
	// PATCHMAN_TEST_DATABASE_URL is set.
	st, err := store.Open(context.Background(), filepath.Join(b.TempDir(), "scale.db"))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = st.Close() })
	return st
}

// seedScale writes the daily host states directly and the evidence items
// through AddEvidence (so the hash chain is real) and returns the number of
// items.
func seedScale(b *testing.B, ctx context.Context, st *store.Store, from, now time.Time) int {
	b.Helper()
	const cols = `day, host_id, hostname, platform, os_name, os_version, agent_version, group_ids, last_seen_at, updates, security_updates,
		critical, high, medium, low, kev, kev_overdue, sla_overdue, reboot_required_since, os_eol, monitored, taken_at`
	platform := func(h int) (string, string) {
		switch {
		case h%10 == 0:
			return store.PlatformWindowsServer, "Windows Server 2022 Standard"
		case h%25 == 1:
			return store.PlatformWindows11, "Windows 11 Pro"
		default:
			return store.PlatformLinux, "Debian GNU/Linux 12 (bookworm)"
		}
	}
	const perStmt = 200
	var rows []string
	var args []any
	flush := func() {
		if len(rows) == 0 {
			return
		}
		if _, err := st.DB().ExecContext(ctx, `INSERT INTO evidence_host_states (`+cols+`) VALUES `+strings.Join(rows, ","), args...); err != nil {
			b.Fatal(err)
		}
		rows, args = rows[:0], args[:0]
	}
	ph := "(" + strings.TrimSuffix(strings.Repeat("?,", 22), ",") + ")"
	for d := 0; d <= scaleDays; d++ {
		day := from.AddDate(0, 0, d)
		for h := 1; h <= scaleHosts; h++ {
			p, osName := platform(h)
			seen := day.Add(23 * time.Hour).Unix()
			if h%40 == 0 && d%7 == 3 { // some hosts are offline now and then
				seen = day.Add(-48 * time.Hour).Unix()
			}
			rows = append(rows, ph)
			args = append(args, day.Unix(), h, fmt.Sprintf("host-%03d", h), p, osName, "", "1.1.0", ","+strconv.Itoa(1+h%5)+",", seen,
				h%7, h%3, h%11/10, h%5, h%4, h%6, 0, 0, h%13/12, 0, "supported", 1, seen)
			if len(rows) == perStmt {
				flush()
			}
		}
	}
	flush()

	var batch []store.EvidenceItem
	total := 0
	add := func(e store.EvidenceItem) {
		batch = append(batch, e)
		if len(batch) == 2000 {
			n, err := st.AddEvidence(ctx, batch)
			if err != nil {
				b.Fatal(err)
			}
			total += n
			batch = batch[:0]
		}
	}
	ref := 0
	item := func(kind, subject, outcome string, host int, at time.Time, payload string) {
		ref++
		e := store.EvidenceItem{Kind: kind, Source: store.SourceAgent, SourceRef: kind + ":" + strconv.Itoa(ref), Subject: subject, Actor: "system",
			Outcome: outcome, OccurredAt: at, Payload: payload}
		if host > 0 {
			e.HostID, e.Hostname = int64(host), fmt.Sprintf("host-%03d", host)
			e.Platform, _ = platform(host)
		}
		add(e)
	}
	for d := 0; d <= scaleDays; d++ {
		day := from.AddDate(0, 0, d)
		for h := 1; h <= scaleHosts; h++ {
			at := day.Add(time.Duration(2+h%20) * time.Hour)
			if at.After(now) {
				continue
			}
			if (d+h)%7 == 0 { // weekly security update
				status := "succeeded"
				if h%50 == 0 {
					status = "failed"
				}
				item(store.EvidenceUpdateJob, "upgrade_security", status, h, at,
					`{"type":"upgrade_security","status":"`+status+`","origin":"schedule","package_count":6,"remaining_count":0,"schedule_id":1}`)
			}
			if (d+h)%30 == 0 { // monthly change
				item(store.EvidenceChangeJob, "reboot", "succeeded", h, at, `{"type":"reboot","status":"succeeded","origin":"user"}`)
			}
			if (d*7+h)%4 == 0 { // ~90 resolved findings per host and year
				item(store.EvidenceVulnResolved, "CVE-2026-"+strconv.Itoa(1000+(d*scaleHosts+h)%9000), "within_sla", h, at,
					`{"cve":"CVE-2026-1000","package":"openssl","severity":"high","kev":false}`)
			}
		}
		for a := 0; a < 20; a++ {
			at := day.Add(time.Duration(a) * time.Hour)
			if !at.After(now) {
				item(store.EvidenceAudit, "job.created", "", 0, at, `{"action":"job.created"}`)
			}
		}
		if at := day.Add(2*time.Hour + 30*time.Minute); !at.After(now) {
			item(store.EvidenceBackup, "backup", "succeeded", 0, at, `{"ok":true}`)
			item(store.EvidenceInventory, "day", "", 0, at, `{"hosts":500}`)
		}
	}
	if len(batch) > 0 {
		n, err := st.AddEvidence(ctx, batch)
		if err != nil {
			b.Fatal(err)
		}
		total += n
	}
	return total
}
