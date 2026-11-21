//go:build live

// Live test against the Microsoft Security Update Guide API.
// Run with: go test -tags live -run LiveMSRC -v ./internal/scanner/
package scanner

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"netio.patchman/internal/config"
	"netio.patchman/internal/i18n"
	"netio.patchman/internal/protocol"
	"netio.patchman/internal/store"
)

func TestLiveMSRC(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	st, err := store.Open(ctx, t.TempDir()+"/live.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	l := i18n.MustLoad().Localizer(i18n.DefaultLocale)
	sc := New(Options{Store: st, OSV: NewOSVClient("https://api.osv.dev"), MSRCURL: config.DefaultMSRCURL,
		KEVURL: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), L: l})
	if err := sc.RefreshKEV(ctx); err != nil {
		t.Logf("KEV refresh failed (network?): %v", err)
	}

	// Windows Server 2022 at build 20348.2700 (September 2024) with the
	// October 2024 cumulative update KB5044281 pending: the October CVEs and
	// nothing older than the host's build.
	info := protocol.HostInfo{Hostname: "ws2022", MachineID: "ws2022", OSID: protocol.OSWindows, OSVersionID: "10.0.20348",
		OSName: "Windows Server 2022 Standard", Kernel: "10.0.20348.2700", PackageManager: protocol.PMWindowsUpdate}
	if _, err := st.CreateEnrollmentToken(ctx, "live", "tok", "p", 0, time.Time{}, 0); err != nil {
		t.Fatal(err)
	}
	id, _, err := st.RegisterHost(ctx, "tok", info, "", "secret")
	if err != nil {
		t.Fatal(err)
	}
	rep := protocol.Report{Host: info, Updates: []protocol.Update{{Name: "KB5044281", AvailableVersion: "2024-10-08", Security: true,
		Title: "2024-10 Cumulative Update for Microsoft server operating system version 21H2 for x64-based Systems (KB5044281)"}}}
	if err := st.SaveReport(ctx, id, rep, "Windows"); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := sc.ScanHost(ctx, id); err != nil {
		t.Fatal(err)
	}
	rows, total, err := st.ListFindings(ctx, store.FindingFilter{HostID: id}, store.Page{Number: 1, Size: 1000})
	if err != nil {
		t.Fatal(err)
	}
	withTitle, withScore, kev := 0, 0, 0
	for _, r := range rows {
		v, err := st.Vulnerability(ctx, r.CVEID)
		if err != nil {
			t.Fatalf("%s not stored: %v", r.CVEID, err)
		}
		if v.Title != "" {
			withTitle++
		}
		if v.CVSSScore != nil {
			withScore++
		}
		if v.KnownExploited {
			kev++
		}
		if r.PackageName != "KB5044281" {
			t.Errorf("%s: package %q", r.CVEID, r.PackageName)
		}
	}
	t.Logf("%d findings in %s; title %d, score %d, KEV %d; sample %s %s %s -> %s", total, time.Since(start).Round(time.Millisecond),
		withTitle, withScore, kev, rows[0].CVEID, rows[0].Severity, rows[0].PackageName, rows[0].FixedVersion)
	if n := len(rows); total < 50 || withTitle*10 < n*9 || withScore*10 < n*9 {
		t.Errorf("unexpected result: %d findings, %d titles, %d scores", total, withTitle, withScore)
	}

	// The same host three months behind (build 20348.2582, July 2024) also
	// misses the August and September updates superseded by KB5044281.
	info.Kernel = "10.0.20348.2582"
	rep.Host = info
	if err := st.SaveReport(ctx, id, rep, "Windows"); err != nil {
		t.Fatal(err)
	}
	if err := sc.ScanHost(ctx, id); err != nil {
		t.Fatal(err)
	}
	_, older, err := st.ListFindings(ctx, store.FindingFilter{HostID: id}, store.Page{Number: 1, Size: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("build 2582: %d findings (build 2700: %d)", older, total)
	if older <= total {
		t.Errorf("superseded updates were not followed")
	}
}
