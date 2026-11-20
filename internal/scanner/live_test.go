//go:build live

// Live test against api.osv.dev. Run with: go test -tags live -run Live -v ./internal/scanner/
package scanner

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"netio.patchman/internal/i18n"
	"netio.patchman/internal/protocol"
	"netio.patchman/internal/store"
)

func TestLiveOSV(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	st, err := store.Open(ctx, t.TempDir()+"/live.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	l := i18n.MustLoad().Localizer(i18n.DefaultLocale)
	sc := New(Options{Store: st, OSV: NewOSVClient("https://api.osv.dev"), KEVURL: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), L: l})

	if err := sc.RefreshKEV(ctx); err != nil {
		t.Logf("KEV refresh failed (network?): %v", err)
	}

	hosts := []struct {
		info protocol.HostInfo
		pkgs []protocol.Package
	}{
		{protocol.HostInfo{Hostname: "deb12", MachineID: "deb12", OSID: "debian", OSVersionID: "12"}, []protocol.Package{
			{Name: "libssl3", Version: "3.0.11-1~deb12u2", SourceName: "openssl", SourceVersion: "3.0.11-1~deb12u2"},
			{Name: "sudo", Version: "1.9.13p3-1+deb12u1", SourceName: "sudo", SourceVersion: "1.9.13p3-1+deb12u1"},
			{Name: "libcurl4", Version: "7.88.1-10+deb12u5", SourceName: "curl", SourceVersion: "7.88.1-10+deb12u5"},
		}},
		{protocol.HostInfo{Hostname: "u2404", MachineID: "u2404", OSID: "ubuntu", OSVersionID: "24.04", OSVersion: "24.04 LTS (Noble Numbat)"}, []protocol.Package{
			{Name: "libssl3t64", Version: "3.0.13-0ubuntu3", SourceName: "openssl", SourceVersion: "3.0.13-0ubuntu3"},
		}},
		{protocol.HostInfo{Hostname: "alma9", MachineID: "alma9", OSID: "almalinux", OSVersionID: "9.3"}, []protocol.Package{
			{Name: "openssl", Version: "1:3.0.7-24.el9", Arch: "x86_64"},
		}},
	}
	for _, h := range hosts {
		tokenHash := "tok-" + h.info.MachineID
		if _, err := st.CreateEnrollmentToken(ctx, "live", tokenHash, "p", 0, time.Time{}, 0); err != nil {
			t.Fatal(err)
		}
		id, _, err := st.RegisterHost(ctx, tokenHash, h.info, "", "secret-"+h.info.MachineID)
		if err != nil {
			t.Fatal(err)
		}
		if err := st.SaveReport(ctx, id, protocol.Report{Host: h.info, Packages: h.pkgs}, ""); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		if err := sc.ScanHost(ctx, id); err != nil {
			t.Fatalf("%s: %v", h.info.Hostname, err)
		}
		rows, total, err := st.ListFindings(ctx, store.FindingFilter{HostID: id}, store.Page{Number: 1, Size: 500})
		if err != nil {
			t.Fatal(err)
		}
		if total == 0 {
			t.Errorf("%s: no findings for known-vulnerable versions", h.info.Hostname)
			continue
		}
		withDesc, withSev, withFix, kev := 0, 0, 0, 0
		for _, r := range rows {
			v, err := st.Vulnerability(ctx, r.CVEID)
			if err != nil {
				t.Errorf("%s: vulnerability %s not stored: %v", h.info.Hostname, r.CVEID, err)
				continue
			}
			if v.Description != "" {
				withDesc++
			}
			if v.Severity != "unknown" {
				withSev++
			}
			if r.FixedVersion != "" {
				withFix++
			}
			if v.KnownExploited {
				kev++
			}
		}
		t.Logf("%s: %d findings in %s; description %d, severity %d, fixed version %d, KEV %d; sample %s %s %s -> %q",
			h.info.Hostname, total, time.Since(start).Round(time.Millisecond), withDesc, withSev, withFix, kev,
			rows[0].CVEID, rows[0].Severity, rows[0].PackageName, rows[0].FixedVersion)
		if withDesc*2 < total {
			t.Errorf("%s: most findings lack descriptions", h.info.Hostname)
		}
	}
}
