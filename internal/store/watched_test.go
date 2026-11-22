package store

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"netio.patchman/internal/protocol"
	"netio.patchman/internal/vuln"
)

func TestWatchedPackages(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	uid, err := s.CreateUser(ctx, User{Email: "w@example.test", Name: "w", PasswordHash: "h", Role: RoleViewer})
	if err != nil {
		t.Fatal(err)
	}
	other, err := s.CreateUser(ctx, User{Email: "o@example.test", Name: "o", PasswordHash: "h", Role: RoleViewer})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateEnrollmentToken(ctx, "t", "tok", "p", 0, time.Time{}, 0); err != nil {
		t.Fatal(err)
	}
	var hosts []int64
	for i, name := range []string{"web-01", "web-02"} {
		info := protocol.HostInfo{Hostname: name, MachineID: fmt.Sprint("m", i), OSID: "debian"}
		id, _, err := s.RegisterHost(ctx, "tok", info, "Debian:12", fmt.Sprint("secret", i))
		if err != nil {
			t.Fatal(err)
		}
		hosts = append(hosts, id)
		ver := fmt.Sprintf("10.11.%d-0+deb12u1", 6+i)
		rep := protocol.Report{Host: info, Packages: []protocol.Package{
			{Name: "mariadb-server", Version: ver, Arch: "amd64", SourceName: "mariadb", SourceVersion: ver},
			{Name: "nginx", Version: "1.22.1-9", Arch: "amd64", SourceName: "nginx", SourceVersion: "1.22.1-9"}}}
		if i == 0 {
			rep.Updates = []protocol.Update{{Name: "mariadb-server", CurrentVersion: ver, AvailableVersion: "10.11.11-0+deb12u1", Security: true}}
		}
		if err := s.SaveReport(ctx, id, rep, "Debian:12"); err != nil {
			t.Fatal(err)
		}
		// Findings are recorded under the source package.
		if _, err := s.ApplyFindings(ctx, id, []DetectedFinding{{CVEID: "CVE-2026-1000", PackageName: "mariadb", InstalledVersion: ver, FixedVersion: "1:10.11.11-0+deb12u1"}}); err != nil {
			t.Fatal(err)
		}
	}
	score := 9.1
	if err := s.UpsertVulnerability(ctx, vuln.Vulnerability{CVEID: "CVE-2026-1000", Title: "t", CVSSScore: &score, Severity: vuln.SeverityCritical, Source: "osv"}); err != nil {
		t.Fatal(err)
	}

	for _, n := range []string{"mariadb-server", "nginx", "redis-server", "nginx"} {
		if err := s.WatchPackage(ctx, uid, n); err != nil {
			t.Fatal(err)
		}
	}
	if names, _ := s.WatchedNames(ctx, other); len(names) != 0 {
		t.Errorf("other user's list: %v", names)
	}
	sum, err := s.WatchedSummary(ctx, uid)
	if err != nil {
		t.Fatal(err)
	}
	if len(sum) != 3 {
		t.Fatalf("summary: %+v", sum)
	}
	m := sum[0]
	if m.Name != "mariadb-server" || m.HostCount != 2 || m.VersionCount != 2 || m.UpdateHosts != 1 || m.SecurityHosts != 1 ||
		m.CVECount != 1 || m.VulnHosts != 2 || m.Severity != vuln.SeverityCritical || m.FindingPackage != "mariadb" {
		t.Errorf("mariadb-server: %+v", m)
	}
	if n := sum[1]; n.Name != "nginx" || n.HostCount != 2 || n.UpdateHosts != 0 || n.CVECount != 0 {
		t.Errorf("nginx: %+v", n)
	}
	if r := sum[2]; r.Name != "redis-server" || r.HostCount != 0 {
		t.Errorf("redis-server: %+v", r)
	}

	// Group-limited view: only web-02.
	g, err := s.CreateGroup(ctx, "B", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddHostsToGroup(ctx, g, hosts[1:]); err != nil {
		t.Fatal(err)
	}
	scoped, err := s.WatchedSummary(WithScope(ctx, []int64{g}), uid)
	if err != nil {
		t.Fatal(err)
	}
	if m := scoped[0]; m.HostCount != 1 || m.UpdateHosts != 0 || m.VulnHosts != 1 {
		t.Errorf("scoped mariadb-server: %+v", m)
	}

	rows, missing, err := s.HostWatched(ctx, uid, hosts[0])
	if err != nil {
		t.Fatal(err)
	}
	if missing != 1 || len(rows) != 2 || rows[0].Name != "mariadb-server" || rows[0].AvailableVersion != "10.11.11-0+deb12u1" || !rows[0].Security ||
		rows[0].CVECount != 1 || rows[0].Versions[0] != "10.11.6-0+deb12u1 (amd64)" || rows[1].Name != "nginx" || rows[1].AvailableVersion != "" {
		t.Errorf("host watched: %d %+v", missing, rows)
	}
	if n, _ := s.CountHostWatched(ctx, uid, hosts[0]); n != 2 {
		t.Errorf("count: %d", n)
	}

	// Host search on the findings: the binary name finds the source package's findings.
	found, total, err := s.ListFindings(ctx, FindingFilter{HostID: hosts[0], Search: "mariadb-ser"}, Page{Number: 1, Size: 10})
	if err != nil || total != 1 || len(found) != 1 {
		t.Errorf("finding search: %d %v", total, err)
	}

	if err := s.UnwatchPackage(ctx, uid, "nginx"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < MaxWatchedPerUser; i++ {
		if err := s.WatchPackage(ctx, uid, fmt.Sprint("p", i)); err != nil {
			if !errors.Is(err, ErrLimit) || i < MaxWatchedPerUser-2 {
				t.Fatalf("watch %d: %v", i, err)
			}
		}
	}
	if err := s.WatchPackage(ctx, uid, "one-more"); !errors.Is(err, ErrLimit) {
		t.Errorf("limit: %v", err)
	}
	if err := s.WatchPackage(ctx, uid, "mariadb-server"); err != nil {
		t.Errorf("re-watch at the limit: %v", err)
	}
}
