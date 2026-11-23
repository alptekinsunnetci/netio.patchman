package store

import (
	"context"
	"testing"
	"time"

	"netio.patchman/internal/protocol"
	"netio.patchman/internal/vuln"
)

func TestSoftwareInventory(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	if _, err := s.CreateEnrollmentToken(ctx, "t", "tok", "p", 0, time.Time{}, 0); err != nil {
		t.Fatal(err)
	}
	info := protocol.HostInfo{Hostname: "web-01", MachineID: "m1", OSID: "debian", PackageManager: "apt", Capabilities: []string{protocol.CapServices}}
	id, _, err := s.RegisterHost(ctx, "tok", info, "Debian:12", "secret")
	if err != nil {
		t.Fatal(err)
	}
	rep := protocol.Report{Host: info,
		Packages: []protocol.Package{
			{Name: "nginx", Version: "1.22.1-9", Arch: "amd64", SourceName: "nginx", SourceVersion: "1.22.1-9"},
			{Name: "libnginx-mod-http-geoip", Version: "1.22.1-9", Arch: "amd64", SourceName: "nginx", SourceVersion: "1.22.1-9"},
		},
		Services: []protocol.Service{{Name: "nginx", State: "running", Enabled: true}, {Name: "cron", State: "running"}, {Name: "bad name;", State: "running"}},
	}
	if err := s.SaveReport(ctx, id, rep, "Debian:12"); err != nil {
		t.Fatal(err)
	}
	svcs, known, err := s.HostServices(ctx, id)
	if err != nil || !known || len(svcs) != 2 || svcs[0].Name != "cron" || !svcs[1].Enabled {
		t.Fatalf("services: %v %v %v", svcs, known, err)
	}
	// A capable agent that could not list services keeps the last list.
	rep.Services = nil
	if err := s.SaveReport(ctx, id, rep, "Debian:12"); err != nil {
		t.Fatal(err)
	}
	if svcs, known, _ := s.HostServices(ctx, id); !known || len(svcs) != 2 {
		t.Errorf("services after a failed listing: %v %v", svcs, known)
	}

	nginx := SoftwareItem{Software: "nginx", Cycle: "1.22", Version: "1.22.1", Package: "nginx", PackageVersion: "1.22.1-9", Running: 1, Service: "nginx"}
	// First inventory: no events.
	ev, err := s.SyncSoftware(ctx, id, "apt", []SoftwareItem{nginx})
	if err != nil || len(ev) != 0 {
		t.Fatalf("first sync: %v %v", ev, err)
	}
	// A finding on the source package counts for the product.
	if _, err := s.ApplyFindings(ctx, id, []DetectedFinding{{CVEID: "CVE-2026-2000", PackageName: "nginx", InstalledVersion: "1.22.1-9"}}); err != nil {
		t.Fatal(err)
	}
	score := 7.5
	if err := s.UpsertVulnerability(ctx, vuln.Vulnerability{CVEID: "CVE-2026-2000", Title: "t", CVSSScore: &score, Severity: vuln.SeverityHigh, Source: "osv"}); err != nil {
		t.Fatal(err)
	}
	rows, err := s.HostSoftware(ctx, id)
	if err != nil || len(rows) != 1 || rows[0].CVECount != 1 || rows[0].Severity != vuln.SeverityHigh || rows[0].Running != 1 {
		t.Fatalf("host software: %+v %v", rows, err)
	}

	// Upgrade, new release, removal.
	nginx2 := nginx
	nginx2.PackageVersion = "1.22.1-9+deb12u1"
	php := SoftwareItem{Software: "php", Cycle: "8.2", Version: "8.2.26", Package: "php8.2-common", PackageVersion: "8.2.26-1", Running: -1}
	ev, err = s.SyncSoftware(ctx, id, "apt", []SoftwareItem{nginx2, php})
	if err != nil || len(ev) != 2 || ev[0].Event != SoftwareUpgraded || ev[0].OldVersion != "1.22.1-9" || ev[1].Event != SoftwareInstalled || ev[1].Hostname != "web-01" {
		t.Fatalf("second sync: %+v %v", ev, err)
	}
	ev, err = s.SyncSoftware(ctx, id, "apt", []SoftwareItem{nginx})
	if err != nil || len(ev) != 2 {
		t.Fatalf("third sync: %+v %v", ev, err)
	}
	kinds := map[string]bool{}
	for _, e := range ev {
		kinds[e.Event] = true
	}
	if !kinds[SoftwareDowngraded] || !kinds[SoftwareRemoved] {
		t.Errorf("third sync events: %+v", ev)
	}
	list, total, err := s.ListSoftwareEvents(ctx, SoftwareEventFilter{HostID: id}, Page{Number: 1, Size: 10})
	if err != nil || total != 4 || len(list) != 4 {
		t.Errorf("history: %d %v", total, err)
	}
	if _, total, _ := s.ListSoftwareEvents(ctx, SoftwareEventFilter{Software: "php", Event: SoftwareInstalled}, Page{Number: 1, Size: 10}); total != 1 {
		t.Errorf("filtered history: %d", total)
	}

	sums, err := s.SoftwareSummaries(ctx)
	if err != nil || len(sums) != 1 || sums[0].Software != "nginx" || sums[0].Hosts != 1 || sums[0].Running != 1 || sums[0].CVECount != 1 || sums[0].Cycles[0].Cycle != "1.22" {
		t.Errorf("summaries: %+v %v", sums, err)
	}
	hosts, err := s.SoftwareHosts(ctx, "nginx", "1.22")
	if err != nil || len(hosts) != 1 || hosts[0].Hostname != "web-01" {
		t.Errorf("software hosts: %+v %v", hosts, err)
	}
	// Group-limited users without this host see nothing.
	if sums, _ := s.SoftwareSummaries(WithScope(ctx, []int64{})); len(sums) != 0 {
		t.Errorf("scoped summaries: %+v", sums)
	}
	if hosts, _ := s.SoftwareHosts(WithScope(ctx, []int64{}), "nginx", ""); len(hosts) != 0 {
		t.Errorf("scoped hosts: %+v", hosts)
	}
}
