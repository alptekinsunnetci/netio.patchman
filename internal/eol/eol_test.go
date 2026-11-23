package eol

import (
	"testing"
	"time"
)

func day(s string) time.Time {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestParseProductAndStatus(t *testing.T) {
	rel, err := ParseProduct([]byte(`[
		{"cycle":"12","releaseDate":"2023-06-10","eol":"2028-06-30","support":"2026-07-11","extendedSupport":"2033-06-30","lts":false,"latest":"12.15"},
		{"cycle":"3.8","eol":false},
		{"cycle":"2.2","eol":true},
		{"cycle":8.0,"eol":"2026-04-30"},
		{"eol":"2020-01-01"}
	]`))
	if err != nil || len(rel) != 4 {
		t.Fatalf("parse: %v %+v", err, rel)
	}
	deb := rel[0]
	if !deb.EOL.Equal(day("2028-06-30")) || !deb.Support.Equal(day("2026-07-11")) || !deb.Extended.Equal(day("2033-06-30")) || deb.Latest != "12.15" {
		t.Errorf("debian 12: %+v", deb)
	}
	if rel[3].Cycle != "8" {
		t.Errorf("numeric cycle: %q", rel[3].Cycle)
	}
	warn := 90 * 24 * time.Hour
	for _, c := range []struct {
		r    Release
		now  string
		want string
	}{
		{deb, "2026-01-01", StatusSupported},
		{deb, "2028-05-01", StatusSoon},
		{deb, "2028-06-30", StatusEOL},
		{rel[1], "2030-01-01", StatusSupported}, // no end announced
		{rel[2], "2000-01-01", StatusEOL},       // ended without a date
	} {
		if got := c.r.Status(day(c.now), warn); got != c.want {
			t.Errorf("%s at %s: %s, want %s", c.r.Cycle, c.now, got, c.want)
		}
	}
	if !deb.ActiveSupportOver(day("2027-01-01")) || deb.ActiveSupportOver(day("2026-01-01")) {
		t.Errorf("active support")
	}
	if n := deb.DaysLeft(day("2028-06-20")); n != 10 {
		t.Errorf("days left: %d", n)
	}
}

func TestEmbeddedCoversProducts(t *testing.T) {
	d := Embedded()
	for _, p := range Products() {
		if len(d[p]) == 0 {
			t.Errorf("no built-in calendar for %s", p)
		}
	}
}

func TestForOS(t *testing.T) {
	d := Embedded()
	for _, c := range []struct {
		id, version, name, kernel string
		product, cycle, via       string
		ok                        bool
	}{
		{"debian", "12", "Debian GNU/Linux 12 (bookworm)", "", "debian", "12", "", true},
		{"ubuntu", "22.04", "Ubuntu 22.04.5 LTS", "", "ubuntu", "22.04", "", true},
		{"rocky", "9.4", "Rocky Linux 9.4 (Blue Onyx)", "", "rocky-linux", "9", "", true},
		{"cloudlinux", "8.10", "CloudLinux 8.10", "", "rhel", "8", "Red Hat Enterprise Linux", true},
		{"centos", "9", "CentOS Stream 9", "", "centos-stream", "9", "", true},
		{"centos", "7", "CentOS Linux 7 (Core)", "", "centos", "7", "", true},
		{"alpine", "3.19.1", "Alpine Linux v3.19", "", "alpine-linux", "3.19", "", true},
		{"sles", "15.6", "SUSE Linux Enterprise Server 15 SP6", "", "sles", "15.6", "", true},
		{"ol", "8.10", "Oracle Linux Server 8.10", "", "oracle-linux", "8", "", true},
		{"windows", "", "Windows Server 2022 Datacenter", "10.0.20348.2762", "windows-server", "2022", "", true},
		{"windows", "", "Windows Server 2019 Standard", "10.0.17763.6532", "windows-server", "2019", "", true},
		{"windows", "", "Windows 11 Pro", "10.0.22631.4460", "", "", "", false},
		{"linuxmint", "21.3", "Linux Mint 21.3", "", "", "", "", false},
	} {
		got, ok := d.ForOS(c.id, c.version, c.name, c.kernel)
		if ok != c.ok || got.Product != c.product || got.Cycle != c.cycle || got.Via != c.via {
			t.Errorf("%s %s: %+v %v", c.id, c.version, got, ok)
		}
	}
}

func TestDistroPackage(t *testing.T) {
	for _, c := range []struct {
		pm, v string
		want  bool
	}{
		{"apt", "8.2.26-1~deb12u1", true},
		{"apt", "1.22.1-9+deb12u2", true},
		{"apt", "8.1.2-1ubuntu2.20", true},
		{"apt", "8.1.31-1+0~20241121.98+debian12~1.gbp9d44f7", false}, // sury
		{"apt", "16.6-1.pgdg120+1", false},
		{"apt", "1:10.11.10+maria~deb12", false},
		{"apt", "1.26.2-1~bookworm", false}, // nginx.org
		{"apt", "11.2.0-2~bpo12+1", false},  // backports: no security support
		{"dnf", "8.0.30-1.module+el8.9.0+1590+64c8a33e", true},
		{"dnf", "2.4.62-1.el9", true},
		{"dnf", "8.2.26-1.el9.remi", false},
		{"dnf", "16.4-1PGDG.rhel9", false},
		{"apk", "8.2.26-r0", true},
	} {
		if got := DistroPackage(c.pm, c.v); got != c.want {
			t.Errorf("%s %s: %v", c.pm, c.v, got)
		}
	}
}

func TestAssess(t *testing.T) {
	d := Data{
		"ubuntu": {{Cycle: "20.04", EOL: day("2025-05-31")}, {Cycle: "22.04", EOL: day("2027-06-01")}},
		"php":    {{Cycle: "8.1", EOL: day("2025-12-31")}, {Cycle: "8.3", EOL: day("2027-12-31")}},
		"nginx":  {{Cycle: "1.24", Ended: true}},
	}
	now := day("2027-04-01")
	hosts := []HostInput{
		{ID: 1, Hostname: "old", OSID: "ubuntu", OSVersionID: "20.04", PackageManager: "apt",
			Software: []SoftwareInput{{Software: "php", Cycle: "8.1", Version: "8.1.2", PackageVersion: "8.1.2-1ubuntu2.20"}}},
		{ID: 2, Hostname: "new", OSID: "ubuntu", OSVersionID: "22.04", PackageManager: "apt",
			Software: []SoftwareInput{
				{Software: "php", Cycle: "8.1", Version: "8.1.2", PackageVersion: "8.1.2-1ubuntu2.20"},
				{Software: "php", Cycle: "8.3", Version: "8.3.1", PackageVersion: "8.3.1-1+ubuntu22.04.1+deb.sury.org+1"},
				{Software: "nginx", Cycle: "1.24", Version: "1.24.0", PackageVersion: "1.24.0-1~jammy"},
				{Software: "openssh", Cycle: "8.9", Version: "8.9p1"}, // no calendar: skipped
				{Software: "redis", Cycle: "7.0", Version: "7.0.15"},  // not in this data: unknown
			}},
	}
	items := Assess(d, now, 90*24*time.Hour, hosts)
	if len(items) != 7 {
		t.Fatalf("items: %d %+v", len(items), items)
	}
	by := map[string]Item{}
	for _, it := range items {
		by[it.Hostname+" "+it.Product+" "+it.Cycle] = it
	}
	check := func(key, status string, distro bool) {
		t.Helper()
		it, ok := by[key]
		if !ok || it.Status != status || it.DistroSupported != distro {
			t.Errorf("%s: %+v", key, it)
		}
	}
	check("old ubuntu 20.04", StatusEOL, false)
	check("old php 8.1", StatusEOL, false) // distribution build, but the OS is out of support too
	check("new ubuntu 22.04", StatusSoon, false)
	check("new php 8.1", StatusEOL, true) // Ubuntu keeps patching its own PHP 8.1
	check("new php 8.3", StatusSupported, false)
	check("new nginx 1.24", StatusEOL, false)
	check("new redis 7.0", StatusUnknown, false)

	groups := GroupItems(items)
	if groups[0].Status != StatusEOL || groups[len(groups)-1].Status != StatusSupported {
		t.Errorf("group order: %+v", groups)
	}
	for _, g := range groups {
		if g.Product == "php" && g.Cycle == "8.1" && (len(g.Hosts) != 2 || g.DistroSupported != 1) {
			t.Errorf("php 8.1 group: %+v", g)
		}
	}
	s := Summarize(items)
	if s.OSEOL != 1 || s.OSSoon != 1 || s.SoftwareEOL != 2 || s.SoftwareEOLDistro != 1 || s.SoftwareSoon != 0 {
		t.Errorf("summary: %+v", s)
	}
}
