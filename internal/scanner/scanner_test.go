package scanner

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"netio.patchman/internal/protocol"
	"netio.patchman/internal/vuln"
)

func TestCVSSBaseScore(t *testing.T) {
	cases := []struct {
		vector  string
		score   float64
		version string
	}{
		// Reference scores from the FIRST CVSS v3.1 calculator.
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "3.1"},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "3.1"},
		{"CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 4.6, "3.1"},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", 5.3, "3.1"},
		{"CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:N", 4.4, "3.0"},
		{"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, "3.1"},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0, "3.1"},
		// CVSS v2 (NVD calculator).
		{"AV:N/AC:L/Au:N/C:P/I:P/A:P", 7.5, "2.0"},
		{"AV:N/AC:M/Au:N/C:N/I:P/A:N", 4.3, "2.0"},
	}
	for _, c := range cases {
		got, ver, ok := CVSSBaseScore(c.vector)
		if !ok || got != c.score || ver != c.version {
			t.Errorf("%s = %v %s %v, want %v %s", c.vector, got, ver, ok, c.score, c.version)
		}
	}
	if _, ver, ok := CVSSBaseScore("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"); ok || ver != "4.0" {
		t.Error("v4 vectors must be reported as not computable")
	}
	if _, _, ok := CVSSBaseScore("CVSS:3.1/AV:X/AC:L"); ok {
		t.Error("malformed vector accepted")
	}
}

func TestTargetFor(t *testing.T) {
	cases := []struct {
		info      protocol.HostInfo
		ecos      []string
		useSource bool
	}{
		{protocol.HostInfo{OSID: "debian", OSVersionID: "12"}, []string{"Debian:12"}, true},
		{protocol.HostInfo{OSID: "ubuntu", OSVersionID: "24.04", OSVersion: "24.04.1 LTS (Noble Numbat)"}, []string{"Ubuntu:24.04:LTS"}, true},
		{protocol.HostInfo{OSID: "ubuntu", OSVersionID: "24.10", OSVersion: "24.10 (Oracular Oriole)"}, []string{"Ubuntu:24.10"}, true},
		{protocol.HostInfo{OSID: "almalinux", OSVersionID: "9.4"}, []string{"AlmaLinux:9"}, false},
		{protocol.HostInfo{OSID: "rocky", OSVersionID: "8.10"}, []string{"Rocky Linux:8"}, false},
		{protocol.HostInfo{OSID: "rhel", OSVersionID: "9.4"}, []string{"Red Hat:enterprise_linux:9::baseos", "Red Hat:enterprise_linux:9::appstream"}, false},
		{protocol.HostInfo{OSID: "alpine", OSVersionID: "3.20.3"}, []string{"Alpine:v3.20"}, true},
		{protocol.HostInfo{OSID: "opensuse-leap", OSVersionID: "15.5"}, []string{"openSUSE:Leap 15.5"}, false},
		{protocol.HostInfo{OSID: "sles", OSVersionID: "15.5"}, []string{"SUSE:Linux Enterprise Server 15 SP5"}, false},
		{protocol.HostInfo{OSID: "cloudlinux", OSVersionID: "8.10"}, []string{"AlmaLinux:8"}, false},
		{protocol.HostInfo{OSID: "cloudlinux", OSVersionID: "9.4"}, []string{"AlmaLinux:9"}, false},
		{protocol.HostInfo{OSID: "cloudlinux", OSVersionID: "7.9"}, []string{"Red Hat:enterprise_linux:7::server", "TuxCare:CentOS:7"}, false},
		{protocol.HostInfo{OSID: "centos", OSVersionID: "7", OSName: "CentOS Linux 7 (Core)"}, []string{"Red Hat:enterprise_linux:7::server", "TuxCare:CentOS:7"}, false},
		{protocol.HostInfo{OSID: "centos", OSVersionID: "8", OSName: "CentOS Linux 8"}, []string{"AlmaLinux:8"}, false},
		{protocol.HostInfo{OSID: "centos", OSVersionID: "9", OSName: "CentOS Stream 9"}, nil, false},
		{protocol.HostInfo{OSID: "ol", OSVersionID: "9.4"}, []string{"AlmaLinux:9"}, false},
		{protocol.HostInfo{OSID: "ol", OSVersionID: "7.9"}, []string{"Red Hat:enterprise_linux:7::server", "TuxCare:CentOS:7"}, false},
		{protocol.HostInfo{OSID: "mageia", OSVersionID: "9"}, []string{"Mageia:9"}, false},
		{protocol.HostInfo{OSID: "openEuler", OSVersionID: "22.03", OSVersion: "22.03 (LTS-SP1)"}, []string{"openEuler:22.03-LTS-SP1"}, false},
		{protocol.HostInfo{OSID: "raspbian", OSVersionID: "12"}, []string{"Debian:12"}, true},
		{protocol.HostInfo{OSID: "linuxmint", OSVersionID: "21.3", Upstream: "ubuntu:jammy"}, []string{"Ubuntu:22.04:LTS"}, true},
		{protocol.HostInfo{OSID: "pop", OSVersionID: "24.10", Upstream: "ubuntu:oracular"}, []string{"Ubuntu:24.10"}, true},
		{protocol.HostInfo{OSID: "linuxmint", OSVersionID: "6", Upstream: "debian:bookworm"}, []string{"Debian:12"}, true},
		{protocol.HostInfo{OSID: "linuxmint", OSVersionID: "99", Upstream: "ubuntu:unknownname"}, nil, false}, {protocol.HostInfo{OSID: "windows", OSVersionID: "10.0.20348"}, []string{"Windows"}, false},
		{protocol.HostInfo{OSID: "fedora", OSVersionID: "40"}, nil, false},
	}
	for _, c := range cases {
		got := TargetFor(c.info)
		if len(got.Ecosystems) != len(c.ecos) || got.UseSource != c.useSource {
			t.Errorf("%s %s: %+v", c.info.OSID, c.info.OSVersionID, got)
			continue
		}
		for i := range c.ecos {
			if got.Ecosystems[i] != c.ecos[i] {
				t.Errorf("%s: ecosystem %q, want %q", c.info.OSID, got.Ecosystems[i], c.ecos[i])
			}
		}
	}
	deb := TargetFor(protocol.HostInfo{OSID: "debian", OSVersionID: "12"})
	name, ver := deb.QueryPackage(protocol.Package{Name: "libssl3", Version: "3.0.11-1~deb12u2", SourceName: "openssl", SourceVersion: "3.0.11-1~deb12u2"})
	if name != "openssl" || ver != "3.0.11-1~deb12u2" {
		t.Errorf("debian must query source package, got %s %s", name, ver)
	}
}

// Shapes taken from api.osv.dev responses.
const debianRecord = `{
 "id": "DEBIAN-CVE-2024-13176", "modified": "2026-11-10T09:47:35Z", "upstream": ["CVE-2024-13176"],
 "details": "Issue summary: A timing side-channel which could potentially allow recovering the private key exists in the ECDSA signature computation.",
 "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
 "affected": [
  {"package": {"name": "openssl", "ecosystem": "Debian:11"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.1.1w-0+deb11u3"}]}]},
  {"package": {"name": "openssl", "ecosystem": "Debian:12"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.0.16-1~deb12u1"}]}], "ecosystem_specific": {"urgency": "low"}}
 ]}`

const almaRecord = `{
 "id": "ALSA-2024:0310", "summary": "Moderate: openssl security update", "modified": "2026-01-01T00:00:00Z",
 "upstream": ["CVE-2023-5363"], "related": ["CVE-2023-5363"],
 "affected": [{"package": {"name": "openssl", "ecosystem": "AlmaLinux:9"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1:3.0.7-25.el9_3"}]}]}],
 "references": [{"type": "ADVISORY", "url": "https://errata.almalinux.org/9/ALSA-2024-0310.html"}]}`

const ubuntuRecord = `{
 "id": "UBUNTU-CVE-2024-13176", "upstream": ["CVE-2024-13176"],
 "severity": [{"type": "Ubuntu", "score": "low"}],
 "affected": [{"package": {"name": "openssl", "ecosystem": "Ubuntu:24.04:LTS"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}]}`

const cveRecord = `{
 "id": "CVE-2024-13176", "summary": "Timing side-channel in ECDSA signature computation",
 "details": "Issue summary: A timing side-channel which could potentially allow recovering\nthe private key exists in the ECDSA signature computation.",
 "published": "2025-01-20T14:15:26Z", "modified": "2026-11-01T00:00:00Z",
 "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
 "references": [{"type": "WEB", "url": "http://www.openwall.com/lists/oss-security/2025/01/20/2"}]}`

func mustParse(t *testing.T, s string) Record {
	t.Helper()
	r, err := ParseRecord([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRecordParsing(t *testing.T) {
	deb := mustParse(t, debianRecord)
	if ids := deb.CVEIDs(); len(ids) != 1 || ids[0] != "CVE-2024-13176" {
		t.Errorf("debian CVE ids: %v", ids)
	}
	if deb.IsAdvisory() {
		t.Error("DEBIAN-CVE record is not an advisory")
	}
	if f := deb.FixedVersion("Debian:12", "openssl"); f != "3.0.16-1~deb12u1" {
		t.Errorf("fixed version picked from wrong ecosystem: %q", f)
	}
	h := deb.SeverityHints("Debian:12", "openssl")
	if h.Score == nil || *h.Score != 4.6 || h.Qualitative != vuln.SeverityLow {
		t.Errorf("debian hints: %+v", h)
	}

	alma := mustParse(t, almaRecord)
	if !alma.IsAdvisory() || alma.AdvisoryURL() != "https://errata.almalinux.org/9/ALSA-2024-0310.html" {
		t.Errorf("alma advisory: %v %q", alma.IsAdvisory(), alma.AdvisoryURL())
	}
	if h := alma.SeverityHints("AlmaLinux:9", "openssl"); h.Qualitative != vuln.SeverityMedium {
		t.Errorf("alma qualitative severity from summary: %+v", h)
	}
	if f := alma.FixedVersion("AlmaLinux:9", "openssl"); f != "1:3.0.7-25.el9_3" {
		t.Errorf("alma fixed: %q", f)
	}

	ub := mustParse(t, ubuntuRecord)
	if f := ub.FixedVersion("Ubuntu:24.04:LTS", "openssl"); f != "" {
		t.Errorf("unfixed ubuntu record returned %q", f)
	}
}

// Ubuntu kernel records list every binary package; the cache keeps only what
// the scanner uses, with text verbatim.
func TestRecordCompact(t *testing.T) {
	bins := make([]string, 2000)
	for i := range bins {
		bins[i] = fmt.Sprintf(`{"binary_name":"linux-modules-6.8.0-%d-generic","binary_version":"6.8.0-%d.%d"}`, i, i, i)
	}
	raw := `{"id":"UBUNTU-CVE-2026-1","modified":"2026-11-01T00:00:00Z","upstream":["CVE-2026-1"],
	 "details":"In the Linux kernel, <b>x</b> & \"y\" ü\n",
	 "severity":[{"type":"Ubuntu","score":"medium"}],
	 "database_specific":{"severity":"High","cwe_ids":["CWE-1"]},
	 "affected":[{"package":{"name":"linux","ecosystem":"Ubuntu:24.04:LTS","purl":"pkg:deb/ubuntu/linux"},
	   "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"6.8.0-149.149"}]}],
	   "versions":["6.8.0-1.1","6.8.0-2.2"],
	   "ecosystem_specific":{"binaries":[` + strings.Join(bins, ",") + `],"urgency":"low"}}]}`
	rec := mustParse(t, raw)
	data, err := rec.Compact()
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > 1024 || len(raw) < 100*1024 {
		t.Fatalf("compact size %d (raw %d)", len(data), len(raw))
	}
	got := mustParse(t, string(data))
	if !reflect.DeepEqual(got, rec) {
		t.Fatalf("round trip differs:\n%+v\n%+v", got, rec)
	}
	if got.Details != "In the Linux kernel, <b>x</b> & \"y\" ü\n" || !strings.Contains(string(data), "<b>x</b> &") {
		t.Errorf("details not verbatim: %q / %s", got.Details, data)
	}
	if f := got.FixedVersion("Ubuntu:24.04:LTS", "linux"); f != "6.8.0-149.149" {
		t.Errorf("fixed %q", f)
	}
	if h := got.SeverityHints("Ubuntu:24.04:LTS", "linux"); h.Qualitative != vuln.SeverityLow {
		t.Errorf("urgency lost: %+v", h)
	}
	if q := qualitative(got.DatabaseSpecific.get("severity")); q != vuln.SeverityHigh {
		t.Errorf("record severity lost: %q", q)
	}
}

func TestBuildVulnerabilityPrefersOfficialRecord(t *testing.T) {
	cve := mustParse(t, cveRecord)
	deb := mustParse(t, debianRecord)
	v := BuildVulnerability("CVE-2024-13176", &cve, []Record{deb}, []SeverityHint{deb.SeverityHints("Debian:12", "openssl")})
	if v.Title != "Timing side-channel in ECDSA signature computation" {
		t.Errorf("title: %q", v.Title)
	}
	if v.Description != cve.Details { // verbatim, including the line break
		t.Errorf("description not verbatim: %q", v.Description)
	}
	if v.CVSSScore == nil || *v.CVSSScore != 4.6 || v.Severity != vuln.SeverityMedium || v.CVSSVersion != "3.1" {
		t.Errorf("severity: %+v", v)
	}
	if v.PublishedAt.IsZero() || len(v.References) != 1 {
		t.Errorf("published/references: %+v", v)
	}

	// Without the official record, the per-CVE distribution record's text is used.
	v2 := BuildVulnerability("CVE-2024-13176", nil, []Record{deb}, []SeverityHint{deb.SeverityHints("Debian:12", "openssl")})
	if v2.Description != deb.Details {
		t.Errorf("fallback description: %q", v2.Description)
	}

	// Only a qualitative rating available.
	ub := mustParse(t, ubuntuRecord)
	v3 := BuildVulnerability("CVE-2024-13176", nil, []Record{ub}, []SeverityHint{ub.SeverityHints("Ubuntu:24.04:LTS", "openssl")})
	if v3.Severity != vuln.SeverityLow || v3.CVSSScore != nil {
		t.Errorf("qualitative severity: %+v", v3)
	}
}
