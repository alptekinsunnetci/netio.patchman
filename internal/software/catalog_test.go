package software

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"netio.patchman/internal/protocol"
)

func detected(pm string, pkgs []protocol.Package, products []protocol.Product, services []protocol.Service) map[string]Installed {
	got := map[string]Installed{}
	for _, in := range Detect(pm, pkgs, products, services, services != nil) {
		got[in.Software+" "+in.Cycle] = in
	}
	return got
}

func expectCycles(t *testing.T, got map[string]Installed, want ...string) {
	t.Helper()
	for _, k := range want {
		if _, ok := got[k]; !ok {
			t.Errorf("%s not detected; got %v", k, keys(got))
		}
	}
	if len(got) != len(want) {
		t.Errorf("detected %d products, want %d: %v", len(got), len(want), keys(got))
	}
}

func keys(m map[string]Installed) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func TestDetectDebianServerStack(t *testing.T) {
	pkgs := []protocol.Package{
		{Name: "python3.11", Version: "3.11.2-6+deb12u4"},
		{Name: "python3", Version: "3.11.2-1+b1"},
		{Name: "python3.11-minimal", Version: "3.11.2-6+deb12u4"},
		{Name: "openjdk-17-jre-headless", Version: "17.0.13+11-2~deb12u1"},
		{Name: "openjdk-8-jre-headless", Version: "8u432-ga-1~deb12u1"},
		{Name: "tomcat10", Version: "10.1.31-1"},
		{Name: "perl", Version: "5.36.0-7+deb12u1"},
		{Name: "perl-base", Version: "5.36.0-7+deb12u1"},
		{Name: "ruby3.1", Version: "3.1.2-7+deb12u1"},
		{Name: "golang-1.19-go", Version: "1.19.8-2"},
		{Name: "libssl3", Version: "3.0.15-1~deb12u1"},
		{Name: "openssl", Version: "3.0.15-1~deb12u1"},
		{Name: "bind9", Version: "1:9.18.33-1~deb12u2"},
		{Name: "dovecot-core", Version: "1:2.3.19.1+dfsg1-2.1+deb12u1"},
		{Name: "proftpd-core", Version: "1.3.8+dfsg-4+deb12u4"},
		{Name: "samba", Version: "2:4.17.12+dfsg-0+deb12u1"},
		{Name: "memcached", Version: "1.6.18-1"},
		{Name: "rabbitmq-server", Version: "3.10.8-1.1"},
		{Name: "zabbix-agent2", Version: "1:7.0.6-1+debian12"},
		{Name: "fail2ban", Version: "1.0.2-2"},
		{Name: "clamav-daemon", Version: "1.0.7+dfsg-1~deb12u1"},
		{Name: "clamav", Version: "1.0.7+dfsg-1~deb12u1"},
		{Name: "wireguard-tools", Version: "1.0.20210914-1+b1"},
		{Name: "slapd", Version: "2.5.13+dfsg-5"},
		{Name: "containerd.io", Version: "1.7.24-1"},
		{Name: "gitlab-ce", Version: "17.5.1-ce.0"},
		{Name: "aspnetcore-runtime-8.0", Version: "8.0.11-1"},
	}
	services := []protocol.Service{
		{Name: "tomcat10", State: "running"}, {Name: "named", State: "running"}, {Name: "dovecot", State: "stopped"},
		{Name: "zabbix-agent2", State: "running"}, {Name: "clamav-daemon", State: "failed"}, {Name: "wg-quick@wg0", State: "running"},
	}
	got := detected(protocol.PMApt, pkgs, nil, services)
	expectCycles(t, got, "python 3.11", "java 17", "java 8", "tomcat 10.1", "perl 5.36", "ruby 3.1", "go 1.19", "openssl 3.0",
		"bind 9.18", "dovecot 2.3", "proftpd 1.3.8", "samba 4.17", "memcached 1.6", "rabbitmq 3.10", "zabbix-agent 7.0",
		"fail2ban 1.0", "clamav 1.0", "wireguard 1.0", "openldap 2.5", "containerd 1.7", "gitlab 17.5", "dotnet 8")
	for k, w := range map[string]struct {
		pkg     string
		running int
	}{
		"python 3.11": {"python3.11", RunningUnknown}, "openssl 3.0": {"libssl3", RunningUnknown}, "tomcat 10.1": {"tomcat10", Running},
		"dovecot 2.3": {"dovecot-core", NotRunning}, "clamav 1.0": {"clamav-daemon", NotRunning}, "wireguard 1.0": {"wireguard-tools", Running},
		"bind 9.18": {"bind9", Running}, "java 8": {"openjdk-8-jre-headless", RunningUnknown},
	} {
		if g := got[k]; g.Package != w.pkg || g.Running != w.running {
			t.Errorf("%s: package %q running %d, want %q %d", k, g.Package, g.Running, w.pkg, w.running)
		}
	}
}

func TestDetectRedHatAndAlpine(t *testing.T) {
	rpm := []protocol.Package{
		{Name: "java-1.8.0-openjdk-headless", Version: "1:1.8.0.432.b06-2.el9"},
		{Name: "java-21-openjdk-headless", Version: "1:21.0.5.0.11-2.el9"},
		{Name: "python3", Version: "3.9.19-8.el9_5.1"},
		{Name: "python3.12", Version: "3.12.5-2.el9_5.2"},
		{Name: "openssl-libs", Version: "1:3.2.2-6.el9_5"},
		{Name: "bind", Version: "32:9.16.23-24.el9_5"},
		{Name: "zabbix-server-pgsql", Version: "7.0.6-release1.el9"},
		{Name: "mssql-server", Version: "16.0.4165.4-7"},
		{Name: "plesk-core", Version: "18.0.65.2-almalinux9.build1800241113.14"},
		{Name: "proftpd", Version: "1.3.8b-1.el9"},
	}
	expectCycles(t, detected(protocol.PMDnf, rpm, nil, nil), "java 8", "java 21", "python 3.9", "python 3.12", "openssl 3.2",
		"bind 9.16", "zabbix-server 7.0", "mssql 16.0", "plesk 18.0.65", "proftpd 1.3.8")

	apk := []protocol.Package{
		{Name: "python3", Version: "3.12.8-r1"},
		{Name: "libssl3", Version: "3.3.2-r1"},
		{Name: "openjdk17-jre-headless", Version: "17.0.13_p11-r0"},
		{Name: "go", Version: "1.23.4-r0"},
		{Name: "unbound", Version: "1.22.0-r0"},
	}
	expectCycles(t, detected(protocol.PMApk, apk, nil, nil), "python 3.12", "openssl 3.3", "java 17", "go 1.23", "unbound 1.22")
}

func TestDetectWindowsPrograms(t *testing.T) {
	progs := []protocol.Package{
		{Name: "Python 3.12.7 (64-bit)", Version: "3.12.7150.0"},
		{Name: "Java 8 Update 431 (64-bit)", Version: "8.0.4310.11"},
		{Name: "Eclipse Temurin JDK with Hotspot 17.0.13+11 (x64)", Version: "17.0.13.11"},
		{Name: "Microsoft .NET Runtime - 8.0.11 (x64)", Version: "8.0.11.34221"},
		{Name: "Microsoft ASP.NET Core 6.0.36 - Shared Framework (x64)", Version: "6.0.36.24516"},
		{Name: "MySQL Server 8.0", Version: "8.0.40"},
		{Name: "PostgreSQL 16 ", Version: "16.6-1"},
		{Name: "Apache Tomcat 9.0 Tomcat9", Version: "9.0.97"},
		{Name: "Zabbix Agent 2 (64-bit)", Version: "7.0.6.2400"},
		{Name: "OpenVPN 2.6.12-I001 amd64", Version: "2.6.1201"},
		{Name: "FileZilla Server", Version: "1.9.4"},
		{Name: "Microsoft Exchange Server", Version: "15.2.1544.4"},
		{Name: "Node.js", Version: "20.18.0"},
		{Name: "7-Zip 24.08 (x64)", Version: "24.08"},
	}
	products := []protocol.Product{{Software: "iis", Version: "10.0"}, {Software: "mssql", Version: "15.0.4385.2"}}
	services := []protocol.Service{{Name: "W3SVC", State: "running"}, {Name: "MSSQLSERVER", State: "running"}, {Name: "Tomcat9", State: "stopped"},
		{Name: "MySQL80", State: "running"}, {Name: "postgresql-x64-16", State: "running"}}
	got := detected(protocol.PMWindowsUpdate, progs, products, services)
	expectCycles(t, got, "python 3.12", "java 8", "java 17", "dotnet 8", "dotnet 6", "mysql 8.0", "postgresql 16", "tomcat 9.0",
		"zabbix-agent 7.0", "openvpn 2.6", "filezilla-server 1.9", "exchange 2019", "nodejs 20", "iis 10.0", "mssql 15.0")
	if g := got["iis 10.0"]; g.Package != "" || g.Version != "10.0" || g.Running != Running || g.Service != "W3SVC" {
		t.Errorf("iis: %+v", g)
	}
	if g := got["mssql 15.0"]; g.Version != "15.0.4385.2" || g.Running != Running {
		t.Errorf("mssql: %+v", g)
	}
	if g := got["tomcat 9.0"]; g.Running != NotRunning || g.Service != "Tomcat9" {
		t.Errorf("tomcat: %+v", g)
	}
}

func TestProbedProductsYieldToPackages(t *testing.T) {
	pkgs := []protocol.Package{{Name: "openlitespeed", Version: "1.8.2-1+bookworm"}}
	products := []protocol.Product{{Software: "openlitespeed", Version: "1.8.2"}, {Software: "cpanel", Version: "11.124.0.15"}}
	got := detected(protocol.PMApt, pkgs, products, nil)
	expectCycles(t, got, "openlitespeed 1.8", "cpanel 11.124")
	if got["openlitespeed 1.8"].Package != "openlitespeed" || got["cpanel 11.124"].Package != "" {
		t.Errorf("sources: %+v", got)
	}
}

func TestCycles(t *testing.T) {
	for _, c := range []struct {
		f    func(string) string
		in   string
		want string
	}{
		{javaCycle, "1.8.0.432.b06", "8"}, {javaCycle, "17.0.13+11", "17"}, {javaCycle, "8u432-ga", "8"}, {javaCycle, "21", "21"},
		{components(3), "1.3.8b", "1.3.8"}, {components(3), "18.0.65", "18.0.65"}, {components(3), "1.3", "1.3"},
		{exchangeCycle, "15.2.1544.4", "2019"}, {exchangeCycle, "15.2.2562.17", "subscription"}, {exchangeCycle, "15.1.2507.39", "2016"},
		{exchangeCycle, "15.0.1497.2", "2013"}, {exchangeCycle, "8.3.517", ""},
	} {
		if got := c.f(c.in); got != c.want {
			t.Errorf("%s: %q, want %q", c.in, got, c.want)
		}
	}
}

// TestCatalogConsistent: unique ids, every category labeled, probed
// products in the catalog, catalog sorted by name.
func TestCatalogConsistent(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "i18n", "locales", "tr-TR.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cat map[string]string
	if err := json.Unmarshal(b, &cat); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for i, d := range Catalog {
		if seen[d.ID] {
			t.Errorf("duplicate id %s", d.ID)
		}
		seen[d.ID] = true
		if cat["software.category."+d.Category] == "" {
			t.Errorf("%s: no label for category %s", d.ID, d.Category)
		}
		if len(d.Packages) == 0 && !slices.Contains(Probed, d.ID) {
			t.Errorf("%s can never be detected", d.ID)
		}
		if i > 0 && lower(Catalog[i-1].Name) > lower(d.Name) {
			t.Errorf("catalog not sorted at %s", d.Name)
		}
	}
	for _, id := range Probed {
		if !seen[id] {
			t.Errorf("probed %s not in the catalog", id)
		}
	}
}

func lower(s string) string { return strings.ToLower(s) }
