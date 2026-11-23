// Package software recognizes well-known server software (web servers,
// databases, runtimes, mail and container platforms) in a host's package
// inventory and service list. Names of products are verbatim and not
// translated; categories are catalog keys.
package software

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	"netio.patchman/internal/pkgver"
	"netio.patchman/internal/protocol"
)

// Categories (catalog key "software.category.<id>").
const (
	CategoryWeb        = "web"
	CategoryDatabase   = "database"
	CategoryCache      = "cache"
	CategoryRuntime    = "runtime"
	CategoryMail       = "mail"
	CategoryContainer  = "container"
	CategoryRemote     = "remote"
	CategorySearch     = "search"
	CategoryQueue      = "queue"
	CategoryDNS        = "dns"
	CategoryFile       = "file"
	CategoryVPN        = "vpn"
	CategoryDirectory  = "directory"
	CategoryMonitoring = "monitoring"
	CategoryDevOps     = "devops"
	CategoryInfra      = "infra"
	CategorySecurity   = "security"
	CategoryPanel      = "panel"
	CategoryLibrary    = "library"
)

// Def describes one product.
type Def struct {
	ID       string // stable id ("nginx"), used in URLs and the database
	Name     string // product name, verbatim
	Category string
	// Packages match the package that carries the product's version, in
	// order of preference (a server package before a metapackage).
	Packages []*regexp.Regexp
	// Services match the product's service names (systemd units without
	// ".service"); none means the product is not a daemon (PHP CLI, Node.js).
	Services []*regexp.Regexp
	// EOL is the endoflife.date product id, "" when the product has no
	// published support calendar.
	EOL string
	// Cycle derives the release cycle from an upstream version; nil uses
	// major.minor.
	Cycle func(upstream string) string
}

func res(patterns ...string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		out[i] = regexp.MustCompile(`(?i)^(?:` + p + `)$`)
	}
	return out
}

// majorFrom uses the major version from release `from` on and major.minor
// before it (PostgreSQL 10, Docker Engine 27).
func majorFrom(from int) func(string) string {
	return func(up string) string {
		m, err := strconv.Atoi(pkgver.Major(up))
		if err == nil && m >= from {
			return strconv.Itoa(m)
		}
		return pkgver.MajorMinor(up)
	}
}

// components returns the first n numeric components of an upstream version
// ("1.3.8b" -> "1.3.8" for n = 3).
func components(n int) func(string) string {
	return func(up string) string {
		var parts []string
		for _, f := range strings.Split(up, ".") {
			i := 0
			for i < len(f) && f[i] >= '0' && f[i] <= '9' {
				i++
			}
			if i == 0 {
				break
			}
			parts = append(parts, strings.TrimLeft(f[:i], "0"))
			if parts[len(parts)-1] == "" {
				parts[len(parts)-1] = "0"
			}
			if len(parts) == n || i < len(f) {
				break
			}
		}
		return strings.Join(parts, ".")
	}
}

// javaCycle is the Java feature release: "1.8.0.432" -> "8", "17.0.13" -> "17".
func javaCycle(up string) string {
	mm := pkgver.MajorMinor(up)
	if major, minor, ok := strings.Cut(mm, "."); ok && major == "1" {
		return minor
	}
	return pkgver.Major(up)
}

// exchangeCycle maps an Exchange build to its release: 15.2 is 2019 (the
// Subscription Edition from build 15.2.2562 on), 15.1 2016, 15.0 2013, 14 2010.
func exchangeCycle(up string) string {
	switch mm := pkgver.MajorMinor(up); {
	case mm == "15.2":
		if b := strings.Split(up, "."); len(b) > 2 {
			if n, err := strconv.Atoi(b[2]); err == nil && n >= 2562 {
				return "subscription"
			}
		}
		return "2019"
	case mm == "15.1":
		return "2016"
	case mm == "15.0":
		return "2013"
	case pkgver.Major(up) == "14":
		return "2010"
	}
	return ""
}

// Catalog is the list of recognized products, ordered by name. Packages
// cover Debian/Ubuntu, the Red Hat family, SUSE and Alpine names and the
// display names of Windows programs; products installed outside the
// package manager (hosting panels, IIS, SQL Server on Windows) come from
// the agent's probes (Report.Products).
var Catalog = []Def{
	{ID: "activemq", Name: "Apache ActiveMQ", Category: CategoryQueue, Packages: res(`activemq`),
		Services: res(`activemq`), EOL: "apache-activemq"},
	{ID: "cassandra", Name: "Apache Cassandra", Category: CategoryDatabase, Packages: res(`cassandra`),
		Services: res(`cassandra`), EOL: "apache-cassandra"},
	{ID: "couchdb", Name: "Apache CouchDB", Category: CategoryDatabase, Packages: res(`couchdb`),
		Services: res(`couchdb`), EOL: "apache-couchdb"},
	{ID: "apache", Name: "Apache HTTP Server", Category: CategoryWeb, Packages: res(`apache2-bin`, `apache2`, `httpd`, `httpd24-httpd`, `ea-apache24`),
		Services: res(`apache2`, `httpd`, `apache2@.+`), EOL: "apache-http-server"},
	{ID: "kafka", Name: "Apache Kafka", Category: CategoryQueue, Packages: res(`kafka`),
		Services: res(`kafka`), EOL: "apache-kafka"},
	{ID: "tomcat", Name: "Apache Tomcat", Category: CategoryWeb, Packages: res(`tomcat\d*`, `apache tomcat \d+.*`),
		Services: res(`tomcat\d*`, `tomcat@.+`), EOL: "tomcat"},
	{ID: "bind", Name: "BIND 9", Category: CategoryDNS, Packages: res(`bind9`, `bind`),
		Services: res(`named`, `bind9`), EOL: "bind-9"},
	{ID: "caddy", Name: "Caddy", Category: CategoryWeb, Packages: res(`caddy`),
		Services: res(`caddy`), EOL: "caddy", Cycle: pkgver.Major},
	{ID: "clamav", Name: "ClamAV", Category: CategorySecurity, Packages: res(`clamav-daemon`, `clamd`, `clamav`),
		Services: res(`clamav-daemon`, `clamd(@.+)?`, `clamd\.scan`), EOL: "clamav"},
	{ID: "clickhouse", Name: "ClickHouse", Category: CategoryDatabase, Packages: res(`clickhouse-server`, `clickhouse-common-static`),
		Services: res(`clickhouse-server`), EOL: "clickhouse"},
	{ID: "cockpit", Name: "Cockpit", Category: CategoryPanel, Packages: res(`cockpit-ws`, `cockpit`)},
	{ID: "consul", Name: "Consul", Category: CategoryInfra, Packages: res(`consul`),
		Services: res(`consul`), EOL: "consul"},
	{ID: "containerd", Name: "containerd", Category: CategoryContainer, Packages: res(`containerd\.io`, `containerd`),
		Services: res(`containerd`), EOL: "containerd"},
	{ID: "cpanel", Name: "cPanel & WHM", Category: CategoryPanel,
		Services: res(`cpanel`)},
	{ID: "directadmin", Name: "DirectAdmin", Category: CategoryPanel,
		Services: res(`directadmin`)},
	{ID: "docker", Name: "Docker Engine", Category: CategoryContainer, Packages: res(`docker-ce`, `docker-engine`, `docker\.io`, `moby-engine`, `docker`),
		Services: res(`docker`), EOL: "docker-engine", Cycle: majorFrom(27)},
	{ID: "dovecot", Name: "Dovecot", Category: CategoryMail, Packages: res(`dovecot-core`, `dovecot`),
		Services: res(`dovecot`), EOL: "dovecot"},
	{ID: "dotnet", Name: ".NET", Category: CategoryRuntime,
		Packages: res(`aspnetcore-runtime-\d+\.\d+`, `dotnet-runtime-\d+\.\d+`, `dotnet\d+`, `microsoft asp\.net core .* shared framework.*`,
			`microsoft \.net runtime - .*`, `microsoft windows desktop runtime - .*`),
		EOL: "dotnet", Cycle: pkgver.Major},
	{ID: "elasticsearch", Name: "Elasticsearch", Category: CategorySearch, Packages: res(`elasticsearch`),
		Services: res(`elasticsearch`), EOL: "elasticsearch"},
	{ID: "exim", Name: "Exim", Category: CategoryMail, Packages: res(`exim4-daemon-heavy`, `exim4-daemon-light`, `exim4-base`, `exim4`, `exim`),
		Services: res(`exim4`, `exim`), EOL: "exim"},
	{ID: "fail2ban", Name: "Fail2ban", Category: CategorySecurity, Packages: res(`fail2ban`),
		Services: res(`fail2ban`)},
	{ID: "filezilla-server", Name: "FileZilla Server", Category: CategoryFile, Packages: res(`filezilla server.*`),
		Services: res(`filezilla-server`, `filezilla server`)},
	{ID: "freeipa", Name: "FreeIPA", Category: CategoryDirectory, Packages: res(`freeipa-server`, `ipa-server`),
		Services: res(`ipa`)},
	{ID: "gitlab", Name: "GitLab", Category: CategoryDevOps, Packages: res(`gitlab-ee`, `gitlab-ce`),
		Services: res(`gitlab-runsvdir`), EOL: "gitlab"},
	{ID: "gitlab-runner", Name: "GitLab Runner", Category: CategoryDevOps, Packages: res(`gitlab-runner`),
		Services: res(`gitlab-runner`)},
	{ID: "go", Name: "Go", Category: CategoryRuntime, Packages: res(`golang-\d+\.\d+-go`, `golang-go`, `golang-bin`, `golang`, `go\d+\.\d+`, `go`, `go programming language .*`),
		EOL: "go"},
	{ID: "grafana", Name: "Grafana", Category: CategoryMonitoring, Packages: res(`grafana-enterprise`, `grafana`),
		Services: res(`grafana-server`, `grafana`), EOL: "grafana"},
	{ID: "haproxy", Name: "HAProxy", Category: CategoryWeb, Packages: res(`haproxy`, `haproxy\d+`),
		Services: res(`haproxy`), EOL: "haproxy"},
	{ID: "influxdb", Name: "InfluxDB", Category: CategoryDatabase, Packages: res(`influxdb3-core`, `influxdb2`, `influxdb`),
		Services: res(`influxdb\d?`, `influxd`), EOL: "influxdb"},
	{ID: "iis", Name: "Internet Information Services (IIS)", Category: CategoryWeb,
		Services: res(`w3svc`)},
	{ID: "java", Name: "Java (OpenJDK)", Category: CategoryRuntime,
		Packages: res(`openjdk-\d+-jre-headless`, `openjdk-\d+-jdk-headless`, `openjdk-\d+-jre`, `openjdk-\d+-jdk`,
			`java-\d+-openjdk-headless`, `java-\d+-openjdk`, `java-1[._]8[._]0-openjdk-headless`, `java-1[._]8[._]0-openjdk`,
			`openjdk\d+-jre-headless`, `openjdk\d+-jre`, `openjdk\d+`, `temurin-\d+-jdk`, `temurin-\d+-jre`,
			`java-\d+-amazon-corretto(-devel|-headless)?`, `zulu\d+-jdk(-headless)?`, `zulu\d+-jre(-headless)?`,
			`java( \d+)? update \d+.*`, `java\(tm\) se development kit .*`, `eclipse temurin (jdk|jre) .*`,
			`microsoft build of openjdk .*`, `amazon corretto .*`),
		EOL: "eclipse-temurin", Cycle: javaCycle},
	{ID: "jenkins", Name: "Jenkins", Category: CategoryDevOps, Packages: res(`jenkins`),
		Services: res(`jenkins`), EOL: "jenkins"},
	{ID: "keepalived", Name: "Keepalived", Category: CategoryInfra, Packages: res(`keepalived`),
		Services: res(`keepalived`)},
	{ID: "kibana", Name: "Kibana", Category: CategorySearch, Packages: res(`kibana`),
		Services: res(`kibana`), EOL: "kibana"},
	{ID: "kubernetes", Name: "Kubernetes", Category: CategoryContainer, Packages: res(`kubelet`, `kubeadm`),
		Services: res(`kubelet`), EOL: "kubernetes"},
	{ID: "lighttpd", Name: "lighttpd", Category: CategoryWeb, Packages: res(`lighttpd`),
		Services: res(`lighttpd`)},
	{ID: "litespeed", Name: "LiteSpeed Web Server", Category: CategoryWeb,
		Services: res(`lshttpd`, `lsws`)},
	{ID: "logstash", Name: "Logstash", Category: CategorySearch, Packages: res(`logstash`),
		Services: res(`logstash`), EOL: "logstash"},
	{ID: "mariadb", Name: "MariaDB", Category: CategoryDatabase,
		Packages: res(`mariadb-server-core(-\d+(\.\d+)?)?`, `mariadb-server(-\d+(\.\d+)?)?`, `mariadb\d*-server`, `mariadb`, `mariadb \d+\.\d+.*`),
		Services: res(`mariadb`, `mariadb@.+`, `mysql`, `mysqld`), EOL: "mariadb"},
	{ID: "memcached", Name: "Memcached", Category: CategoryCache, Packages: res(`memcached`),
		Services: res(`memcached(@.+)?`), EOL: "memcached"},
	{ID: "exchange", Name: "Microsoft Exchange Server", Category: CategoryMail, Packages: res(`microsoft exchange server.*`),
		Services: res(`msexchangetransport`, `msexchangeis`), EOL: "msexchange", Cycle: exchangeCycle},
	{ID: "mssql", Name: "Microsoft SQL Server", Category: CategoryDatabase, Packages: res(`mssql-server`),
		Services: res(`mssql-server`, `mssqlserver`, `mssql\$.+`), EOL: "mssqlserver"},
	{ID: "mongodb", Name: "MongoDB", Category: CategoryDatabase, Packages: res(`mongodb-org-server`, `mongodb-server`, `mongodb \d.*`),
		Services: res(`mongod`, `mongodb`), EOL: "mongodb"},
	{ID: "mosquitto", Name: "Mosquitto", Category: CategoryQueue, Packages: res(`mosquitto`),
		Services: res(`mosquitto`)},
	{ID: "mysql", Name: "MySQL", Category: CategoryDatabase,
		Packages: res(`mysql-server-core-\d+(\.\d+)?`, `mysql-community-server`, `mysql\d*(\.\d+)?-server`, `mysql-server(-\d+(\.\d+)?)?`, `mysql server \d+\.\d+`),
		Services: res(`mysql`, `mysqld`, `mysql\d+`), EOL: "mysql"},
	{ID: "nagios", Name: "Nagios Core", Category: CategoryMonitoring, Packages: res(`nagios4`, `nagios`),
		Services: res(`nagios4?`)},
	{ID: "nrpe", Name: "Nagios NRPE", Category: CategoryMonitoring, Packages: res(`nagios-nrpe-server`, `nrpe`),
		Services: res(`nagios-nrpe-server`, `nrpe`)},
	{ID: "netdata", Name: "Netdata", Category: CategoryMonitoring, Packages: res(`netdata`),
		Services: res(`netdata`)},
	{ID: "nginx", Name: "Nginx", Category: CategoryWeb, Packages: res(`nginx`, `nginx-core`, `nginx-full`, `nginx-light`, `nginx-extras`, `nginx-mainline`, `nginx-plus`, `ea-nginx`),
		Services: res(`nginx`), EOL: "nginx"},
	{ID: "nodejs", Name: "Node.js", Category: CategoryRuntime, Packages: res(`nodejs`, `nodejs\d+`, `node\.js`),
		EOL: "nodejs", Cycle: pkgver.Major},
	{ID: "openldap", Name: "OpenLDAP", Category: CategoryDirectory, Packages: res(`slapd`, `openldap-servers`, `openldap2`),
		Services: res(`slapd`)},
	{ID: "openlitespeed", Name: "OpenLiteSpeed", Category: CategoryWeb, Packages: res(`openlitespeed`),
		Services: res(`lshttpd`, `lsws`)},
	{ID: "opensearch", Name: "OpenSearch", Category: CategorySearch, Packages: res(`opensearch`),
		Services: res(`opensearch`), EOL: "opensearch", Cycle: pkgver.Major},
	{ID: "openssh", Name: "OpenSSH", Category: CategoryRemote, Packages: res(`openssh-server`, `openssh`),
		Services: res(`ssh`, `sshd`)},
	{ID: "openssl", Name: "OpenSSL", Category: CategoryLibrary,
		Packages: res(`openssl-libs`, `libssl3t64`, `libssl3`, `libssl1\.1`, `libssl1\.0\.\d`, `libopenssl3`, `libopenssl1_1`, `openssl`, `openssl\d+`),
		EOL:      "openssl"},
	{ID: "openvpn", Name: "OpenVPN", Category: CategoryVPN, Packages: res(`openvpn`, `openvpn \d.*`),
		Services: res(`openvpn`, `openvpn@.+`, `openvpn-server@.+`, `openvpn-client@.+`, `openvpnservice`), EOL: "openvpn"},
	{ID: "perl", Name: "Perl", Category: CategoryRuntime, Packages: res(`perl`, `strawberry perl .*`),
		EOL: "perl"},
	{ID: "php", Name: "PHP", Category: CategoryRuntime, Packages: res(`php(\d+(\.\d+)?)?-common`, `php(\d+(\.\d+)?)?-cli`, `php\d+(\.\d+)?`, `php`, `ea-php\d+`, `alt-php\d+`),
		EOL: "php"},
	{ID: "php-fpm", Name: "PHP-FPM", Category: CategoryRuntime, Packages: res(`php(\d+(\.\d+)?)?-fpm`, `ea-php\d+-php-fpm`, `alt-php\d+-fpm`),
		Services: res(`php.*-fpm`, `php-fpm.*`), EOL: "php"},
	{ID: "plesk", Name: "Plesk", Category: CategoryPanel, Packages: res(`plesk-core`, `psa`),
		Services: res(`psa`, `sw-engine`, `sw-cp-server`), EOL: "plesk", Cycle: components(3)},
	{ID: "podman", Name: "Podman", Category: CategoryContainer, Packages: res(`podman`),
		EOL: "podman"},
	{ID: "postfix", Name: "Postfix", Category: CategoryMail, Packages: res(`postfix`),
		Services: res(`postfix`, `postfix@.+`), EOL: "postfix"},
	{ID: "postgresql", Name: "PostgreSQL", Category: CategoryDatabase, Packages: res(`postgresql-\d+(\.\d+)?`, `postgresql\d*-server`, `postgresql\d+`, `postgresql \d+.*`),
		Services: res(`postgresql(@.+)?`, `postgresql-\d+(\.\d+)?`, `postgresql-x64-\d+`), EOL: "postgresql", Cycle: majorFrom(10)},
	{ID: "powerdns", Name: "PowerDNS Authoritative Server", Category: CategoryDNS, Packages: res(`pdns-server`, `pdns`),
		Services: res(`pdns(@.+)?`)},
	{ID: "pdns-recursor", Name: "PowerDNS Recursor", Category: CategoryDNS, Packages: res(`pdns-recursor`),
		Services: res(`pdns-recursor(@.+)?`)},
	{ID: "prometheus", Name: "Prometheus", Category: CategoryMonitoring, Packages: res(`prometheus`, `prometheus\d`),
		Services: res(`prometheus`), EOL: "prometheus"},
	{ID: "proftpd", Name: "ProFTPD", Category: CategoryFile, Packages: res(`proftpd-core`, `proftpd-basic`, `proftpd`),
		Services: res(`proftpd`), EOL: "proftpd", Cycle: components(3)},
	{ID: "pure-ftpd", Name: "Pure-FTPd", Category: CategoryFile, Packages: res(`pure-ftpd`, `pure-ftpd-(mysql|postgresql|ldap)`),
		Services: res(`pure-ftpd(-mysql|-postgresql|-ldap)?`)},
	{ID: "python", Name: "Python", Category: CategoryRuntime,
		Packages: res(`python3\.\d+`, `python3\d+`, `python3`, `python2\.\d`, `python2`, `python`, `python 3\.\d+\.\d+ \((64|32)-bit\)`),
		EOL:      "python"},
	{ID: "rabbitmq", Name: "RabbitMQ", Category: CategoryQueue, Packages: res(`rabbitmq-server`, `rabbitmq server.*`),
		Services: res(`rabbitmq-server`, `rabbitmq`), EOL: "rabbitmq"},
	{ID: "redis", Name: "Redis", Category: CategoryCache, Packages: res(`redis-server`, `redis`, `redis\d+`),
		Services: res(`redis-server`, `redis`, `redis@.+`, `redis-server@.+`), EOL: "redis"},
	{ID: "ruby", Name: "Ruby", Category: CategoryRuntime, Packages: res(`ruby\d+\.\d+`, `ruby-libs`, `ruby`, `ruby \d+\.\d+\.\d+-\d+.*`),
		EOL: "ruby"},
	{ID: "samba", Name: "Samba", Category: CategoryFile, Packages: res(`samba`),
		Services: res(`smbd`, `smb`, `samba-ad-dc`, `samba`), EOL: "samba"},
	{ID: "sendmail", Name: "Sendmail", Category: CategoryMail, Packages: res(`sendmail-bin`, `sendmail`),
		Services: res(`sendmail`)},
	{ID: "squid", Name: "Squid", Category: CategoryWeb, Packages: res(`squid`, `squid-openssl`),
		Services: res(`squid`), EOL: "squid", Cycle: pkgver.Major},
	{ID: "strongswan", Name: "strongSwan", Category: CategoryVPN, Packages: res(`strongswan-charon`, `strongswan`),
		Services: res(`strongswan(-starter)?`, `ipsec`)},
	{ID: "traefik", Name: "Traefik", Category: CategoryWeb, Packages: res(`traefik`),
		Services: res(`traefik`), EOL: "traefik"},
	{ID: "unbound", Name: "Unbound", Category: CategoryDNS, Packages: res(`unbound`),
		Services: res(`unbound`)},
	{ID: "valkey", Name: "Valkey", Category: CategoryCache, Packages: res(`valkey-server`, `valkey`),
		Services: res(`valkey-server`, `valkey`, `valkey@.+`), EOL: "valkey"},
	{ID: "varnish", Name: "Varnish Cache", Category: CategoryWeb, Packages: res(`varnish`),
		Services: res(`varnish`)},
	{ID: "vault", Name: "Vault", Category: CategoryInfra, Packages: res(`vault`),
		Services: res(`vault`), EOL: "hashicorp-vault"},
	{ID: "etcd", Name: "etcd", Category: CategoryInfra, Packages: res(`etcd-server`, `etcd`),
		Services: res(`etcd`), EOL: "etcd"},
	{ID: "vsftpd", Name: "vsftpd", Category: CategoryFile, Packages: res(`vsftpd`),
		Services: res(`vsftpd`)},
	{ID: "webmin", Name: "Webmin", Category: CategoryPanel, Packages: res(`webmin`),
		Services: res(`webmin`)},
	{ID: "wireguard", Name: "WireGuard", Category: CategoryVPN, Packages: res(`wireguard-tools`, `wireguard`),
		Services: res(`wg-quick@.+`, `wireguardtunnel\$.+`)},
	{ID: "zabbix-agent", Name: "Zabbix Agent", Category: CategoryMonitoring, Packages: res(`zabbix-agent2`, `zabbix-agent`, `zabbix agent( 2)?( \((64|32)-bit\))?`),
		Services: res(`zabbix-agent2?`, `zabbix agent( 2)?`), EOL: "zabbix"},
	{ID: "zabbix-proxy", Name: "Zabbix Proxy", Category: CategoryMonitoring, Packages: res(`zabbix-proxy-(mysql|pgsql|sqlite3)`),
		Services: res(`zabbix-proxy`), EOL: "zabbix"},
	{ID: "zabbix-server", Name: "Zabbix Server", Category: CategoryMonitoring, Packages: res(`zabbix-server-(mysql|pgsql)`),
		Services: res(`zabbix-server`), EOL: "zabbix"},
}

// Probed lists the products the agent detects outside the package manager.
var Probed = []string{"cpanel", "directadmin", "litespeed", "openlitespeed", "plesk", "iis", "mssql", "csf", "maldet", "ispconfig"}

func init() {
	Catalog = append(Catalog, extended...)
	sort.SliceStable(Catalog, func(i, j int) bool { return strings.ToLower(Catalog[i].Name) < strings.ToLower(Catalog[j].Name) })
}

// ByID returns a catalog entry.
func ByID(id string) (Def, bool) {
	for _, d := range Catalog {
		if d.ID == id {
			return d, true
		}
	}
	return Def{}, false
}

// CycleOf returns the release cycle of an upstream version.
func (d Def) CycleOf(upstream string) string {
	if d.Cycle != nil {
		return d.Cycle(upstream)
	}
	return pkgver.MajorMinor(upstream)
}

// Running states of an installed product.
const (
	RunningUnknown = -1 // the product has no service, or services were not reported
	NotRunning     = 0
	Running        = 1
)

// Installed is one product release found on a host. A host can run two
// releases side by side (PHP 8.1 and 8.2, PostgreSQL 15 and 16).
type Installed struct {
	Software       string
	Cycle          string // release cycle ("8.2", "16"); "" if the version has no number
	Version        string // upstream version ("8.2.7")
	Package        string // the package the version comes from
	PackageVersion string // full distribution version ("8.2.7-1~deb12u1")
	Running        int
	Service        string // the matching service, "" when none
}

// Detect finds the catalog's products in a host's packages and in the
// products the agent probed outside the package manager. services is the
// host's service list; servicesKnown is false when the agent did not
// report services (running state unknown).
func Detect(pm string, pkgs []protocol.Package, products []protocol.Product, services []protocol.Service, servicesKnown bool) []Installed {
	var out []Installed
	for _, d := range Catalog {
		// The most preferred package per release cycle; probed products
		// rank after every package.
		type cand struct {
			rank     int
			pkg      protocol.Package
			upstream string
		}
		best := map[string]cand{}
		consider := func(rank int, p protocol.Package, upstream string) {
			cycle := d.CycleOf(upstream)
			if c, ok := best[cycle]; !ok || rank < c.rank || (rank == c.rank && p.Name < c.pkg.Name) {
				best[cycle] = cand{rank, p, upstream}
			}
		}
		for _, p := range pkgs {
			rank := -1
			for i, re := range d.Packages {
				if re.MatchString(p.Name) {
					rank = i
					break
				}
			}
			if rank < 0 || p.Version == "" {
				continue
			}
			consider(rank, p, pkgver.Upstream(pm, p.Version))
		}
		for _, p := range products {
			if p.Software == d.ID {
				consider(len(d.Packages), protocol.Package{Version: p.Version}, p.Version)
			}
		}
		cycles := make([]string, 0, len(best))
		for c := range best {
			cycles = append(cycles, c)
		}
		sort.Strings(cycles)
		for _, cycle := range cycles {
			p, up := best[cycle].pkg, best[cycle].upstream
			in := Installed{Software: d.ID, Cycle: cycle, Version: up, Package: p.Name, PackageVersion: p.Version, Running: RunningUnknown}
			if len(d.Services) > 0 && servicesKnown {
				in.Running, in.Service = serviceState(d, cycle, len(best) > 1, services)
			}
			out = append(out, in)
		}
	}
	return out
}

// serviceState finds the product's service. With several releases on one
// host, services naming the cycle ("php8.2-fpm", "postgresql@16-main") are
// matched to it.
func serviceState(d Def, cycle string, multi bool, services []protocol.Service) (int, string) {
	state, name := NotRunning, ""
	for _, s := range services {
		matched := false
		for _, re := range d.Services {
			if re.MatchString(s.Name) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		if multi && cycle != "" && !strings.Contains(s.Name, cycle) {
			continue
		}
		if s.State == protocol.ServiceRunning {
			return Running, s.Name
		}
		if name == "" {
			name = s.Name
		}
	}
	return state, name
}
