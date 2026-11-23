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
	CategoryWeb       = "web"
	CategoryDatabase  = "database"
	CategoryCache     = "cache"
	CategoryRuntime   = "runtime"
	CategoryMail      = "mail"
	CategoryContainer = "container"
	CategoryRemote    = "remote"
	CategorySearch    = "search"
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

// Catalog is the list of recognized products, ordered by name.
var Catalog = []Def{
	{ID: "apache", Name: "Apache HTTP Server", Category: CategoryWeb, Packages: res(`apache2-bin`, `apache2`, `httpd`, `httpd24-httpd`),
		Services: res(`apache2`, `httpd`, `apache2@.+`), EOL: "apache-http-server"},
	{ID: "docker", Name: "Docker Engine", Category: CategoryContainer, Packages: res(`docker-ce`, `docker-engine`, `docker\.io`, `moby-engine`, `docker`),
		Services: res(`docker`), EOL: "docker-engine", Cycle: majorFrom(27)},
	{ID: "elasticsearch", Name: "Elasticsearch", Category: CategorySearch, Packages: res(`elasticsearch`),
		Services: res(`elasticsearch`), EOL: "elasticsearch"},
	{ID: "exim", Name: "Exim", Category: CategoryMail, Packages: res(`exim4-daemon-heavy`, `exim4-daemon-light`, `exim4-base`, `exim4`, `exim`),
		Services: res(`exim4`, `exim`), EOL: "exim"},
	{ID: "haproxy", Name: "HAProxy", Category: CategoryWeb, Packages: res(`haproxy`, `haproxy\d+`),
		Services: res(`haproxy`), EOL: "haproxy"},
	{ID: "kubernetes", Name: "Kubernetes", Category: CategoryContainer, Packages: res(`kubelet`, `kubeadm`),
		Services: res(`kubelet`), EOL: "kubernetes"},
	{ID: "mariadb", Name: "MariaDB", Category: CategoryDatabase, Packages: res(`mariadb-server-core(-\d+(\.\d+)?)?`, `mariadb-server(-\d+(\.\d+)?)?`, `mariadb\d*-server`, `mariadb`),
		Services: res(`mariadb`, `mariadb@.+`, `mysql`, `mysqld`), EOL: "mariadb"},
	{ID: "mongodb", Name: "MongoDB", Category: CategoryDatabase, Packages: res(`mongodb-org-server`, `mongodb-server`),
		Services: res(`mongod`, `mongodb`), EOL: "mongodb"},
	{ID: "mysql", Name: "MySQL", Category: CategoryDatabase, Packages: res(`mysql-server-core-\d+(\.\d+)?`, `mysql-community-server`, `mysql\d*(\.\d+)?-server`, `mysql-server(-\d+(\.\d+)?)?`),
		Services: res(`mysql`, `mysqld`), EOL: "mysql"},
	{ID: "nginx", Name: "Nginx", Category: CategoryWeb, Packages: res(`nginx`, `nginx-core`, `nginx-full`, `nginx-light`, `nginx-extras`, `nginx-mainline`, `nginx-plus`),
		Services: res(`nginx`), EOL: "nginx"},
	{ID: "nodejs", Name: "Node.js", Category: CategoryRuntime, Packages: res(`nodejs`, `nodejs\d+`),
		EOL: "nodejs", Cycle: pkgver.Major},
	{ID: "openssh", Name: "OpenSSH", Category: CategoryRemote, Packages: res(`openssh-server`, `openssh`),
		Services: res(`ssh`, `sshd`)},
	{ID: "php", Name: "PHP", Category: CategoryRuntime, Packages: res(`php(\d+(\.\d+)?)?-common`, `php(\d+(\.\d+)?)?-cli`, `php\d+(\.\d+)?`, `php`),
		EOL: "php"},
	{ID: "php-fpm", Name: "PHP-FPM", Category: CategoryRuntime, Packages: res(`php(\d+(\.\d+)?)?-fpm`),
		Services: res(`php.*-fpm`, `php-fpm.*`), EOL: "php"},
	{ID: "postfix", Name: "Postfix", Category: CategoryMail, Packages: res(`postfix`),
		Services: res(`postfix`, `postfix@.+`), EOL: "postfix"},
	{ID: "postgresql", Name: "PostgreSQL", Category: CategoryDatabase, Packages: res(`postgresql-\d+(\.\d+)?`, `postgresql\d*-server`, `postgresql\d+`),
		Services: res(`postgresql(@.+)?`, `postgresql-\d+(\.\d+)?`), EOL: "postgresql", Cycle: majorFrom(10)},
	{ID: "redis", Name: "Redis", Category: CategoryCache, Packages: res(`redis-server`, `redis`, `redis\d+`),
		Services: res(`redis-server`, `redis`, `redis@.+`, `redis-server@.+`), EOL: "redis"},
	{ID: "valkey", Name: "Valkey", Category: CategoryCache, Packages: res(`valkey-server`, `valkey`),
		Services: res(`valkey-server`, `valkey`, `valkey@.+`), EOL: "valkey"},
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

// Detect finds the catalog's products in a host's packages. services is
// the host's service list; servicesKnown is false when the agent did not
// report services (running state unknown).
func Detect(pm string, pkgs []protocol.Package, services []protocol.Service, servicesKnown bool) []Installed {
	var out []Installed
	for _, d := range Catalog {
		// The most preferred package per release cycle.
		type cand struct {
			rank int
			pkg  protocol.Package
		}
		best := map[string]cand{}
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
			cycle := d.CycleOf(pkgver.Upstream(pm, p.Version))
			if c, ok := best[cycle]; !ok || rank < c.rank || (rank == c.rank && p.Name < c.pkg.Name) {
				best[cycle] = cand{rank, p}
			}
		}
		cycles := make([]string, 0, len(best))
		for c := range best {
			cycles = append(cycles, c)
		}
		sort.Strings(cycles)
		for _, cycle := range cycles {
			p := best[cycle].pkg
			in := Installed{Software: d.ID, Cycle: cycle, Version: pkgver.Upstream(pm, p.Version), Package: p.Name, PackageVersion: p.Version, Running: RunningUnknown}
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
