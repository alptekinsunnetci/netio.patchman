// Package eol tracks support end dates (end of life) of operating systems
// and server software. The calendars come from endoflife.date: a snapshot is
// built into the binary (air-gapped installs) and refreshed daily when the
// source is enabled. Product and release names are verbatim.
package eol

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"netio.patchman/internal/pkgver"
	"netio.patchman/internal/protocol"
	"netio.patchman/internal/software"
)

//go:embed data.json
var embedded []byte

// Release is one release cycle of a product.
type Release struct {
	Cycle    string
	Released time.Time
	// EOL is the end of security support; zero when no date is published.
	EOL time.Time
	// Ended: the release is out of support but no date is published.
	Ended bool
	// Support is the end of active (bug fix) support, zero when not published.
	Support time.Time
	// Extended is the end of extended (often paid) support, zero when none.
	Extended time.Time
	LTS      bool
	Latest   string
}

// Statuses.
const (
	StatusEOL       = "eol"       // out of support
	StatusSoon      = "soon"      // support ends within the warning period
	StatusSupported = "supported" // supported
	StatusUnknown   = "unknown"   // no calendar for this release
)

// Status classifies the release at now; warn is the warning period.
func (r Release) Status(now time.Time, warn time.Duration) string {
	switch {
	case r.Ended:
		return StatusEOL
	case r.EOL.IsZero():
		return StatusSupported
	case !now.Before(r.EOL):
		return StatusEOL
	case r.EOL.Sub(now) <= warn:
		return StatusSoon
	}
	return StatusSupported
}

// DaysLeft returns the whole days until the end of support (negative after
// it); 0 when no date is known.
func (r Release) DaysLeft(now time.Time) int {
	if r.EOL.IsZero() {
		return 0
	}
	return int(r.EOL.Sub(now).Hours() / 24)
}

// ActiveSupportOver reports whether only security support is left.
func (r Release) ActiveSupportOver(now time.Time) bool {
	return !r.Support.IsZero() && !now.Before(r.Support)
}

// Data maps endoflife.date product ids to their release cycles.
type Data map[string][]Release

// Find returns the release cycle of a product.
func (d Data) Find(product, cycle string) (Release, bool) {
	for _, r := range d[product] {
		if r.Cycle == cycle {
			return r, true
		}
	}
	return Release{}, false
}

// Products lists the calendars this package uses.
func Products() []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if p != "" && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, o := range osProducts {
		add(o.product)
	}
	for _, d := range software.Catalog {
		add(d.EOL)
	}
	sort.Strings(out)
	return out
}

// ParseProduct parses one endoflife.date product file (a JSON array).
func ParseProduct(raw []byte) ([]Release, error) {
	var items []map[string]any
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, err
	}
	out := make([]Release, 0, len(items))
	for _, it := range items {
		r := Release{Cycle: str(it["cycle"]), Latest: str(it["latest"])}
		if r.Cycle == "" {
			continue
		}
		r.Released, _ = dateOrBool(it["releaseDate"])
		var ended bool
		r.EOL, ended = dateOrBool(it["eol"])
		r.Ended = ended && r.EOL.IsZero()
		r.Support, _ = dateOrBool(it["support"])
		r.Extended, _ = dateOrBool(it["extendedSupport"])
		r.LTS, _ = it["lts"].(bool)
		out = append(out, r)
	}
	if len(out) == 0 {
		return nil, errors.New("eol: no release cycles")
	}
	return out, nil
}

// str renders a JSON scalar (cycles can be numbers in some files).
func str(v any) string {
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	}
	return ""
}

// dateOrBool reads "2028-06-30", true or false.
func dateOrBool(v any) (time.Time, bool) {
	switch x := v.(type) {
	case string:
		t, err := time.Parse("2006-01-02", x)
		if err == nil {
			return t.UTC(), true
		}
	case bool:
		return time.Time{}, x
	}
	return time.Time{}, false
}

// Embedded returns the calendars built into the binary.
func Embedded() Data {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(embedded, &raw); err != nil {
		panic(fmt.Sprintf("eol: embedded data: %v", err))
	}
	d := Data{}
	for p, b := range raw {
		if rel, err := ParseProduct(b); err == nil {
			d[p] = rel
		}
	}
	return d
}

// ---------- operating systems ----------

type osProduct struct {
	ids     []string // os-release IDs
	product string   // endoflife.date product
	name    string   // product name, verbatim
	cycle   func(versionID string) string
	// via names the distribution whose calendar is used for one without
	// its own (CloudLinux follows RHEL).
	via string
}

func major(v string) string { return pkgver.Major(v) }

func majorMinor(v string) string { return pkgver.MajorMinor(v) }

func exact(v string) string { return strings.TrimSpace(v) }

var osProducts = []osProduct{
	{ids: []string{"debian"}, product: "debian", name: "Debian", cycle: major},
	{ids: []string{"ubuntu"}, product: "ubuntu", name: "Ubuntu", cycle: exact},
	{ids: []string{"rhel"}, product: "rhel", name: "Red Hat Enterprise Linux", cycle: major},
	{ids: []string{"rocky"}, product: "rocky-linux", name: "Rocky Linux", cycle: major},
	{ids: []string{"almalinux"}, product: "almalinux", name: "AlmaLinux", cycle: major},
	{ids: []string{"ol"}, product: "oracle-linux", name: "Oracle Linux", cycle: major},
	{ids: []string{"cloudlinux"}, product: "rhel", name: "CloudLinux", cycle: major, via: "Red Hat Enterprise Linux"},
	{ids: []string{"centos"}, product: "centos", name: "CentOS", cycle: major},
	{ids: []string{"sles", "sled"}, product: "sles", name: "SUSE Linux Enterprise Server", cycle: majorMinor},
	{ids: []string{"opensuse-leap"}, product: "opensuse", name: "openSUSE Leap", cycle: majorMinor},
	{ids: []string{"alpine"}, product: "alpine-linux", name: "Alpine Linux", cycle: majorMinor},
	{ids: []string{"amzn"}, product: "amazon-linux", name: "Amazon Linux", cycle: major},
	{ids: []string{"fedora"}, product: "fedora", name: "Fedora", cycle: major},
	{ids: []string{protocol.OSWindows}, product: "windows-server", name: "Windows Server"},
}

// Target is the support calendar entry that applies to a host or product.
type Target struct {
	Product string // endoflife.date id
	Cycle   string
	Name    string // product name, verbatim ("Ubuntu", "PHP")
	Via     string // calendar of another distribution (CloudLinux -> RHEL)
}

// ForOS finds the calendar of a host's operating system. CentOS Stream is
// told apart from CentOS Linux by its name; Windows Server releases by the
// build number in the kernel field.
func (d Data) ForOS(osID, versionID, osName, kernel string) (Target, bool) {
	id := strings.ToLower(strings.TrimSpace(osID))
	for _, o := range osProducts {
		if !contains(o.ids, id) {
			continue
		}
		if id == protocol.OSWindows {
			return d.windowsServer(osName, kernel)
		}
		t := Target{Product: o.product, Name: o.name, Via: o.via, Cycle: o.cycle(versionID)}
		if id == "centos" && strings.Contains(strings.ToLower(osName), "stream") {
			t.Product, t.Name = "centos-stream", "CentOS Stream"
		}
		return t, t.Cycle != ""
	}
	return Target{}, false
}

// windowsServer maps a build ("10.0.20348.2762") to the long-term release
// with that build (2016, 2019, 2022, 2025). Desktop Windows is not covered.
func (d Data) windowsServer(osName, kernel string) (Target, bool) {
	if !strings.Contains(strings.ToLower(osName), "server") {
		return Target{}, false
	}
	parts := strings.Split(kernel, ".")
	if len(parts) < 3 {
		return Target{}, false
	}
	build := strings.Join(parts[:3], ".")
	var match *Release
	for i, r := range d["windows-server"] {
		if r.Latest == build && (match == nil || (r.LTS && !match.LTS)) {
			match = &d["windows-server"][i]
		}
	}
	if match == nil {
		return Target{}, false
	}
	return Target{Product: "windows-server", Cycle: match.Cycle, Name: "Windows Server"}, true
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// ---------- distribution packages ----------

var (
	debDistroRE = regexp.MustCompile(`(deb\d+u\d+|~deb\d+|\+deb\d+|ubuntu\d|build\d)`)
	rpmDistroRE = regexp.MustCompile(`(\.el\d+|module\+el\d+|\.amzn\d|\.fc\d+|\.sle\d|\.suse)`)
	thirdRE     = regexp.MustCompile(`(?i)(pgdg|remi|sury|maria~|mariadb|percona|nginx\.org|~bpo)`)
)

// DistroPackage reports whether a package version looks like one built by
// the distribution itself (with backported security fixes), not by a
// third-party repository. Such packages are maintained by the distribution
// for as long as the distribution release is supported, so an upstream end
// of life does not mean they stop receiving fixes.
func DistroPackage(pm, version string) bool {
	if thirdRE.MatchString(version) {
		return false
	}
	switch pm {
	case protocol.PMApt:
		return debDistroRE.MatchString(version)
	case protocol.PMApk:
		return true // Alpine repositories carry only distribution builds
	case protocol.PMDnf, protocol.PMYum, protocol.PMZypper:
		return rpmDistroRE.MatchString(version)
	}
	return false
}
