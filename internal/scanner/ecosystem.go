package scanner

import (
	"strings"

	"netio.patchman/internal/protocol"
)

// Target describes how a host's packages are matched against OSV.
type Target struct {
	// Ecosystems are OSV ecosystem names to query, e.g. "Debian:12".
	Ecosystems []string
	// UseSource selects the source package name/version (deb, apk) instead
	// of the binary package (rpm distributions publish per binary package).
	UseSource bool
}

// Supported reports whether vulnerability matching is available.
func (t Target) Supported() bool { return len(t.Ecosystems) > 0 }

// TargetFor maps /etc/os-release values to OSV ecosystems. Verified against
// api.osv.dev record formats:
//   - Debian/Ubuntu/Alpine records are keyed by source package.
//   - AlmaLinux/Rocky/RHEL/SUSE records are keyed by binary package and use
//     epoch-prefixed versions ("1:3.0.7-25.el9_3").
func TargetFor(h protocol.HostInfo) Target {
	id := strings.ToLower(h.OSID)
	ver := h.OSVersionID
	major, _, _ := strings.Cut(ver, ".")
	switch id {
	case protocol.OSWindows:
		// Not an OSV ecosystem: Windows hosts are matched through their pending
		// updates and the Security Update Guide (see scanWindows).
		return Target{Ecosystems: []string{"Windows"}}
	case "debian":
		if major == "" {
			return Target{}
		}
		return Target{Ecosystems: []string{"Debian:" + major}, UseSource: true}
	case "ubuntu":
		if ver == "" {
			return Target{}
		}
		eco := "Ubuntu:" + ver
		if strings.Contains(h.OSVersion, "LTS") {
			eco += ":LTS"
		}
		return Target{Ecosystems: []string{eco}, UseSource: true}
	case "alpine":
		parts := strings.SplitN(ver, ".", 3)
		if len(parts) < 2 {
			return Target{}
		}
		return Target{Ecosystems: []string{"Alpine:v" + parts[0] + "." + parts[1]}, UseSource: true}
	case "almalinux":
		return rpmTarget("AlmaLinux:" + major)
	case "rocky":
		return rpmTarget("Rocky Linux:" + major)
	case "cloudlinux":
		// CloudLinux 8 and 9 are built from AlmaLinux sources with the same package
		// names and versions (verified against api.osv.dev; .lve/.cloudlinux release
		// suffixes compare as newer builds of the same release). OSV has no CloudLinux
		// ecosystem; CloudLinux 7 (CentOS 7 based) stays unsupported.
		if major == "8" || major == "9" {
			return rpmTarget("AlmaLinux:" + major)
		}
		return Target{}
	case "rhel":
		if major == "" {
			return Target{}
		}
		base := "Red Hat:enterprise_linux:" + major + "::"
		return Target{Ecosystems: []string{base + "baseos", base + "appstream"}}
	case "opensuse-leap":
		if ver == "" {
			return Target{}
		}
		return Target{Ecosystems: []string{"openSUSE:Leap " + ver}}
	case "sles", "sled":
		product := "SUSE:Linux Enterprise Server "
		if id == "sled" {
			product = "SUSE:Linux Enterprise Desktop "
		}
		maj, minor, _ := strings.Cut(ver, ".")
		if maj == "" {
			return Target{}
		}
		eco := product + maj
		if minor != "" && minor != "0" {
			eco += " SP" + minor
		}
		return Target{Ecosystems: []string{eco}}
	}
	return Target{}
}

func rpmTarget(eco string) Target {
	if strings.HasSuffix(eco, ":") {
		return Target{}
	}
	return Target{Ecosystems: []string{eco}}
}

// QueryPackage returns the name and version to send to OSV for p.
func (t Target) QueryPackage(p protocol.Package) (name, version string) {
	if t.UseSource && p.SourceName != "" {
		v := p.SourceVersion
		if v == "" {
			v = p.Version
		}
		return p.SourceName, v
	}
	return p.Name, p.Version
}
