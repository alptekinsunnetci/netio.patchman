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
	case "cloudlinux", "ol":
		// CloudLinux and Oracle Linux 8 and 9 are rebuilds with the same package
		// names and versions as AlmaLinux (verified against api.osv.dev; .lve,
		// .cloudlinux and .0.1 release suffixes compare as newer builds of the same
		// release). OSV has no CloudLinux or Oracle Linux ecosystem. Version 7 is
		// a CentOS/RHEL 7 rebuild.
		switch major {
		case "8", "9":
			return rpmTarget("AlmaLinux:" + major)
		case "7":
			return el7Target()
		}
		return Target{}
	case "centos":
		// CentOS Stream runs ahead of RHEL: no matching data.
		if strings.Contains(strings.ToLower(h.OSName), "stream") {
			return Target{}
		}
		switch major {
		case "7":
			return el7Target()
		case "8":
			return rpmTarget("AlmaLinux:8")
		}
		return Target{}
	case "mageia":
		return rpmTarget("Mageia:" + major)
	case "openeuler":
		// VERSION="22.03 (LTS-SP1)" -> "openEuler:22.03-LTS-SP1".
		if ver == "" {
			return Target{}
		}
		eco := "openEuler:" + ver
		if _, rest, ok := strings.Cut(h.OSVersion, "("); ok {
			if edition := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(rest), ")")); edition != "" {
				eco += "-" + edition
			}
		}
		return Target{Ecosystems: []string{eco}}
	case "raspbian":
		if major == "" {
			return Target{}
		}
		return Target{Ecosystems: []string{"Debian:" + major}, UseSource: true}
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
	return upstreamTarget(h.Upstream)
}

// el7Target covers CentOS 7 and its rebuilds: Red Hat data for the release
// and TuxCare's extended lifecycle support fixes published after its end of
// life (package versions verified against api.osv.dev).
func el7Target() Target {
	return Target{Ecosystems: []string{"Red Hat:enterprise_linux:7::server", "TuxCare:CentOS:7"}}
}

// Ubuntu and Debian releases by codename, for derivatives that name their
// upstream release (Linux Mint, Pop!_OS, Zorin OS, elementary OS, LMDE).
var (
	ubuntuReleases = map[string]string{
		"xenial": "16.04", "bionic": "18.04", "focal": "20.04", "jammy": "22.04", "noble": "24.04",
		"lunar": "23.04", "mantic": "23.10", "oracular": "24.10", "plucky": "25.04", "questing": "25.10",
	}
	debianReleases = map[string]string{"buster": "10", "bullseye": "11", "bookworm": "12", "trixie": "13"}
)

func upstreamTarget(upstream string) Target {
	distro, codename, _ := strings.Cut(upstream, ":")
	switch distro {
	case "ubuntu":
		ver, ok := ubuntuReleases[codename]
		if !ok {
			return Target{}
		}
		eco := "Ubuntu:" + ver
		// LTS releases come out in April of even years.
		if strings.HasSuffix(ver, ".04") && (ver[1]-'0')%2 == 0 {
			eco += ":LTS"
		}
		return Target{Ecosystems: []string{eco}, UseSource: true}
	case "debian":
		if ver, ok := debianReleases[codename]; ok {
			return Target{Ecosystems: []string{"Debian:" + ver}, UseSource: true}
		}
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
