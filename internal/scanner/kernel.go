package scanner

import (
	"regexp"
	"strings"

	"netio.patchman/internal/protocol"
)

// Hosts keep several kernels installed (RHEL-family installonly_limit=3,
// Ubuntu keeps the previous kernel). Old kernel packages are never upgraded,
// only removed, so matching them would leave findings open forever even
// after the fixed kernel is installed and running. Vulnerability matching
// therefore uses only the packages of the running kernel (uname -r).
//
// If the running kernel is not one of the installed kernel packages (WSL,
// containers, custom kernels) nothing is filtered. When a newer kernel is
// installed but the host has not rebooted yet, the running (older) kernel is
// the one that counts, so its findings stay open until the reboot.

// debKernelABI matches the kernel ABI in Debian/Ubuntu version-specific
// package names (linux-image-6.8.0-45-generic, linux-headers-6.1.0-18-common)
// and in uname -r (6.8.0-45-generic, 6.1.0-18-amd64).
var debKernelABI = regexp.MustCompile(`(?:^|-)(\d+\.\d+\.\d+-\d+)(?:-|$)`)

// ActiveKernelPackages returns pkgs without the packages of installed kernels
// that are not running.
func ActiveKernelPackages(pkgs []protocol.Package, running string) []protocol.Package {
	running = strings.TrimSpace(running)
	if running == "" {
		return pkgs
	}
	if out, ok := filterDebKernels(pkgs, running); ok {
		return out
	}
	if out, ok := filterRPMKernels(pkgs, running); ok {
		return out
	}
	return pkgs
}

func debABI(name string) string {
	if !strings.HasPrefix(name, "linux-") {
		return ""
	}
	if m := debKernelABI.FindStringSubmatch(name); m != nil {
		return m[1]
	}
	return ""
}

func filterDebKernels(pkgs []protocol.Package, running string) ([]protocol.Package, bool) {
	m := debKernelABI.FindStringSubmatch(running)
	if m == nil {
		return nil, false
	}
	runABI := m[1]
	found := false
	for _, p := range pkgs {
		if debABI(p.Name) == runABI && strings.HasPrefix(p.Name, "linux-image-") {
			found = true
			break
		}
	}
	if !found {
		return nil, false
	}
	out := make([]protocol.Package, 0, len(pkgs))
	for _, p := range pkgs {
		if abi := debABI(p.Name); abi != "" && abi != runABI {
			continue
		}
		out = append(out, p)
	}
	return out, true
}

// isRPMKernel reports whether name is an install-only kernel package
// (kernel, kernel-core, kernel-modules-extra, kernel-default, kernel-uek, …).
func isRPMKernel(name string) bool {
	return name == "kernel" || (strings.HasPrefix(name, "kernel-") &&
		!strings.HasPrefix(name, "kernel-headers") && !strings.HasPrefix(name, "kernel-tools") &&
		!strings.HasPrefix(name, "kernel-firmware") && !strings.HasPrefix(name, "kernel-srpm"))
}

// rpmKernelRunning reports whether an installed kernel version (optionally
// epoch-prefixed) is the running kernel. RHEL: uname -r is
// "5.14.0-427.13.1.el9_4.x86_64" for version "5.14.0-427.13.1.el9_4".
// SUSE: "6.4.0-150600.23.25-default" for version "6.4.0-150600.23.25.1".
func rpmKernelRunning(version, running string) bool {
	if _, v, ok := strings.Cut(version, ":"); ok {
		version = v
	}
	if version == "" {
		return false
	}
	if hasPrefixAt(running, version) {
		return true
	}
	if i := strings.LastIndex(running, "-"); i > 0 {
		return hasPrefixAt(version, running[:i])
	}
	return false
}

// hasPrefixAt reports whether s starts with prefix followed by the end of s
// or a '.' (so "23.2" does not match "23.25").
func hasPrefixAt(s, prefix string) bool {
	return strings.HasPrefix(s, prefix) && (len(s) == len(prefix) || s[len(prefix)] == '.')
}

func filterRPMKernels(pkgs []protocol.Package, running string) ([]protocol.Package, bool) {
	versions := map[string]map[string]bool{}
	found := false
	for _, p := range pkgs {
		if !isRPMKernel(p.Name) {
			continue
		}
		if versions[p.Name] == nil {
			versions[p.Name] = map[string]bool{}
		}
		versions[p.Name][p.Version] = true
		if rpmKernelRunning(p.Version, running) {
			found = true
		}
	}
	if !found {
		return nil, false
	}
	out := make([]protocol.Package, 0, len(pkgs))
	for _, p := range pkgs {
		if isRPMKernel(p.Name) && len(versions[p.Name]) > 1 && !rpmKernelRunning(p.Version, running) {
			continue
		}
		out = append(out, p)
	}
	return out, true
}
