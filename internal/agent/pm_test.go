package agent

import (
	"slices"
	"testing"

	"netio.patchman/internal/protocol"
)

func TestPickPackageManager(t *testing.T) {
	tools := func(bins ...string) func(string) bool { return func(b string) bool { return slices.Contains(bins, b) } }
	cases := []struct {
		name string
		rel  map[string]string
		has  func(string) bool
		want string
	}{
		// CloudLinux/cPanel servers often have dpkg installed as well.
		{"cloudlinux with dpkg", map[string]string{"ID": "cloudlinux", "ID_LIKE": "rhel fedora centos"}, tools("dpkg-query", "rpm", "dnf", "yum"), protocol.PMDnf},
		{"cloudlinux 7", map[string]string{"ID": "cloudlinux", "ID_LIKE": "rhel fedora centos"}, tools("dpkg-query", "rpm", "yum"), protocol.PMYum},
		{"debian with rpm", map[string]string{"ID": "debian"}, tools("apt-get", "dpkg-query", "rpm", "yum"), protocol.PMApt},
		{"ubuntu", map[string]string{"ID": "ubuntu", "ID_LIKE": "debian"}, tools("apt-get", "dpkg-query"), protocol.PMApt},
		{"opensuse", map[string]string{"ID": "opensuse-leap", "ID_LIKE": "suse opensuse"}, tools("zypper", "rpm", "dpkg-query"), protocol.PMZypper},
		{"alpine", map[string]string{"ID": "alpine"}, tools("apk", "dpkg-query"), protocol.PMApk},
		{"amazon linux", map[string]string{"ID": "amzn", "ID_LIKE": "centos rhel fedora"}, tools("dnf", "yum"), protocol.PMDnf},
		// Unknown family: first available, dpkg alone is not apt.
		{"unknown, dpkg only", map[string]string{"ID": "custom"}, tools("dpkg-query", "yum"), protocol.PMYum},
		{"no os-release", nil, tools("apt-get", "dpkg-query"), protocol.PMApt},
		{"nothing", nil, tools(), ""},
	}
	for _, c := range cases {
		if got := pickPackageManager(c.rel, c.has); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}
