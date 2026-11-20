package scanner

import (
	"slices"
	"testing"

	"netio.patchman/internal/protocol"
)

func names(pkgs []protocol.Package) []string {
	out := make([]string, len(pkgs))
	for i, p := range pkgs {
		out[i] = p.Name + "=" + p.Version
	}
	return out
}

func TestActiveKernelPackagesUbuntu(t *testing.T) {
	pkgs := []protocol.Package{
		{Name: "linux-image-6.8.0-140-generic", Version: "6.8.0-140.140", SourceName: "linux", SourceVersion: "6.8.0-140.140"},
		{Name: "linux-modules-6.8.0-140-generic", Version: "6.8.0-140.140", SourceName: "linux", SourceVersion: "6.8.0-140.140"},
		{Name: "linux-headers-6.8.0-140", Version: "6.8.0-140.140", SourceName: "linux", SourceVersion: "6.8.0-140.140"},
		{Name: "linux-image-6.8.0-146-generic", Version: "6.8.0-146.146", SourceName: "linux", SourceVersion: "6.8.0-146.146"},
		{Name: "linux-modules-6.8.0-146-generic", Version: "6.8.0-146.146", SourceName: "linux", SourceVersion: "6.8.0-146.146"},
		{Name: "linux-headers-6.8.0-146", Version: "6.8.0-146.146", SourceName: "linux", SourceVersion: "6.8.0-146.146"},
		{Name: "linux-libc-dev", Version: "6.8.0-146.146", SourceName: "linux", SourceVersion: "6.8.0-146.146"},
		{Name: "linux-image-generic", Version: "6.8.0-146.146"},
		{Name: "openssl", Version: "3.0.13-0ubuntu3.5"},
	}
	got := names(ActiveKernelPackages(pkgs, "6.8.0-146-generic"))
	want := []string{
		"linux-image-6.8.0-146-generic=6.8.0-146.146", "linux-modules-6.8.0-146-generic=6.8.0-146.146",
		"linux-headers-6.8.0-146=6.8.0-146.146", "linux-libc-dev=6.8.0-146.146",
		"linux-image-generic=6.8.0-146.146", "openssl=3.0.13-0ubuntu3.5",
	}
	if !slices.Equal(got, want) {
		t.Errorf("running 146:\n got %v\nwant %v", got, want)
	}

	// Not rebooted yet: the older running kernel is the one that counts.
	got = names(ActiveKernelPackages(pkgs, "6.8.0-140-generic"))
	if slices.Contains(got, "linux-image-6.8.0-146-generic=6.8.0-146.146") || !slices.Contains(got, "linux-image-6.8.0-140-generic=6.8.0-140.140") {
		t.Errorf("running 140: %v", got)
	}

	// Running kernel not managed by dpkg (WSL, containers): nothing filtered.
	for _, k := range []string{"6.6.87.2-microsoft-standard-WSL2", "6.8.0-999-generic", ""} {
		if got := ActiveKernelPackages(pkgs, k); len(got) != len(pkgs) {
			t.Errorf("%q filtered: %v", k, names(got))
		}
	}
}

func TestActiveKernelPackagesDebian(t *testing.T) {
	pkgs := []protocol.Package{
		{Name: "linux-image-6.1.0-17-amd64", Version: "6.1.69-1", SourceName: "linux"},
		{Name: "linux-image-6.1.0-18-amd64", Version: "6.1.76-1", SourceName: "linux"},
		{Name: "linux-headers-6.1.0-18-common", Version: "6.1.76-1", SourceName: "linux"},
		{Name: "linux-headers-6.1.0-17-common", Version: "6.1.69-1", SourceName: "linux"},
		{Name: "linux-kbuild-6.1", Version: "6.1.76-1", SourceName: "linux"},
	}
	got := names(ActiveKernelPackages(pkgs, "6.1.0-18-amd64"))
	want := []string{"linux-image-6.1.0-18-amd64=6.1.76-1", "linux-headers-6.1.0-18-common=6.1.76-1", "linux-kbuild-6.1=6.1.76-1"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestActiveKernelPackagesRPM(t *testing.T) {
	pkgs := []protocol.Package{
		{Name: "kernel", Version: "5.14.0-362.24.1.el9_3"},
		{Name: "kernel-core", Version: "5.14.0-362.24.1.el9_3"},
		{Name: "kernel", Version: "5.14.0-427.13.1.el9_4"},
		{Name: "kernel-core", Version: "5.14.0-427.13.1.el9_4"},
		{Name: "kernel-modules-extra", Version: "5.14.0-427.13.1.el9_4"},
		{Name: "kernel-headers", Version: "5.14.0-427.13.1.el9_4"},
		{Name: "kernel-tools", Version: "5.14.0-427.13.1.el9_4"},
		{Name: "openssl", Version: "1:3.0.7-27.el9"},
	}
	got := names(ActiveKernelPackages(pkgs, "5.14.0-427.13.1.el9_4.x86_64"))
	want := []string{
		"kernel=5.14.0-427.13.1.el9_4", "kernel-core=5.14.0-427.13.1.el9_4", "kernel-modules-extra=5.14.0-427.13.1.el9_4",
		"kernel-headers=5.14.0-427.13.1.el9_4", "kernel-tools=5.14.0-427.13.1.el9_4", "openssl=1:3.0.7-27.el9",
	}
	if !slices.Equal(got, want) {
		t.Errorf("rhel:\n got %v\nwant %v", got, want)
	}

	suse := []protocol.Package{
		{Name: "kernel-default", Version: "6.4.0-150600.23.2.1"},
		{Name: "kernel-default", Version: "6.4.0-150600.23.25.1"},
	}
	got = names(ActiveKernelPackages(suse, "6.4.0-150600.23.25-default"))
	if !slices.Equal(got, []string{"kernel-default=6.4.0-150600.23.25.1"}) {
		t.Errorf("suse: %v", got)
	}
	if got := ActiveKernelPackages(suse, "6.4.0-150600.23.3-default"); len(got) != 2 {
		t.Errorf("unknown running kernel must not filter: %v", names(got))
	}
}
