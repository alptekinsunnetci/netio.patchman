package scanner

import (
	"testing"

	"netio.patchman/internal/protocol"
)

func TestApplyKernelCare(t *testing.T) {
	pkgs := []protocol.Package{
		{Name: "kernel", Version: "4.18.0-553.22.1.lve.el8"},
		{Name: "kernel-core", Version: "4.18.0-553.22.1.lve.el8"},
		{Name: "kernel-headers", Version: "4.18.0-553.22.1.lve.el8"},
		{Name: "openssl", Version: "1:1.1.1k-12.el8_9"},
	}
	got := ApplyKernelCare(pkgs, "4.18.0-553.22.1.lve.el8.x86_64", "4.18.0-553.40.1.lve.el8.x86_64")
	if got[0].Version != "4.18.0-553.40.1.lve.el8" || got[1].Version != "4.18.0-553.40.1.lve.el8" {
		t.Errorf("running kernel packages: %+v", got)
	}
	if got[2].Version != "4.18.0-553.22.1.lve.el8" || got[3].Version != "1:1.1.1k-12.el8_9" {
		t.Errorf("other packages changed: %+v", got)
	}
	if pkgs[0].Version != "4.18.0-553.22.1.lve.el8" {
		t.Error("input modified")
	}
	// Debian/Ubuntu uname has no arch suffix: unchanged.
	deb := []protocol.Package{{Name: "linux-image-5.15.0-105-generic", Version: "5.15.0-105.115"}}
	if out := ApplyKernelCare(deb, "5.15.0-105-generic", "5.15.0-113-generic"); out[0].Version != "5.15.0-105.115" {
		t.Errorf("deb: %+v", out)
	}
	if out := ApplyKernelCare(pkgs, "4.18.0-553.22.1.lve.el8.x86_64", ""); out[0].Version != pkgs[0].Version {
		t.Error("no effective kernel")
	}
}

func TestIsKernelPackage(t *testing.T) {
	for name, want := range map[string]bool{"linux": true, "linux-hwe-6.8": true, "linux-aws": true, "kernel": true,
		"kernel-core": true, "linux-firmware": false, "openssl": false, "kernel-headers": false} {
		if isKernelPackage(name) != want {
			t.Errorf("%s: %v", name, !want)
		}
	}
}
