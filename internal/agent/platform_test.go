package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"netio.patchman/internal/protocol"
)

func writeFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for p, v := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDetectVirtualization(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"vmware", map[string]string{"sys/class/dmi/id/sys_vendor": "VMware, Inc.\n", "sys/class/dmi/id/product_name": "VMware Virtual Platform\n"}, "vmware"},
		{"hyper-v", map[string]string{"sys/class/dmi/id/sys_vendor": "Microsoft Corporation", "sys/class/dmi/id/product_name": "Virtual Machine"}, "microsoft"},
		{"kvm", map[string]string{"sys/class/dmi/id/sys_vendor": "QEMU", "sys/class/dmi/id/product_name": "Standard PC (Q35 + ICH9, 2009)"}, "qemu"},
		{"virtualbox", map[string]string{"sys/class/dmi/id/sys_vendor": "innotek GmbH", "sys/class/dmi/id/product_name": "VirtualBox"}, "oracle"},
		{"physical", map[string]string{"sys/class/dmi/id/sys_vendor": "Dell Inc.", "sys/class/dmi/id/product_name": "PowerEdge R750", "proc/cpuinfo": "flags: fpu vme"}, "none"},
		{"unknown hypervisor", map[string]string{"sys/class/dmi/id/sys_vendor": "Acme", "proc/cpuinfo": "flags: fpu hypervisor"}, "vm-other"},
		{"docker", map[string]string{".dockerenv": "", "sys/class/dmi/id/sys_vendor": "Dell Inc."}, "docker"},
		{"lxc", map[string]string{"proc/1/environ": "PATH=/bin\x00container=lxc\x00"}, "lxc"},
		{"wsl", map[string]string{"proc/sys/kernel/osrelease": "5.15.153.1-microsoft-standard-WSL2"}, "wsl"},
		{"nothing", map[string]string{}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeFiles(t, root, tc.files)
			if got := detectVirtualization(context.Background(), root); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAptKernelPending(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"proc/sys/kernel/osrelease":   "6.1.0-18-amd64\n",
		"boot/vmlinuz-6.1.0-18-amd64": "old",
	})
	if aptKernelPending(root) {
		t.Fatal("only the running kernel installed")
	}
	writeFiles(t, root, map[string]string{"boot/vmlinuz-6.1.0-21-amd64": "new"})
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(filepath.Join(root, "boot/vmlinuz-6.1.0-18-amd64"), old, old); err != nil {
		t.Fatal(err)
	}
	if !aptKernelPending(root) {
		t.Error("newer kernel not detected")
	}
	// A container: the running kernel is not in /boot.
	c := t.TempDir()
	writeFiles(t, c, map[string]string{"proc/sys/kernel/osrelease": "5.15.0-1-generic", "boot/vmlinuz-6.1.0-21-amd64": "x"})
	if aptKernelPending(c) {
		t.Error("container reported a pending kernel")
	}
}

func TestApkKernelPending(t *testing.T) {
	pkgs := []protocol.Package{{Name: "musl", Version: "1.2.4-r2"}, {Name: "linux-lts", Version: "6.6.14-r0"}}
	if apkKernelPending("6.6.14-0-lts\n", pkgs) {
		t.Error("running kernel reported pending")
	}
	if !apkKernelPending("6.6.13-0-lts", pkgs) {
		t.Error("upgraded kernel not detected")
	}
	if apkKernelPending("6.6.13-0-virt", pkgs) {
		t.Error("other flavor matched")
	}
	if apkKernelPending("5.15.153.1-microsoft-standard-WSL2", pkgs[:1]) {
		t.Error("container without kernel package reported pending")
	}
}

func TestCleanVirtualization(t *testing.T) {
	for in, want := range map[string]string{"vmware": "vmware", "vm-other": "vm-other", "none": "none", "": "", "VMware": "", "kvm; rm": "", "a23456789012345678901234567890123": ""} {
		if got := protocol.CleanVirtualization(in); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}
