package agent

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"netio.patchman/internal/protocol"
)

var (
	virtOnce sync.Once
	virtID   string
)

// Virtualization returns the platform id, detected once per process:
// systemd-detect-virt when available, otherwise DMI and container markers.
// "none" means a physical machine, "" that it could not be determined.
func Virtualization() string {
	virtOnce.Do(func() { virtID = detectVirtualization(context.Background(), "/") })
	return virtID
}

func detectVirtualization(ctx context.Context, root string) string {
	if root == "/" {
		if _, err := exec.LookPath("systemd-detect-virt"); err == nil {
			// Exit status 1 with "none" means no virtualization was found.
			out, _, _ := run(ctx, 10*time.Second, "systemd-detect-virt")
			if v := protocol.CleanVirtualization(strings.TrimSpace(string(out))); v != "" {
				return v
			}
		}
	}
	read := func(p string) string {
		b, err := os.ReadFile(filepath.Join(root, p))
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(b))
	}
	exists := func(p string) bool {
		_, err := os.Stat(filepath.Join(root, p))
		return err == nil
	}
	// Containers first: they see the host's DMI data.
	switch {
	case exists(".dockerenv"):
		return "docker"
	case exists("run/.containerenv"):
		return "podman"
	}
	if env := read("proc/1/environ"); env != "" {
		for _, kv := range strings.Split(env, "\x00") {
			if v, ok := strings.CutPrefix(kv, "container="); ok {
				return protocol.CleanVirtualization(strings.ToLower(v))
			}
		}
	}
	if rel := strings.ToLower(read("proc/sys/kernel/osrelease")); strings.Contains(rel, "microsoft") {
		return "wsl"
	}
	vendor := strings.ToLower(read("sys/class/dmi/id/sys_vendor"))
	product := strings.ToLower(read("sys/class/dmi/id/product_name"))
	if vendor == "" && product == "" {
		return ""
	}
	dmi := vendor + " " + product
	for _, m := range []struct{ match, id string }{
		{"vmware", "vmware"},
		{"virtualbox", "oracle"},
		{"innotek", "oracle"},
		{"microsoft corporation virtual machine", "microsoft"},
		{"qemu", "qemu"},
		{"kvm", "kvm"},
		{"xen", "xen"},
		{"amazon ec2", "amazon"},
		{"google compute engine", "google"},
		{"parallels", "parallels"},
		{"bochs", "bochs"},
		{"openstack", "kvm"},
	} {
		if strings.Contains(dmi, m.match) {
			return m.id
		}
	}
	if strings.Contains(read("proc/cpuinfo"), "hypervisor") {
		return "vm-other"
	}
	return "none"
}

// aptKernelPending reports whether a newer kernel image was installed after
// the running one (Debian has no /var/run/reboot-required by default). Only
// hosts that boot a kernel from /boot are considered.
func aptKernelPending(root string) bool {
	running, err := os.ReadFile(filepath.Join(root, "proc/sys/kernel/osrelease"))
	if err != nil {
		return false
	}
	rel := strings.TrimSpace(string(running))
	cur, err := os.Stat(filepath.Join(root, "boot", "vmlinuz-"+rel))
	if err != nil {
		return false // containers, WSL, custom kernels
	}
	matches, _ := filepath.Glob(filepath.Join(root, "boot", "vmlinuz-*"))
	for _, m := range matches {
		st, err := os.Stat(m)
		if err != nil || filepath.Base(m) == "vmlinuz-"+rel {
			continue
		}
		if st.ModTime().After(cur.ModTime()) {
			return true
		}
	}
	return false
}

// apkKernelPending compares the running Alpine kernel ("6.6.14-0-lts") with
// the installed kernel package of the same flavor ("linux-lts" 6.6.14-r0).
func apkKernelPending(osrelease string, pkgs []protocol.Package) bool {
	rel := strings.TrimSpace(osrelease)
	i := strings.LastIndex(rel, "-")
	if i <= 0 {
		return false
	}
	flavor, ver := rel[i+1:], rel[:i] // "lts", "6.6.14-0"
	for _, p := range pkgs {
		if p.Name != "linux-"+flavor {
			continue
		}
		installed := strings.Replace(p.Version, "-r", "-", 1)
		return installed != ver
	}
	return false
}
