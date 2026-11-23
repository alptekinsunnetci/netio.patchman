package agent

import (
	"context"
	"strings"
	"testing"

	"netio.patchman/internal/i18n"
	"netio.patchman/internal/protocol"
)

const aptSim = `NOTE: This is only a simulation!
Reading package lists...
Inst libssl3 [3.0.11-1~deb12u2] (3.0.15-1~deb12u1 Debian-Security:12/stable-security [amd64])
Inst openssl [3.0.11-1~deb12u2] (3.0.15-1~deb12u1 Debian-Security:12/stable-security [amd64])
Inst linux-image-6.1.0-28-amd64 (6.1.119-1 Debian-Security:12/stable-security [amd64])
Inst linux-image-amd64 [6.1.115-1] (6.1.119-1 Debian-Security:12/stable-security [amd64])
Inst tzdata [2025a-0+deb12u1] (2024b-0+deb12u1 Debian:12/stable [all])
Remv oldpkg [1.0-1]
Conf libssl3 (3.0.15-1~deb12u1 Debian-Security:12/stable-security [amd64])
`

const aptAssumeNo = `Need to get 0 B/72.3 MB of archives.
After this operation, 412 MB of additional disk space will be used.
Do you want to continue? [Y/n] N
Abort.
`

func TestParseAptPlan(t *testing.T) {
	up, inst, rem, down := parseAptPlan(aptSim)
	if len(up) != 3 || up[0] != (protocol.PackageChange{Name: "libssl3", Arch: "amd64", From: "3.0.11-1~deb12u2", To: "3.0.15-1~deb12u1"}) {
		t.Errorf("upgrades: %+v", up)
	}
	if len(inst) != 1 || inst[0].Name != "linux-image-6.1.0-28-amd64" || inst[0].From != "" {
		t.Errorf("installs: %+v", inst)
	}
	if len(rem) != 1 || rem[0] != (protocol.PackageChange{Name: "oldpkg", From: "1.0-1"}) {
		t.Errorf("removals: %+v", rem)
	}
	if len(down) != 1 || down[0].Name != "tzdata" {
		t.Errorf("downgrades: %+v", down)
	}
	dl, disk := parseAptSizes(aptAssumeNo)
	if dl != 0 || disk != 412_000_000 {
		t.Errorf("sizes: %d %d", dl, disk)
	}
	if dl, disk := parseAptSizes("Need to get 1,024 kB of archives.\nAfter this operation, 3,072 B disk space will be freed.\n"); dl != 1_024_000 || disk != -3072 {
		t.Errorf("sizes 2: %d %d", dl, disk)
	}
}

const dnf4Plan = `Last metadata expiration check: 0:10:03 ago on Mon 25 Nov 2024 10:00:00 AM UTC.
Dependencies resolved.
================================================================================
 Package                 Arch     Version                     Repository   Size
================================================================================
Upgrading:
 openssl                 x86_64   1:3.0.7-28.el9_4            baseos      1.2 M
 openssl-libs            x86_64   1:3.0.7-28.el9_4            baseos      2.1 M
Installing:
 kernel                  x86_64   5.14.0-427.42.1.el9_4       baseos      5.0 M
Installing dependencies:
 kernel-core             x86_64   5.14.0-427.42.1.el9_4       baseos       18 M
 a-very-long-package-name-that-wraps-the-column
                         noarch   1.0-1.el9                   appstream    10 k
Removing:
 kernel-core             x86_64   5.14.0-362.8.1.el9_3        @baseos      62 M

Transaction Summary
================================================================================
Install  3 Packages
Upgrade  2 Packages
Remove   1 Package

Total download size: 26 M
Operation aborted.
`

const dnf5Plan = `Package                     Arch    Version                     Repository      Size
Upgrading:
 openssl                    x86_64  1:3.2.2-6.fc40              updates      1.3 MiB
   replacing openssl        x86_64  1:3.2.1-2.fc40              updates      1.3 MiB
Transaction Summary:
 Upgrading:          1 package
 Replacing:          1 package

Total size of inbound packages is 1 MiB. Need to download 1 MiB.
After this operation, 3 KiB extra will be used (install 1 MiB, remove 1 MiB).
Operation aborted by the user.
`

func TestParseDnfPlan(t *testing.T) {
	installed := map[string]string{"openssl": "1:3.0.7-27.el9", "openssl-libs": "1:3.0.7-27.el9"}
	up, inst, rem, down := parseDnfPlan(dnf4Plan, installed)
	if len(up) != 2 || up[0] != (protocol.PackageChange{Name: "openssl", Arch: "x86_64", From: "1:3.0.7-27.el9", To: "1:3.0.7-28.el9_4"}) {
		t.Errorf("upgrades: %+v", up)
	}
	if len(inst) != 3 || inst[2].Name != "a-very-long-package-name-that-wraps-the-column" || inst[2].Arch != "noarch" {
		t.Errorf("installs: %+v", inst)
	}
	if len(rem) != 1 || rem[0].From != "5.14.0-362.8.1.el9_3" || len(down) != 0 {
		t.Errorf("removals: %+v %+v", rem, down)
	}
	if dl, disk := parseDnfSizes(dnf4Plan); dl != 26*1024*1024 || disk != -1 {
		t.Errorf("dnf4 sizes: %d %d", dl, disk)
	}
	if errs := dnfErrors(dnf4Plan); len(errs) != 0 {
		t.Errorf("dnf4 errors: %v", errs)
	}
	up, _, _, _ = parseDnfPlan(dnf5Plan, nil)
	if len(up) != 1 || up[0].From != "1:3.2.1-2.fc40" || up[0].To != "1:3.2.2-6.fc40" {
		t.Errorf("dnf5 upgrades: %+v", up)
	}
	if dl, disk := parseDnfSizes(dnf5Plan); dl != 1024*1024 || disk != 3*1024 {
		t.Errorf("dnf5 sizes: %d %d", dl, disk)
	}
	errs := dnfErrors("Error: \n Problem: package foo-2.0 requires libbar >= 3, but none of the providers can be installed\n  - conflicting requests\n  - nothing provides libbar >= 3\n")
	if len(errs) != 4 {
		t.Errorf("dnf errors: %q", errs)
	}
}

const zypperPlan = `Loading repository data...
Reading installed packages...
Resolving package dependencies...

The following 2 packages are going to be upgraded:
  libopenssl3 openssl-3

The following NEW package is going to be installed:
  kernel-default-6.4.0-150600.23.25.1

2 packages to upgrade, 1 new.
Overall download size: 12.3 MiB. Already cached: 0 B. After the operation, additional 45.0 MiB will be used.
`

func TestParseZypperAndApk(t *testing.T) {
	pending := []protocol.Update{{Name: "openssl-3", CurrentVersion: "3.1.4-150600.5.7.1", AvailableVersion: "3.1.4-150600.5.15.1"}}
	up, inst, _, _ := parseZypperPlan(zypperPlan, pending)
	if len(up) != 2 || up[1].From != "3.1.4-150600.5.7.1" || len(inst) != 1 {
		t.Errorf("zypper: %+v %+v", up, inst)
	}
	if dl, disk := parseZypperSizes(zypperPlan); dl != 12897484 || disk != 45*1024*1024 {
		t.Errorf("zypper sizes: %d %d", dl, disk)
	}
	up, inst, rem, _ := parseApkPlan("(1/3) Upgrading musl (1.2.4_git20230717-r4 -> 1.2.4_git20230717-r5)\n(2/3) Installing linux-firmware-none (20240811-r0)\n(3/3) Purging oldthing (1.0-r0)\nOK: 50 MiB in 30 packages\n")
	if len(up) != 1 || up[0].To != "1.2.4_git20230717-r5" || len(inst) != 1 || len(rem) != 1 || rem[0].From != "1.0-r0" {
		t.Errorf("apk: %+v %+v %+v", up, inst, rem)
	}
}

func TestPlanNeedsReboot(t *testing.T) {
	k, r := planNeedsReboot(&protocol.Preview{Upgrades: []protocol.PackageChange{{Name: "openssl"}}})
	if k || r {
		t.Errorf("openssl: %v %v", k, r)
	}
	k, r = planNeedsReboot(&protocol.Preview{Installs: []protocol.PackageChange{{Name: "linux-image-6.1.0-28-amd64"}}})
	if !k || !r {
		t.Errorf("kernel: %v %v", k, r)
	}
	k, r = planNeedsReboot(&protocol.Preview{Upgrades: []protocol.PackageChange{{Name: "libc6"}}})
	if k || !r {
		t.Errorf("libc6: %v %v", k, r)
	}
}

func TestPreviewJob(t *testing.T) {
	var ran []string
	exec := func(_ context.Context, c command, out *tailBuffer) int {
		line := c.name + " " + strings.Join(c.args, " ")
		ran = append(ran, line)
		switch {
		case strings.Contains(line, " -s "):
			_, _ = out.Write([]byte(aptSim))
		case strings.Contains(line, "--assume-no"):
			_, _ = out.Write([]byte(aptAssumeNo))
			return 1
		}
		return 0
	}
	r := JobRunner{L: i18n.MustLoad().Localizer(i18n.DefaultLocale), PM: protocol.PMApt, RemoteUpdates: false, Exec: exec,
		Pending: func(context.Context) ([]protocol.Update, error) {
			return []protocol.Update{{Name: "openssl", CurrentVersion: "3.0.11-1~deb12u2", AvailableVersion: "3.0.15-1~deb12u1", Security: true}}, nil
		}}
	res := r.Run(context.Background(), protocol.Job{ID: 1, Type: protocol.JobPreview, Params: map[string]string{protocol.ParamPreviewType: protocol.JobUpgradeAll}})
	if !res.Succeeded || res.Preview == nil {
		t.Fatalf("preview: %+v", res)
	}
	p := res.Preview
	if len(p.Upgrades) != 3 || !p.Kernel || !p.Reboot || p.DiskBytes != 412_000_000 || p.PackageManager != "apt" {
		t.Errorf("plan: %+v", p)
	}
	for _, l := range ran {
		if strings.Contains(l, " -y ") && !strings.Contains(l, " -s ") {
			t.Errorf("a command could change the host: %s", l)
		}
	}
	if len(ran) != 3 || !strings.HasPrefix(ran[0], "apt-get update") {
		t.Errorf("commands: %v", ran)
	}
	// Unknown job type to simulate.
	if res := r.Run(context.Background(), protocol.Job{ID: 2, Type: protocol.JobPreview, Params: map[string]string{protocol.ParamPreviewType: "reboot"}}); res.Succeeded {
		t.Errorf("preview of a reboot accepted")
	}
}
