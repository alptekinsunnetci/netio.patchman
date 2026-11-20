package agent

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"netio.patchman/internal/i18n"
	"netio.patchman/internal/protocol"
)

func TestLoadConfigFromFileWithEnvOverride(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.env")
	content := "# netio.patchman ajan yapılandırması\nPATCHMAN_SERVER_URL=\"https://patchman.example.test/\"\nPATCHMAN_ENROLLMENT_TOKEN=from-file\nPATCHMAN_REMOTE_UPDATES=false\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	l := i18n.MustLoad().Localizer(i18n.DefaultLocale)
	cfg, err := LoadConfig(l, path, func(k string) string {
		if k == "PATCHMAN_ENROLLMENT_TOKEN" {
			return "from-env"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServerURL.String() != "https://patchman.example.test" || cfg.EnrollmentToken != "from-env" || cfg.RemoteUpdates {
		t.Errorf("unexpected config: %+v", cfg)
	}
}

func TestLoadConfigTurkishErrors(t *testing.T) {
	l := i18n.MustLoad().Localizer(i18n.DefaultLocale)
	_, err := LoadConfig(l, filepath.Join(t.TempDir(), "missing.env"), func(string) string { return "" })
	if err == nil || !strings.Contains(err.Error(), "zorunludur") {
		t.Errorf("expected Turkish required-field error, got %v", err)
	}
}

func TestParseDpkg(t *testing.T) {
	out := "ii \tlibssl3\t3.0.11-1~deb12u2\tamd64\topenssl\t3.0.11-1~deb12u2\topenssl\n" +
		"ii \tbash\t5.2.15-2+b2\tamd64\t\t\tbash (5.2.15-2)\n" +
		"rc \toldpkg\t1.0\tamd64\toldpkg\t1.0\t\n" +
		"hi \tlibc6\t2.36-9+deb12u4\tamd64\tglibc\t2.36-9+deb12u4\tglibc\n"
	pkgs := parseDpkg([]byte(out))
	if len(pkgs) != 3 {
		t.Fatalf("got %d packages: %+v", len(pkgs), pkgs)
	}
	if pkgs[0].SourceName != "openssl" || pkgs[0].SourceVersion != "3.0.11-1~deb12u2" {
		t.Errorf("libssl3: %+v", pkgs[0])
	}
	if pkgs[1].SourceName != "bash" || pkgs[1].SourceVersion != "5.2.15-2" {
		t.Errorf("bash fallback: %+v", pkgs[1])
	}
	if pkgs[2].Name != "libc6" || pkgs[2].SourceName != "glibc" {
		t.Errorf("held package: %+v", pkgs[2])
	}
}

func TestParseAptSimulate(t *testing.T) {
	out := `Reading package lists...
Inst libssl3 [3.0.11-1~deb12u1] (3.0.11-1~deb12u2 Debian-Security:12/stable-security [amd64])
Inst tzdata [2024a-0+deb12u1] (2025b-0+deb12u1 Debian:12.11/stable-updates [all])
Inst linux-image-6.1.0-37-amd64 (6.1.140-1 Debian-Security:12/stable-security [amd64])
Inst linux-firmware-amd-graphics (20240318.git3b128b60-0ubuntu2.17 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [all])
Inst libc6 [2.39-0ubuntu8.5] (2.39-0ubuntu8.6 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
Conf libssl3 (3.0.11-1~deb12u2 Debian-Security:12/stable-security [amd64])
`
	// New packages pulled in as dependencies are not installed, so they are
	// not updates: "install --only-upgrade" would skip them.
	ups := parseAptSimulate([]byte(out))
	if len(ups) != 3 {
		t.Fatalf("got %+v", ups)
	}
	if !ups[0].Security || ups[0].CurrentVersion != "3.0.11-1~deb12u1" || ups[0].AvailableVersion != "3.0.11-1~deb12u2" {
		t.Errorf("libssl3: %+v", ups[0])
	}
	if ups[1].Security || ups[1].Repository != "Debian:12.11/stable-updates" {
		t.Errorf("tzdata: %+v", ups[1])
	}
	if ups[2].Name != "libc6" || !ups[2].Security || ups[2].Repository != "Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security" {
		t.Errorf("libc6 from two pockets: %+v", ups[2])
	}
}

func TestParseRPMAndCheckUpdate(t *testing.T) {
	pkgs := parseRPM([]byte("openssl\t1\t3.0.7-24.el9\tx86_64\topenssl-3.0.7-24.el9.src.rpm\nbash\t0\t5.1.8-6.el9\tx86_64\tbash-5.1.8-6.el9.src.rpm\ngpg-pubkey\t0\tabc-def\t(none)\t(none)\n"))
	if len(pkgs) != 2 || pkgs[0].Version != "1:3.0.7-24.el9" || pkgs[1].Version != "5.1.8-6.el9" || pkgs[0].SourceName != "openssl" {
		t.Fatalf("rpm: %+v", pkgs)
	}
	ups := parseCheckUpdate([]byte(`
openssl.x86_64                        1:3.0.7-27.el9                   baseos
a-very-long-package-name-that-wraps.noarch
                                      2.0-1.el9                        appstream
Obsoleting Packages
grub2-tools.x86_64                    1:2.06-80.el9                    baseos
`))
	if len(ups) != 2 || ups[0].Name != "openssl.x86_64" || ups[1].AvailableVersion != "2.0-1.el9" {
		t.Fatalf("check-update: %+v", ups)
	}
}

func TestNewestRPMKernel(t *testing.T) {
	out := "1715000000 5.14.0-427.13.1.el9_4.x86_64\npackage kernel is not installed\n1731000000 5.14.0-503.14.1.el9_5.x86_64\n1720000000 5.14.0-427.42.1.el9_4.x86_64\n"
	if got := newestRPMKernel([]byte(out)); got != "5.14.0-503.14.1.el9_5.x86_64" {
		t.Errorf("newest kernel: %q", got)
	}
	if got := newestRPMKernel([]byte("package kernel-core is not installed\n")); got != "" {
		t.Errorf("no kernel installed: %q", got)
	}
	// Containers have no kernel package: no reboot is reported and rpm is not run.
	if _, err := exec.LookPath("needs-restarting"); err == nil {
		return // the host's own answer would be used instead
	}
	if rpmRebootRequired(context.Background(), []protocol.Package{{Name: "bash", Version: "5.1.8-6.el9"}}) {
		t.Error("reboot reported without an installed kernel")
	}
}

func TestApk(t *testing.T) {
	db := filepath.Join(t.TempDir(), "installed")
	content := "C:Q1abc=\nP:musl\nV:1.2.4-r2\nA:x86_64\no:musl\n\nC:Q1def=\nP:libcrypto3\nV:3.1.4-r0\nA:x86_64\no:openssl\n"
	if err := os.WriteFile(db, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	pkgs, err := apkPackages(db)
	if err != nil || len(pkgs) != 2 || pkgs[1].SourceName != "openssl" || pkgs[1].SourceVersion != "3.1.4-r0" {
		t.Fatalf("apk db: %+v %v", pkgs, err)
	}
	ups := parseApkList([]byte("libcrypto3-3.1.4-r5 x86_64 {openssl} (Apache-2.0) [upgradable from: libcrypto3-3.1.4-r0]\n"))
	if len(ups) != 1 || ups[0].Name != "libcrypto3" || ups[0].AvailableVersion != "3.1.4-r5" || ups[0].CurrentVersion != "3.1.4-r0" {
		t.Fatalf("apk list: %+v", ups)
	}
}

func TestJobRunnerRejectsUnsafeInput(t *testing.T) {
	l := i18n.MustLoad().Localizer(i18n.DefaultLocale)
	r := JobRunner{L: l, PM: protocol.PMApt, RemoteUpdates: true}
	res := r.Run(context.Background(), protocol.Job{ID: 1, Type: protocol.JobUpgradePackages, Packages: []string{"--allow-unauthenticated"}})
	if res.Succeeded || !strings.Contains(res.Output, "Geçersiz paket adı") {
		t.Errorf("option injection not rejected: %+v", res)
	}
	r.RemoteUpdates = false
	res = r.Run(context.Background(), protocol.Job{ID: 2, Type: protocol.JobUpgradeAll})
	if res.Succeeded || !strings.Contains(res.Output, "devre dışı") {
		t.Errorf("disabled remote updates not enforced: %+v", res)
	}
	res = r.Run(context.Background(), protocol.Job{ID: 3, Type: protocol.JobRefresh})
	if !res.Succeeded {
		t.Errorf("refresh should succeed: %+v", res)
	}
}

func TestTailBufferCarriageReturn(t *testing.T) {
	b := &tailBuffer{max: 1 << 10}
	// dpkg progress, split across writes, then CRLF output.
	for _, s := range []string{"Unpacking libc6 ...\n(Reading database ... \r(Reading data", "base ... 5%\r(Reading database ... 100%\r",
		"(Reading database ... 4988 files and directories currently installed.)\n", "Setting up libc6\r\n", "done\r"} {
		_, _ = b.Write([]byte(s))
	}
	want := "Unpacking libc6 ...\n(Reading database ... 4988 files and directories currently installed.)\nSetting up libc6\ndone"
	if got := b.String(); got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
	// The size limit still applies.
	small := &tailBuffer{max: 8}
	_, _ = small.Write([]byte("0123456789\nabc"))
	if got := small.String(); got != "…\n6789\nabc" {
		t.Errorf("tail: %q", got)
	}
}

func TestParseRestartServices(t *testing.T) {
	svc, reboot := parseNeedrestart([]byte(`NEEDRESTART-VER: 3.6
NEEDRESTART-KCUR: 6.8.0-31-generic
NEEDRESTART-KEXP: 6.8.0-45-generic
NEEDRESTART-KSTA: 3
NEEDRESTART-UCSTA: 1
NEEDRESTART-SVC: ssh.service
NEEDRESTART-SVC: cron.service
NEEDRESTART-SVC: cron.service
NEEDRESTART-SESS: root @ session #1
`))
	if !reboot || strings.Join(svc, ",") != "cron.service,ssh.service" {
		t.Errorf("needrestart: %v %v", svc, reboot)
	}
	if _, reboot := parseNeedrestart([]byte("NEEDRESTART-KSTA: 1" + string(rune(10)) + "NEEDRESTART-UCSTA: 1")); reboot {
		t.Error("current kernel reported as pending reboot")
	}
	svc = parseServiceList([]byte(`Updating Subscription Management repositories.
sshd.service
chronyd.service

bad name
`))
	if strings.Join(svc, ",") != "chronyd.service,sshd.service" {
		t.Errorf("needs-restarting: %v", svc)
	}
}

// fakeHost simulates a package manager for JobRunner tests.
type fakeHost struct {
	pending  []protocol.Update
	upgrade  map[string]bool // packages the upgrade command really upgrades
	services []string
	ran      []string
}

func (f *fakeHost) exec(_ context.Context, c command, out *tailBuffer) int {
	line := c.name + " " + strings.Join(c.args, " ")
	f.ran = append(f.ran, line)
	if c.name == "systemctl" {
		f.services = slices.DeleteFunc(f.services, func(s string) bool { return s == c.args[1] })
		return 0
	}
	if slices.Contains(c.args, "update") {
		return 0
	}
	var left []protocol.Update
	for _, u := range f.pending {
		if !f.upgrade[u.Name] || !strings.Contains(line, " "+u.Name) && !strings.HasSuffix(line, "--with-new-pkgs") {
			left = append(left, u)
		}
	}
	f.pending = left
	return 0
}

func (f *fakeHost) runner(t *testing.T) JobRunner {
	return JobRunner{L: i18n.MustLoad().Localizer(i18n.DefaultLocale), PM: protocol.PMApt, RemoteUpdates: true, Exec: f.exec,
		Pending:  func(context.Context) ([]protocol.Update, error) { return slices.Clone(f.pending), nil },
		Services: func(context.Context) []string { return slices.Clone(f.services) },
	}
}

func TestJobVerification(t *testing.T) {
	ctx := context.Background()
	// Every package upgraded: success.
	f := &fakeHost{pending: []protocol.Update{{Name: "libssl3", Security: true}, {Name: "tzdata"}}, upgrade: map[string]bool{"libssl3": true, "tzdata": true}}
	res := f.runner(t).Run(ctx, protocol.Job{Type: protocol.JobUpgradeSecurity})
	if !res.Succeeded || len(res.Remaining) != 0 || !strings.Contains(f.ran[1], "--only-upgrade libssl3") || strings.Contains(f.ran[1], "tzdata") {
		t.Errorf("security job: %+v %v", res, f.ran)
	}

	// The command exits 0 but nothing changes: failed, with the packages left.
	f = &fakeHost{pending: []protocol.Update{{Name: "libssl3", Security: true}}}
	res = f.runner(t).Run(ctx, protocol.Job{Type: protocol.JobUpgradeSecurity})
	if res.Succeeded || strings.Join(res.Remaining, ",") != "libssl3" || !strings.Contains(res.Output, "hiçbiri güncellenmedi") {
		t.Errorf("unverified success: %+v", res)
	}

	// Some packages left: partial (succeeded with remaining).
	f = &fakeHost{pending: []protocol.Update{{Name: "a"}, {Name: "b"}}, upgrade: map[string]bool{"a": true}}
	res = f.runner(t).Run(ctx, protocol.Job{Type: protocol.JobUpgradeAll})
	if !res.Succeeded || strings.Join(res.Remaining, ",") != "b" {
		t.Errorf("partial: %+v", res)
	}

	// Selected packages without a pending update are not sent to apt.
	f = &fakeHost{pending: []protocol.Update{{Name: "a"}}, upgrade: map[string]bool{"a": true}}
	res = f.runner(t).Run(ctx, protocol.Job{Type: protocol.JobUpgradePackages, Packages: []string{"a", "libdrm-amdgpu1"}})
	if !res.Succeeded || strings.Contains(f.ran[1], "libdrm") || !strings.Contains(res.Output, "libdrm-amdgpu1") {
		t.Errorf("not pending package: %+v %v", res, f.ran)
	}
	f = &fakeHost{}
	res = f.runner(t).Run(ctx, protocol.Job{Type: protocol.JobUpgradePackages, Packages: []string{"libdrm-amdgpu1"}})
	if !res.Succeeded || len(f.ran) != 1 {
		t.Errorf("nothing pending should run only the list refresh: %+v %v", res, f.ran)
	}
}

func TestRestartServicesJob(t *testing.T) {
	ctx := context.Background()
	f := &fakeHost{services: []string{"cron.service", "dbus.service", "ssh.service"}}
	res := f.runner(t).Run(ctx, protocol.Job{Type: protocol.JobRestartServices, Packages: []string{"cron.service", "dbus.service", "ssh.service"}})
	if !res.Succeeded || len(res.Remaining) != 0 || len(f.ran) != 2 || !strings.Contains(res.Output, "dbus.service atlandı") {
		t.Errorf("restart: %+v %v", res, f.ran)
	}
	res = f.runner(t).Run(ctx, protocol.Job{Type: protocol.JobRestartServices, Packages: []string{"-evil"}})
	if res.Succeeded {
		t.Errorf("invalid service accepted: %+v", res)
	}
	res = f.runner(t).Run(ctx, protocol.Job{Type: protocol.JobReboot})
	if !res.Succeeded || !strings.HasPrefix(f.ran[len(f.ran)-1], "shutdown -r +1 ") {
		t.Errorf("reboot: %+v %v", res, f.ran)
	}
}
