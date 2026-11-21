package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"netio.patchman/internal/protocol"
)

// run executes a command with a C locale so output is parseable.
func run(ctx context.Context, timeout time.Duration, name string, args ...string) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LANG=C", "LC_ALL=C", "DEBIAN_FRONTEND=noninteractive")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code = exitErr.ExitCode()
	}
	if err != nil && code == 0 {
		return stdout.Bytes(), -1, err
	}
	if code != 0 {
		err = fmt.Errorf("%s: exit %d: %s", name, code, strings.TrimSpace(lastLines(stderr.String(), 3)))
	}
	return stdout.Bytes(), code, err
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}

// Collector gathers the inventory for one package manager.
type Collector struct {
	PM           string
	RefreshLists bool
	StateDir     string
}

// Inventory is what one collection run found.
type Inventory struct {
	Packages []protocol.Package
	Updates  []protocol.Update
	Reboot   bool
	// Services still running replaced code; see RestartServices.
	Services []string
	Errors   []string
	// KernelPatch is the live kernel patching service, nil when none.
	KernelPatch *protocol.KernelPatch
}

// Collect gathers packages, pending updates, the reboot flag and services
// that need a restart. Partial failures are listed in Errors so the server
// still receives what worked.
func (c Collector) Collect(ctx context.Context) Inventory {
	pkgs, updates, reboot, errs := c.collect(ctx)
	services, kernelPending := RestartServices(ctx, c.PM)
	var kp *protocol.KernelPatch
	if c.PM != protocol.PMWindowsUpdate {
		kp = kernelPatch(ctx)
	}
	// A kernel update already active through KernelCare needs no reboot;
	// updated core libraries (glibc, systemd) still do.
	if reboot && kp != nil && kp.Provider == protocol.KernelCare && (c.PM == protocol.PMDnf || c.PM == protocol.PMYum) &&
		kernelCareCovers(kp.EffectiveKernel, newestKernel(ctx, pkgs)) {
		reboot = rpmNonKernelReboot(ctx)
	}
	return Inventory{Packages: pkgs, Updates: updates, Reboot: reboot || kernelPending, Services: services, Errors: errs, KernelPatch: kp}
}

// PendingUpdates lists pending updates without refreshing the package lists.
func PendingUpdates(ctx context.Context, pm string) ([]protocol.Update, error) {
	switch pm {
	case protocol.PMApt:
		return aptUpdates(ctx)
	case protocol.PMDnf, protocol.PMYum:
		pkgs, err := rpmPackages(ctx)
		if err != nil {
			return nil, err
		}
		return dnfUpdates(ctx, pm, pkgs)
	case protocol.PMZypper:
		pkgs, err := rpmPackages(ctx)
		if err != nil {
			return nil, err
		}
		return zypperUpdates(ctx, pkgs)
	case protocol.PMApk:
		return apkUpdates(ctx)
	case protocol.PMWindowsUpdate:
		// Jobs ask the update service so targets match what will be installed.
		ups, _, err := wuPending(ctx, true)
		if err != nil {
			return nil, err
		}
		if exe := wingetExe(); exe != "" && wingetEnabled {
			if more, err := wingetList(ctx, exe); err == nil {
				ups = append(ups, more...)
			}
		}
		return ups, nil
	}
	return nil, errors.New("unsupported package manager")
}

func (c Collector) collect(ctx context.Context) (pkgs []protocol.Package, updates []protocol.Update, reboot bool, errs []string) {
	addErr := func(err error) {
		if err != nil {
			errs = append(errs, err.Error())
		}
	}
	var err error
	switch c.PM {
	case protocol.PMApt:
		pkgs, err = dpkgPackages(ctx)
		addErr(err)
		if c.refreshDue() {
			_, _, err = run(ctx, 10*time.Minute, "apt-get", "update", "-qq")
			addErr(err)
			if err == nil {
				c.markRefreshed()
			}
		}
		updates, err = aptUpdates(ctx)
		addErr(err)
		// Ubuntu's update-notifier writes the flag file; Debian has none, so
		// a kernel image newer than the running one also counts.
		_, statErr := os.Stat("/var/run/reboot-required")
		reboot = statErr == nil || aptKernelPending("/")
	case protocol.PMDnf, protocol.PMYum:
		pkgs, err = rpmPackages(ctx)
		addErr(err)
		updates, err = dnfUpdates(ctx, c.PM, pkgs)
		addErr(err)
		reboot = rpmRebootRequired(ctx, pkgs)
	case protocol.PMZypper:
		pkgs, err = rpmPackages(ctx)
		addErr(err)
		if c.refreshDue() {
			_, _, err = run(ctx, 10*time.Minute, "zypper", "--non-interactive", "--quiet", "refresh")
			addErr(err)
			if err == nil {
				c.markRefreshed()
			}
		}
		updates, err = zypperUpdates(ctx, pkgs)
		addErr(err)
		_, code, _ := run(ctx, time.Minute, "zypper", "needs-rebooting")
		reboot = code == 102
	case protocol.PMApk:
		pkgs, err = apkPackages("/lib/apk/db/installed")
		addErr(err)
		if c.refreshDue() {
			_, _, err = run(ctx, 10*time.Minute, "apk", "update", "-q")
			addErr(err)
			if err == nil {
				c.markRefreshed()
			}
		}
		updates, err = apkUpdates(ctx)
		addErr(err)
		if rel, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
			reboot = apkKernelPending(string(rel), pkgs)
		}
	case protocol.PMWindowsUpdate:
		return c.collectWindows(ctx)
	default:
		errs = append(errs, "unsupported package manager")
	}
	return
}

const refreshEvery = 6 * time.Hour

func (c Collector) refreshDue() bool {
	if !c.RefreshLists {
		return false
	}
	st, err := os.Stat(filepath.Join(c.StateDir, "lists-refreshed"))
	return err != nil || time.Since(st.ModTime()) > refreshEvery
}

func (c Collector) markRefreshed() {
	p := filepath.Join(c.StateDir, "lists-refreshed")
	_ = os.WriteFile(p, []byte(time.Now().UTC().Format(time.RFC3339)), 0o600)
	now := time.Now()
	_ = os.Chtimes(p, now, now)
}

// ---------- dpkg / apt ----------

const dpkgFormat = "${db:Status-Abbrev}\t${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\t${Source}\n"

func dpkgPackages(ctx context.Context) ([]protocol.Package, error) {
	out, _, err := run(ctx, 2*time.Minute, "dpkg-query", "-W", "-f="+dpkgFormat)
	if err != nil {
		return nil, err
	}
	return parseDpkg(out), nil
}

func parseDpkg(out []byte) []protocol.Package {
	var pkgs []protocol.Package
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		f := strings.Split(sc.Text(), "\t")
		if len(f) < 7 {
			continue
		}
		status := strings.TrimSpace(f[0])
		// "ii" installed, "hi" held; skip removed/config-files ("rc") and half states.
		if len(status) < 2 || status[1] != 'i' {
			continue
		}
		p := protocol.Package{Name: f[1], Version: f[2], Arch: f[3], SourceName: f[4], SourceVersion: f[5]}
		if p.SourceName == "" {
			// Older dpkg: parse "${Source}" which is "name" or "name (version)".
			src := strings.TrimSpace(f[6])
			if name, ver, ok := strings.Cut(src, " ("); ok {
				p.SourceName, p.SourceVersion = name, strings.TrimSuffix(ver, ")")
			} else if src != "" {
				p.SourceName = src
			} else {
				p.SourceName = p.Name
			}
		}
		if p.SourceVersion == "" {
			p.SourceVersion = p.Version
		}
		pkgs = append(pkgs, p)
	}
	return pkgs
}

func aptUpdates(ctx context.Context) ([]protocol.Update, error) {
	out, _, err := run(ctx, 5*time.Minute, "apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade", "--with-new-pkgs")
	if err != nil {
		return nil, err
	}
	return parseAptSimulate(out), nil
}

// Inst libssl3 [3.0.11-1~deb12u1] (3.0.11-1~deb12u2 Debian-Security:12/stable-security [amd64])
var aptInstRE = regexp.MustCompile(`^Inst (\S+) (?:\[([^\]]*)\] )?\((\S+) (.*?)(?: \[[^\]]*\])?\)`)

// parseAptSimulate returns upgrades of installed packages. "Inst" lines
// without a current version ("[...]") are new packages pulled in as
// dependencies (a new kernel ABI, a split firmware package): they are not
// installed, "install --only-upgrade" skips them, and apt installs them by
// itself when the package that needs them is upgraded.
func parseAptSimulate(out []byte) []protocol.Update {
	var ups []protocol.Update
	seen := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		m := aptInstRE.FindStringSubmatch(sc.Text())
		if m == nil || m[2] == "" || seen[m[1]] {
			continue
		}
		seen[m[1]] = true
		repo := strings.TrimSpace(m[4])
		ups = append(ups, protocol.Update{
			Name: m[1], CurrentVersion: m[2], AvailableVersion: m[3], Repository: repo,
			Security: strings.Contains(strings.ToLower(repo), "security"),
		})
	}
	return ups
}

// ---------- rpm / dnf / yum / zypper ----------

func rpmPackages(ctx context.Context) ([]protocol.Package, error) {
	out, _, err := run(ctx, 2*time.Minute, "rpm", "-qa", "--qf", `%{NAME}\t%{EPOCHNUM}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\n`)
	if err != nil {
		return nil, err
	}
	return parseRPM(out), nil
}

func parseRPM(out []byte) []protocol.Package {
	var pkgs []protocol.Package
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Split(sc.Text(), "\t")
		if len(f) < 5 || f[0] == "gpg-pubkey" {
			continue
		}
		ver := f[2]
		if f[1] != "" && f[1] != "0" && f[1] != "(none)" {
			ver = f[1] + ":" + ver // OSV RPM ecosystems use epoch-prefixed versions
		}
		p := protocol.Package{Name: f[0], Version: ver, Arch: f[3]}
		if src := strings.TrimSuffix(f[4], ".src.rpm"); src != f[4] {
			// name-version-release
			if i := strings.LastIndex(src, "-"); i > 0 {
				if j := strings.LastIndex(src[:i], "-"); j > 0 {
					p.SourceName = src[:j]
				}
			}
		}
		pkgs = append(pkgs, p)
	}
	return pkgs
}

func installedIndex(pkgs []protocol.Package) map[string]string {
	idx := make(map[string]string, len(pkgs)*2)
	for _, p := range pkgs {
		idx[p.Name+"."+p.Arch] = p.Version
		if _, ok := idx[p.Name]; !ok {
			idx[p.Name] = p.Version
		}
	}
	return idx
}

func dnfUpdates(ctx context.Context, pm string, installed []protocol.Package) ([]protocol.Update, error) {
	out, code, err := run(ctx, 10*time.Minute, pm, "-q", "check-update")
	if code != 100 && err != nil {
		return nil, err
	}
	all := parseCheckUpdate(out)
	sec := map[string]bool{}
	if out, code, _ := run(ctx, 10*time.Minute, pm, "-q", "check-update", "--security"); code == 0 || code == 100 {
		for _, u := range parseCheckUpdate(out) {
			sec[u.Name] = true
		}
	}
	idx := installedIndex(installed)
	res := make([]protocol.Update, 0, len(all))
	seen := map[string]bool{}
	for _, u := range all {
		name, arch := splitNameArch(u.Name)
		if seen[name] {
			continue
		}
		seen[name] = true
		res = append(res, protocol.Update{
			Name: name, CurrentVersion: firstNonEmpty(idx[name+"."+arch], idx[name]), AvailableVersion: u.AvailableVersion,
			Repository: u.Repository, Security: sec[u.Name],
		})
	}
	return res, nil
}

// parseCheckUpdate parses "name.arch  version  repo" lines, joining wrapped lines.
func parseCheckUpdate(out []byte) []protocol.Update {
	var ups []protocol.Update
	var pending []string
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "Obsoleting") || strings.HasPrefix(line, "Security:") {
			break
		}
		f := strings.Fields(line)
		if len(f) == 0 {
			pending = nil
			continue
		}
		f = append(pending, f...)
		if len(f) < 3 {
			pending = f
			continue
		}
		pending = nil
		if !strings.Contains(f[0], ".") {
			continue
		}
		ups = append(ups, protocol.Update{Name: f[0], AvailableVersion: f[1], Repository: f[2]})
	}
	return ups
}

func splitNameArch(s string) (string, string) {
	i := strings.LastIndex(s, ".")
	if i <= 0 {
		return s, ""
	}
	return s[:i], s[i+1:]
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func rpmRebootRequired(ctx context.Context, pkgs []protocol.Package) bool {
	if _, err := exec.LookPath("needs-restarting"); err == nil {
		_, code, err := run(ctx, 2*time.Minute, "needs-restarting", "-r")
		if code == 1 {
			return true
		}
		if err == nil {
			return false
		}
	}
	// Fallback: the most recently installed kernel is not the running one.
	// Only kernel packages that are actually installed are queried: rpm prints
	// "package X is not installed" to stdout for the others, and containers
	// have no kernel package at all.
	running, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return false
	}
	newest := newestKernel(ctx, pkgs)
	return newest != "" && newest != strings.TrimSpace(string(running))
}

// newestKernel returns the most recently installed kernel as
// "<version>-<release>.<arch>" (uname -r form), "" without kernel packages.
func newestKernel(ctx context.Context, pkgs []protocol.Package) string {
	var names []string
	for _, p := range pkgs {
		if rpmKernelPackages[p.Name] && !slices.Contains(names, p.Name) {
			names = append(names, p.Name)
		}
	}
	if len(names) == 0 {
		return ""
	}
	args := append([]string{"-q", "--qf", `%{INSTALLTIME} %{VERSION}-%{RELEASE}.%{ARCH}\n`}, names...)
	out, _, _ := run(ctx, time.Minute, "rpm", args...)
	return newestRPMKernel(out)
}

// rpmKernelPackages are the package names whose VERSION-RELEASE.ARCH equals
// the kernel release of the running kernel (/proc/sys/kernel/osrelease).
var rpmKernelPackages = map[string]bool{
	"kernel": true, "kernel-core": true, "kernel-uek": true, "kernel-uek-core": true, "kernel-rt-core": true,
}

// newestRPMKernel picks the release with the latest install time from lines
// of "<installtime> <version>-<release>.<arch>"; other lines are ignored.
func newestRPMKernel(out []byte) string {
	var newest string
	var newestAt int64 = -1
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 2 {
			continue
		}
		at, err := strconv.ParseInt(f[0], 10, 64)
		if err != nil {
			continue
		}
		if at > newestAt {
			newest, newestAt = f[1], at
		}
	}
	return newest
}

type zypperStream struct {
	Updates []struct {
		Kind    string `xml:"kind,attr"`
		Name    string `xml:"name,attr"`
		Edition string `xml:"edition,attr"`
		Arch    string `xml:"arch,attr"`
		Source  struct {
			Alias string `xml:"alias,attr"`
		} `xml:"source"`
	} `xml:"update-status>update-list>update"`
}

func zypperUpdates(ctx context.Context, installed []protocol.Package) ([]protocol.Update, error) {
	out, _, err := run(ctx, 10*time.Minute, "zypper", "--non-interactive", "--no-refresh", "--xmlout", "list-updates")
	if err != nil && len(out) == 0 {
		return nil, err
	}
	var doc zypperStream
	if err := xml.Unmarshal(out, &doc); err != nil {
		return nil, fmt.Errorf("zypper: %w", err)
	}
	idx := installedIndex(installed)
	var res []protocol.Update
	for _, u := range doc.Updates {
		if u.Kind != "" && u.Kind != "package" {
			continue
		}
		res = append(res, protocol.Update{
			Name: u.Name, CurrentVersion: firstNonEmpty(idx[u.Name+"."+u.Arch], idx[u.Name]),
			AvailableVersion: u.Edition, Repository: u.Source.Alias,
		})
	}
	return res, nil
}

// ---------- apk ----------

// apkPackages reads the apk installed database directly.
func apkPackages(path string) ([]protocol.Package, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var pkgs []protocol.Package
	var cur protocol.Package
	flush := func() {
		if cur.Name != "" && cur.Version != "" {
			if cur.SourceName == "" {
				cur.SourceName = cur.Name
			}
			cur.SourceVersion = cur.Version
			pkgs = append(pkgs, cur)
		}
		cur = protocol.Package{}
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			flush()
			continue
		}
		if len(line) < 2 || line[1] != ':' {
			continue
		}
		switch line[0] {
		case 'P':
			cur.Name = line[2:]
		case 'V':
			cur.Version = line[2:]
		case 'A':
			cur.Arch = line[2:]
		case 'o':
			cur.SourceName = line[2:]
		}
	}
	flush()
	return pkgs, sc.Err()
}

func apkUpdates(ctx context.Context) ([]protocol.Update, error) {
	out, _, err := run(ctx, 5*time.Minute, "apk", "list", "-u")
	if err != nil {
		return nil, err
	}
	return parseApkList(out), nil
}

// musl-1.2.4-r3 x86_64 {musl} (MIT) [upgradable from: musl-1.2.4-r2]
var apkListRE = regexp.MustCompile(`^(\S+) \S+ \{[^}]*\} \([^)]*\) \[upgradable from: (\S+)\]`)

func parseApkList(out []byte) []protocol.Update {
	var ups []protocol.Update
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		m := apkListRE.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		name, newVer := splitApkNameVersion(m[1])
		_, oldVer := splitApkNameVersion(m[2])
		if name == "" {
			continue
		}
		ups = append(ups, protocol.Update{Name: name, CurrentVersion: oldVer, AvailableVersion: newVer})
	}
	return ups
}

// splitApkNameVersion splits "name-1.2.3-r0" into ("name", "1.2.3-r0").
func splitApkNameVersion(s string) (string, string) {
	i := strings.LastIndex(s, "-r")
	if i <= 0 {
		return "", ""
	}
	j := strings.LastIndex(s[:i], "-")
	if j <= 0 {
		return "", ""
	}
	return s[:j], s[j+1:]
}

// ---------- services that need a restart ----------

// RestartServices lists services that still run code replaced by an update
// (deleted libraries or binaries), and whether a newer kernel or microcode
// waits for a reboot. It uses needrestart (Debian/Ubuntu), needs-restarting
// (RHEL family) or "zypper ps" (SUSE); without them it returns nothing.
func RestartServices(ctx context.Context, pm string) (services []string, rebootPending bool) {
	switch pm {
	case protocol.PMApt:
		if _, err := exec.LookPath("needrestart"); err != nil {
			return nil, false
		}
		// -b batch output, -r l: list only, never restart anything.
		out, _, err := run(ctx, 3*time.Minute, "needrestart", "-b", "-r", "l")
		if err != nil {
			return nil, false
		}
		return parseNeedrestart(out)
	case protocol.PMDnf, protocol.PMYum:
		var out []byte
		var err error
		if _, lerr := exec.LookPath("needs-restarting"); lerr == nil {
			out, _, err = run(ctx, 3*time.Minute, "needs-restarting", "-s")
		} else if pm == protocol.PMDnf {
			out, _, err = run(ctx, 3*time.Minute, "dnf", "-q", "needs-restarting", "-s")
		} else {
			return nil, false
		}
		if err != nil {
			return nil, false
		}
		return parseServiceList(out), false
	case protocol.PMZypper:
		out, _, err := run(ctx, 3*time.Minute, "zypper", "--quiet", "ps", "-sss")
		if err != nil {
			return nil, false
		}
		return parseServiceList(out), false
	}
	return nil, false
}

// parseNeedrestart reads "needrestart -b" output:
//
//	NEEDRESTART-KSTA: 3
//	NEEDRESTART-UCSTA: 2
//	NEEDRESTART-SVC: cron.service
//
// KSTA 2 and 3 mean a newer kernel is installed; UCSTA 2 means new microcode.
func parseNeedrestart(out []byte) (services []string, rebootPending bool) {
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		key, val, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		switch key {
		case "NEEDRESTART-SVC":
			if protocol.ValidServiceName(val) && !slices.Contains(services, val) {
				services = append(services, val)
			}
		case "NEEDRESTART-KSTA":
			rebootPending = rebootPending || val == "2" || val == "3"
		case "NEEDRESTART-UCSTA":
			rebootPending = rebootPending || val == "2"
		}
	}
	slices.Sort(services)
	return services, rebootPending
}

// parseServiceList reads one service name per line (needs-restarting -s,
// zypper ps -sss). Other lines (headers, warnings) are ignored.
func parseServiceList(out []byte) []string {
	var services []string
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		name := strings.TrimSpace(sc.Text())
		if !protocol.ValidServiceName(name) || slices.Contains(services, name) {
			continue
		}
		services = append(services, name)
	}
	slices.Sort(services)
	return services
}
