package agent

import (
	"bufio"
	"context"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"netio.patchman/internal/pkgver"
	"netio.patchman/internal/protocol"
)

// preview runs the package manager's dry run of a package job and returns
// the plan. Nothing is installed or removed; only the package lists may be
// refreshed, as the real job does first.
func (r JobRunner) preview(ctx context.Context, s *jobState, job protocol.Job) protocol.JobResult {
	typ := job.Params[protocol.ParamPreviewType]
	if !isPackageJob(typ) {
		return s.finish(false, -1, r.L.T("agent.job.unknown_type", "type", typ))
	}
	for _, p := range job.Packages {
		if !protocol.ValidPackageName(p) {
			return s.finish(false, -1, r.L.T("agent.job.invalid_package", "package", p))
		}
	}
	if r.PM == protocol.PMWindowsUpdate || r.PM == "" {
		return s.finish(false, -1, r.L.T("agent.preview.unsupported"))
	}
	if c := r.refreshCommand(); c != nil {
		if code, failed := s.step(ctx, *c); failed {
			return r.failStep(s, ctx, *c, code)
		}
	}
	var before []protocol.Update
	known := false
	if r.Pending != nil {
		var err error
		if before, err = r.Pending(ctx); err == nil {
			known = true
		}
	}
	sim := protocol.Job{ID: job.ID, Type: typ, Packages: job.Packages, Params: job.Params}
	cmds, _, msg, err := r.plan(sim, before, known)
	if err != nil {
		return s.finish(false, -1, err.Error())
	}
	p := &protocol.Preview{PackageManager: r.PM, DownloadBytes: -1, DiskBytes: -1, FreeBytes: freeBytes()}
	s.res.Preview = p
	if len(cmds) == 0 {
		return s.finish(true, 0, msg)
	}
	s.note(msg)
	c := cmds[0]
	var out string
	switch r.PM {
	case protocol.PMApt:
		out = r.capture(ctx, s, command{name: c.name, args: withAptFlag(c.args, "-s")})
		p.Upgrades, p.Installs, p.Removals, p.Downgrades = parseAptPlan(out)
		sizes := r.capture(ctx, s, command{name: c.name, args: withAptFlag(dropArg(c.args, "-y"), "--assume-no")})
		p.DownloadBytes, p.DiskBytes = parseAptSizes(sizes)
		p.Conflicts = errorLines(out+"\n"+sizes, "E: ")
	case protocol.PMDnf, protocol.PMYum:
		out = r.capture(ctx, s, command{name: c.name, args: append(dropArg(c.args, "-y"), "--assumeno")})
		p.Upgrades, p.Installs, p.Removals, p.Downgrades = parseDnfPlan(out, installedVersions(before))
		p.DownloadBytes, p.DiskBytes = parseDnfSizes(out)
		p.Conflicts = dnfErrors(out)
	case protocol.PMZypper:
		args := slices.Clone(c.args)
		// "zypper --non-interactive update|patch ..." -> add --dry-run after the command.
		for i, a := range args {
			if a == "update" || a == "patch" {
				args = slices.Insert(args, i+1, "--dry-run")
				break
			}
		}
		out = r.capture(ctx, s, command{name: c.name, args: args, okCodes: c.okCodes})
		p.Upgrades, p.Installs, p.Removals, p.Downgrades = parseZypperPlan(out, before)
		p.DownloadBytes, p.DiskBytes = parseZypperSizes(out)
		p.Conflicts = errorLines(out, "Problem:", "Error:")
	case protocol.PMApk:
		out = r.capture(ctx, s, command{name: c.name, args: append([]string{"--simulate"}, c.args...)})
		p.Upgrades, p.Installs, p.Removals, p.Downgrades = parseApkPlan(out)
		p.Conflicts = errorLines(out, "ERROR:")
	}
	p.Kernel, p.Reboot = planNeedsReboot(p)
	if p.DiskBytes > 0 && p.FreeBytes >= 0 && p.DiskBytes+max(p.DownloadBytes, 0) > p.FreeBytes {
		p.Conflicts = append(p.Conflicts, r.L.T("agent.preview.disk_space"))
	}
	p.Plan = lastLines(out, 400)
	trim := func(l []protocol.PackageChange) []protocol.PackageChange {
		if len(l) > protocol.MaxPreviewPackages {
			return l[:protocol.MaxPreviewPackages]
		}
		return l
	}
	p.Upgrades, p.Installs, p.Removals, p.Downgrades = trim(p.Upgrades), trim(p.Installs), trim(p.Removals), trim(p.Downgrades)
	summary := r.L.T("agent.preview.summary", "upgrades", len(p.Upgrades), "installs", len(p.Installs), "removals", len(p.Removals))
	if len(p.Conflicts) > 0 {
		summary += " " + r.L.T("agent.preview.conflicts", "count", len(p.Conflicts))
	}
	return s.finish(true, 0, summary)
}

// capture runs a dry-run command and returns its output (also kept in the
// job output). Non-zero exits are expected (--assume-no answers "no").
func (r JobRunner) capture(ctx context.Context, s *jobState, c command) string {
	buf := &tailBuffer{max: 2 << 20}
	_, _ = s.out.Write([]byte("$ " + c.name + " " + strings.Join(c.args, " ") + "\n"))
	exe := r.Exec
	if exe == nil {
		exe = execCommand
	}
	exe(ctx, c, buf)
	out := buf.String()
	_, _ = s.out.Write([]byte(lastLines(out, 60) + "\n"))
	return out
}

// withAptFlag inserts a flag before the apt-get command word.
func withAptFlag(args []string, flag string) []string {
	out := make([]string, 0, len(args)+1)
	done := false
	for _, a := range args {
		if !done && (a == "upgrade" || a == "install" || a == "dist-upgrade") {
			out = append(out, flag)
			done = true
		}
		out = append(out, a)
	}
	if !done {
		out = append(out, flag)
	}
	return out
}

func dropArg(args []string, drop string) []string {
	return slices.DeleteFunc(slices.Clone(args), func(a string) bool { return a == drop })
}

func installedVersions(updates []protocol.Update) map[string]string {
	out := map[string]string{}
	for _, u := range updates {
		if u.CurrentVersion != "" {
			out[u.Name] = u.CurrentVersion
		}
	}
	return out
}

// errorLines keeps the lines starting with one of the prefixes.
func errorLines(out string, prefixes ...string) []string {
	var lines []string
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		for _, p := range prefixes {
			if strings.HasPrefix(line, p) && !slices.Contains(lines, line) && len(lines) < 50 {
				lines = append(lines, line)
				break
			}
		}
	}
	return lines
}

// ---------- apt ----------

var (
	aptPlanInstRE = regexp.MustCompile(`^Inst (\S+) (?:\[([^\]]*)\] )?\((\S+) .*?(?:\[([^\]]*)\])?\)`)
	aptPlanRemvRE = regexp.MustCompile(`^Remv (\S+)(?: \[([^\]]*)\])?`)
	aptNeedRE     = regexp.MustCompile(`Need to get ([\d.,]+ ?[kKMGT]?B)(?:/[\d.,]+ ?[kKMGT]?B)? of archives`)
	aptAfterRE    = regexp.MustCompile(`After this operation, ([\d.,]+ ?[kKMGT]?B) (of additional disk space will be used|disk space will be freed)`)
)

// parseAptPlan reads "apt-get -s" output: Inst lines with a current version
// are upgrades (or downgrades), without one new packages; Remv lines removals.
func parseAptPlan(out string) (up, inst, rem, down []protocol.PackageChange) {
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		if m := aptPlanInstRE.FindStringSubmatch(line); m != nil {
			c := protocol.PackageChange{Name: m[1], From: m[2], To: m[3], Arch: m[4]}
			switch {
			case c.From == "":
				inst = append(inst, c)
			case pkgver.CompareDeb(c.To, c.From) < 0:
				down = append(down, c)
			default:
				up = append(up, c)
			}
			continue
		}
		if m := aptPlanRemvRE.FindStringSubmatch(line); m != nil {
			rem = append(rem, protocol.PackageChange{Name: m[1], From: m[2]})
		}
	}
	return
}

// parseAptSizes reads the download size and the disk space change from
// "apt-get --assume-no" (apt units: kB = 1000 bytes).
func parseAptSizes(out string) (download, disk int64) {
	download, disk = -1, -1
	if m := aptNeedRE.FindStringSubmatch(out); m != nil {
		download = parseSize(m[1], 1000)
	}
	if m := aptAfterRE.FindStringSubmatch(out); m != nil {
		disk = parseSize(m[1], 1000)
		if strings.Contains(m[2], "freed") {
			disk = -disk
		}
	}
	return
}

// parseSize reads "1,024 kB", "12.6 MB", "3.4 M", "1.2 MiB", "0 B".
func parseSize(s string, base float64) int64 {
	s = strings.TrimSpace(strings.ReplaceAll(s, ",", ""))
	i := strings.IndexFunc(s, func(r rune) bool { return (r < '0' || r > '9') && r != '.' })
	if i < 0 {
		i = len(s)
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(s[:i]), 64)
	if err != nil {
		return -1
	}
	unit := strings.ToLower(strings.TrimSpace(s[i:]))
	if strings.HasSuffix(unit, "ib") {
		base = 1024
	}
	switch {
	case strings.HasPrefix(unit, "k"):
		v *= base
	case strings.HasPrefix(unit, "m"):
		v *= base * base
	case strings.HasPrefix(unit, "g"):
		v *= base * base * base
	case strings.HasPrefix(unit, "t"):
		v *= base * base * base * base
	}
	return int64(v)
}

// ---------- dnf / yum ----------

var dnfSections = map[string]string{
	"Upgrading": "up", "Updating": "up", "Upgrading dependencies": "up",
	"Installing": "inst", "Installing dependencies": "inst", "Installing weak dependencies": "inst", "Installing group/module packages": "inst",
	"Removing": "rem", "Removing dependent packages": "rem", "Removing unused dependencies": "rem", "Erasing": "rem",
	"Downgrading": "down",
}

var dnfSizeRE = regexp.MustCompile(`(?m)^(Total download size|Total size|Installed size|Freed space): ([\d.,]+ ?[kKMGT]?i?B?)\s*$`)
var dnf5DownloadRE = regexp.MustCompile(`Need to download ([\d.,]+ ?[kKMGT]?i?B)`)
var dnf5AfterRE = regexp.MustCompile(`After this operation,? ([\d.,]+ ?[kKMGT]?i?B) (extra will be used|will be freed)`)

// parseDnfPlan reads the transaction table of "dnf/yum --assumeno" (dnf 4
// and dnf 5). Versions of upgraded packages come from "replacing" lines
// (dnf 5) or the installed versions.
func parseDnfPlan(out string, installed map[string]string) (up, inst, rem, down []protocol.PackageChange) {
	section := ""
	var pending []string // tokens of a wrapped line
	add := func(f []string) {
		if len(f) < 3 {
			return
		}
		c := protocol.PackageChange{Name: f[0], Arch: f[1]}
		switch section {
		case "up":
			c.To, c.From = f[2], installed[f[0]]
			up = append(up, c)
		case "inst":
			c.To = f[2]
			inst = append(inst, c)
		case "rem":
			c.From = f[2]
			rem = append(rem, c)
		case "down":
			c.To, c.From = f[2], installed[f[0]]
			down = append(down, c)
		}
	}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		raw := sc.Text()
		line := strings.TrimSpace(raw)
		if name, ok := strings.CutSuffix(line, ":"); ok {
			if s, known := dnfSections[name]; known {
				section, pending = s, nil
				continue
			}
		}
		if line == "" || strings.HasPrefix(line, "Transaction Summary") || strings.HasPrefix(line, "Transaction Summary:") {
			if strings.HasPrefix(line, "Transaction Summary") {
				section = ""
			}
			pending = nil
			continue
		}
		if section == "" || !strings.HasPrefix(raw, " ") {
			if !strings.HasPrefix(raw, " ") {
				section = ""
			}
			continue
		}
		f := strings.Fields(line)
		if f[0] == "replacing" && len(f) >= 4 && len(up) > 0 && section == "up" {
			// dnf 5: "replacing openssl x86_64 1:3.0.7-27.el9 ..." follows its upgrade.
			up[len(up)-1].From = f[3]
			continue
		}
		if len(pending) > 0 {
			f = append(pending, f...)
			pending = nil
		}
		if len(f) == 1 {
			pending = f // a long name wrapped onto its own line
			continue
		}
		add(f)
	}
	return
}

func parseDnfSizes(out string) (download, disk int64) {
	download, disk = -1, -1
	for _, m := range dnfSizeRE.FindAllStringSubmatch(out, -1) {
		v := parseSize(m[2], 1024)
		switch m[1] {
		case "Total download size", "Total size":
			if download < 0 || m[1] == "Total download size" {
				download = v
			}
		case "Installed size":
			disk = v
		case "Freed space":
			disk = -v
		}
	}
	if m := dnf5DownloadRE.FindStringSubmatch(out); m != nil {
		download = parseSize(m[1], 1024)
	}
	if m := dnf5AfterRE.FindStringSubmatch(out); m != nil {
		disk = parseSize(m[1], 1024)
		if strings.Contains(m[2], "freed") {
			disk = -disk
		}
	}
	return
}

// dnfErrors keeps dependency problems ("Error:", "Problem" and the "- "
// lines under a problem); "Operation aborted" is the normal end of an
// --assumeno run.
func dnfErrors(out string) []string {
	var lines []string
	problem := false
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		switch {
		case strings.Contains(l, "Operation aborted"):
			continue
		case strings.HasPrefix(l, "Error:") || strings.HasPrefix(l, "Problem") || strings.HasPrefix(l, "Failed to resolve"):
			problem = true
		case problem && strings.HasPrefix(l, "- "):
		default:
			problem = problem && l != ""
			continue
		}
		if len(lines) < 50 && !slices.Contains(lines, l) {
			lines = append(lines, l)
		}
	}
	return lines
}

// ---------- zypper ----------

var (
	zypperHeadRE  = regexp.MustCompile(`^The following (?:\d+ )?(NEW )?(?:package|packages|patch|patches) (?:is|are) going to be (upgraded|installed|REMOVED|downgraded)`)
	zypperSizeRE  = regexp.MustCompile(`Overall download size: ([\d.,]+ ?[kKMGT]?i?B)`)
	zypperAfterRE = regexp.MustCompile(`After the operation, (?:additional )?([\d.,]+ ?[kKMGT]?i?B) (?:will be used|will be freed)`)
)

// parseZypperPlan reads "zypper update --dry-run": package names follow
// each heading until a blank line; versions come from the pending updates.
func parseZypperPlan(out string, pending []protocol.Update) (up, inst, rem, down []protocol.PackageChange) {
	ver := map[string]protocol.Update{}
	for _, u := range pending {
		ver[u.Name] = u
	}
	kind := ""
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		if m := zypperHeadRE.FindStringSubmatch(line); m != nil {
			switch {
			case m[1] != "" || m[2] == "installed":
				kind = "inst"
			case m[2] == "upgraded":
				kind = "up"
			case m[2] == "REMOVED":
				kind = "rem"
			case m[2] == "downgraded":
				kind = "down"
			}
			continue
		}
		if strings.TrimSpace(line) == "" {
			kind = ""
			continue
		}
		if kind == "" || !strings.HasPrefix(line, " ") {
			continue
		}
		for _, name := range strings.Fields(line) {
			c := protocol.PackageChange{Name: name}
			if u, ok := ver[name]; ok {
				c.From, c.To = u.CurrentVersion, u.AvailableVersion
			}
			switch kind {
			case "up":
				up = append(up, c)
			case "inst":
				inst = append(inst, c)
			case "rem":
				rem = append(rem, c)
			case "down":
				down = append(down, c)
			}
		}
	}
	return
}

func parseZypperSizes(out string) (download, disk int64) {
	download, disk = -1, -1
	if m := zypperSizeRE.FindStringSubmatch(out); m != nil {
		download = parseSize(m[1], 1024)
	}
	if m := zypperAfterRE.FindStringSubmatch(out); m != nil {
		disk = parseSize(m[1], 1024)
		if strings.Contains(m[0], "freed") {
			disk = -disk
		}
	}
	return
}

// ---------- apk ----------

var apkPlanRE = regexp.MustCompile(`^\(\d+/\d+\) (Upgrading|Installing|Purging|Downgrading|Replacing) (\S+) \(([^)]*)\)`)

// parseApkPlan reads "apk --simulate upgrade" output.
func parseApkPlan(out string) (up, inst, rem, down []protocol.PackageChange) {
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		m := apkPlanRE.FindStringSubmatch(strings.TrimSpace(sc.Text()))
		if m == nil {
			continue
		}
		c := protocol.PackageChange{Name: m[2]}
		from, to, ok := strings.Cut(m[3], " -> ")
		switch m[1] {
		case "Upgrading", "Replacing":
			if ok {
				c.From, c.To = from, to
			}
			up = append(up, c)
		case "Downgrading":
			if ok {
				c.From, c.To = from, to
			}
			down = append(down, c)
		case "Installing":
			c.To = m[3]
			inst = append(inst, c)
		case "Purging":
			c.From = m[3]
			rem = append(rem, c)
		}
	}
	return
}

// ---------- reboot need ----------

var (
	kernelRE = regexp.MustCompile(`^(linux-image-|linux-modules-|linux-generic|linux-virtual|linux-aws|linux-azure|linux-gcp|linux-oracle|kernel$|kernel-core$|kernel-modules|kernel-default$|kernel-uek|kernel-rt|linux-lts$|linux-virt$|linux-edge$|linux-firmware)`)
	rebootRE = regexp.MustCompile(`^(libc6|glibc|glibc-common|musl|systemd|systemd-libs|libsystemd0|dbus|dbus-daemon|intel-microcode|amd64-microcode|microcode_ctl|ucode-intel|ucode-amd)$`)
)

// planNeedsReboot reports whether the plan changes a kernel, and whether a
// reboot is needed afterwards (kernel, C library, init system, microcode).
func planNeedsReboot(p *protocol.Preview) (kernel, reboot bool) {
	for _, l := range [][]protocol.PackageChange{p.Upgrades, p.Installs, p.Downgrades} {
		for _, c := range l {
			if kernelRE.MatchString(c.Name) && !strings.HasPrefix(c.Name, "linux-firmware") {
				kernel = true
			}
			if kernelRE.MatchString(c.Name) || rebootRE.MatchString(c.Name) {
				reboot = true
			}
		}
	}
	return
}
