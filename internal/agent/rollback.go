package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	"netio.patchman/internal/pkgver"
	"netio.patchman/internal/protocol"
)

// InstalledPackages lists the installed packages of a package manager.
func InstalledPackages(ctx context.Context, pm string) ([]protocol.Package, error) {
	switch pm {
	case protocol.PMApt:
		return dpkgPackages(ctx)
	case protocol.PMDnf, protocol.PMYum, protocol.PMZypper:
		return rpmPackages(ctx)
	case protocol.PMApk:
		return apkPackages("/lib/apk/db/installed")
	case protocol.PMWindowsUpdate:
		return windowsPrograms()
	}
	return nil, errors.New("unsupported package manager")
}

func pkgKey(name, arch string) string { return name + "\x00" + arch }

// runTracked runs a job and, for package jobs, records which package
// versions it changed (the basis of a later rollback).
func (r JobRunner) runTracked(ctx context.Context, s *jobState, job protocol.Job) protocol.JobResult {
	if r.Installed == nil || !isPackageJob(job.Type) || !r.RemoteUpdates {
		return r.run(ctx, s, job)
	}
	before, err := r.Installed(ctx)
	res := r.run(ctx, s, job)
	if err != nil || ctx.Err() != nil {
		return res
	}
	if after, err := r.Installed(ctx); err == nil {
		res.Changes = protocol.DiffPackages(before, after)
	}
	return res
}

var archRE = regexp.MustCompile(`^[A-Za-z0-9_]{0,20}$`)

// parseRollbackTargets decodes and validates the targets of a rollback job.
func parseRollbackTargets(raw string) ([]protocol.PackageChange, error) {
	var targets []protocol.PackageChange
	if err := json.Unmarshal([]byte(raw), &targets); err != nil {
		return nil, err
	}
	if len(targets) == 0 || len(targets) > protocol.MaxRollbackTargets {
		return nil, errors.New("target count")
	}
	for _, t := range targets {
		if !protocol.ValidPackageName(t.Name) || !protocol.ValidPackageVersion(t.To) || !archRE.MatchString(t.Arch) {
			return nil, errors.New(t.Name)
		}
	}
	return targets, nil
}

// rollback checks and applies a return to earlier package versions. Only
// versions a repository still offers are installed; the package manager
// simulates the change first, and the installed versions are verified
// afterwards. Nothing is reported as done that was not verified.
func (r JobRunner) rollback(ctx context.Context, s *jobState, job protocol.Job) protocol.JobResult {
	mode := job.Params[protocol.ParamRollbackMode]
	if mode != protocol.RollbackCheck && mode != protocol.RollbackApply {
		return s.finish(false, -1, r.L.T("agent.job.unknown_type", "type", "rollback/"+mode))
	}
	targets, err := parseRollbackTargets(job.Params[protocol.ParamRollbackTargets])
	if err != nil {
		return s.finish(false, -1, r.L.T("agent.rollback.invalid"))
	}
	if mode == protocol.RollbackApply && !r.RemoteUpdates {
		return s.finish(false, -1, r.L.T("agent.job.remote_updates_disabled"))
	}
	switch r.PM {
	case protocol.PMApt, protocol.PMDnf, protocol.PMYum, protocol.PMZypper:
	default:
		for _, t := range targets {
			s.res.Rollback = append(s.res.Rollback, protocol.RollbackItem{Name: t.Name, Arch: t.Arch, To: t.To, Status: protocol.RollbackUnavailable,
				Message: r.L.T("agent.rollback.pm_unsupported")})
		}
		return s.finish(false, -1, r.L.T("agent.rollback.pm_unsupported"))
	}
	if r.Installed == nil || r.Available == nil {
		return s.finish(false, -1, r.L.T("agent.rollback.pm_unsupported"))
	}
	if c := r.refreshCommand(); c != nil {
		if code, failed := s.step(ctx, *c); failed {
			return r.failStep(s, ctx, *c, code)
		}
	}
	before, err := r.Installed(ctx)
	if err != nil {
		return s.finish(false, -1, r.L.T("agent.rollback.inventory", "error", err.Error()))
	}
	installed := map[string]string{}
	for _, p := range before {
		installed[pkgKey(p.Name, p.Arch)] = p.Version
		if _, ok := installed[pkgKey(p.Name, "")]; !ok {
			installed[pkgKey(p.Name, "")] = p.Version
		}
	}
	var todo []protocol.PackageChange
	unavailable := 0
	for _, t := range targets {
		it := protocol.RollbackItem{Name: t.Name, Arch: t.Arch, From: installed[pkgKey(t.Name, t.Arch)], To: t.To}
		switch {
		case it.From == "":
			it.Status, it.Message = protocol.RollbackUnavailable, r.L.T("agent.rollback.not_installed")
			unavailable++
		case sameVersion(r.PM, it.From, t.To):
			it.Status = protocol.RollbackCurrent
		default:
			ok, err := r.Available(ctx, r.PM, t.Name, t.Arch, t.To)
			switch {
			case err != nil:
				it.Status, it.Message = protocol.RollbackUnavailable, r.L.T("agent.rollback.lookup_failed", "error", err.Error())
				unavailable++
			case !ok:
				it.Status, it.Message = protocol.RollbackUnavailable, r.L.T("agent.rollback.version_gone")
				unavailable++
			default:
				it.Status = protocol.RollbackAvailable
				todo = append(todo, protocol.PackageChange{Name: t.Name, Arch: t.Arch, From: it.From, To: t.To})
			}
		}
		s.res.Rollback = append(s.res.Rollback, it)
	}
	if len(todo) == 0 {
		if unavailable > 0 {
			return s.finish(false, -1, r.L.T("agent.rollback.nothing_possible"))
		}
		return s.finish(true, 0, r.L.T("agent.rollback.already_current"))
	}
	// The package manager's own simulation: dependencies, removals, conflicts.
	plan := &protocol.Preview{PackageManager: r.PM, DownloadBytes: -1, DiskBytes: -1, FreeBytes: freeBytes()}
	out := ""
	for _, c := range rollbackCommands(r.PM, todo, true) {
		out += r.capture(ctx, s, c) + "\n"
	}
	switch r.PM {
	case protocol.PMApt:
		plan.Upgrades, plan.Installs, plan.Removals, plan.Downgrades = parseAptPlan(out)
		plan.Conflicts = errorLines(out, "E: ")
	case protocol.PMDnf, protocol.PMYum:
		cur := map[string]string{}
		for _, t := range todo {
			cur[t.Name] = t.From
		}
		plan.Upgrades, plan.Installs, plan.Removals, plan.Downgrades = parseDnfPlan(out, cur)
		plan.Conflicts = dnfErrors(out)
	case protocol.PMZypper:
		plan.Conflicts = errorLines(out, "Problem:", "Error:")
	}
	plan.Kernel, plan.Reboot = planNeedsReboot(plan)
	plan.Plan = lastLines(out, 400)
	s.res.Preview = plan
	if mode == protocol.RollbackCheck {
		msg := r.L.T("agent.rollback.checked", "available", len(todo), "unavailable", unavailable)
		if len(plan.Conflicts) > 0 {
			msg += " " + r.L.T("agent.preview.conflicts", "count", len(plan.Conflicts))
		}
		return s.finish(true, 0, msg)
	}
	// Apply: all or nothing up front; partial availability is chosen on the
	// server by approving only the available packages.
	if unavailable > 0 {
		return s.finish(false, -1, r.L.T("agent.rollback.unavailable_abort", "count", unavailable))
	}
	if len(plan.Conflicts) > 0 {
		return s.finish(false, -1, r.L.T("agent.rollback.conflicts_abort"))
	}
	var runErr error
	for _, c := range rollbackCommands(r.PM, todo, false) {
		if code, failed := s.step(ctx, c); failed {
			runErr = errors.New(r.L.T("agent.job.command_failed", "command", c.name, "code", code))
			break
		}
	}
	after, err := r.Installed(ctx)
	if err != nil {
		return s.finish(false, -1, r.L.T("agent.rollback.inventory", "error", err.Error()))
	}
	s.res.Changes = protocol.DiffPackages(before, after)
	now := map[string]string{}
	for _, p := range after {
		now[pkgKey(p.Name, p.Arch)] = p.Version
		if _, ok := now[pkgKey(p.Name, "")]; !ok {
			now[pkgKey(p.Name, "")] = p.Version
		}
	}
	done, failed := 0, []string{}
	for i, it := range s.res.Rollback {
		if it.Status != protocol.RollbackAvailable {
			continue
		}
		if v := now[pkgKey(it.Name, it.Arch)]; sameVersion(r.PM, v, it.To) {
			s.res.Rollback[i].Status = protocol.RollbackDone
			done++
		} else {
			s.res.Rollback[i].Status = protocol.RollbackFailed
			s.res.Rollback[i].Message = r.L.T("agent.rollback.still", "version", v)
			failed = append(failed, it.Name)
		}
	}
	s.res.Remaining = failed
	switch {
	case done == 0:
		msg := r.L.T("agent.rollback.none_done")
		if runErr != nil {
			msg = runErr.Error() + "\n" + msg
		}
		return s.finish(false, 1, msg)
	case len(failed) > 0:
		return s.finish(true, 0, r.L.T("agent.rollback.partial", "done", done, "packages", listNames(failed)))
	}
	return s.finish(true, 0, r.L.T("agent.rollback.done", "count", done))
}

// sameVersion compares installed and target versions, ignoring a zero epoch.
func sameVersion(pm, a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return a == b || pkgver.Compare(pm, strings.TrimPrefix(a, "0:"), strings.TrimPrefix(b, "0:")) == 0 && strings.Count(a, "-") == strings.Count(b, "-")
}

// rollbackCommands returns the commands that install the target versions;
// simulate returns their dry-run form.
func rollbackCommands(pm string, todo []protocol.PackageChange, simulate bool) []command {
	switch pm {
	case protocol.PMApt:
		args := []string{"-y", "-q", "--allow-downgrades", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold"}
		if simulate {
			args = []string{"-s", "-q", "--allow-downgrades"}
		}
		args = append(args, "install")
		for _, t := range todo {
			name := t.Name
			if t.Arch != "" && t.Arch != "all" {
				name += ":" + t.Arch
			}
			args = append(args, name+"="+t.To)
		}
		return []command{{name: "apt-get", args: args}}
	case protocol.PMDnf, protocol.PMYum:
		var down, up []string
		for _, t := range todo {
			nevra := t.Name + "-" + t.To
			if t.Arch != "" {
				nevra += "." + t.Arch
			}
			if pkgver.CompareRPM(t.To, t.From) < 0 {
				down = append(down, nevra)
			} else {
				up = append(up, nevra)
			}
		}
		flag := "-y"
		if simulate {
			flag = "--assumeno"
		}
		var out []command
		if len(down) > 0 {
			out = append(out, command{name: pm, args: append([]string{flag, "downgrade"}, down...)})
		}
		if len(up) > 0 {
			out = append(out, command{name: pm, args: append([]string{flag, "install"}, up...)})
		}
		return out
	case protocol.PMZypper:
		args := []string{"--non-interactive", "install", "--oldpackage"}
		if simulate {
			args = append(args, "--dry-run")
		}
		for _, t := range todo {
			name := t.Name
			if t.Arch != "" && t.Arch != "noarch" {
				name += "." + t.Arch
			}
			args = append(args, name+"="+t.To)
		}
		return []command{{name: "zypper", args: args, okCodes: []int{102, 103}}}
	}
	return nil
}

// versionAvailable asks the package manager whether a repository offers a
// version of a package.
func versionAvailable(ctx context.Context, pm, name, arch, version string) (bool, error) {
	switch pm {
	case protocol.PMApt:
		q := name
		if arch != "" && arch != "all" {
			q += ":" + arch
		}
		out, _, err := run(ctx, time.Minute, "apt-cache", "policy", q)
		if err != nil {
			return false, err
		}
		return aptPolicyHas(string(out), version), nil
	case protocol.PMDnf, protocol.PMYum:
		args := []string{"-q", "list", "--showduplicates", "--available", name}
		if pm == protocol.PMYum {
			args = []string{"-q", "--showduplicates", "list", "available", name}
		}
		out, code, err := run(ctx, 5*time.Minute, pm, args...)
		if err != nil && code != 1 { // 1: no matching packages
			return false, err
		}
		return dnfListHas(string(out), name, arch, version), nil
	case protocol.PMZypper:
		out, code, err := run(ctx, 5*time.Minute, "zypper", "--non-interactive", "search", "-s", "--match-exact", name)
		if err != nil && code != 104 { // 104: nothing found
			return false, err
		}
		return zypperSearchHas(string(out), name, arch, version), nil
	}
	return false, errors.New("unsupported package manager")
}

var (
	aptPolicyVersionRE = regexp.MustCompile(`^\s+(?:\*\*\*\s+)?(\S+)\s+-?\d+\s*$`)
	aptPolicySourceRE  = regexp.MustCompile(`^\s+-?\d+\s+(\S+)`)
)

// aptPolicyHas reports whether "apt-cache policy" lists the version from a
// repository (not only as the installed package in /var/lib/dpkg/status).
func aptPolicyHas(out, version string) bool {
	cur := ""
	sc := bufio.NewScanner(strings.NewReader(out))
	inTable := false
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "Version table:" {
			inTable = true
			continue
		}
		if !inTable {
			continue
		}
		if m := aptPolicyVersionRE.FindStringSubmatch(line); m != nil && !aptPolicySourceRE.MatchString(line) {
			cur = m[1]
			continue
		}
		if m := aptPolicySourceRE.FindStringSubmatch(line); m != nil && cur == version && m[1] != "/var/lib/dpkg/status" {
			return true
		}
	}
	return false
}

// dnfListHas reads "dnf list --showduplicates --available" lines
// ("openssl.x86_64   1:3.0.7-27.el9   baseos").
func dnfListHas(out, name, arch, version string) bool {
	want := strings.TrimPrefix(version, "0:")
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 3 {
			continue
		}
		n, a := splitNameArch(f[0])
		if n != name || (arch != "" && a != arch && a != "noarch") {
			continue
		}
		if strings.TrimPrefix(f[1], "0:") == want {
			return true
		}
	}
	return false
}

// zypperSearchHas reads "zypper search -s" table rows
// ("v  | openssl-3 | package | 3.1.4-150600.5.7.1 | x86_64 | Main Update").
func zypperSearchHas(out, name, arch, version string) bool {
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		cols := strings.Split(sc.Text(), "|")
		if len(cols) < 6 {
			continue
		}
		for i := range cols {
			cols[i] = strings.TrimSpace(cols[i])
		}
		if cols[1] == name && cols[2] == "package" && cols[3] == version && (arch == "" || cols[4] == arch || cols[4] == "noarch") {
			return true
		}
	}
	return false
}
