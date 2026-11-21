package agent

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"time"

	"netio.patchman/internal/i18n"
	"netio.patchman/internal/protocol"
	"netio.patchman/internal/timeutil"
)

// JobTimeout bounds a single update job.
const JobTimeout = 2 * time.Hour

// command is one step of a job.
type command struct {
	name string
	args []string
	// okCodes are exit codes treated as success besides 0.
	okCodes []int
	// fn, when set, runs the step in-process instead of exec (Windows Update);
	// name and args are then only shown in the output.
	fn func(ctx context.Context, out io.Writer) int
	// soft steps do not stop the job when they fail (one winget package);
	// the verification reports what is left.
	soft bool
}

// tailBuffer keeps the last max bytes written. A lone carriage return
// overwrites the current line as a terminal would, so progress output
// ("(Reading database ... 5%\r... 10%\r") leaves only its final state
// instead of dozens of lines; CRLF counts as a line end.
type tailBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
	max int
	cut bool
	cr  bool // last byte was '\r'
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, c := range p {
		if t.cr {
			t.cr = false
			if c != '\n' {
				t.buf.Truncate(bytes.LastIndexByte(t.buf.Bytes(), '\n') + 1)
			}
		}
		if c == '\r' {
			t.cr = true
			continue
		}
		t.buf.WriteByte(c)
	}
	if t.buf.Len() > t.max {
		b := t.buf.Bytes()
		keep := append([]byte(nil), b[len(b)-t.max:]...)
		t.buf.Reset()
		t.buf.Write(keep)
		t.cut = true
	}
	return len(p), nil
}

func (t *tailBuffer) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cut {
		return "…\n" + t.buf.String()
	}
	return t.buf.String()
}

// JobRunner executes update jobs.
type JobRunner struct {
	L             i18n.Localizer
	PM            string
	RemoteUpdates bool
	// Winget is the winget executable for third-party Windows programs, "" without.
	Winget string
	// Pending lists pending updates without refreshing the package lists.
	// It sets the job's targets and verifies them afterwards; nil skips both.
	Pending func(ctx context.Context) ([]protocol.Update, error)
	// Services lists services that still need a restart; nil skips the check.
	Services func(ctx context.Context) []string
	// Exec runs one command; nil uses execCommand. Tests replace it.
	Exec func(ctx context.Context, c command, out *tailBuffer) int
}

// jobState collects the output of one job.
type jobState struct {
	r   JobRunner
	res protocol.JobResult
	out *tailBuffer
}

func (s *jobState) note(msg string) {
	if msg != "" {
		_, _ = s.out.Write([]byte("\n[netio.patchman] " + msg + "\n"))
	}
}

func (s *jobState) finish(ok bool, code int, msg string) protocol.JobResult {
	s.note(msg)
	s.res.Succeeded, s.res.ExitCode, s.res.Output, s.res.FinishedAt = ok, code, strings.TrimLeft(s.out.String(), "\n"), timeutil.Now()
	return s.res
}

// step runs a command and reports whether it failed (the job is then finished).
func (s *jobState) step(ctx context.Context, c command) (code int, failed bool) {
	_, _ = s.out.Write([]byte("$ " + c.name + " " + strings.Join(c.args, " ") + "\n"))
	exe := s.r.Exec
	switch {
	case exe != nil:
	case c.fn != nil:
		exe = func(ctx context.Context, c command, out *tailBuffer) int { return c.fn(ctx, out) }
	default:
		exe = execCommand
	}
	code = exe(ctx, c, s.out)
	if ctx.Err() == context.DeadlineExceeded {
		return -1, true
	}
	return code, code != 0 && !slices.Contains(c.okCodes, code)
}

func execCommand(ctx context.Context, c command, out *tailBuffer) int {
	cmd := exec.CommandContext(ctx, c.name, c.args...)
	cmd.Env = append(os.Environ(), "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=a", "APT_LISTCHANGES_FRONTEND=none")
	cmd.Stdout, cmd.Stderr = out, out
	cmd.WaitDelay = 30 * time.Second
	err := cmd.Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	if err != nil {
		_, _ = out.Write([]byte(err.Error() + "\n"))
		return -1
	}
	return 0
}

// Run executes the job and returns the result. It never panics on bad input.
func (r JobRunner) Run(ctx context.Context, job protocol.Job) protocol.JobResult {
	s := &jobState{r: r, res: protocol.JobResult{StartedAt: timeutil.Now()}, out: &tailBuffer{max: protocol.MaxOutputBytes - 1024}}
	if job.Type == protocol.JobRefresh {
		return s.finish(true, 0, r.L.T("agent.job.refresh_done"))
	}
	if !r.RemoteUpdates {
		return s.finish(false, -1, r.L.T("agent.job.remote_updates_disabled"))
	}
	ctx, cancel := context.WithTimeout(ctx, JobTimeout)
	defer cancel()
	switch job.Type {
	case protocol.JobRestartServices:
		return r.restartServices(ctx, s, job.Packages)
	case protocol.JobReboot:
		return r.reboot(s)
	}
	for _, p := range job.Packages {
		if !protocol.ValidPackageName(p) {
			return s.finish(false, -1, r.L.T("agent.job.invalid_package", "package", p))
		}
	}
	if job.Type == protocol.JobUpgradePackages && len(job.Packages) == 0 {
		return s.finish(false, -1, r.L.T("agent.job.no_packages"))
	}
	if !slices.Contains([]string{protocol.JobUpgradeAll, protocol.JobUpgradeSecurity, protocol.JobUpgradePackages}, job.Type) {
		return s.finish(false, -1, r.L.T("agent.job.unknown_type", "type", job.Type))
	}

	// Refresh the package lists first so the targets match what will be installed.
	if c := r.refreshCommand(); c != nil {
		if code, failed := s.step(ctx, *c); failed {
			return r.failStep(s, ctx, *c, code)
		}
	}
	var before []protocol.Update
	known := false
	if r.Pending != nil {
		var err error
		if before, err = r.Pending(ctx); err != nil {
			s.note(r.L.T("agent.job.pending_unknown", "error", err.Error()))
		} else {
			known = true
		}
	}
	cmds, targets, msg, err := r.plan(job, before, known)
	if err != nil {
		return s.finish(false, -1, err.Error())
	}
	if len(cmds) == 0 {
		return s.finish(true, 0, msg)
	}
	s.note(msg)
	for _, c := range cmds {
		if code, failed := s.step(ctx, c); failed {
			if c.soft && ctx.Err() == nil {
				s.note(r.L.T("agent.job.command_failed", "command", c.name, "code", code))
				continue
			}
			s.res.Remaining = r.stillPending(ctx, targets)
			return r.failStep(s, ctx, c, code)
		}
	}
	return r.verify(ctx, s, targets)
}

func (r JobRunner) failStep(s *jobState, ctx context.Context, c command, code int) protocol.JobResult {
	if ctx.Err() == context.DeadlineExceeded {
		return s.finish(false, -1, r.L.T("agent.job.timeout"))
	}
	return s.finish(false, code, r.L.T("agent.job.command_failed", "command", c.name, "code", code))
}

// refreshCommand updates the package lists where the upgrade command does not.
func (r JobRunner) refreshCommand() *command {
	switch r.PM {
	case protocol.PMApt:
		return &command{name: "apt-get", args: []string{"update", "-q"}}
	case protocol.PMApk:
		return &command{name: "apk", args: []string{"update", "-q"}}
	}
	return nil
}

// plan returns the commands and the packages they are expected to upgrade.
// before is the pending update list (valid when known).
func (r JobRunner) plan(job protocol.Job, before []protocol.Update, known bool) (cmds []command, targets []string, msg string, err error) {
	// Packages on the exclusion lists (fleet, group, host) are never targeted.
	exclude, _ := protocol.ParseExcludePatterns(job.Params[protocol.ParamExclude])
	var excluded []string
	keep := func(name string) bool {
		if !protocol.Excluded(exclude, name) {
			return true
		}
		if !slices.Contains(excluded, name) {
			excluded = append(excluded, name)
		}
		return false
	}
	pending := map[string]bool{}
	var all, security []string
	for _, u := range before {
		if !pending[u.Name] {
			pending[u.Name] = true
			if !keep(u.Name) {
				continue
			}
			all = append(all, u.Name)
			if u.Security {
				security = append(security, u.Name)
			}
		}
	}
	pkgs := slices.DeleteFunc(slices.Clone(job.Packages), func(p string) bool { return !keep(p) })
	var notes []string
	if len(excluded) > 0 {
		notes = append(notes, r.L.T("agent.job.excluded", "packages", listNames(excluded)))
	}
	defer func() {
		if len(notes) > 0 {
			msg = strings.Join(append(notes, msg), "\n")
			msg = strings.TrimSpace(msg)
		}
	}()
	// Without the pending list the exclusions can only be passed to dnf/yum.
	if len(exclude) > 0 && !known && r.PM != protocol.PMDnf && r.PM != protocol.PMYum && job.Type != protocol.JobUpgradePackages {
		return nil, nil, "", errors.New(r.L.T("agent.job.exclude_unknown"))
	}
	switch job.Type {
	case protocol.JobUpgradeAll:
		targets = all
		if known && len(all) == 0 {
			return nil, nil, r.L.T("agent.job.no_updates"), nil
		}
	case protocol.JobUpgradeSecurity:
		targets = security
	case protocol.JobUpgradePackages:
		if len(pkgs) == 0 {
			return nil, nil, r.L.T("agent.job.nothing_pending"), nil
		}
		if known {
			// Packages without a pending update (already upgraded, not
			// installed) would be skipped silently by the package manager.
			var skipped []string
			candidates := pkgs
			pkgs, skipped = nil, nil
			for _, p := range candidates {
				if pending[p] {
					pkgs = append(pkgs, p)
				} else {
					skipped = append(skipped, p)
				}
			}
			if len(skipped) > 0 {
				notes = append(notes, r.L.T("agent.job.packages_skipped", "packages", listNames(skipped)))
			}
			if len(pkgs) == 0 {
				return nil, nil, r.L.T("agent.job.nothing_pending"), nil
			}
		}
		targets = pkgs
	}

	aptOpts := []string{"-y", "-q", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold"}
	switch r.PM {
	case protocol.PMApt:
		switch job.Type {
		case protocol.JobUpgradeAll:
			if len(exclude) > 0 {
				// apt-get upgrade cannot exclude packages: upgrade the rest by name.
				cmds = []command{{name: "apt-get", args: append(append(aptOpts, "install", "--only-upgrade"), all...)}}
				break
			}
			cmds = []command{{name: "apt-get", args: append(aptOpts, "upgrade", "--with-new-pkgs")}}
		case protocol.JobUpgradeSecurity:
			if !known {
				return nil, nil, "", errors.New(r.L.T("agent.job.security_unsupported"))
			}
			if len(security) == 0 {
				return nil, nil, r.L.T("agent.job.no_security_updates"), nil
			}
			cmds = []command{{name: "apt-get", args: append(append(aptOpts, "install", "--only-upgrade"), security...)}}
		case protocol.JobUpgradePackages:
			cmds = []command{{name: "apt-get", args: append(append(aptOpts, "install", "--only-upgrade"), pkgs...)}}
		}
	case protocol.PMDnf, protocol.PMYum:
		switch job.Type {
		case protocol.JobUpgradeAll:
			cmds = []command{{name: r.PM, args: append([]string{"-y", "upgrade"}, dnfExcludes(exclude)...)}}
		case protocol.JobUpgradeSecurity:
			cmds = []command{{name: r.PM, args: append([]string{"-y", "upgrade", "--security"}, dnfExcludes(exclude)...)}}
		case protocol.JobUpgradePackages:
			cmds = []command{{name: r.PM, args: append([]string{"-y", "upgrade"}, pkgs...)}}
		}
	case protocol.PMZypper:
		// 102: reboot needed, 103: zypper itself was updated; both mean success.
		ok := []int{102, 103}
		switch job.Type {
		case protocol.JobUpgradeAll:
			if len(exclude) > 0 {
				cmds = []command{{name: "zypper", args: append([]string{"--non-interactive", "update"}, all...), okCodes: ok}}
				break
			}
			cmds = []command{{name: "zypper", args: []string{"--non-interactive", "update"}, okCodes: ok}}
		case protocol.JobUpgradeSecurity:
			if len(exclude) > 0 {
				// Patches do not map to package names.
				return nil, nil, "", errors.New(r.L.T("agent.job.exclude_unknown"))
			}
			// Patches do not map to the package list; the result is not verified.
			targets = nil
			cmds = []command{{name: "zypper", args: []string{"--non-interactive", "patch", "--category", "security"}, okCodes: ok}}
		case protocol.JobUpgradePackages:
			cmds = []command{{name: "zypper", args: append([]string{"--non-interactive", "update"}, pkgs...), okCodes: ok}}
		}
	case protocol.PMApk:
		switch job.Type {
		case protocol.JobUpgradeAll:
			if len(exclude) > 0 {
				cmds = []command{{name: "apk", args: append([]string{"upgrade"}, all...)}}
				break
			}
			cmds = []command{{name: "apk", args: []string{"upgrade"}}}
		case protocol.JobUpgradeSecurity:
			return nil, nil, "", errors.New(r.L.T("agent.job.security_unsupported"))
		case protocol.JobUpgradePackages:
			cmds = []command{{name: "apk", args: append([]string{"upgrade"}, pkgs...)}}
		}
	case protocol.PMWindowsUpdate:
		// winget packages (third-party programs) and Windows Update KBs.
		winget := map[string]bool{}
		for _, u := range before {
			if u.Repository == WingetRepository {
				winget[u.Name] = true
			}
		}
		windowsCmds := func(names []string) []command {
			var kbs []string
			var out []command
			for _, n := range names {
				if winget[n] {
					if r.Winget != "" {
						out = append(out, wingetUpgradeCommand(r.Winget, n))
					}
					continue
				}
				kbs = append(kbs, n)
			}
			if len(kbs) > 0 {
				out = append([]command{windowsInstallCommand(r.L, kbs, "")}, out...)
			}
			return out
		}
		switch job.Type {
		case protocol.JobUpgradeAll:
			if known {
				cmds = windowsCmds(all)
			} else {
				cmds = []command{windowsInstallCommand(r.L, nil, "all")}
			}
		case protocol.JobUpgradeSecurity:
			if !known {
				cmds = []command{windowsInstallCommand(r.L, nil, "security")}
				break
			}
			if len(security) == 0 {
				return nil, nil, r.L.T("agent.job.no_security_updates"), nil
			}
			cmds = windowsCmds(security)
		case protocol.JobUpgradePackages:
			cmds = windowsCmds(pkgs)
		}
	default:
		return nil, nil, "", errors.New(r.L.T("agent.job.pm_unsupported"))
	}
	return cmds, targets, msg, nil
}

// remaining returns the targets that still have a pending update.
func (r JobRunner) remaining(ctx context.Context, targets []string) ([]string, error) {
	after, err := r.Pending(ctx)
	if err != nil {
		return nil, err
	}
	pending := map[string]bool{}
	for _, u := range after {
		pending[u.Name] = true
	}
	var left []string
	for _, t := range targets {
		if pending[t] {
			left = append(left, t)
		}
	}
	return left, nil
}

// stillPending is remaining for a failed job: nil when unknown.
func (r JobRunner) stillPending(ctx context.Context, targets []string) []string {
	if r.Pending == nil || len(targets) == 0 || ctx.Err() != nil {
		return nil
	}
	left, _ := r.remaining(ctx, targets)
	return left
}

// verify checks after a successful run that the targeted packages were
// upgraded. A package manager can exit 0 without upgrading anything (a
// package kept back, excluded, or skipped by --only-upgrade).
func (r JobRunner) verify(ctx context.Context, s *jobState, targets []string) protocol.JobResult {
	if r.Pending == nil || len(targets) == 0 {
		return s.finish(true, 0, r.L.T("agent.job.completed"))
	}
	left, err := r.remaining(ctx, targets)
	if err != nil {
		s.note(r.L.T("agent.job.verify_failed", "error", err.Error()))
		return s.finish(true, 0, r.L.T("agent.job.completed"))
	}
	s.res.Remaining = left
	switch {
	case len(left) == 0:
		return s.finish(true, 0, r.L.T("agent.job.verified", "count", len(targets)))
	case len(left) == len(targets):
		return s.finish(false, 0, r.L.T("agent.job.verify_none", "packages", listNames(left)))
	default:
		return s.finish(true, 0, r.L.T("agent.job.verify_partial", "done", len(targets)-len(left), "total", len(targets), "packages", listNames(left)))
	}
}

// listNames joins names for a message, shortening long lists.
func listNames(names []string) string {
	const max = 20
	if len(names) > max {
		return strings.Join(names[:max], ", ") + ", …"
	}
	return strings.Join(names, ", ")
}

// protectedServices are not restarted by a job: restarting them ends user
// sessions, drops the network or stops the agent itself. A reboot is the safe
// way to activate their updates.
var protectedServices = []string{
	"dbus", "dbus-broker", "systemd-logind", "user@", "getty@", "serial-getty@", "autovt@", "console-getty",
	"display-manager", "gdm", "gdm3", "lightdm", "sddm", "NetworkManager", "systemd-networkd", "networking",
	"network", "wpa_supplicant", "netio-patchman-agent", "emergency", "rescue",
}

func protectedService(name string) bool {
	base := strings.TrimSuffix(name, ".service")
	for _, p := range protectedServices {
		if base == p || (strings.HasSuffix(p, "@") && strings.HasPrefix(base, p)) {
			return true
		}
	}
	return false
}

// restartServices restarts the listed services and checks afterwards which of
// them still need a restart.
func (r JobRunner) restartServices(ctx context.Context, s *jobState, services []string) protocol.JobResult {
	if len(services) == 0 {
		return s.finish(false, -1, r.L.T("agent.job.no_services"))
	}
	for _, svc := range services {
		if !protocol.ValidServiceName(svc) {
			return s.finish(false, -1, r.L.T("agent.job.invalid_service", "service", svc))
		}
	}
	restart := func(svc string) command { return command{name: "systemctl", args: []string{"restart", svc}} }
	if r.Exec == nil {
		if _, err := exec.LookPath("systemctl"); err != nil {
			if _, err := exec.LookPath("rc-service"); err != nil {
				return s.finish(false, -1, r.L.T("agent.job.no_service_manager"))
			}
			restart = func(svc string) command { return command{name: "rc-service", args: []string{svc, "restart"}} }
		}
	}
	var attempted, failed []string
	for _, svc := range services {
		if protectedService(svc) {
			s.note(r.L.T("agent.job.service_protected", "service", svc))
			continue
		}
		attempted = append(attempted, svc)
		code, bad := s.step(ctx, restart(svc))
		if ctx.Err() != nil {
			return s.finish(false, -1, r.L.T("agent.job.timeout"))
		}
		if bad {
			failed = append(failed, svc)
			s.note(r.L.T("agent.job.service_failed", "service", svc, "code", code))
		}
	}
	if len(attempted) == 0 {
		return s.finish(false, -1, r.L.T("agent.job.services_none_restartable"))
	}
	left := failed
	if r.Services != nil {
		current := r.Services(ctx)
		for _, svc := range attempted {
			if slices.Contains(current, svc) && !slices.Contains(left, svc) {
				left = append(left, svc)
			}
		}
	}
	s.res.Remaining = left
	switch {
	case len(left) == 0:
		return s.finish(true, 0, r.L.T("agent.job.services_done", "count", len(attempted)))
	case len(left) == len(attempted):
		return s.finish(false, 1, r.L.T("agent.job.services_remaining", "services", listNames(left)))
	default:
		return s.finish(true, 0, r.L.T("agent.job.services_remaining", "services", listNames(left)))
	}
}

// reboot schedules a reboot one minute ahead so the result reaches the server
// first. After the reboot the agent starts again and sends a fresh report.
func (r JobRunner) reboot(s *jobState) protocol.JobResult {
	if r.PM == protocol.PMWindowsUpdate {
		// Returns at once; Windows restarts after 60 seconds (planned: security fix).
		c := command{name: "shutdown.exe", args: []string{"/r", "/t", "60", "/d", "p:2:17", "/c", r.L.T("agent.job.reboot_wall")}}
		if code, failed := s.step(context.Background(), c); failed {
			return s.finish(false, code, r.L.T("agent.job.command_failed", "command", c.name, "code", code))
		}
		return s.finish(true, 0, r.L.T("agent.job.reboot_scheduled"))
	}
	if _, err := exec.LookPath("shutdown"); err == nil || r.Exec != nil {
		// systemd and sysvinit: returns at once, the reboot happens later.
		c := command{name: "shutdown", args: []string{"-r", "+1", r.L.T("agent.job.reboot_wall")}}
		if code, failed := s.step(context.Background(), c); failed {
			return s.finish(false, code, r.L.T("agent.job.command_failed", "command", c.name, "code", code))
		}
		return s.finish(true, 0, r.L.T("agent.job.reboot_scheduled"))
	}
	// BusyBox (Alpine) has no shutdown; "reboot -d 60" sleeps itself, so it
	// is started and not awaited.
	_, _ = s.out.Write([]byte("$ reboot -d 60\n"))
	c := exec.Command("reboot", "-d", "60")
	if err := c.Start(); err != nil {
		return s.finish(false, -1, err.Error())
	}
	_ = c.Process.Release()
	return s.finish(true, 0, r.L.T("agent.job.reboot_scheduled"))
}

// dnfExcludes returns dnf/yum --exclude options for the patterns.
func dnfExcludes(patterns []string) []string {
	out := make([]string, 0, len(patterns))
	for _, p := range patterns {
		out = append(out, "--exclude="+p)
	}
	return out
}
