package agent

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
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
}

// tailBuffer keeps the last max bytes written.
type tailBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
	max int
	cut bool
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf.Write(p)
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
	// SecurityUpdates returns the names of pending security updates (apt).
	SecurityUpdates func(ctx context.Context) ([]string, error)
}

// Run executes the job and returns the result. It never panics on bad input.
func (r JobRunner) Run(ctx context.Context, job protocol.Job) protocol.JobResult {
	res := protocol.JobResult{StartedAt: timeutil.Now()}
	out := &tailBuffer{max: protocol.MaxOutputBytes - 1024}
	finish := func(ok bool, code int, msg string) protocol.JobResult {
		if msg != "" {
			_, _ = out.Write([]byte("\n[netio.patchman] " + msg + "\n"))
		}
		res.Succeeded, res.ExitCode, res.Output, res.FinishedAt = ok, code, strings.TrimLeft(out.String(), "\n"), timeutil.Now()
		return res
	}

	if job.Type == protocol.JobRefresh {
		return finish(true, 0, r.L.T("agent.job.refresh_done"))
	}
	if !r.RemoteUpdates {
		return finish(false, -1, r.L.T("agent.job.remote_updates_disabled"))
	}
	for _, p := range job.Packages {
		if !protocol.ValidPackageName(p) {
			return finish(false, -1, r.L.T("agent.job.invalid_package", "package", p))
		}
	}
	cmds, msg, err := r.plan(ctx, job)
	if err != nil {
		return finish(false, -1, err.Error())
	}
	if len(cmds) == 0 {
		return finish(true, 0, msg)
	}

	ctx, cancel := context.WithTimeout(ctx, JobTimeout)
	defer cancel()
	for _, c := range cmds {
		_, _ = out.Write([]byte("$ " + c.name + " " + strings.Join(c.args, " ") + "\n"))
		cmd := exec.CommandContext(ctx, c.name, c.args...)
		cmd.Env = append(os.Environ(), "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=a", "APT_LISTCHANGES_FRONTEND=none")
		cmd.Stdout, cmd.Stderr = out, out
		cmd.WaitDelay = 30 * time.Second
		err := cmd.Run()
		code := 0
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			code = exitErr.ExitCode()
		} else if err != nil {
			code = -1
		}
		if ctx.Err() == context.DeadlineExceeded {
			return finish(false, -1, r.L.T("agent.job.timeout"))
		}
		if code != 0 && !contains(c.okCodes, code) {
			return finish(false, code, r.L.T("agent.job.command_failed", "command", c.name, "code", code))
		}
	}
	return finish(true, 0, r.L.T("agent.job.completed"))
}

func contains(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func (r JobRunner) plan(ctx context.Context, job protocol.Job) ([]command, string, error) {
	pkgs := job.Packages
	if job.Type == protocol.JobUpgradePackages && len(pkgs) == 0 {
		return nil, "", errors.New(r.L.T("agent.job.no_packages"))
	}
	aptOpts := []string{"-y", "-q", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold"}
	switch r.PM {
	case protocol.PMApt:
		update := command{name: "apt-get", args: []string{"update", "-q"}}
		switch job.Type {
		case protocol.JobUpgradeAll:
			return []command{update, {name: "apt-get", args: append(aptOpts, "upgrade", "--with-new-pkgs")}}, "", nil
		case protocol.JobUpgradeSecurity:
			if r.SecurityUpdates == nil {
				return nil, "", errors.New(r.L.T("agent.job.security_unsupported"))
			}
			names, err := r.SecurityUpdates(ctx)
			if err != nil {
				return nil, "", err
			}
			if len(names) == 0 {
				return nil, r.L.T("agent.job.no_security_updates"), nil
			}
			return []command{{name: "apt-get", args: append(append(aptOpts, "install", "--only-upgrade"), names...)}}, "", nil
		case protocol.JobUpgradePackages:
			return []command{update, {name: "apt-get", args: append(append(aptOpts, "install", "--only-upgrade"), pkgs...)}}, "", nil
		}
	case protocol.PMDnf, protocol.PMYum:
		switch job.Type {
		case protocol.JobUpgradeAll:
			return []command{{name: r.PM, args: []string{"-y", "upgrade"}}}, "", nil
		case protocol.JobUpgradeSecurity:
			return []command{{name: r.PM, args: []string{"-y", "upgrade", "--security"}}}, "", nil
		case protocol.JobUpgradePackages:
			return []command{{name: r.PM, args: append([]string{"-y", "upgrade"}, pkgs...)}}, "", nil
		}
	case protocol.PMZypper:
		// 102: reboot needed, 103: zypper itself was updated; both mean success.
		ok := []int{102, 103}
		switch job.Type {
		case protocol.JobUpgradeAll:
			return []command{{name: "zypper", args: []string{"--non-interactive", "update"}, okCodes: ok}}, "", nil
		case protocol.JobUpgradeSecurity:
			return []command{{name: "zypper", args: []string{"--non-interactive", "patch", "--category", "security"}, okCodes: ok}}, "", nil
		case protocol.JobUpgradePackages:
			return []command{{name: "zypper", args: append([]string{"--non-interactive", "update"}, pkgs...), okCodes: ok}}, "", nil
		}
	case protocol.PMApk:
		switch job.Type {
		case protocol.JobUpgradeAll:
			return []command{{name: "apk", args: []string{"update", "-q"}}, {name: "apk", args: []string{"upgrade"}}}, "", nil
		case protocol.JobUpgradeSecurity:
			return nil, "", errors.New(r.L.T("agent.job.security_unsupported"))
		case protocol.JobUpgradePackages:
			return []command{{name: "apk", args: []string{"update", "-q"}}, {name: "apk", args: append([]string{"upgrade"}, pkgs...)}}, "", nil
		}
	default:
		return nil, "", errors.New(r.L.T("agent.job.pm_unsupported"))
	}
	return nil, "", errors.New(r.L.T("agent.job.unknown_type", "type", job.Type))
}
