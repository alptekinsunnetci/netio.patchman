package agent

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"sort"
	"time"

	"netio.patchman/internal/i18n"
	"netio.patchman/internal/protocol"
	"netio.patchman/internal/timeutil"
)

// Runner is the agent main loop.
type Runner struct {
	cfg       Config
	l         i18n.Localizer
	logger    *slog.Logger
	client    *Client
	collector Collector
	jobs      JobRunner
	updater   SelfUpdater
	pm        string
	restart   bool
}

// RestartRequested reports whether the agent replaced its binary and must be
// restarted (systemd restarts it after the process exits).
func (r *Runner) RestartRequested() bool { return r.restart }

// runJob executes one job; agent updates are handled here, package jobs by JobRunner.
func (r *Runner) runJob(ctx context.Context, job protocol.Job) protocol.JobResult {
	if job.Type != protocol.JobAgentUpdate {
		return r.jobs.Run(ctx, job)
	}
	res := protocol.JobResult{StartedAt: timeutil.Now()}
	msg, restart, err := r.updater.Update(ctx, job)
	res.FinishedAt = timeutil.Now()
	if err != nil {
		res.ExitCode, res.Output = -1, "[netio.patchman] "+err.Error()
		return res
	}
	res.Succeeded, res.Output = true, "[netio.patchman] "+msg
	if restart {
		r.restart = true
		res.Output += "\n[netio.patchman] " + r.l.T("agent.update.restarting")
	}
	return res
}

// NewRunner prepares the agent.
func NewRunner(cfg Config, l i18n.Localizer, logger *slog.Logger) (*Runner, error) {
	client, err := NewClient(cfg)
	if err != nil {
		return nil, err
	}
	pm := DetectPackageManager()
	wingetEnabled = cfg.Winget
	winget := ""
	if cfg.Winget {
		winget = wingetExe()
	}
	r := &Runner{cfg: cfg, l: l, logger: logger, client: client, pm: pm,
		collector: Collector{PM: pm, RefreshLists: cfg.RefreshLists, StateDir: cfg.StateDir},
	}
	r.jobs = JobRunner{L: l, PM: pm, RemoteUpdates: cfg.RemoteUpdates, Winget: winget, Health: HealthRunner{L: l},
		Installed: func(ctx context.Context) ([]protocol.Package, error) { return InstalledPackages(ctx, pm) },
		Available: versionAvailable,
		Pending:   func(ctx context.Context) ([]protocol.Update, error) { return PendingUpdates(ctx, pm) },
		Services:  func(ctx context.Context) []string { s, _ := RestartServices(ctx, pm); return s },
	}
	r.updater = SelfUpdater{L: l, Client: client, Enabled: cfg.AutoUpdate}
	return r, nil
}

func (r *Runner) hostInfo() protocol.HostInfo {
	info, err := ReadHostInfo(r.cfg.RemoteUpdates, r.cfg.AutoUpdate)
	if err != nil {
		r.logger.Warn(r.l.T("log.agent.sysinfo_failed"), slog.String("error", err.Error()))
	}
	return info
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func jitter(d time.Duration) time.Duration {
	return d + time.Duration(rand.Int64N(int64(d)/5+1)) - d/10
}

// ensureRegistered loads or obtains credentials, retrying until ctx ends.
func (r *Runner) ensureRegistered(ctx context.Context) bool {
	server := r.cfg.ServerURL.String()
	for {
		if c, ok := LoadCredentials(r.cfg.StateDir, server); ok {
			r.client.SetSecret(c.AgentSecret)
			return true
		}
		if r.cfg.EnrollmentToken == "" {
			r.logger.Error(r.l.T("log.agent.no_token"))
		} else {
			info := r.hostInfo()
			resp, err := r.client.Register(ctx, r.cfg.EnrollmentToken, info)
			if err == nil {
				if err := SaveCredentials(r.cfg.StateDir, Credentials{ServerURL: server, HostID: resp.HostID, AgentSecret: resp.AgentSecret}); err != nil {
					r.logger.Error(r.l.T("log.agent.credentials_failed"), slog.String("error", err.Error()))
				}
				r.client.SetSecret(resp.AgentSecret)
				r.logger.Info(r.l.T("log.agent.registered"), slog.Int64("host_id", resp.HostID))
				return true
			}
			r.logger.Error(r.l.T("log.agent.register_failed"), slog.String("error", err.Error()))
		}
		if !sleep(ctx, 5*time.Minute) {
			return false
		}
	}
}

func (r *Runner) sendReport(ctx context.Context) {
	start := time.Now()
	inv := r.collector.Collect(ctx)
	rep := protocol.Report{
		Host: r.hostInfo(), Packages: inv.Packages, Updates: inv.Updates, RebootRequired: inv.Reboot,
		RestartServices: inv.Services, CollectedAt: timeutil.Now(), Errors: inv.Errors, KernelPatch: inv.KernelPatch, Services: inv.ServiceList,
	}
	for _, e := range inv.Errors {
		r.logger.Warn(r.l.T("log.agent.collect_warning"), slog.String("error", e))
	}
	if err := r.client.Report(ctx, rep); err != nil {
		r.logger.Error(r.l.T("log.agent.report_failed"), slog.String("error", err.Error()))
		return
	}
	r.logger.Info(r.l.T("log.agent.report_sent"), slog.Int("packages", len(inv.Packages)), slog.Int("updates", len(inv.Updates)),
		slog.Bool("reboot_required", inv.Reboot), slog.Int("restart_services", len(inv.Services)), slog.Duration("duration", time.Since(start).Round(time.Millisecond)))
}

// Run executes the agent until ctx is cancelled.
func (r *Runner) Run(ctx context.Context) {
	if r.pm == "" {
		r.logger.Warn(r.l.T("log.agent.no_package_manager"))
	}
	if !r.ensureRegistered(ctx) {
		return
	}
	r.sendReport(ctx)

	interval := 60 * time.Second
	failures := 0
	for {
		resp, err := r.client.Checkin(ctx, r.hostInfo())
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if IsUnauthorized(err) {
				// The host was removed on the server or the secret was rotated.
				r.logger.Error(r.l.T("log.agent.unauthorized"))
				DeleteCredentials(r.cfg.StateDir)
				r.client.SetSecret("")
				if !r.ensureRegistered(ctx) {
					return
				}
				r.sendReport(ctx)
				continue
			}
			failures++
			backoff := min(interval*time.Duration(1<<min(failures, 4)), 10*time.Minute)
			r.logger.Warn(r.l.T("log.agent.checkin_failed"), slog.String("error", err.Error()), slog.Duration("retry_in", backoff))
			if !sleep(ctx, backoff) {
				return
			}
			continue
		}
		failures = 0
		if resp.CheckinIntervalSeconds >= 15 {
			interval = time.Duration(resp.CheckinIntervalSeconds) * time.Second
		}
		needReport := resp.ReportRequested
		// A reboot and an agent update end the process, so they run after all
		// other jobs; the agent update last because it exits at once.
		sort.SliceStable(resp.Jobs, func(i, j int) bool { return jobOrder(resp.Jobs[i].Type) < jobOrder(resp.Jobs[j].Type) })
		for _, job := range resp.Jobs {
			r.logger.Info(r.l.T("log.agent.job_started"), slog.Int64("job_id", job.ID), slog.String("type", job.Type), slog.Any("packages", job.Packages))
			res := r.runJob(ctx, job)
			r.logger.Info(r.l.T("log.agent.job_finished"), slog.Int64("job_id", job.ID), slog.Bool("succeeded", res.Succeeded), slog.Int("exit_code", res.ExitCode))
			for attempt := 0; attempt < 5; attempt++ {
				err := r.client.JobResult(ctx, job.ID, res)
				var apiErr *APIError
				if err == nil || (errors.As(err, &apiErr) && apiErr.Status == http.StatusNotFound) {
					break
				}
				r.logger.Warn(r.l.T("log.agent.job_result_failed"), slog.String("error", err.Error()))
				if !sleep(ctx, 30*time.Second) {
					return
				}
			}
			needReport = true
			if r.restart {
				break
			}
		}
		if r.restart {
			// The new binary sends a fresh report when it starts; main logs the restart.
			return
		}
		if needReport {
			r.sendReport(ctx)
		}
		if !sleep(ctx, jitter(interval)) {
			return
		}
	}
}

func jobOrder(typ string) int {
	switch typ {
	case protocol.JobReboot:
		return 1
	case protocol.JobAgentUpdate:
		return 2
	}
	return 0
}
