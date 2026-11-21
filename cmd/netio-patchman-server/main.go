// Command netio-patchman-server is the central netio.patchman server.
//
// Subcommands:
//
//	netio-patchman-server                     run the server (default)
//	netio-patchman-server backup -out FILE    write a consistent database copy
//	netio-patchman-server reset-password -email ADDRESS
//	netio-patchman-server reset-mfa -email ADDRESS   remove a lost authenticator
//	netio-patchman-server healthcheck         exit 0 when /healthz answers
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	agentdist "netio.patchman/deploy/agent"
	"netio.patchman/internal/api"
	"netio.patchman/internal/auth"
	"netio.patchman/internal/backup"
	"netio.patchman/internal/brand"
	"netio.patchman/internal/config"
	"netio.patchman/internal/i18n"
	"netio.patchman/internal/logging"
	"netio.patchman/internal/notify"
	"netio.patchman/internal/notify/email"
	"netio.patchman/internal/release"
	"netio.patchman/internal/scanner"
	"netio.patchman/internal/schedule"
	"netio.patchman/internal/settings"
	"netio.patchman/internal/store"
	"netio.patchman/internal/timeutil"
	"netio.patchman/internal/updatecheck"
	"netio.patchman/internal/version"
	"netio.patchman/internal/web"
)

func main() {
	bundle := i18n.MustLoad()
	boot := bundle.Localizer(i18n.DefaultLocale)

	args := os.Args[1:]
	cmd := "serve"
	if len(args) > 0 && len(args[0]) > 0 && args[0][0] != '-' {
		cmd, args = args[0], args[1:]
	}

	fs := flag.NewFlagSet(brand.ServerBinary, flag.ExitOnError)
	showVersion := fs.Bool("version", false, boot.T("flag.version"))
	out := fs.String("out", "", boot.T("flag.backup_out"))
	emailAddr := fs.String("email", "", boot.T("flag.email"))
	_ = fs.Parse(args)
	if *showVersion {
		fmt.Printf("%s %s (%s)\n", brand.ServerBinary, version.Version, brand.Name)
		return
	}

	cfg, err := config.Load(bundle, os.Getenv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n%s\n", brand.Name, boot.T("log.config.failed"), err)
		os.Exit(1)
	}
	// The level can be changed on the server configuration page.
	level := new(slog.LevelVar)
	level.Set(cfg.LogLevel)
	logger := logging.New(os.Stdout, "server", level, cfg.LogFormat)
	l := bundle.Localizer(cfg.Locale)

	if cmd == "healthcheck" {
		os.Exit(healthcheck(cfg))
	}

	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		logger.Error(l.T("log.store.failed"), slog.String("path", cfg.DataDir), slog.String("error", err.Error()))
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	st, err := store.Open(ctx, cfg.DatabasePath())
	if err != nil {
		logger.Error(l.T("log.store.failed"), slog.String("path", cfg.DatabasePath()), slog.String("error", err.Error()))
		os.Exit(1)
	}
	defer st.Close()

	switch cmd {
	case "serve":
		os.Exit(serve(ctx, cfg, st, bundle, l, logger, level))
	case "backup":
		if *out == "" {
			fmt.Fprintln(os.Stderr, l.T("cli.backup.out_required"))
			os.Exit(2)
		}
		if err := st.Backup(ctx, *out); err != nil {
			fmt.Fprintln(os.Stderr, l.T("cli.backup.failed", "error", err.Error()))
			os.Exit(1)
		}
		fmt.Println(l.T("cli.backup.done", "path", *out))
	case "reset-password":
		u, err := st.UserByEmail(ctx, *emailAddr)
		if err != nil {
			fmt.Fprintln(os.Stderr, l.T("cli.reset.user_not_found", "email", *emailAddr))
			os.Exit(1)
		}
		pw := auth.RandomPassword()
		hash, err := auth.HashPassword(pw)
		if err == nil {
			err = st.SetPassword(ctx, u.ID, hash, "")
		}
		if err == nil {
			err = st.UpdateUser(ctx, u.ID, u.Name, u.Role, false)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		_ = st.Audit(ctx, store.AuditEntry{Action: "user.password_reset", Target: u.Email, Details: "cli"})
		fmt.Println(l.T("cli.reset.done", "email", u.Email, "password", pw))
	case "reset-mfa":
		u, err := st.UserByEmail(ctx, *emailAddr)
		if err != nil {
			fmt.Fprintln(os.Stderr, l.T("cli.reset.user_not_found", "email", *emailAddr))
			os.Exit(1)
		}
		if err := st.DisableTOTP(ctx, u.ID, ""); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		_ = st.Audit(ctx, store.AuditEntry{Action: "user.mfa_reset", Target: u.Email, Details: "cli"})
		fmt.Println(l.T("cli.reset_mfa.done", "email", u.Email))
	default:
		fmt.Fprintln(os.Stderr, l.T("cli.unknown_command", "command", cmd))
		os.Exit(2)
	}
}

func serve(ctx context.Context, cfg config.Config, st *store.Store, bundle *i18n.Bundle, l i18n.Localizer, logger *slog.Logger, level *slog.LevelVar) int {
	// Values saved on the server configuration page override PATCHMAN_*
	// environment variables and apply without a restart.
	live, err := settings.NewLive(ctx, cfg, st)
	if err != nil {
		logger.Error(l.T("log.server.failed"), slog.String("error", err.Error()))
		return 1
	}
	sys := live.Get()
	level.Set(sys.LogLevel)
	logger.Info(l.T("log.server.starting"),
		slog.String("locale", cfg.Locale),
		slog.String("timezone", sys.Timezone),
		slog.String("base_url", sys.BaseURLString()),
		slog.String("database", cfg.DatabasePath()),
	)
	formatter := timeutil.NewFormatter(sys.Location, l)

	renderer, err := email.NewRenderer(l, formatter, sys.SMTP.From)
	if err != nil {
		logger.Error(l.T("log.server.failed"), slog.String("error", err.Error()))
		return 1
	}
	if !sys.SMTP.Enabled() {
		logger.Warn(l.T("log.email.disabled"))
	}
	notifier := notify.New(notify.Options{Store: st, L: l, F: formatter, Logger: logger, System: live, Renderer: renderer})
	// Every stored notification is also forwarded to Slack, Teams, Telegram
	// and webhook channels.
	channels := notify.NewDispatcher(notify.DispatcherOptions{Store: st, L: l, System: live, Logger: logger})
	st.OnNotification(channels.Enqueue)
	go channels.Run(ctx)
	backups := &backup.Runner{Store: st, Dir: cfg.BackupDir, Zone: formatter.Zone(), L: l, Logger: logger, OnFailure: notifier.BackupFailed}

	retention := func(ctx context.Context) {
		v, err := settings.Load(ctx, st)
		if err != nil {
			return
		}
		r := v.Retention()
		for _, fn := range []func(context.Context, time.Duration) error{st.PruneResolvedFindings, st.PruneJobs, st.PruneNotifications} {
			if err := fn(ctx, r); err != nil {
				logger.Warn(l.T("log.maintenance.failed"), slog.String("error", err.Error()))
			}
		}
		_ = st.PruneAudit(ctx, 365*24*time.Hour)
		_ = st.PruneSnapshots(ctx, 2*365*24*time.Hour)
		_ = st.PruneOSVQueries(ctx, 30*24*time.Hour)
		_ = st.PruneOSVRecords(ctx, 90*24*time.Hour)
		_ = st.PruneMSRCKB(ctx, 30*24*time.Hour)
		_ = st.DeleteExpiredSessions(ctx)
		_ = st.ReclaimSpace(ctx)
	}

	scan := scanner.New(scanner.Options{
		Store: st, OSV: scanner.NewOSVClient(sys.OSVURL), System: live, Logger: logger, L: l,
		AfterScan: notifier.ProcessAlerts, Daily: retention,
	})
	agentRelease := release.Load(cfg.AgentDistDir, version.Version)
	if agentRelease.Available() {
		archs := make([]string, 0, len(agentRelease.Binaries))
		for a := range agentRelease.Binaries {
			archs = append(archs, a)
		}
		logger.Info(l.T("log.server.agent_release"), slog.String("agent_version", agentRelease.Version), slog.Any("archs", archs))
	} else {
		logger.Warn(l.T("log.server.agent_release_missing"), slog.String("dir", cfg.AgentDistDir))
	}
	agentAPI := api.New(api.Options{
		Store: st, L: l, Logger: logger, Scanner: scan, Notifier: notifier,
		AgentDistDir: cfg.AgentDistDir, Assets: agentdist.Assets(), System: live, Release: agentRelease,
	})
	updates := updatecheck.New(ctx, updatecheck.Options{
		Current: version.Version, Store: st, System: live, Logger: logger, L: l,
		OnNewVersion: func(ctx context.Context, s updatecheck.Status) {
			notifier.ServerUpdate(ctx, s.Current, s.Latest, s.ChangesURL())
		},
	})
	site, err := web.New(web.Options{
		Store: st, Localizer: l, Formatter: formatter, Logger: logger, Scanner: scan, Notifier: notifier,
		System: live, API: agentAPI, Release: agentRelease, Updates: updates, Bundle: bundle, Backups: backups, Channels: channels,
	})
	if err != nil {
		logger.Error(l.T("log.server.failed"), slog.String("error", err.Error()))
		return 1
	}

	if n, _ := st.CountUsers(ctx); n == 0 {
		logger.Warn(l.T("log.server.setup_required"), slog.String("url", sys.BaseURLString()+"/setup"))
	}

	go scan.Run(ctx)
	go updates.Run(ctx)
	sched := &schedule.Runner{Store: st, Zone: formatter.Zone(), L: l, Logger: logger}
	live.OnChange(func(old, cur settings.System) {
		level.Set(cur.LogLevel)
		formatter.Zone().Set(cur.Location)
		if old.Timezone != cur.Timezone {
			// Schedules are wall-clock times in the display zone.
			if err := sched.Reschedule(ctx, timeutil.Now()); err != nil {
				logger.Warn(l.T("log.schedule.failed"), slog.String("error", err.Error()))
			}
		}
		if cur.KEVURL != "" && old.KEVURL != cur.KEVURL {
			go func() {
				if err := scan.RefreshKEV(ctx); err != nil {
					logger.Warn(l.T("log.scan.kev_failed"), slog.String("error", err.Error()))
				}
			}()
		}
		if cur.EPSSURL != "" && old.EPSSURL != cur.EPSSURL {
			go func() {
				if err := scan.RefreshEPSS(ctx); err != nil {
					logger.Warn(l.T("log.scan.epss_failed"), slog.String("error", err.Error()))
				}
			}()
		}
		if cur.UpdateURL != "" && old.UpdateURL != cur.UpdateURL {
			go updates.Check(ctx)
		}
		logger.Info(l.T("log.config.updated"), slog.String("base_url", cur.BaseURLString()), slog.String("timezone", cur.Timezone),
			slog.String("log_level", cur.LogLevelName()), slog.Bool("smtp", cur.SMTP.Enabled()))
	})
	go maintenance(ctx, st, notifier, sched, backups, l, logger)

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           site.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       2 * time.Minute,
		WriteTimeout:      5 * time.Minute,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	errCh := make(chan error, 1)
	go func() {
		logger.Info(l.T("log.server.listening"), slog.String("addr", cfg.HTTPAddr), slog.Bool("tls", cfg.TLSCertFile != ""))
		if cfg.TLSCertFile != "" {
			errCh <- srv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
		} else {
			errCh <- srv.ListenAndServe()
		}
	}()

	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Error(l.T("log.server.failed"), slog.String("error", err.Error()))
			return 1
		}
	case <-ctx.Done():
		logger.Info(l.T("log.server.stopping"))
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.Error(l.T("log.server.failed"), slog.String("error", err.Error()))
		}
	}
	logger.Info(l.T("log.server.stopped"))
	return 0
}

// healthcheck probes the local /healthz endpoint (used by the container
// HEALTHCHECK, since the distroless image has no curl).
func healthcheck(cfg config.Config) int {
	_, port, err := net.SplitHostPort(cfg.HTTPAddr)
	if err != nil {
		return 1
	}
	scheme := "http"
	client := &http.Client{Timeout: 5 * time.Second}
	if cfg.TLSCertFile != "" {
		scheme = "https"
		// Loopback liveness probe: the certificate is issued for the public name.
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec
	}
	resp, err := client.Get(scheme + "://127.0.0.1:" + port + "/healthz")
	if err != nil {
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

// maintenance runs periodic checks: scheduled updates, offline agents and
// stale jobs.
func maintenance(ctx context.Context, st *store.Store, n *notify.Notifier, sched *schedule.Runner, backups *backup.Runner, l i18n.Localizer, logger *slog.Logger) {
	// Align ticks to the start of a minute so a 03:00 schedule fires at 03:00.
	if !sleepUntil(ctx, timeutil.Now().Truncate(time.Minute).Add(time.Minute)) {
		return
	}
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	var lastSnapshot time.Time
	for {
		now := timeutil.Now()
		sched.Tick(ctx, now)
		go backups.Tick(ctx, now)
		n.CheckOffline(ctx)
		if risks, err := st.ExpireAcceptedRisks(ctx, now); err != nil {
			logger.Warn(l.T("log.maintenance.failed"), slog.String("error", err.Error()))
		} else if len(risks) > 0 {
			for _, r := range risks {
				_ = st.Audit(ctx, store.AuditEntry{Action: "finding.risk_expired", Target: r.CVEID, Details: "host=" + r.Hostname + " package=" + r.Package})
			}
			logger.Info(l.T("log.risk.expired"), slog.Int("findings", len(risks)))
			n.RisksExpired(ctx, risks)
		}
		n.SLAOverdue(ctx)
		// The trend chart keeps one row per day with the latest state.
		if now.Sub(lastSnapshot) >= 15*time.Minute {
			if err := st.TakeSnapshot(ctx, now); err != nil {
				logger.Warn(l.T("log.maintenance.failed"), slog.String("error", err.Error()))
			} else {
				lastSnapshot = now
			}
		}
		jobs, err := st.TimeOutJobs(ctx, 3*time.Hour)
		if err != nil {
			logger.Warn(l.T("log.maintenance.failed"), slog.String("error", err.Error()))
		}
		for _, j := range jobs {
			n.JobFinished(ctx, j)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func sleepUntil(ctx context.Context, t time.Time) bool {
	timer := time.NewTimer(time.Until(t))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
