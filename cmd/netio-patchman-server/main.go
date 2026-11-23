// Command netio-patchman-server is the central netio.patchman server.
//
// Subcommands:
//
//	netio-patchman-server                     run the server (default)
//	netio-patchman-server backup -out FILE    write a consistent database copy (a SQLite file)
//	netio-patchman-server restore -in FILE    replace all data with a backup (stop the server first)
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
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	agentdist "netio.patchman/deploy/agent"
	"netio.patchman/internal/api"
	"netio.patchman/internal/auth"
	"netio.patchman/internal/backup"
	"netio.patchman/internal/brand"
	"netio.patchman/internal/config"
	"netio.patchman/internal/drift"
	"netio.patchman/internal/eol"
	"netio.patchman/internal/i18n"
	"netio.patchman/internal/logging"
	"netio.patchman/internal/notify"
	"netio.patchman/internal/notify/email"
	"netio.patchman/internal/release"
	"netio.patchman/internal/rollout"
	"netio.patchman/internal/scanner"
	"netio.patchman/internal/schedule"
	"netio.patchman/internal/scoring"
	"netio.patchman/internal/selfupdate"
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
	in := fs.String("in", "", boot.T("flag.restore_in"))
	emailAddr := fs.String("email", "", boot.T("flag.email"))
	_ = fs.Parse(args)
	if *showVersion {
		fmt.Printf("%s %s %q (%s)\n", brand.ServerBinary, version.Version, version.CurrentCodename(), brand.Name)
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
	st, err := openStore(ctx, cfg, l, logger)
	if err != nil {
		logger.Error(l.T("log.store.failed"), slog.String("database", cfg.DatabaseDisplay()), slog.String("error", err.Error()))
		os.Exit(1)
	}
	defer st.Close()
	if !importSQLite(ctx, cfg, st, l, logger) {
		st.Close()
		os.Exit(1)
	}

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
	case "restore":
		if *in == "" {
			fmt.Fprintln(os.Stderr, l.T("cli.restore.in_required"))
			os.Exit(2)
		}
		res, err := st.Restore(ctx, *in)
		if err != nil {
			fmt.Fprintln(os.Stderr, l.T("cli.restore.failed", "error", err.Error()))
			os.Exit(1)
		}
		_ = st.Audit(ctx, store.AuditEntry{Action: "system.restore", Target: filepath.Base(*in),
			Details: fmt.Sprintf("cli tables=%d rows=%d", res.Tables, res.Rows)})
		fmt.Println(l.T("cli.restore.done", "path", *in, "tables", res.Tables, "rows", res.Rows))
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
		slog.String("database", cfg.DatabaseDisplay()),
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
		for _, fn := range []func(context.Context, time.Duration) error{st.PruneResolvedFindings, st.PruneJobs, st.PruneNotifications, st.PruneHealthResults, st.PruneDeliveries} {
			if err := fn(ctx, r); err != nil {
				logger.Warn(l.T("log.maintenance.failed"), slog.String("error", err.Error()))
			}
		}
		_ = st.PruneAudit(ctx, 365*24*time.Hour)
		_ = st.PruneSnapshots(ctx, 2*365*24*time.Hour)
		_ = st.PruneSoftwareEvents(ctx, 2*365*24*time.Hour)
		_ = st.PruneHostScores(ctx, 2*365*24*time.Hour)
		_ = st.PruneHostMetrics(ctx, 30*24*time.Hour)
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
	// Support calendars: built-in snapshot plus the stored daily downloads.
	eolSrc := &eol.Source{Store: st, System: live, Logger: logger, L: l}
	if err := eolSrc.Load(ctx); err != nil {
		logger.Warn(l.T("log.eol.failed"), slog.String("error", err.Error()))
	}
	scores := &scoring.Engine{Store: st, EOL: eolSrc.Data, OnBelow: notifier.ScoreBelow}
	rollouts := &rollout.Runner{Store: st, L: l, Logger: logger, Notify: func(ctx context.Context, kind, level string, r store.Rollout) {
		// Counts are read again so the notification shows the final numbers.
		if cur, err := st.RolloutByID(ctx, r.ID); err == nil {
			r.Counts = cur.Counts
		}
		notifier.RolloutEvent(ctx, kind, level, r)
	}}
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
		System: live, API: agentAPI, Release: agentRelease, Updates: updates, Bundle: bundle, Backups: backups, Channels: channels, EOL: eolSrc, Scores: scores, Rollouts: rollouts,
		SelfUpdate: &selfupdate.Manager{DataDir: cfg.DataDir},
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
		if cur.EOLURL != "" && old.EOLURL != cur.EOLURL {
			go func() {
				if err := eolSrc.Refresh(ctx); err != nil {
					logger.Warn(l.T("log.eol.failed"), slog.String("error", err.Error()))
				}
			}()
		}
		if cur.UpdateURL != "" && old.UpdateURL != cur.UpdateURL {
			go updates.Check(ctx)
		}
		logger.Info(l.T("log.config.updated"), slog.String("base_url", cur.BaseURLString()), slog.String("timezone", cur.Timezone),
			slog.String("log_level", cur.LogLevelName()), slog.Bool("smtp", cur.SMTP.Enabled()))
	})
	go maintenance(ctx, st, notifier, sched, backups, &selfupdate.Manager{DataDir: cfg.DataDir}, eolSrc, scores, rollouts, l, logger)

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

// openStore opens the database. PostgreSQL may still be starting (or be
// restarting), so connection attempts are repeated for two minutes.
func openStore(ctx context.Context, cfg config.Config, l i18n.Localizer, logger *slog.Logger) (*store.Store, error) {
	deadline := time.Now().Add(2 * time.Minute)
	for {
		st, err := store.Open(ctx, cfg.Database())
		if err == nil || !cfg.Postgres() || time.Now().After(deadline) {
			return st, err
		}
		logger.Warn(l.T("log.store.waiting"), slog.String("database", cfg.DatabaseDisplay()), slog.String("error", err.Error()))
		select {
		case <-ctx.Done():
			return nil, err
		case <-time.After(3 * time.Second):
		}
	}
}

// importSQLite moves the SQLite database of an earlier installation into a
// new, empty PostgreSQL database on the first start with PostgreSQL. The
// copy runs in one transaction and is verified table by table; on failure
// nothing is changed and the server does not start (so nobody sets up a
// fresh, empty installation by mistake). Afterwards the SQLite file is
// renamed, not deleted. It returns false when the server must not start.
func importSQLite(ctx context.Context, cfg config.Config, st *store.Store, l i18n.Localizer, logger *slog.Logger) bool {
	path := cfg.DatabasePath()
	if !st.Postgres() {
		return true
	}
	if _, err := os.Stat(path); err != nil {
		return true
	}
	empty, err := st.Empty(ctx)
	if err != nil {
		logger.Error(l.T("log.store.import_failed"), slog.String("file", path), slog.String("error", err.Error()))
		return false
	}
	if !empty {
		logger.Warn(l.T("log.store.import_skipped"), slog.String("file", path), slog.String("database", cfg.DatabaseDisplay()))
		return true
	}
	logger.Info(l.T("log.store.import_started"), slog.String("file", path), slog.String("database", cfg.DatabaseDisplay()))
	res, err := st.ImportSQLite(ctx, path)
	if errors.Is(err, store.ErrNotEmpty) {
		// Another process (a CLI command next to the server) was faster.
		logger.Warn(l.T("log.store.import_skipped"), slog.String("file", path), slog.String("database", cfg.DatabaseDisplay()))
		return true
	}
	if err != nil {
		logger.Error(l.T("log.store.import_failed"), slog.String("file", path), slog.String("error", err.Error()))
		return false
	}
	kept := path + ".imported-" + time.Now().UTC().Format("20060102-150405")
	if err := os.Rename(path, kept); err != nil {
		logger.Warn(l.T("log.store.import_rename_failed"), slog.String("file", path), slog.String("error", err.Error()))
		kept = path
	} else {
		for _, suffix := range []string{"-wal", "-shm"} {
			if _, err := os.Stat(path + suffix); err == nil {
				_ = os.Rename(path+suffix, kept+suffix)
			}
		}
	}
	logger.Info(l.T("log.store.import_done"), slog.Int("tables", res.Tables), slog.Int64("rows", res.Rows),
		slog.Int64("sanitized", res.Sanitized), slog.Int64("orphans", res.Orphans), slog.Duration("duration", res.Duration.Round(time.Millisecond)), slog.String("kept", kept))
	_ = st.Audit(ctx, store.AuditEntry{Action: "system.database_import", Target: filepath.Base(path),
		Details: fmt.Sprintf("tables=%d rows=%d sanitized=%d orphans=%d kept=%s", res.Tables, res.Rows, res.Sanitized, res.Orphans, filepath.Base(kept))})
	_ = st.AddNotification(ctx, store.LevelInfo, "database_imported", map[string]string{
		"tables": strconv.Itoa(res.Tables), "rows": strconv.FormatInt(res.Rows, 10), "file": filepath.Base(kept)}, "")
	return true
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
func maintenance(ctx context.Context, st *store.Store, n *notify.Notifier, sched *schedule.Runner, backups *backup.Runner, su *selfupdate.Manager, eolSrc *eol.Source, scores *scoring.Engine, rollouts *rollout.Runner, l i18n.Localizer, logger *slog.Logger) {
	// Align ticks to the start of a minute so a 03:00 schedule fires at 03:00.
	if !sleepUntil(ctx, timeutil.Now().Truncate(time.Minute).Add(time.Minute)) {
		return
	}
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	var lastSnapshot, lastEOL time.Time
	for {
		now := timeutil.Now()
		sched.Tick(ctx, now)
		rollouts.Tick(ctx, now)
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
		n.SelfUpdateFinished(ctx, su)
		// Support calendars: refreshed daily, end-of-life notices checked hourly.
		if now.Sub(lastEOL) >= time.Hour {
			lastEOL = now
			go func() {
				if eolSrc.Due(ctx, now) {
					if err := eolSrc.Refresh(ctx); err != nil {
						logger.Warn(l.T("log.eol.failed"), slog.String("error", err.Error()))
					}
				}
				n.EOLCheck(ctx, eolSrc.Data())
			}()
		}
		// The trend chart keeps one row per day with the latest state; the
		// security scores are computed first so the day's average is current.
		if now.Sub(lastSnapshot) >= 15*time.Minute {
			if err := scores.Run(ctx, now); err != nil {
				logger.Warn(l.T("log.maintenance.failed"), slog.String("error", err.Error()))
			}
			if hosts, err := drift.Check(ctx, st); err != nil {
				logger.Warn(l.T("log.maintenance.failed"), slog.String("error", err.Error()))
			} else if len(hosts) > 0 {
				n.DriftDetected(ctx, hosts)
			}
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
