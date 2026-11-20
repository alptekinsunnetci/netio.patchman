// Command netio-patchman-agent runs on each managed Linux server and reports
// to the netio.patchman server.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"netio.patchman/internal/agent"
	"netio.patchman/internal/brand"
	"netio.patchman/internal/i18n"
	"netio.patchman/internal/logging"
	"netio.patchman/internal/version"
)

func main() {
	l := i18n.MustLoad().Localizer(i18n.DefaultLocale)

	fs := flag.NewFlagSet(brand.AgentBinary, flag.ExitOnError)
	configPath := fs.String("config", agent.DefaultConfigPath, l.T("flag.config"))
	showVersion := fs.Bool("version", false, l.T("flag.version"))
	debug := fs.Bool("debug", false, l.T("flag.debug"))
	_ = fs.Parse(os.Args[1:])

	if *showVersion {
		fmt.Printf("%s %s (%s)\n", brand.AgentBinary, version.Version, brand.Name)
		return
	}

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	// journald adds timestamps; text format keeps journal lines readable.
	logger := logging.New(os.Stdout, "agent", level, "text")

	if runtime.GOOS != "linux" {
		logger.Error(l.T("log.agent.not_linux"), slog.String("os", runtime.GOOS))
		os.Exit(1)
	}

	cfg, err := agent.LoadConfig(l, *configPath, os.Getenv)
	if err != nil {
		logger.Error(l.T("log.config.failed"), slog.String("path", *configPath), slog.String("error", err.Error()))
		os.Exit(1)
	}

	runner, err := agent.NewRunner(cfg, l, logger)
	if err != nil {
		logger.Error(l.T("log.config.failed"), slog.String("error", err.Error()))
		os.Exit(1)
	}

	logger.Info(l.T("log.agent.starting"),
		slog.String("server_url", cfg.ServerURL.String()),
		slog.String("package_manager", agent.DetectPackageManager()),
		slog.Bool("remote_updates", cfg.RemoteUpdates),
		slog.Bool("auto_update", cfg.AutoUpdate),
		slog.String("user_agent", brand.AgentUserAgent(version.Version, runtime.GOOS, runtime.GOARCH)),
	)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	runner.Run(ctx)
	if runner.RestartRequested() {
		// systemd (Restart=always) starts the new binary.
		logger.Info(l.T("agent.update.restarting"))
		return
	}
	logger.Info(l.T("log.agent.stopping"))
}
