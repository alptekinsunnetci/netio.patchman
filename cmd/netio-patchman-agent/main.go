// Command netio-patchman-agent runs on each managed Linux or Windows server
// and reports to the netio.patchman server.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime"

	"netio.patchman/internal/agent"
	"netio.patchman/internal/brand"
	"netio.patchman/internal/i18n"
	"netio.patchman/internal/logging"
	"netio.patchman/internal/version"
)

func main() {
	// platformMain runs agentMain in the foreground or, on Windows, as a
	// service; it handles stop signals and where the log goes.
	os.Exit(platformMain(agentMain))
}

func agentMain(ctx context.Context, logOut io.Writer) int {
	bundle := i18n.MustLoad()
	// PATCHMAN_LOCALE from the environment chooses the language of flag help
	// and config errors; the value in agent.env applies after the config loads.
	l := bundle.Localizer(os.Getenv(brand.EnvPrefix + "LOCALE"))

	fs := flag.NewFlagSet(brand.AgentBinary, flag.ExitOnError)
	configPath := fs.String("config", agent.DefaultConfigPath, l.T("flag.config"))
	showVersion := fs.Bool("version", false, l.T("flag.version"))
	debug := fs.Bool("debug", false, l.T("flag.debug"))
	_ = fs.Parse(os.Args[1:])

	if *showVersion {
		fmt.Printf("%s %s %q (%s)\n", brand.AgentBinary, version.Version, version.CurrentCodename(), brand.Name)
		return 0
	}

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	// journald adds timestamps; text format keeps journal lines readable.
	logger := logging.New(logOut, "agent", level, "text")

	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		logger.Error(l.T("log.agent.not_linux"), slog.String("os", runtime.GOOS))
		return 1
	}

	cfg, err := agent.LoadConfig(l, *configPath, os.Getenv)
	if err != nil {
		logger.Error(l.T("log.config.failed"), slog.String("path", *configPath), slog.String("error", err.Error()))
		return 1
	}
	// Log and job messages (shown in the panel) use the configured language.
	l = bundle.Localizer(cfg.Locale)

	runner, err := agent.NewRunner(cfg, l, logger)
	if err != nil {
		logger.Error(l.T("log.config.failed"), slog.String("error", err.Error()))
		return 1
	}

	logger.Info(l.T("log.agent.starting"),
		slog.String("server_url", cfg.ServerURL.String()),
		slog.String("package_manager", agent.DetectPackageManager()),
		slog.Bool("remote_updates", cfg.RemoteUpdates),
		slog.Bool("auto_update", cfg.AutoUpdate),
		slog.String("user_agent", brand.AgentUserAgent(version.Version, runtime.GOOS, runtime.GOARCH)),
	)

	runner.Run(ctx)
	if runner.RestartRequested() {
		// systemd (Restart=always) or the Windows service recovery settings
		// start the new binary.
		logger.Info(l.T("agent.update.restarting"))
		return restartExitCode
	}
	logger.Info(l.T("log.agent.stopping"))
	return 0
}
