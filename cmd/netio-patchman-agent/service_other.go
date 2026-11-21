//go:build !windows

package main

import (
	"context"
	"io"
	"os"
	"os/signal"
	"syscall"
)

// restartExitCode ends the process after a self-update; systemd
// (Restart=always) and OpenRC supervise-daemon start the new binary.
const restartExitCode = 0

func platformMain(run func(ctx context.Context, logOut io.Writer) int) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return run(ctx, os.Stdout)
}
