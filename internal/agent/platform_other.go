//go:build !windows

package agent

import (
	"context"
	"errors"

	"netio.patchman/internal/brand"
	"netio.patchman/internal/protocol"
)

// DefaultConfigPath is the agent's environment file.
const DefaultConfigPath = brand.ConfigDir + "/agent.env"

// DefaultStateDir holds the agent credentials.
const DefaultStateDir = "/var/lib/netio-patchman"

func readPlatform(h *protocol.HostInfo) error { return readLinuxPlatform(h) }

func platformVirtualization() string { return detectVirtualization(context.Background(), "/") }

var errNotWindows = errors.New("windows update: not a Windows host")

// runWU runs the Windows Update helper script (Windows only).
func runWU(ctx context.Context, env []string) ([]byte, error) { return nil, errNotWindows }

// wingetExe returns the winget executable (Windows only).
func wingetExe() string { return "" }

// wingetList lists third-party program updates (Windows only).
func wingetList(ctx context.Context, exe string) ([]protocol.Update, error) {
	return nil, errNotWindows
}

// windowsPrograms lists installed programs (Windows only).
func windowsPrograms() ([]protocol.Package, error) { return nil, errNotWindows }
