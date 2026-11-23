package agent

import (
	"slices"
	"testing"

	"netio.patchman/internal/protocol"
)

// Preview and rollback are only declared where the package manager has them.
func TestCapabilitiesByPackageManager(t *testing.T) {
	for pm, want := range map[string][2]bool{
		protocol.PMApt: {true, true}, protocol.PMDnf: {true, true}, protocol.PMZypper: {true, true},
		protocol.PMApk: {true, false}, protocol.PMWindowsUpdate: {false, false}, "": {false, false},
	} {
		caps := Capabilities(pm)
		if slices.Contains(caps, protocol.CapPreview) != want[0] || slices.Contains(caps, protocol.CapRollback) != want[1] {
			t.Errorf("%q: %v", pm, caps)
		}
		if !slices.Contains(caps, protocol.CapHealthMonitor) || !slices.Contains(caps, protocol.CapServices) {
			t.Errorf("%q lost a capability: %v", pm, caps)
		}
	}
}
