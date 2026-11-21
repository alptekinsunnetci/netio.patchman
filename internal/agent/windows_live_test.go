//go:build windows && live

package agent

import (
	"context"
	"testing"
	"time"
)

// TestLiveWindows reads the real host: go test -tags live -run LiveWindows -v ./internal/agent/
// It only searches (offline, then online); nothing is installed.
func TestLiveWindows(t *testing.T) {
	h, err := ReadHostInfo(true, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("host: %+v", h)
	if h.OSID != "windows" || h.Kernel == "" || h.OSName == "" || h.MachineID == "" {
		t.Errorf("incomplete host info")
	}
	pkgs, err := windowsPrograms()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d programs, first: %+v", len(pkgs), pkgs[:min(3, len(pkgs))])
	if exe := wingetExe(); exe != "" {
		ups, err := wingetList(context.Background(), exe)
		t.Logf("winget %s: %d updates, err=%v, first: %+v", exe, len(ups), err, ups[:min(3, len(ups))])
	} else {
		t.Log("winget not installed")
	}
	for _, online := range []bool{false, true} {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
		start := time.Now()
		ups, reboot, err := wuPending(ctx, online)
		cancel()
		if err != nil {
			t.Fatalf("online=%v: %v", online, err)
		}
		t.Logf("online=%v: %d updates, reboot=%v in %s", online, len(ups), reboot, time.Since(start).Round(time.Second))
		for _, u := range ups {
			t.Logf("  %+v", u)
		}
	}
}
