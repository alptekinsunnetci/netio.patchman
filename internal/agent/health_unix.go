//go:build !windows

package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func defaultDiskPath() string { return "/" }

// readResources reads the 1-minute load average per core (/proc/loadavg),
// memory in use (/proc/meminfo: MemTotal - MemAvailable) and disk usage of
// each path (statfs, space available to unprivileged users).
func readResources(paths []string) (cpu, mem float64, disk map[string]float64, err error) {
	cpu, mem = -1, -1
	if b, e := os.ReadFile("/proc/loadavg"); e == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			if v, e := strconv.ParseFloat(f[0], 64); e == nil {
				cpu = v / float64(runtime.NumCPU()) * 100
			}
		}
	}
	if f, e := os.Open("/proc/meminfo"); e == nil {
		mem = parseMeminfo(f)
		f.Close()
	}
	disk = map[string]float64{}
	for _, p := range paths {
		var st unix.Statfs_t
		if unix.Statfs(p, &st) != nil || st.Blocks == 0 {
			continue
		}
		// "Use%" as df shows it: used over used plus available.
		used := float64(st.Blocks - st.Bfree)
		disk[p] = used / (used + float64(st.Bavail)) * 100
	}
	return cpu, mem, disk, nil
}

// serviceRunning asks systemd or OpenRC whether a service runs.
func serviceRunning(ctx context.Context, name string) (bool, error) {
	if st, err := os.Stat("/run/systemd/system"); err == nil && st.IsDir() {
		out, code, err := run(ctx, 30*time.Second, "systemctl", "is-active", name)
		state := strings.TrimSpace(string(out))
		if state == "active" || state == "reloading" {
			return true, nil
		}
		if code != 0 && state != "" {
			return false, nil
		}
		return false, err
	}
	if _, err := exec.LookPath("rc-service"); err == nil {
		_, code, _ := run(ctx, 30*time.Second, "rc-service", name, "status")
		return code == 0, nil
	}
	return false, errors.New("no service manager")
}

// checkCommandFile allows only a regular file owned by root, not writable
// by group or others, in a directory with the same properties.
func checkCommandFile(dir, path string) error {
	for _, p := range []string{dir, path} {
		st, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if p == path && !st.Mode().IsRegular() {
			return errors.New("not a regular file")
		}
		if st.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s is writable by group or others", p)
		}
		if sys, ok := st.Sys().(*syscall.Stat_t); ok && sys.Uid != 0 && os.Geteuid() == 0 {
			return fmt.Errorf("%s is not owned by root", p)
		}
	}
	return nil
}

func commandFor(ctx context.Context, path string) *exec.Cmd { return exec.CommandContext(ctx, path) }

// freeBytes is the space available to unprivileged users on /, -1 when unknown.
func freeBytes() int64 {
	var st unix.Statfs_t
	if unix.Statfs("/", &st) != nil {
		return -1
	}
	return int64(st.Bavail) * int64(st.Bsize)
}
