//go:build !windows

package agent

import (
	"os"
	"runtime"

	"golang.org/x/sys/unix"

	"netio.patchman/internal/protocol"
)

// ReadResources reads load (/proc/loadavg), memory and swap (/proc/meminfo)
// and the usage of every real file system (/proc/self/mounts, statfs).
func ReadResources() protocol.Resources {
	r := protocol.Resources{CPUs: runtime.NumCPU()}
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		r.Load = parseLoadavg(string(b))
	}
	if f, err := os.Open("/proc/meminfo"); err == nil {
		m := parseMeminfoBytes(f)
		f.Close()
		r.MemoryTotal, r.SwapTotal, r.SwapFree = m["MemTotal"], m["SwapTotal"], m["SwapFree"]
		if v, ok := m["MemAvailable"]; ok {
			r.MemoryAvailable = v
		} else {
			r.MemoryAvailable = m["MemFree"] + m["Buffers"] + m["Cached"]
		}
	}
	paths := []string{"/"}
	if f, err := os.Open("/proc/self/mounts"); err == nil {
		if p := parseMounts(f); len(p) > 0 {
			paths = p
		}
		f.Close()
	}
	for _, p := range paths {
		var st unix.Statfs_t
		if unix.Statfs(p, &st) != nil || st.Blocks == 0 {
			continue
		}
		bs := int64(st.Bsize)
		r.Disks = append(r.Disks, protocol.DiskUsage{Path: p, Total: int64(st.Blocks) * bs, Used: int64(st.Blocks-st.Bfree) * bs, Available: int64(st.Bavail) * bs})
	}
	return r
}

// cpuTimes reads the busy and total CPU time from /proc/stat.
func cpuTimes() (busy, total uint64, ok bool) {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0, false
	}
	return parseProcStat(string(b))
}
