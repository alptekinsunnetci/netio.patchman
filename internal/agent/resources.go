package agent

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"netio.patchman/internal/protocol"
	"netio.patchman/internal/timeutil"
)

// realFS are the file system types whose usage is reported; pseudo file
// systems (proc, tmpfs, overlay, squashfs snaps) are left out, and so are
// network file systems: statfs on a hung NFS or CIFS share never returns.
var realFS = map[string]bool{
	"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "zfs": true, "f2fs": true, "jfs": true, "reiserfs": true,
}

// parseMounts returns the mount points of real file systems from
// /proc/self/mounts, "/" first. A device mounted more than once (bind
// mounts, container volumes) is reported once, at its first mount point.
func parseMounts(r io.Reader) []string {
	var out []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 3 || !realFS[f[2]] {
			continue
		}
		// Octal escapes for spaces and tabs ("\040").
		p := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\134`, `\`).Replace(f[1])
		dev := f[0]
		if strings.HasPrefix(dev, "/dev/") {
			if seen["dev "+dev] && p != "/" {
				continue
			}
			seen["dev "+dev] = true
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		if p == "/" {
			out = append([]string{p}, out...)
		} else {
			out = append(out, p)
		}
	}
	if len(out) > protocol.MaxDisks {
		out = out[:protocol.MaxDisks]
	}
	return out
}

// parseLoadavg reads the three load averages of /proc/loadavg.
func parseLoadavg(s string) []float64 {
	f := strings.Fields(s)
	if len(f) < 3 {
		return nil
	}
	out := make([]float64, 3)
	for i := range out {
		v, err := strconv.ParseFloat(f[i], 64)
		if err != nil {
			return nil
		}
		out[i] = v
	}
	return out
}

// parseMeminfoBytes returns the values of /proc/meminfo in bytes.
func parseMeminfoBytes(r io.Reader) map[string]int64 {
	out := map[string]int64{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		name, rest, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) == 0 {
			continue
		}
		v, err := strconv.ParseInt(f[0], 10, 64)
		if err != nil {
			continue
		}
		if len(f) > 1 && f[1] == "kB" {
			v *= 1024
		}
		out[name] = v
	}
	return out
}

// parseProcStat returns the busy and total CPU time of the "cpu" line of
// /proc/stat (iowait counts as idle; guest time is already in user).
func parseProcStat(s string) (busy, total uint64, ok bool) {
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || f[0] != "cpu" {
			continue
		}
		var v [8]uint64
		for i := 0; i < 8 && i+1 < len(f); i++ {
			n, err := strconv.ParseUint(f[i+1], 10, 64)
			if err != nil {
				return 0, 0, false
			}
			v[i] = n
		}
		for _, n := range v {
			total += n
		}
		idle := v[3] + v[4]
		return total - idle, total, total > 0
	}
	return 0, 0, false
}

// cpuSample is a reading of the CPU time counters.
type cpuSample struct {
	busy, total uint64
	ok          bool
}

// cpuPercent is the CPU use since the previous round; the first round
// measures one second. -1 when the counters cannot be read.
func (r *Runner) cpuPercent(ctx context.Context) float64 {
	busy, total, ok := cpuTimes()
	if !ok {
		return -1
	}
	prev := r.cpuPrev
	if !prev.ok || total <= prev.total {
		if !sleep(ctx, time.Second) {
			return -1
		}
		prev = cpuSample{busy, total, true}
		if busy, total, ok = cpuTimes(); !ok {
			return -1
		}
	}
	r.cpuPrev = cpuSample{busy, total, true}
	dt, db := total-prev.total, busy-prev.busy
	if dt == 0 || busy < prev.busy {
		return -1
	}
	return min(float64(db)/float64(dt)*100, 100)
}

// monitor runs one monitoring round in the background: the scheduled
// checks and a resource snapshot, posted to the server. Rounds never
// overlap; the next one is due IntervalSeconds after this one started.
func (r *Runner) monitor(ctx context.Context, h *protocol.HealthSchedule) {
	if h == nil || h.IntervalSeconds < 60 || time.Now().Before(r.healthNext) || !r.healthBusy.CompareAndSwap(false, true) {
		return
	}
	r.healthNext = time.Now().Add(time.Duration(h.IntervalSeconds) * time.Second)
	checks := h.Checks
	if len(checks) > protocol.MaxHealthChecks {
		checks = checks[:protocol.MaxHealthChecks]
	}
	go func() {
		defer r.healthBusy.Store(false)
		ctx, cancel := context.WithTimeout(ctx, time.Duration(h.IntervalSeconds)*time.Second)
		defer cancel()
		res := ReadResources()
		if v := r.cpuPercent(ctx); v >= 0 {
			res.CPUPercent = &v
		}
		st := protocol.HealthStatus{Results: r.jobs.Health.Run(ctx, checks), Resources: &res, CheckedAt: timeutil.Now()}
		if err := r.client.Health(ctx, st); err != nil && ctx.Err() == nil {
			r.logger.Warn(r.l.T("log.agent.health_failed"), slog.String("error", err.Error()))
		}
	}()
}
