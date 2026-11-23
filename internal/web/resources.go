package web

import (
	"time"

	"netio.patchman/internal/settings"
	"netio.patchman/internal/store"
)

// resourceRange is a period of the resource charts: Span divided into
// slots of Slot, each the average of its samples.
type resourceRange struct {
	Key        string
	Span, Slot time.Duration
}

var resourceRanges = []resourceRange{
	{"24h", 24 * time.Hour, 5 * time.Minute},
	{"7d", 7 * 24 * time.Hour, time.Hour},
	{"30d", 30 * 24 * time.Hour, 4 * time.Hour},
}

func resourceRangeOf(key string) resourceRange {
	for _, r := range resourceRanges {
		if r.Key == key {
			return r
		}
	}
	return resourceRanges[0]
}

// resourceCharts lays out CPU (the load per core for agents that do not
// report CPU use), memory and the fullest disk over rg ending at now.
func (s *Server) resourceCharts(samples []store.MetricSample, rg resourceRange, now time.Time) []trendChart {
	n := int(rg.Span / rg.Slot)
	start := now.Truncate(rg.Slot).Add(-time.Duration(n-1) * rg.Slot)
	labels := make([]string, n)
	for i := range labels {
		labels[i] = s.f.DateTime(start.Add(time.Duration(i) * rg.Slot))
	}
	type acc struct{ sum, cnt [4]int }
	slots := make([]acc, n)
	cpuKnown := false
	for _, m := range samples {
		i := int(m.At.Sub(start) / rg.Slot)
		if m.At.Before(start) || i < 0 || i >= n {
			continue
		}
		for k, v := range [4]int{m.CPU, m.Load, m.Memory, m.Disk} {
			if v >= 0 {
				slots[i].sum[k] += v
				slots[i].cnt[k]++
			}
		}
		cpuKnown = cpuKnown || m.CPU >= 0
	}
	series := func(k int) ([]int, []bool) {
		vals, has := make([]int, n), make([]bool, n)
		for i, a := range slots {
			if a.cnt[k] > 0 {
				// Tenths of a percent to whole percent, rounded.
				vals[i], has[i] = (a.sum[k]/a.cnt[k]+5)/10, true
			}
		}
		return vals, has
	}
	var charts []trendChart
	if cpuKnown {
		v, h := series(0)
		charts = append(charts, buildChart("cpu", labels, v, h, 100))
	} else {
		v, h := series(1)
		charts = append(charts, buildChart("load", labels, v, h, 0))
	}
	v, h := series(2)
	charts = append(charts, buildChart("memory", labels, v, h, 100))
	v, h = series(3)
	charts = append(charts, buildChart("disk", labels, v, h, 100))
	return charts
}

// resourcesFresh is how old a resource snapshot may be to be shown as
// current (three monitoring rounds, at least 15 minutes).
func resourcesFresh(cfg settings.Values) time.Duration {
	return max(3*time.Duration(cfg.HealthMonitor)*time.Minute, 15*time.Minute)
}
