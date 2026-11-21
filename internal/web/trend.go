package web

import (
	"math"
	"strconv"
	"strings"
	"time"

	"netio.patchman/internal/store"
)

// Trend charts are small multiples: one metric per chart in the accent
// color, so no categorical palette is needed. The server computes the SVG
// path in a 100x40 box (preserveAspectRatio="none", non-scaling 2px stroke);
// app.js adds the hover crosshair and tooltip from the data attributes.

const (
	trendW = 100.0
	trendH = 40.0
)

// trendChart is one metric over the snapshot days.
type trendChart struct {
	Key    string // catalog key suffix (dashboard.trend.<Key>)
	Line   string // SVG path
	Area   string
	Max    int // top tick
	Last   int
	First  int
	Values string // comma-separated, one per day ("" for days without data)
	Labels string // "|"-separated dates
}

// trendSet is the charts for a period plus the table rows.
type trendSet struct {
	Charts    []trendChart
	Rows      []store.Snapshot
	From, To  string
	Available bool
}

// niceCeil rounds up to 1, 2 or 5 times a power of ten (minimum 1).
func niceCeil(v int) int {
	if v <= 1 {
		return 1
	}
	p := math.Pow(10, math.Floor(math.Log10(float64(v))))
	for _, m := range []float64{1, 2, 5, 10} {
		if float64(v) <= m*p {
			return int(m * p)
		}
	}
	return v
}

// calendarDay maps t's calendar date (in its own zone) to that UTC day,
// which is how snapshots are keyed.
func calendarDay(t time.Time) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

func coord(f float64) string { return strconv.FormatFloat(math.Round(f*100)/100, 'f', -1, 64) }

// buildTrends lays out the snapshots between from and to (UTC days).
func (s *Server) buildTrends(snaps []store.Snapshot, from, to time.Time) trendSet {
	from, to = calendarDay(from), calendarDay(to)
	days := int(to.Sub(from).Hours()/24) + 1
	if days < 2 {
		days = 2
	}
	byDay := make(map[int]store.Snapshot, len(snaps))
	for _, sn := range snaps {
		byDay[int(sn.Day.Sub(from).Hours()/24)] = sn
	}
	labels := make([]string, days)
	for i := range labels {
		labels[i] = s.f.Date(from.AddDate(0, 0, i))
	}
	metrics := []struct {
		key string
		val func(store.Snapshot) int
	}{
		{"critical_high", func(sn store.Snapshot) int { return sn.Sev.Critical + sn.Sev.High }},
		{"kev", func(sn store.Snapshot) int { return sn.KEV }},
		{"open_findings", func(sn store.Snapshot) int { return sn.OpenFindings }},
		{"security_updates", func(sn store.Snapshot) int { return sn.SecurityUpdates }},
	}
	set := trendSet{Rows: snaps, From: labels[0], To: labels[days-1], Available: len(snaps) >= 2}
	for _, m := range metrics {
		c := trendChart{Key: m.key, Labels: strings.Join(labels, "|")}
		vals := make([]string, days)
		peak := 0
		for i := 0; i < days; i++ {
			if sn, ok := byDay[i]; ok {
				peak = max(peak, m.val(sn))
			}
		}
		c.Max = niceCeil(peak)
		// Days without a snapshot (server down) break the line instead of
		// being bridged; each run of days is its own segment.
		var line, area strings.Builder
		prev, segX := -2, 0.0
		lastX := 0.0
		seen := false
		closeArea := func() { area.WriteString(" L" + coord(lastX) + " " + coord(trendH) + " Z") }
		for i := 0; i < days; i++ {
			sn, ok := byDay[i]
			if !ok {
				continue
			}
			v := m.val(sn)
			vals[i] = strconv.Itoa(v)
			x := float64(i) / float64(days-1) * trendW
			y := trendH - float64(v)/float64(c.Max)*trendH
			if !seen {
				c.First = v
			}
			if prev != i-1 {
				if seen {
					closeArea()
					line.WriteString(" ")
					area.WriteString(" ")
				}
				segX = x
				line.WriteString("M" + coord(x) + " " + coord(y))
				area.WriteString("M" + coord(segX) + " " + coord(trendH) + " L" + coord(x) + " " + coord(y))
			} else {
				line.WriteString(" L" + coord(x) + " " + coord(y))
				area.WriteString(" L" + coord(x) + " " + coord(y))
			}
			seen, prev = true, i
			c.Last, lastX = v, x
		}
		if seen {
			closeArea()
		}
		c.Line, c.Area, c.Values = line.String(), area.String(), strings.Join(vals, ",")
		set.Charts = append(set.Charts, c)
	}
	return set
}
