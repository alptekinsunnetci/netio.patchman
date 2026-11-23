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
	// Scores is the table of a score trend (host or group), nil otherwise.
	Scores []store.DayScore
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

// trendMetric is one chart: a value per day (ok false: no data that day)
// and an optional fixed top (scores use 100).
type trendMetric struct {
	key      string
	val      func(store.Snapshot) (int, bool)
	fixedMax int
}

func count(f func(store.Snapshot) int) func(store.Snapshot) (int, bool) {
	return func(sn store.Snapshot) (int, bool) { return f(sn), true }
}

// buildTrends lays out the snapshots between from and to (UTC days).
func (s *Server) buildTrends(snaps []store.Snapshot, from, to time.Time) trendSet {
	metrics := []trendMetric{
		{key: "security_score", val: func(sn store.Snapshot) (int, bool) { return sn.SecurityScore, sn.SecurityScore >= 0 }, fixedMax: 100},
		{key: "critical_high", val: count(func(sn store.Snapshot) int { return sn.Sev.Critical + sn.Sev.High })},
		{key: "kev", val: count(func(sn store.Snapshot) int { return sn.KEV })},
		{key: "open_findings", val: count(func(sn store.Snapshot) int { return sn.OpenFindings })},
		{key: "security_updates", val: count(func(sn store.Snapshot) int { return sn.SecurityUpdates })},
	}
	return s.layoutTrends(snaps, from, to, metrics)
}

// scoreTrend lays out daily scores (host or group) as one chart.
func (s *Server) scoreTrend(scores []store.DayScore, from, to time.Time) trendSet {
	snaps := make([]store.Snapshot, len(scores))
	for i, d := range scores {
		snaps[i] = store.Snapshot{Day: d.Day, SecurityScore: d.Score}
	}
	set := s.layoutTrends(snaps, from, to, []trendMetric{
		{key: "security_score", val: func(sn store.Snapshot) (int, bool) { return sn.SecurityScore, sn.SecurityScore >= 0 }, fixedMax: 100},
	})
	set.Rows, set.Scores = nil, scores // the snapshot table does not apply
	if set.Scores == nil {
		set.Scores = []store.DayScore{}
	}
	return set
}

func (s *Server) layoutTrends(snaps []store.Snapshot, from, to time.Time, metrics []trendMetric) trendSet {
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
	set := trendSet{Rows: snaps, From: labels[0], To: labels[days-1], Available: len(snaps) >= 2}
	for _, m := range metrics {
		c := trendChart{Key: m.key, Labels: strings.Join(labels, "|")}
		vals := make([]string, days)
		peak := 0
		for i := 0; i < days; i++ {
			if sn, ok := byDay[i]; ok {
				if v, ok := m.val(sn); ok {
					peak = max(peak, v)
				}
			}
		}
		c.Max = niceCeil(peak)
		if m.fixedMax > 0 {
			c.Max = m.fixedMax
		}
		// Days without a value (server down, nothing computed) break the line
		// instead of being bridged; each run of days is its own segment.
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
			v, ok := m.val(sn)
			if !ok {
				continue
			}
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
