// Package score computes the security score of a server (0-100, higher is
// better) from its open vulnerabilities, end-of-life software and pending
// security updates. The algorithm is additive and transparent: every point
// deducted is attributed to one item, and every weight can be changed.
//
// A CVE is penalized once per host: with the highest of its applicable
// criteria (severity, CISA KEV, EPSS probability, SLA overdue), never with
// their sum. Pending security updates only count when no open finding
// already covers their package, so the same flaw is not deducted twice.
package score

import (
	"math"
	"sort"
	"strconv"

	"netio.patchman/internal/vuln"
)

// Weights are the points deducted per item and the caps per category.
type Weights struct {
	Critical, High, Medium, Low, Unknown float64 // per CVE by severity
	KEV                                  float64 // per CVE listed in CISA KEV
	EPSS                                 float64 // per CVE, multiplied by its EPSS probability (0..1)
	Overdue                              float64 // per CVE past its SLA due date
	VulnCap                              float64 // all CVEs together
	OSEOL, OSSoon                        float64 // operating system out of support / ending soon
	SoftwareEOL, SoftwareEOLCap          float64 // per product release out of support (not distribution-maintained)
	SecurityUpdate, SecurityUpdateCap    float64 // per pending security update without an open finding
}

// DefaultWeights are the built-in weights.
func DefaultWeights() Weights {
	return Weights{
		Critical: 10, High: 5, Medium: 2, Low: 0.5, Unknown: 1,
		KEV: 25, EPSS: 20, Overdue: 12, VulnCap: 70,
		OSEOL: 25, OSSoon: 5,
		SoftwareEOL: 5, SoftwareEOLCap: 15,
		SecurityUpdate: 1, SecurityUpdateCap: 10,
	}
}

// Finding is one open CVE on a host.
type Finding struct {
	CVE      string
	Severity vuln.Severity
	KEV      bool
	EPSS     *float64
	Overdue  bool
}

// Input is everything the score of one host depends on.
type Input struct {
	Findings []Finding
	// OSStatus is the operating system's support status (eol.Status*), "" if unknown.
	OSStatus string
	OSName   string // "Ubuntu 20.04", shown in the explanation
	// SoftwareEOL lists product releases out of support that the
	// distribution does not maintain ("PHP 7.4").
	SoftwareEOL []string
	// SecurityUpdates counts pending security updates whose package has no
	// open finding.
	SecurityUpdates int
}

// Reasons a CVE was penalized for (the criterion with the most points).
const (
	ReasonSeverity = "severity"
	ReasonKEV      = "kev"
	ReasonEPSS     = "epss"
	ReasonOverdue  = "overdue"
)

// Item is one deduction.
type Item struct {
	Label  string  `json:"label"`            // CVE id, product release or OS name (verbatim)
	Reason string  `json:"reason,omitempty"` // Reason* for CVEs
	Points float64 `json:"points"`           // before the category cap
	// Severity of a CVE item.
	Severity vuln.Severity `json:"severity,omitempty"`
}

// Category groups the deductions of one kind.
type Category struct {
	Key    string  `json:"key"` // "vulns", "os_eol", "software_eol", "security_updates"
	Points float64 `json:"points"`
	Cap    float64 `json:"cap"`    // 0: uncapped
	Capped bool    `json:"capped"` // the cap limited this category
	Items  []Item  `json:"items"`  // largest first
	Count  int     `json:"count"`
}

// Result is a host's score with its explanation.
type Result struct {
	Score      int        `json:"score"`
	Deducted   float64    `json:"deducted"`
	Categories []Category `json:"categories"`
}

func (w Weights) severity(s vuln.Severity) float64 {
	switch s {
	case vuln.SeverityCritical:
		return w.Critical
	case vuln.SeverityHigh:
		return w.High
	case vuln.SeverityMedium:
		return w.Medium
	case vuln.SeverityLow:
		return w.Low
	case vuln.SeverityNone:
		return 0
	}
	return w.Unknown
}

// Compute scores one host.
func Compute(w Weights, in Input) Result {
	var r Result
	// Vulnerabilities: one deduction per CVE, the highest criterion.
	best := map[string]Item{}
	var order []string
	for _, f := range in.Findings {
		it := Item{Label: f.CVE, Reason: ReasonSeverity, Points: w.severity(f.Severity), Severity: f.Severity}
		if f.KEV && w.KEV > it.Points {
			it.Reason, it.Points = ReasonKEV, w.KEV
		}
		if f.EPSS != nil {
			if p := w.EPSS * clamp(*f.EPSS, 0, 1); p > it.Points {
				it.Reason, it.Points = ReasonEPSS, p
			}
		}
		if f.Overdue && w.Overdue > it.Points {
			it.Reason, it.Points = ReasonOverdue, w.Overdue
		}
		prev, seen := best[f.CVE]
		if !seen {
			order = append(order, f.CVE)
		}
		if !seen || it.Points > prev.Points {
			best[f.CVE] = it
		}
	}
	vulns := Category{Key: "vulns", Cap: w.VulnCap}
	for _, id := range order {
		vulns.Items = append(vulns.Items, best[id])
	}
	r.add(vulns)

	osCat := Category{Key: "os_eol"}
	switch in.OSStatus {
	case "eol":
		osCat.Items = []Item{{Label: in.OSName, Reason: "eol", Points: w.OSEOL}}
	case "soon":
		osCat.Items = []Item{{Label: in.OSName, Reason: "soon", Points: w.OSSoon}}
	}
	r.add(osCat)

	sw := Category{Key: "software_eol", Cap: w.SoftwareEOLCap}
	for _, name := range in.SoftwareEOL {
		sw.Items = append(sw.Items, Item{Label: name, Reason: "eol", Points: w.SoftwareEOL})
	}
	r.add(sw)

	upd := Category{Key: "security_updates", Cap: w.SecurityUpdateCap}
	if in.SecurityUpdates > 0 {
		upd.Items = []Item{{Label: strconv.Itoa(in.SecurityUpdates), Points: w.SecurityUpdate * float64(in.SecurityUpdates)}}
		upd.Count = in.SecurityUpdates
	}
	r.add(upd)

	r.Score = int(math.Round(clamp(100-r.Deducted, 0, 100)))
	return r
}

func (r *Result) add(c Category) {
	sort.SliceStable(c.Items, func(i, j int) bool { return c.Items[i].Points > c.Items[j].Points })
	for _, it := range c.Items {
		c.Points += it.Points
	}
	if c.Count == 0 {
		c.Count = len(c.Items)
	}
	if c.Cap > 0 && c.Points > c.Cap {
		c.Points, c.Capped = c.Cap, true
	}
	c.Points = math.Round(c.Points*10) / 10
	r.Deducted += c.Points
	r.Categories = append(r.Categories, c)
}

func clamp(v, lo, hi float64) float64 { return math.Max(lo, math.Min(hi, v)) }

// Band names the score range: "good" (80+), "fair" (60-79), "poor" (40-59), "critical" (<40).
func Band(score int) string {
	switch {
	case score < 0:
		return "unknown"
	case score >= 80:
		return "good"
	case score >= 60:
		return "fair"
	case score >= 40:
		return "poor"
	}
	return "critical"
}
