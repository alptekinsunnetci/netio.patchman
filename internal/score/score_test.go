package score

import (
	"testing"

	"netio.patchman/internal/vuln"
)

func f64(v float64) *float64 { return &v }

func TestComputeTakesTheHighestCriterionOnce(t *testing.T) {
	w := DefaultWeights()
	in := Input{Findings: []Finding{
		// A critical KEV CVE overdue with a high EPSS: KEV (25) wins, counted once.
		{CVE: "CVE-1", Severity: vuln.SeverityCritical, KEV: true, EPSS: f64(0.9), Overdue: true},
		// The same CVE through a second package: still once.
		{CVE: "CVE-1", Severity: vuln.SeverityCritical},
		// Medium with EPSS 0.5: 20*0.5 = 10 beats 2.
		{CVE: "CVE-2", Severity: vuln.SeverityMedium, EPSS: f64(0.5)},
		// Low overdue: overdue (12) beats 0.5.
		{CVE: "CVE-3", Severity: vuln.SeverityLow, Overdue: true},
		{CVE: "CVE-4", Severity: vuln.SeverityHigh},
	}}
	r := Compute(w, in)
	v := r.Categories[0]
	if v.Key != "vulns" || v.Count != 4 || v.Points != 25+10+12+5 {
		t.Fatalf("vulns: %+v", v)
	}
	want := map[string]string{"CVE-1": ReasonKEV, "CVE-2": ReasonEPSS, "CVE-3": ReasonOverdue, "CVE-4": ReasonSeverity}
	for _, it := range v.Items {
		if want[it.Label] != it.Reason {
			t.Errorf("%s: %s", it.Label, it.Reason)
		}
	}
	if v.Items[0].Label != "CVE-1" {
		t.Errorf("largest first: %+v", v.Items)
	}
	if r.Score != 100-52 {
		t.Errorf("score %d", r.Score)
	}
}

func TestComputeCapsAndOtherCategories(t *testing.T) {
	w := DefaultWeights()
	var fs []Finding
	for i := 0; i < 20; i++ {
		fs = append(fs, Finding{CVE: "CVE-" + string(rune('a'+i)), Severity: vuln.SeverityCritical})
	}
	r := Compute(w, Input{Findings: fs, OSStatus: "eol", OSName: "Ubuntu 20.04",
		SoftwareEOL: []string{"PHP 7.4", "Nginx 1.18", "MySQL 5.7", "Redis 5.0"}, SecurityUpdates: 30})
	by := map[string]Category{}
	for _, c := range r.Categories {
		by[c.Key] = c
	}
	if c := by["vulns"]; c.Points != 70 || !c.Capped {
		t.Errorf("vuln cap: %+v", c)
	}
	if c := by["os_eol"]; c.Points != 25 {
		t.Errorf("os: %+v", c)
	}
	if c := by["software_eol"]; c.Points != 15 || !c.Capped || c.Count != 4 {
		t.Errorf("software: %+v", c)
	}
	if c := by["security_updates"]; c.Points != 10 || c.Count != 30 {
		t.Errorf("updates: %+v", c)
	}
	if r.Score != 0 {
		t.Errorf("score %d (floor at 0)", r.Score)
	}
	clean := Compute(w, Input{OSStatus: "supported"})
	if clean.Score != 100 || clean.Deducted != 0 {
		t.Errorf("clean host: %+v", clean)
	}
	soon := Compute(w, Input{OSStatus: "soon", OSName: "Debian 11"})
	if soon.Score != 95 {
		t.Errorf("OS ending soon: %d", soon.Score)
	}
}

func TestCustomWeightsAndBand(t *testing.T) {
	w := DefaultWeights()
	w.KEV, w.Critical = 0, 40
	r := Compute(w, Input{Findings: []Finding{{CVE: "CVE-1", Severity: vuln.SeverityCritical, KEV: true}}})
	if r.Score != 60 || r.Categories[0].Items[0].Reason != ReasonSeverity {
		t.Errorf("custom weights: %+v", r)
	}
	for s, want := range map[int]string{100: "good", 80: "good", 79: "fair", 60: "fair", 59: "poor", 40: "poor", 39: "critical", 0: "critical", -1: "unknown"} {
		if Band(s) != want {
			t.Errorf("band %d: %s", s, Band(s))
		}
	}
}
