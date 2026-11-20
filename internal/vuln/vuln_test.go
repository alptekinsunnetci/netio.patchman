package vuln

import (
	"math"
	"testing"
)

func TestSeverityFromCVSS(t *testing.T) {
	cases := []struct {
		score float64
		want  Severity
	}{
		{10, SeverityCritical}, {9.0, SeverityCritical}, {8.9, SeverityHigh}, {7.0, SeverityHigh},
		{6.9, SeverityMedium}, {4.0, SeverityMedium}, {3.9, SeverityLow}, {0.1, SeverityLow},
		{0, SeverityNone}, {-1, SeverityUnknown}, {10.1, SeverityUnknown}, {math.NaN(), SeverityUnknown},
	}
	for _, c := range cases {
		if got := SeverityFromCVSS(c.score); got != c.want {
			t.Errorf("SeverityFromCVSS(%v) = %s, want %s", c.score, got, c.want)
		}
	}
}

func TestLabelKeys(t *testing.T) {
	if got := SeverityCritical.LabelKey(); got != "severity.critical" {
		t.Errorf("got %s", got)
	}
	if got := Severity("bogus").LabelKey(); got != "severity.unknown" {
		t.Errorf("got %s", got)
	}
	if got := StatusAcceptedRisk.LabelKey(); got != "status.accepted_risk" {
		t.Errorf("got %s", got)
	}
}
