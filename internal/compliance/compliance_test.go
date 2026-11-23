package compliance

import (
	"os"
	"regexp"
	"testing"

	"netio.patchman/internal/i18n"
	"netio.patchman/internal/store"
)

// TestProfilesValid checks the built-in profiles: unique control ids, known
// checks and platforms, a relevance on every reference and at least one
// primary check (or manual evidence) per control.
func TestProfilesValid(t *testing.T) {
	if len(Profiles()) != len(ProfileOrder) {
		t.Fatalf("profiles: %d, want %d", len(Profiles()), len(ProfileOrder))
	}
	used := map[string]bool{}
	for _, p := range AllProfileVersions() {
		seen := map[string]bool{}
		for _, c := range p.Controls {
			if seen[c.ID] {
				t.Errorf("%s: duplicate control %s", p.Key(), c.ID)
			}
			seen[c.ID] = true
			if c.Manual != "" && c.Manual != ManualPolicy && c.Manual != ManualProcess {
				t.Errorf("%s %s: manual %q", p.Key(), c.ID, c.Manual)
			}
			primary := false
			for _, r := range c.Checks {
				used[r.Check] = true
				if !knownCheck(r.Check) {
					t.Errorf("%s %s: unknown check %q", p.Key(), c.ID, r.Check)
				}
				if r.Relevance != RelevancePrimary && r.Relevance != RelevanceSupporting {
					t.Errorf("%s %s: relevance %q", p.Key(), c.ID, r.Relevance)
				}
				primary = primary || r.Relevance == RelevancePrimary
				if !platformsValid(r.Platforms) {
					t.Errorf("%s %s: platforms %v", p.Key(), c.ID, r.Platforms)
				}
			}
			if !primary && c.Manual == "" {
				t.Errorf("%s %s: neither a primary check nor manual evidence", p.Key(), c.ID)
			}
		}
	}
	for _, c := range Checks {
		if !used[c] {
			t.Errorf("check %s is used by no control", c)
		}
	}
}

// TestCatalogKeys checks that every key built at runtime exists in every
// catalog (TestCatalogsMatch then keeps the languages in step).
func TestCatalogKeys(t *testing.T) {
	b := i18n.MustLoad()
	var keys []string
	for _, p := range AllProfileVersions() {
		keys = append(keys, p.NameKey(), p.NameKey()+".desc")
		for _, c := range p.Controls {
			keys = append(keys, c.TitleKey(p.ID), c.DescKey(p.ID))
		}
	}
	for _, c := range Checks {
		keys = append(keys, "compliance.check."+c, "compliance.check."+c+".fix")
	}
	for _, o := range Outcomes {
		keys = append(keys, "compliance.outcome."+o)
	}
	for _, s := range []string{store.ReviewNone, store.ReviewAccepted, store.ReviewGap} {
		keys = append(keys, "compliance.review."+s)
	}
	for _, p := range store.Platforms {
		keys = append(keys, "compliance.platform."+p)
	}
	for _, k := range store.EvidenceKinds {
		keys = append(keys, "compliance.kind."+k)
	}
	for _, s := range []string{store.SourceAgent, store.SourceScanner, store.SourceSystem, store.SourceUser} {
		keys = append(keys, "compliance.source."+s)
	}
	for _, s := range []string{RelevancePrimary, RelevanceSupporting, RelevanceManual} {
		keys = append(keys, "compliance.relevance."+s)
	}
	for _, s := range []string{"user", "schedule", "rollout", "system"} {
		keys = append(keys, "compliance.origin."+s)
	}
	for _, s := range []string{store.ReportDraft, store.ReportFinal} {
		keys = append(keys, "compliance.status."+s)
	}
	for _, s := range []string{"30d", "90d", "quarter", "12m", "year", "custom"} {
		keys = append(keys, "compliance.preset."+s)
	}
	for _, s := range []string{"content", "link", "head"} {
		keys = append(keys, "compliance.chain.reason."+s)
	}
	for _, s := range []string{ManualPolicy, ManualProcess} {
		keys = append(keys, "compliance.manual."+s, "compliance.manual."+s+".fix")
	}
	// Metric names and gap texts are literals in checks.go.
	src, err := os.ReadFile("checks.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range regexp.MustCompile(`(?:count|percent|daysMetric)\("([a-z0-9_]+)"`).FindAllStringSubmatch(string(src), -1) {
		keys = append(keys, "compliance.metric."+m[1])
	}
	for _, m := range regexp.MustCompile(`tx\("(compliance\.[a-z0-9_.]+)"`).FindAllStringSubmatch(string(src), -1) {
		keys = append(keys, m[1])
	}
	for _, loc := range b.Locales() {
		have := map[string]bool{}
		for _, k := range b.Keys(loc) {
			have[k] = true
		}
		for _, k := range keys {
			if !have[k] {
				t.Errorf("%s: missing %q", loc, k)
			}
		}
	}
}

// TestOutcomeOrder: a deviation outweighs missing evidence, which outweighs
// a partial result.
func TestOutcomeOrder(t *testing.T) {
	order := []string{OutcomeSufficient, OutcomePartial, OutcomeMissing, OutcomeDeviation}
	for i := 1; i < len(order); i++ {
		if severity(order[i]) <= severity(order[i-1]) {
			t.Errorf("%s should rank above %s", order[i], order[i-1])
		}
	}
}
