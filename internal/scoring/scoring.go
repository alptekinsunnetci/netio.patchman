// Package scoring computes the security scores of all hosts in the
// background (see package score for the algorithm) and stores them with
// their explanation and daily history.
package scoring

import (
	"context"
	"encoding/json"
	"time"

	"netio.patchman/internal/eol"
	"netio.patchman/internal/score"
	"netio.patchman/internal/settings"
	"netio.patchman/internal/store"
)

// maxDetailItems bounds the items stored per category in the explanation
// (the category keeps the full count and points).
const maxDetailItems = 25

// Engine computes and stores scores.
type Engine struct {
	Store *store.Store
	// EOL returns the current support calendars.
	EOL func() eol.Data
	// OnBelow is called with hosts that dropped below the alert threshold.
	OnBelow func(ctx context.Context, hosts []store.HostRef, threshold int)
}

// Inputs builds the score inputs of every host.
func Inputs(cfg settings.Values, data eol.Data, now time.Time, findings map[int64][]store.ScoreFinding, updates map[int64]int, hosts []store.EOLHost) map[int64]score.Input {
	out := make(map[int64]score.Input, len(hosts))
	for _, h := range hosts {
		in := score.Input{SecurityUpdates: updates[h.ID]}
		for _, f := range findings[h.ID] {
			in.Findings = append(in.Findings, score.Finding{CVE: f.CVE, Severity: f.Severity, KEV: f.KEV, EPSS: f.EPSS, Overdue: f.Overdue})
		}
		out[h.ID] = in
	}
	for _, it := range eol.Assess(data, now, cfg.EOLWarn(), eol.Inputs(hosts)) {
		in := out[it.HostID]
		switch {
		case it.Kind == eol.KindOS:
			in.OSStatus, in.OSName = it.Status, it.Name+" "+it.Cycle
		case it.Status == eol.StatusEOL && !it.DistroSupported:
			in.SoftwareEOL = append(in.SoftwareEOL, it.Name+" "+it.Cycle)
		}
		out[it.HostID] = in
	}
	return out
}

// Run computes every host's score now.
func (e *Engine) Run(ctx context.Context, now time.Time) error {
	cfg, err := settings.Load(ctx, e.Store)
	if err != nil {
		return err
	}
	findings, err := e.Store.ScoreFindings(ctx, cfg.SLA())
	if err != nil {
		return err
	}
	updates, err := e.Store.UncoveredSecurityUpdates(ctx)
	if err != nil {
		return err
	}
	hosts, err := e.Store.EOLHosts(ctx, 0)
	if err != nil {
		return err
	}
	var data eol.Data
	if e.EOL != nil {
		data = e.EOL()
	} else {
		data = eol.Embedded()
	}
	scores := map[int64]store.HostScore{}
	for id, in := range Inputs(cfg, data, now, findings, updates, hosts) {
		r := score.Compute(cfg.ScoreWeights, in)
		for i := range r.Categories {
			if len(r.Categories[i].Items) > maxDetailItems {
				r.Categories[i].Items = r.Categories[i].Items[:maxDetailItems]
			}
		}
		b, _ := json.Marshal(r)
		scores[id] = store.HostScore{Score: r.Score, Detail: string(b)}
	}
	if err := e.Store.SaveScores(ctx, now, scores); err != nil {
		return err
	}
	below, err := e.Store.ScoreAlerts(ctx, cfg.ScoreAlertBelow)
	if err != nil {
		return err
	}
	if len(below) > 0 && e.OnBelow != nil {
		e.OnBelow(ctx, below, cfg.ScoreAlertBelow)
	}
	return nil
}

// Detail decodes a stored explanation; ok is false before the first run.
func Detail(raw string) (score.Result, bool) {
	var r score.Result
	if raw == "" || json.Unmarshal([]byte(raw), &r) != nil {
		return r, false
	}
	return r, true
}
