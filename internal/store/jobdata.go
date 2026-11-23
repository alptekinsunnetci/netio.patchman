package store

import (
	"encoding/json"

	"netio.patchman/internal/protocol"
)

// JobData is the structured part of a job result, stored as JSON in
// jobs.result. Each field is filled by agents that declared the matching
// capability; old agents leave it empty.
type JobData struct {
	Health   *protocol.HealthReport   `json:"health,omitempty"`
	Preview  *protocol.Preview        `json:"preview,omitempty"`
	Changes  []protocol.PackageChange `json:"changes,omitempty"`
	Rollback []protocol.RollbackItem  `json:"rollback,omitempty"`
}

// empty reports whether nothing structured was reported.
func (d JobData) empty() bool {
	return d.Health == nil && d.Preview == nil && len(d.Changes) == 0 && len(d.Rollback) == 0
}

func (d JobData) encode() string {
	if d.empty() {
		return ""
	}
	b, err := json.Marshal(d)
	if err != nil {
		return ""
	}
	return string(b)
}

// jobDataFrom takes the structured fields of an agent's result, validated
// and bounded so a misbehaving agent cannot store arbitrary amounts of data.
func jobDataFrom(r protocol.JobResult) JobData {
	var d JobData
	if h := r.Health; h != nil {
		d.Health = &protocol.HealthReport{Aborted: h.Aborted, Before: cleanHealth(h.Before), After: cleanHealth(h.After), Checks: cleanHealth(h.Checks)}
	}
	if p := r.Preview; p != nil {
		c := *p
		c.PackageManager = truncate(c.PackageManager, 20)
		c.Upgrades, c.Installs, c.Removals, c.Downgrades = cleanChanges(c.Upgrades), cleanChanges(c.Installs), cleanChanges(c.Removals), cleanChanges(c.Downgrades)
		if len(c.Conflicts) > 50 {
			c.Conflicts = c.Conflicts[:50]
		}
		for i := range c.Conflicts {
			c.Conflicts[i] = truncate(c.Conflicts[i], 500)
		}
		c.Plan = truncate(c.Plan, 64<<10)
		d.Preview = &c
	}
	d.Changes = cleanChanges(r.Changes)
	for _, it := range r.Rollback {
		if len(d.Rollback) >= protocol.MaxRollbackTargets {
			break
		}
		switch it.Status {
		case protocol.RollbackAvailable, protocol.RollbackUnavailable, protocol.RollbackCurrent, protocol.RollbackDone, protocol.RollbackFailed:
		default:
			continue
		}
		d.Rollback = append(d.Rollback, protocol.RollbackItem{Name: truncate(it.Name, 200), Arch: truncate(it.Arch, 40), From: truncate(it.From, 200),
			To: truncate(it.To, 200), Status: it.Status, Message: truncate(it.Message, 500)})
	}
	return d
}

func cleanChanges(in []protocol.PackageChange) []protocol.PackageChange {
	if len(in) > protocol.MaxPreviewPackages {
		in = in[:protocol.MaxPreviewPackages]
	}
	out := make([]protocol.PackageChange, 0, len(in))
	for _, c := range in {
		out = append(out, protocol.PackageChange{Name: truncate(c.Name, 200), Arch: truncate(c.Arch, 40), From: truncate(c.From, 200), To: truncate(c.To, 200)})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func cleanHealth(in []protocol.HealthResult) []protocol.HealthResult {
	if len(in) > protocol.MaxHealthChecks {
		in = in[:protocol.MaxHealthChecks]
	}
	out := make([]protocol.HealthResult, 0, len(in))
	for _, r := range in {
		r.Name, r.Type, r.Value, r.Message = truncate(r.Name, 200), truncate(r.Type, 20), truncate(r.Value, 500), truncate(r.Message, 500)
		out = append(out, r)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// ParamNoHealth is a server-side job parameter: run the update without
// health checks.
const ParamNoHealth = "no_health"

// Server-side parameters of rollback jobs: the job whose changes are
// undone, the check the apply was approved from, and whether rolled-back
// packages are added to the host's exclusion list.
const (
	ParamRollbackOf    = "rollback_of"
	ParamRollbackCheck = "rollback_check"
	ParamRollbackHold  = "hold"
)

// Health outcomes of a job.
const (
	HealthNone      = ""          // no checks ran
	HealthPassed    = "passed"    // every check passed
	HealthRegressed = "regressed" // a check passed before the update and failed after it
	HealthFailed    = "failed"    // checks failed (also before the update, or a manual run)
	HealthAborted   = "aborted"   // checks failed before the update; it was not run
)

// HealthOutcome summarizes the health checks of a job and names the
// checks behind a bad outcome.
func (d JobData) HealthOutcome() (string, []string) {
	h := d.Health
	if h == nil {
		return HealthNone, nil
	}
	failed := func(list []protocol.HealthResult) []string {
		var out []string
		for _, r := range list {
			if !r.OK {
				out = append(out, r.Name)
			}
		}
		return out
	}
	switch {
	case h.Aborted:
		return HealthAborted, failed(h.Before)
	case len(h.Checks) > 0:
		if f := failed(h.Checks); len(f) > 0 {
			return HealthFailed, f
		}
		return HealthPassed, nil
	case len(h.After) == 0:
		return HealthNone, nil
	}
	okBefore := map[int64]bool{}
	for _, r := range h.Before {
		okBefore[r.ID] = r.OK
	}
	var regressed, other []string
	for _, r := range h.After {
		if r.OK {
			continue
		}
		if okBefore[r.ID] {
			regressed = append(regressed, r.Name)
		} else {
			other = append(other, r.Name)
		}
	}
	switch {
	case len(regressed) > 0:
		return HealthRegressed, regressed
	case len(other) > 0:
		return HealthFailed, other
	}
	return HealthPassed, nil
}
