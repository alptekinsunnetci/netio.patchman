package compliance

import (
	"context"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"netio.patchman/internal/settings"
	"netio.patchman/internal/store"
)

// Checks lists the shared checks. A check knows nothing about profiles: it
// measures the period's evidence for a set of hosts and returns an outcome,
// metrics, gaps and the evidence it used.
var Checks = []string{
	"inventory.completeness", "agent.coverage", "patch.applied", "patch.currency", "vuln.sla", "vuln.kev", "risk.accepted",
	"eol.unsupported", "reboot.pending", "change.recorded", "change.approval", "config.drift", "access.mfa", "backup.daily",
	"log.integrity", "monitoring.coverage",
}

// hostChecks are measured on hosts: limited to platforms without such
// hosts they do not apply.
var hostChecks = map[string]bool{
	"inventory.completeness": true, "agent.coverage": true, "patch.applied": true, "patch.currency": true, "vuln.sla": true,
	"vuln.kev": true, "risk.accepted": true, "eol.unsupported": true, "reboot.pending": true, "change.recorded": true,
	"config.drift": true, "monitoring.coverage": true,
}

// knownCheck reports whether id is a registered check.
func knownCheck(id string) bool {
	for _, c := range Checks {
		if c == id {
			return true
		}
	}
	return false
}

func tx(key string, kv ...string) Text {
	t := Text{Key: key}
	if len(kv) > 1 {
		t.Params = map[string]string{}
		for i := 0; i+1 < len(kv); i += 2 {
			t.Params[kv[i]] = kv[i+1]
		}
	}
	return t
}

func itoa(n int) string { return strconv.Itoa(n) }

func pct(part, whole int) float64 {
	if whole == 0 {
		return 0
	}
	return math.Round(float64(part)*1000/float64(whole)) / 10
}

func pctText(v float64) string { return strconv.FormatFloat(v, 'f', 1, 64) }

// env is the data a check works on: the states and evidence of the report's
// hosts, limited to the check's platforms.
type env struct {
	ctx     context.Context
	st      *store.Store
	from    time.Time
	to      time.Time // exclusive
	end     time.Time // min(to, generation time)
	cfg     settings.Values
	sla     store.SLA
	start   time.Time // evidence collection start
	chain   store.ChainStatus
	states  []store.HostState
	last    map[int64]store.HostState
	first   map[int64]store.HostState
	items   map[string][]store.EvidenceItem
	limited bool // limited to platforms
}

func (e *env) hostIDs() []int64 {
	out := make([]int64, 0, len(e.last))
	for id := range e.last {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func ids(items []store.EvidenceItem) []int64 {
	out := make([]int64, len(items))
	for i, it := range items {
		out[i] = it.ID
	}
	return out
}

func (e *env) auditWith(match func(action string) bool) []store.EvidenceItem {
	var out []store.EvidenceItem
	for _, it := range e.items[store.EvidenceAudit] {
		if match(it.Subject) {
			out = append(out, it)
		}
	}
	return out
}

func prefixes(ps ...string) func(string) bool {
	return func(a string) bool {
		for _, p := range ps {
			if strings.HasPrefix(a, p) {
				return true
			}
		}
		return false
	}
}

func result(outcome string, ev []int64, metrics []Metric, gaps ...Text) CheckResult {
	return CheckResult{Outcome: outcome, Metrics: metrics, Gaps: gaps, ids: ev, Evidence: len(ev)}
}

func count(k string, v int) Metric          { return Metric{Key: k, Value: float64(v), Unit: UnitCount} }
func percent(k string, v float64) Metric    { return Metric{Key: k, Value: v, Unit: UnitPercent} }
func daysMetric(k string, v float64) Metric { return Metric{Key: k, Value: v, Unit: UnitDays} }

// run evaluates one check.
func (e *env) run(check string) CheckResult {
	if hostChecks[check] && e.limited && len(e.last) == 0 {
		return result(OutcomeNotApplicable, nil, nil, tx("compliance.gap.no_platform_hosts"))
	}
	inv := ids(e.items[store.EvidenceInventory])
	noStates := tx("compliance.gap.no_host_states")
	switch check {
	case "inventory.completeness":
		if len(e.last) == 0 {
			return result(OutcomeMissing, inv, nil, noStates)
		}
		stale := 0
		for _, h := range e.last {
			if h.LastSeenAt.Before(e.end.Add(-7 * 24 * time.Hour)) {
				stale++
			}
		}
		m := []Metric{count("hosts", len(e.last)), count("stale_hosts", stale)}
		if stale > 0 {
			return result(OutcomePartial, inv, m, tx("compliance.gap.stale_hosts", "n", itoa(stale)))
		}
		return result(OutcomeSufficient, inv, m)

	case "agent.coverage":
		if len(e.states) == 0 {
			return result(OutcomeMissing, inv, nil, noStates)
		}
		seen := 0
		for _, h := range e.states {
			if !h.LastSeenAt.Before(h.Day) {
				seen++
			}
		}
		p := pct(seen, len(e.states))
		m := []Metric{count("host_days", len(e.states)), count("host_days_reachable", seen), percent("coverage", p)}
		if p < float64(e.cfg.ComplianceCoverageMin) {
			return result(OutcomePartial, inv, m, tx("compliance.gap.coverage_low", "pct", pctText(p), "min", itoa(e.cfg.ComplianceCoverageMin)))
		}
		return result(OutcomeSufficient, inv, m)

	case "patch.applied":
		jobs := e.items[store.EvidenceUpdateJob]
		var ok, partial, failed, notRun int
		for _, j := range jobs {
			switch j.Outcome {
			case "succeeded":
				ok++
			case "partial":
				partial++
			case "failed", "timed_out":
				failed++
			default:
				notRun++
			}
		}
		ran := ok + partial + failed
		rate := pct(failed, ran)
		m := []Metric{count("update_jobs", len(jobs)), count("succeeded", ok), count("partial", partial), count("failed", failed),
			count("not_run", notRun), percent("failure_rate", rate)}
		if ran == 0 {
			return result(OutcomeMissing, ids(jobs), m, tx("compliance.gap.no_update_jobs"))
		}
		if rate > float64(e.cfg.CompliancePatchFailMax) {
			return result(OutcomePartial, ids(jobs), m, tx("compliance.gap.failure_rate", "pct", pctText(rate), "max", itoa(e.cfg.CompliancePatchFailMax)))
		}
		return result(OutcomeSufficient, ids(jobs), m)

	case "patch.currency":
		if len(e.last) == 0 {
			return result(OutcomeMissing, inv, nil, noStates)
		}
		clean, pending := 0, 0
		for _, h := range e.last {
			if h.SecurityUpdates == 0 {
				clean++
			}
			pending += h.SecurityUpdates
		}
		p := pct(clean, len(e.last))
		m := []Metric{count("hosts", len(e.last)), count("hosts_clean", clean), count("security_updates", pending), percent("clean_rate", p)}
		if p < float64(e.cfg.ComplianceCurrencyMin) {
			return result(OutcomePartial, inv, m, tx("compliance.gap.currency_low", "pct", pctText(p), "min", itoa(e.cfg.ComplianceCurrencyMin)))
		}
		return result(OutcomeSufficient, inv, m)

	case "vuln.sla":
		res := e.items[store.EvidenceVulnResolved]
		ev := append(ids(res), inv...)
		if !e.sla.Enabled() {
			return result(OutcomeMissing, ev, nil, tx("compliance.gap.sla_undefined"))
		}
		if len(e.last) == 0 && len(res) == 0 {
			return result(OutcomeMissing, ev, nil, noStates)
		}
		within, late := 0, 0
		for _, r := range res {
			switch r.Outcome {
			case "within_sla":
				within++
			case "overdue":
				late++
			}
		}
		open := 0
		for _, h := range e.last {
			open += h.SLAOverdue
		}
		p := pct(within, within+late)
		m := []Metric{count("resolved", len(res)), count("within_sla", within), count("resolved_late", late), count("open_overdue", open)}
		if within+late > 0 {
			m = append(m, percent("within_rate", p))
		}
		if open > 0 {
			return result(OutcomeDeviation, ev, m, tx("compliance.gap.sla_overdue_open", "n", itoa(open)))
		}
		if within+late > 0 && p < float64(e.cfg.ComplianceSLAMin) {
			return result(OutcomePartial, ev, m, tx("compliance.gap.sla_rate_low", "pct", pctText(p), "min", itoa(e.cfg.ComplianceSLAMin)))
		}
		return result(OutcomeSufficient, ev, m)

	case "vuln.kev":
		var kevRes []store.EvidenceItem
		for _, r := range e.items[store.EvidenceVulnResolved] {
			if v, _ := r.PayloadMap()["kev"].(bool); v {
				kevRes = append(kevRes, r)
			}
		}
		ev := append(ids(kevRes), inv...)
		if len(e.last) == 0 {
			return result(OutcomeMissing, ev, nil, noStates)
		}
		open, over := 0, 0
		for _, h := range e.last {
			open += h.KEV
			over += h.KEVOverdue
		}
		m := []Metric{count("kev_open", open), count("kev_overdue", over), count("kev_resolved", len(kevRes))}
		if over > 0 {
			return result(OutcomeDeviation, ev, m, tx("compliance.gap.kev_overdue", "n", itoa(over)))
		}
		return result(OutcomeSufficient, ev, m)

	case "risk.accepted":
		ev := ids(e.auditWith(prefixes("finding.status", "finding.risk_expired")))
		rs, err := e.st.AcceptedRiskStats(e.ctx, e.hostIDs())
		if err != nil {
			return result(OutcomeMissing, ev, nil, tx("compliance.gap.error"))
		}
		m := []Metric{count("accepted_risks", rs.Accepted), count("no_expiry", rs.NoExpiry), count("no_note", rs.NoNote), count("expiring_30d", rs.Expiring)}
		var gaps []Text
		if rs.NoExpiry > 0 {
			gaps = append(gaps, tx("compliance.gap.risk_no_expiry", "n", itoa(rs.NoExpiry)))
		}
		if rs.NoNote > 0 {
			gaps = append(gaps, tx("compliance.gap.risk_no_note", "n", itoa(rs.NoNote)))
		}
		if len(gaps) > 0 {
			return result(OutcomePartial, ev, m, gaps...)
		}
		return result(OutcomeSufficient, ev, m)

	case "eol.unsupported":
		if len(e.last) == 0 {
			return result(OutcomeMissing, inv, nil, noStates)
		}
		eolN, soon, unknown := 0, 0, 0
		for _, h := range e.last {
			switch h.OSEOL {
			case "eol":
				eolN++
			case "soon":
				soon++
			case "", "unknown":
				unknown++
			}
		}
		m := []Metric{count("hosts", len(e.last)), count("os_eol", eolN), count("os_soon", soon), count("os_unknown", unknown)}
		if eolN > 0 {
			return result(OutcomeDeviation, inv, m, tx("compliance.gap.os_eol", "n", itoa(eolN)))
		}
		if unknown == len(e.last) {
			return result(OutcomePartial, inv, m, tx("compliance.gap.eol_unknown"))
		}
		return result(OutcomeSufficient, inv, m)

	case "reboot.pending":
		if len(e.last) == 0 {
			return result(OutcomeMissing, inv, nil, noStates)
		}
		var reboots []store.EvidenceItem
		for _, j := range e.items[store.EvidenceChangeJob] {
			if j.Subject == "reboot" {
				reboots = append(reboots, j)
			}
		}
		ev := append(ids(reboots), inv...)
		pending, long := 0, 0
		limit := time.Duration(e.cfg.ComplianceRebootMaxDays) * 24 * time.Hour
		for _, h := range e.last {
			if h.RebootRequiredSince.IsZero() {
				continue
			}
			pending++
			if e.end.Sub(h.RebootRequiredSince) > limit {
				long++
			}
		}
		m := []Metric{count("reboot_pending", pending), count("reboot_long", long), count("reboots", len(reboots))}
		if long > 0 {
			return result(OutcomePartial, ev, m, tx("compliance.gap.reboot_long", "n", itoa(long), "days", itoa(e.cfg.ComplianceRebootMaxDays)))
		}
		return result(OutcomeSufficient, ev, m)

	case "change.recorded":
		jobs := append(append([]store.EvidenceItem{}, e.items[store.EvidenceUpdateJob]...), e.items[store.EvidenceChangeJob]...)
		origins := map[string]int{}
		for _, j := range jobs {
			o, _ := j.PayloadMap()["origin"].(string)
			origins[o]++
		}
		ev := append(ids(jobs), ids(e.auditWith(prefixes("job.", "schedule.", "rollout.", "rollback.")))...)
		m := []Metric{count("changes", len(jobs)), count("by_user", origins["user"]), count("by_schedule", origins["schedule"]),
			count("by_rollout", origins["rollout"]), count("automatic", origins["system"])}
		if len(jobs) == 0 {
			return result(OutcomeMissing, ev, m, tx("compliance.gap.no_changes"))
		}
		return result(OutcomeSufficient, ev, m)

	case "change.approval":
		approvals := e.auditWith(prefixes("job.approve"))
		scheduled := e.auditWith(prefixes("schedule.create", "schedule.update", "rollout.create"))
		ev := append(ids(approvals), ids(scheduled)...)
		previewed := 0
		for _, j := range e.items[store.EvidenceUpdateJob] {
			if _, ok := j.PayloadMap()["approved_preview"]; ok {
				previewed++
				ev = append(ev, j.ID)
			}
		}
		m := []Metric{count("approvals", len(approvals)), count("approved_updates", previewed), count("planned_changes", len(scheduled))}
		if !e.cfg.RequirePreview {
			return result(OutcomePartial, ev, m, tx("compliance.gap.preview_not_required"))
		}
		return result(OutcomeSufficient, ev, m)

	case "config.drift":
		ev := append(ids(e.items[store.EvidenceDrift]), ids(e.auditWith(prefixes("standard.")))...)
		standards, devs, hosts, err := e.st.DriftStats(e.ctx, e.hostIDs())
		if err != nil {
			return result(OutcomeMissing, ev, nil, tx("compliance.gap.error"))
		}
		m := []Metric{count("standards", standards), count("deviations", devs), count("hosts_deviating", hosts), count("deviations_detected", len(e.items[store.EvidenceDrift]))}
		if standards == 0 {
			return result(OutcomeMissing, ev, m, tx("compliance.gap.no_standards"))
		}
		if devs > 0 {
			return result(OutcomeDeviation, ev, m, tx("compliance.gap.drift_open", "n", itoa(devs), "hosts", itoa(hosts)))
		}
		return result(OutcomeSufficient, ev, m)

	case "access.mfa":
		ev := ids(e.auditWith(prefixes("user.", "apitoken.", "auth.mfa_failed")))
		admins, without, err := e.st.AdminMFAStats(e.ctx)
		if err != nil {
			return result(OutcomeMissing, ev, nil, tx("compliance.gap.error"))
		}
		m := []Metric{count("admins", admins), count("admins_without_mfa", without)}
		if without > 0 {
			return result(OutcomeDeviation, ev, m, tx("compliance.gap.admins_without_mfa", "n", itoa(without)))
		}
		if !e.cfg.AuthRequireMFA {
			return result(OutcomePartial, ev, m, tx("compliance.gap.mfa_not_required"))
		}
		return result(OutcomeSufficient, ev, m)

	case "backup.daily":
		items := e.items[store.EvidenceBackup]
		ev := ids(items)
		if !e.cfg.BackupEnabled {
			return result(OutcomeMissing, ev, nil, tx("compliance.gap.backup_disabled"))
		}
		from := e.from
		if e.start.After(from) {
			from = store.DayStart(e.start)
		}
		days := int(math.Ceil(e.end.Sub(from).Hours() / 24))
		okDays := map[int64]bool{}
		failed := 0
		for _, it := range items {
			if it.Outcome == "succeeded" {
				okDays[store.DayStart(it.OccurredAt).Unix()] = true
			} else {
				failed++
			}
		}
		if days <= 0 {
			return result(OutcomeMissing, ev, nil, tx("compliance.gap.no_backups"))
		}
		p := pct(min(len(okDays), days), days)
		m := []Metric{count("days", days), count("backup_days", len(okDays)), count("backup_failures", failed), percent("backup_rate", p)}
		if len(okDays) == 0 {
			return result(OutcomeMissing, ev, m, tx("compliance.gap.no_backups"))
		}
		var gaps []Text
		if failed > 0 {
			gaps = append(gaps, tx("compliance.gap.backup_failures", "n", itoa(failed)))
		}
		if p < float64(e.cfg.ComplianceCoverageMin) {
			gaps = append(gaps, tx("compliance.gap.backup_rate_low", "pct", pctText(p), "min", itoa(e.cfg.ComplianceCoverageMin)))
		}
		if len(gaps) > 0 {
			return result(OutcomePartial, ev, m, gaps...)
		}
		return result(OutcomeSufficient, ev, m)

	case "log.integrity":
		audit := e.items[store.EvidenceAudit]
		ev := ids(audit)
		m := []Metric{count("audit_events", len(audit)), count("chain_items", e.chain.Items)}
		if !e.chain.OK {
			return result(OutcomeDeviation, ev, m, tx("compliance.gap.chain_broken", "id", strconv.FormatInt(e.chain.BrokenID, 10)))
		}
		if len(audit) == 0 {
			return result(OutcomePartial, ev, m, tx("compliance.gap.no_audit_events"))
		}
		return result(OutcomeSufficient, ev, m)

	case "monitoring.coverage":
		if e.cfg.HealthMonitor == 0 {
			return result(OutcomeMissing, inv, nil, tx("compliance.gap.monitoring_off"))
		}
		if len(e.states) == 0 {
			return result(OutcomeMissing, inv, nil, noStates)
		}
		mon := 0
		for _, h := range e.states {
			if h.Monitored {
				mon++
			}
		}
		p := pct(mon, len(e.states))
		m := []Metric{count("host_days", len(e.states)), count("host_days_monitored", mon), percent("monitoring_rate", p)}
		if p < float64(e.cfg.ComplianceCoverageMin) {
			return result(OutcomePartial, inv, m, tx("compliance.gap.monitoring_low", "pct", pctText(p), "min", itoa(e.cfg.ComplianceCoverageMin)))
		}
		return result(OutcomeSufficient, inv, m)
	}
	return result(OutcomeMissing, nil, nil, tx("compliance.gap.error"))
}

// forPlatforms returns the env limited to hosts of the platforms.
func (e *env) forPlatforms(ps []string) *env {
	if len(ps) == 0 {
		return e
	}
	keep := map[string]bool{}
	for _, p := range ps {
		keep[p] = true
	}
	out := *e
	out.limited = true
	out.states = nil
	out.last, out.first = map[int64]store.HostState{}, map[int64]store.HostState{}
	hosts := map[int64]bool{}
	for _, h := range e.states {
		if keep[h.Platform] {
			out.states = append(out.states, h)
		}
	}
	for id, h := range e.last {
		if keep[h.Platform] {
			out.last[id] = h
			hosts[id] = true
		}
	}
	for id, h := range e.first {
		if hosts[id] {
			out.first[id] = h
		}
	}
	out.items = map[string][]store.EvidenceItem{}
	for kind, items := range e.items {
		for _, it := range items {
			if it.HostID == 0 || keep[it.Platform] {
				out.items[kind] = append(out.items[kind], it)
			}
		}
	}
	return &out
}
