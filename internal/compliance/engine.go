package compliance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"netio.patchman/internal/brand"
	"netio.patchman/internal/settings"
	"netio.patchman/internal/store"
	"netio.patchman/internal/version"
)

// maxIndexItems bounds the evidence index stored in a version.
const maxIndexItems = 1000

// Request describes a generation.
type Request struct {
	Report      store.ComplianceReport
	GeneratedBy string
	Now         time.Time
	// Previous are the assessments of the version before: a review is kept
	// when the automated outcome did not change.
	Previous []store.ControlAssessment
}

// Result is a generated version ready to store.
type Result struct {
	Report      Report
	Content     string
	SHA256      string
	Assessments []store.ControlAssessment
	Mapping     []store.AssessmentEvidence
}

// ValidProfiles reports whether every key names a stored profile version.
func ValidProfiles(keys []string) bool {
	if len(keys) == 0 {
		return false
	}
	for _, k := range keys {
		if _, ok := ProfileByKey(k); !ok {
			return false
		}
	}
	return true
}

// Generate evaluates a report over its period and scope. It reads with a
// context without the user's group scope: the report's own scope decides.
func Generate(st *store.Store, req Request) (Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	rep := req.Report
	cfg, err := settings.Load(ctx, st)
	if err != nil {
		return Result{}, err
	}
	sla := store.SLA{Critical: cfg.SLACriticalDays, High: cfg.SLAHighDays, Medium: cfg.SLAMediumDays, Low: cfg.SLALowDays}
	end := rep.To
	if req.Now.Before(end) {
		end = req.Now
	}
	states, err := st.HostStates(ctx, rep.From, rep.To, rep.GroupID)
	if err != nil {
		return Result{}, err
	}
	keepPlatform := map[string]bool{}
	for _, p := range rep.Platforms {
		keepPlatform[p] = true
	}
	e := &env{ctx: ctx, st: st, from: rep.From, to: rep.To, end: end, cfg: cfg, sla: sla,
		last: map[int64]store.HostState{}, first: map[int64]store.HostState{}, items: map[string][]store.EvidenceItem{}}
	for _, h := range states {
		if len(keepPlatform) > 0 && !keepPlatform[h.Platform] {
			continue
		}
		e.states = append(e.states, h)
		if _, ok := e.first[h.HostID]; !ok {
			e.first[h.HostID] = h
		}
		e.last[h.HostID] = h
	}
	scoped := rep.GroupID != 0 || len(keepPlatform) > 0
	all, err := st.EvidenceItems(ctx, store.EvidenceFilter{From: rep.From, To: rep.To})
	if err != nil {
		return Result{}, err
	}
	for _, it := range all {
		if it.Kind == store.EvidenceManual {
			continue
		}
		if it.HostID != 0 && scoped {
			if _, ok := e.last[it.HostID]; !ok {
				continue
			}
		}
		e.items[it.Kind] = append(e.items[it.Kind], it)
	}
	manual, err := st.EvidenceItems(ctx, store.EvidenceFilter{Kinds: []string{store.EvidenceManual}, To: rep.To})
	if err != nil {
		return Result{}, err
	}
	if e.chain, err = st.VerifyEvidence(ctx); err != nil {
		return Result{}, err
	}
	if e.start, err = st.EvidenceStart(ctx); err != nil {
		return Result{}, err
	}
	ctlSettings, err := st.ControlSettings(ctx)
	if err != nil {
		return Result{}, err
	}
	groups, err := st.ListGroups(ctx)
	if err != nil {
		return Result{}, err
	}
	groupName := map[int64]string{}
	for _, g := range groups {
		groupName[g.ID] = g.Name
	}

	out := Report{Schema: Schema, Engine: EngineVersion, Product: brand.Name, ProductVersion: version.Version, ReportID: rep.ID,
		Title: rep.Title, Note: rep.Note, GeneratedAt: req.Now.UTC(), GeneratedBy: req.GeneratedBy, PeriodFrom: rep.From.UTC(), PeriodTo: rep.To.UTC(),
		Scope: Scope{GroupID: rep.GroupID, GroupName: groupName[rep.GroupID], Platforms: rep.Platforms}, CollectionStart: e.start}

	// Checks: each check and platform combination is measured once.
	cache := map[string]CheckResult{}
	measure := func(ref CheckRef) CheckResult {
		if r, ok := cache[ref.Key()]; ok {
			return r
		}
		r := e.forPlatforms(ref.Platforms).run(ref.Check)
		r.Key, r.Check, r.Platforms = ref.Key(), ref.Check, ref.Platforms
		cache[ref.Key()] = r
		return r
	}
	prev := map[string]store.ControlAssessment{}
	for _, a := range req.Previous {
		prev[a.Profile+":"+a.Control] = a
	}
	var res Result
	used := map[int64][]string{}
	for _, key := range rep.Profiles {
		p, ok := ProfileByKey(key)
		if !ok {
			return Result{}, fmt.Errorf("unknown profile %q", key)
		}
		pa := ProfileAssessment{Profile: p.ID, Version: p.Version}
		ps := ProfileSummary{Profile: p.ID, Outcomes: map[string]int{}}
		for _, c := range p.Controls {
			ca := ControlAssessment{ID: c.ID, Applicable: true, Manual: c.Manual}
			ctlKey := p.ID + ":" + c.ID
			var mapping []store.AssessmentEvidence
			var gaps, recs []Text
			if s, ok := ctlSettings[ctlKey]; ok && !s.Applicable {
				ca.Applicable, ca.Justification, ca.Outcome = false, s.Justification, OutcomeNotApplicable
			} else {
				worst, primaries := 0, 0
				for _, ref := range c.Checks {
					r := measure(ref)
					ca.Checks = append(ca.Checks, ControlCheck{Key: r.Key, Check: ref.Check, Relevance: ref.Relevance, Outcome: r.Outcome})
					for _, id := range r.ids {
						mapping = append(mapping, store.AssessmentEvidence{Profile: p.ID, Control: c.ID, EvidenceID: id, Relevance: ref.Relevance})
					}
					if r.Outcome == OutcomeNotApplicable {
						continue
					}
					if ref.Relevance == RelevancePrimary {
						primaries++
						worst = max(worst, severity(r.Outcome))
					}
					if r.Outcome != OutcomeSufficient {
						gaps = append(gaps, r.Gaps...)
						recs = append(recs, tx("compliance.check."+ref.Check+".fix"))
					}
				}
				var docs []store.EvidenceItem
				for _, m := range manual {
					if manualCovers(m, ctlKey) {
						docs = append(docs, m)
						mapping = append(mapping, store.AssessmentEvidence{Profile: p.ID, Control: c.ID, EvidenceID: m.ID, Relevance: RelevanceManual})
					}
				}
				ca.ManualItems = len(docs)
				switch {
				case len(c.Checks) == 0 && len(docs) > 0:
					ca.Outcome = OutcomeManualEvidence
				case len(c.Checks) == 0:
					ca.Outcome = OutcomeManualRequired
				case primaries == 0:
					ca.Outcome = OutcomeNotApplicable
					ca.Justification = ""
				default:
					for _, o := range []string{OutcomeDeviation, OutcomeMissing, OutcomePartial, OutcomeSufficient} {
						if severity(o) == worst {
							ca.Outcome = o
						}
					}
				}
				if c.Manual != "" && len(docs) == 0 {
					gaps = append(gaps, tx("compliance.gap.manual_missing", "type", c.Manual))
					recs = append(recs, tx("compliance.manual."+c.Manual+".fix"))
				}
			}
			ca.Evidence = len(uniqueIDs(mapping))
			for _, m := range mapping {
				used[m.EvidenceID] = appendOnce(used[m.EvidenceID], ctlKey)
			}
			res.Mapping = append(res.Mapping, mapping...)
			pa.Controls = append(pa.Controls, ca)
			ps.Outcomes[ca.Outcome]++
			ps.Controls++
			a := store.ControlAssessment{Profile: p.ID, Control: c.ID, Outcome: ca.Outcome, Applicable: ca.Applicable, ReviewStatus: store.ReviewNone}
			if old, ok := prev[ctlKey]; ok && old.Outcome == ca.Outcome && old.ReviewStatus != store.ReviewNone {
				a.ReviewStatus, a.ReviewNote, a.ReviewedBy, a.ReviewedAt = old.ReviewStatus, old.ReviewNote, old.ReviewedBy, old.ReviewedAt
			}
			res.Assessments = append(res.Assessments, a)
			if ca.Outcome != OutcomeNotApplicable && (ca.Outcome != OutcomeSufficient || len(gaps) > 0) {
				out.Gaps = append(out.Gaps, GapRow{Profile: p.ID, Control: c.ID, Outcome: ca.Outcome, Gaps: dedupTexts(gaps), Recommendations: dedupTexts(recs)})
			}
		}
		out.Profiles = append(out.Profiles, ProfileRef{ID: p.ID, Version: p.Version})
		out.Controls = append(out.Controls, pa)
		out.Summary.Profiles = append(out.Summary.Profiles, ps)
	}
	keys := make([]string, 0, len(cache))
	for k := range cache {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out.Checks = append(out.Checks, cache[k])
	}

	e.sections(&out, groupName)
	out.Evidence = evidenceIndex(e, manual, used)

	// Executive summary warnings.
	switch {
	case e.start.IsZero():
		out.Summary.Warnings = append(out.Summary.Warnings, tx("compliance.warn.no_evidence"))
	case e.start.After(rep.From):
		out.Summary.Warnings = append(out.Summary.Warnings, tx("compliance.warn.collection_started", "date", e.start.UTC().Format(time.RFC3339)))
	}
	if len(e.last) == 0 {
		out.Summary.Warnings = append(out.Summary.Warnings, tx("compliance.warn.no_hosts"))
	}
	if !e.chain.OK {
		out.Summary.Warnings = append(out.Summary.Warnings, tx("compliance.warn.chain_broken"))
	}

	content, err := json.Marshal(out)
	if err != nil {
		return Result{}, err
	}
	sum := sha256.Sum256(content)
	res.Report, res.Content, res.SHA256 = out, string(content), hex.EncodeToString(sum[:])
	return res, nil
}

func manualCovers(m store.EvidenceItem, ctlKey string) bool {
	list, _ := m.PayloadMap()["controls"].([]any)
	for _, v := range list {
		if s, _ := v.(string); s == ctlKey {
			return true
		}
	}
	return false
}

func uniqueIDs(m []store.AssessmentEvidence) map[int64]bool {
	out := map[int64]bool{}
	for _, x := range m {
		out[x.EvidenceID] = true
	}
	return out
}

func appendOnce(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}

func dedupTexts(in []Text) []Text {
	seen := map[string]bool{}
	var out []Text
	for _, t := range in {
		b, _ := json.Marshal(t)
		if !seen[string(b)] {
			seen[string(b)] = true
			out = append(out, t)
		}
	}
	return out
}

// sections fills the report sections from the report-wide data.
func (e *env) sections(out *Report, groupName map[int64]string) {
	out.Summary.Hosts = len(e.last)
	out.Summary.ByPlatform = map[string]int{}
	rows := map[string]*PlatformRow{}
	row := func(p string) *PlatformRow {
		r := rows[p]
		if r == nil {
			r = &PlatformRow{Platform: p}
			rows[p] = r
		}
		return r
	}
	for _, h := range e.last {
		out.Summary.ByPlatform[h.Platform]++
		a := Asset{HostID: h.HostID, Hostname: h.Hostname, Platform: h.Platform, OSName: h.OSName, OSVersion: h.OSVersion,
			AgentVersion: h.AgentVersion, LastSeen: h.LastSeenAt, OSSupport: h.OSEOL}
		for _, g := range strings.Split(strings.Trim(h.GroupIDs, ","), ",") {
			if id, err := strconv.ParseInt(g, 10, 64); err == nil {
				if n := groupName[id]; n != "" {
					a.Groups = append(a.Groups, n)
				}
			}
		}
		out.Inventory = append(out.Inventory, a)
		r := row(h.Platform)
		r.Hosts++
		r.Updates += h.Updates
		r.SecurityUpdates += h.SecurityUpdates
		if h.SecurityUpdates > 0 {
			r.HostsWithSecurity++
		} else {
			out.Patch.HostsClean++
		}
		if !h.RebootRequiredSince.IsZero() {
			r.RebootPending++
		}
		out.Vulnerabilities.OpenAtEnd.add(h)
		out.Vulnerabilities.KEVOverdue += h.KEVOverdue
		out.SLA.OpenOverdue += h.SLAOverdue
		if h.OSEOL == "eol" || h.OSEOL == "soon" {
			out.EOL = append(out.EOL, EOLRow{Hostname: h.Hostname, Platform: h.Platform, OSName: h.OSName, Status: h.OSEOL})
		}
	}
	for _, h := range e.first {
		out.Vulnerabilities.OpenAtStart.add(h)
	}
	out.Patch.Hosts = len(e.last)
	sort.Slice(out.Inventory, func(i, j int) bool { return out.Inventory[i].Hostname < out.Inventory[j].Hostname })
	sort.Slice(out.EOL, func(i, j int) bool {
		if out.EOL[i].Status != out.EOL[j].Status {
			return out.EOL[i].Status == "eol"
		}
		return out.EOL[i].Hostname < out.EOL[j].Hostname
	})

	// Update jobs and other changes.
	out.Changes = ChangeSection{ByType: map[string]int{}, ByStatus: map[string]int{}, ByOrigin: map[string]int{}, RequirePreview: e.cfg.RequirePreview}
	for _, kind := range []string{store.EvidenceUpdateJob, store.EvidenceChangeJob} {
		for _, j := range e.items[kind] {
			pm := j.PayloadMap()
			origin, _ := pm["origin"].(string)
			out.Changes.Total++
			out.Changes.ByType[j.Subject]++
			out.Changes.ByStatus[j.Outcome]++
			out.Changes.ByOrigin[origin]++
			if kind != store.EvidenceUpdateJob {
				continue
			}
			out.Patch.Jobs++
			r := row(j.Platform)
			switch j.Outcome {
			case "succeeded":
				out.Patch.Succeeded++
				r.UpdateJobsSucceeded++
				if n, ok := pm["package_count"].(float64); ok {
					out.Patch.Packages += int(n)
				}
			case "partial":
				out.Patch.Partial++
				r.UpdateJobsSucceeded++
			case "failed", "timed_out":
				out.Patch.Failed++
				r.UpdateJobsFailed++
			default:
				out.Patch.NotRun++
			}
		}
	}
	for _, it := range e.items[store.EvidenceAudit] {
		if it.Subject == "job.approve" {
			out.Changes.Approvals++
		}
	}
	for _, p := range store.Platforms {
		if r := rows[p]; r != nil && (r.Hosts > 0 || r.UpdateJobsSucceeded+r.UpdateJobsFailed > 0) {
			out.Updates = append(out.Updates, *r)
		}
	}

	// Vulnerabilities and SLA.
	var fix float64
	for _, it := range e.items[store.EvidenceVulnResolved] {
		pm := it.PayloadMap()
		out.Vulnerabilities.Resolved++
		if v, _ := pm["kev"].(bool); v {
			out.Vulnerabilities.KEVResolved++
		}
		d, _ := pm["first_detected_at"].(float64)
		r, _ := pm["resolved_at"].(float64)
		if r > d && d > 0 {
			fix += (r - d) / 86400
		}
		switch it.Outcome {
		case "within_sla":
			out.SLA.WithinSLA++
		case "overdue":
			out.SLA.Late++
		}
	}
	if out.Vulnerabilities.Resolved > 0 {
		out.Vulnerabilities.MeanFixDays = math.Round(fix*10/float64(out.Vulnerabilities.Resolved)) / 10
	}
	out.SLA.Enabled = e.sla.Enabled()
	out.SLA.Resolved = out.Vulnerabilities.Resolved
	out.SLA.Days = map[string]int{"critical": e.sla.Critical, "high": e.sla.High, "medium": e.sla.Medium, "low": e.sla.Low}
	if kev, err := e.st.OpenKEV(e.ctx, out.Scope.GroupID); err == nil {
		names := map[string]bool{}
		for _, h := range e.last {
			names[h.Hostname] = true
		}
		for _, k := range kev {
			n := 0
			for _, h := range k.Hostnames {
				if names[h] {
					n++
				}
			}
			if n > 0 {
				out.Vulnerabilities.KEVOpen = append(out.Vulnerabilities.KEVOpen, KEVRow{CVE: k.CVEID, Title: k.Title, DueDate: k.DueDate, Hosts: n})
			}
		}
	}

	// Audit log.
	out.Audit = AuditSection{ByAction: map[string]int{}, ChainOK: e.chain.OK, ChainItems: e.chain.Items, ChainBroken: e.chain.BrokenID, ChainReason: e.chain.Reason}
	for _, it := range e.items[store.EvidenceAudit] {
		out.Audit.Events++
		out.Audit.ByAction[it.Subject]++
	}
}

func (s *SeverityCounts) add(h store.HostState) {
	s.Critical += h.Critical
	s.High += h.High
	s.Medium += h.Medium
	s.Low += h.Low
	s.KEV += h.KEV
}

// evidenceIndex lists the newest items the version used.
func evidenceIndex(e *env, manual []store.EvidenceItem, used map[int64][]string) EvidenceIndex {
	var items []store.EvidenceItem
	for _, list := range e.items {
		for _, it := range list {
			if _, ok := used[it.ID]; ok {
				items = append(items, it)
			}
		}
	}
	for _, it := range manual {
		if _, ok := used[it.ID]; ok {
			items = append(items, it)
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if !items[i].OccurredAt.Equal(items[j].OccurredAt) {
			return items[i].OccurredAt.After(items[j].OccurredAt)
		}
		return items[i].ID > items[j].ID
	})
	idx := EvidenceIndex{Total: len(items)}
	for _, it := range items[:min(len(items), maxIndexItems)] {
		ctl := append([]string{}, used[it.ID]...)
		sort.Strings(ctl)
		ref := EvidenceRef{ID: it.ID, Kind: it.Kind, OccurredAt: it.OccurredAt, Hostname: it.Hostname, Subject: it.Subject, Outcome: it.Outcome,
			SHA256: it.SHA256, Controls: ctl}
		if it.Kind == store.EvidenceManual {
			if t, _ := it.PayloadMap()["title"].(string); t != "" {
				ref.Subject = t
			}
		}
		idx.Items = append(idx.Items, ref)
	}
	idx.Shown = len(idx.Items)
	return idx
}

// FinalDigest is the SHA-256 over a version's content hash and its reviews,
// stored when the version becomes final.
func FinalDigest(contentSHA string, assessments []store.ControlAssessment) string {
	list := append([]store.ControlAssessment{}, assessments...)
	sort.Slice(list, func(i, j int) bool {
		if list[i].Profile != list[j].Profile {
			return list[i].Profile < list[j].Profile
		}
		return list[i].Control < list[j].Control
	})
	h := sha256.New()
	fmt.Fprintf(h, "netio.patchman/compliance-final/v1\n%s\n", contentSHA)
	for _, a := range list {
		fmt.Fprintf(h, "%s|%s|%s|%t|%s|%d|%s|%d|%q\n", a.Profile, a.Control, a.Outcome, a.Applicable, a.ReviewStatus, len(a.ReviewNote), a.ReviewedBy,
			a.ReviewedAt.Unix(), a.ReviewNote)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Decode parses a stored version's content.
func Decode(content string) (Report, error) {
	var r Report
	err := json.Unmarshal([]byte(content), &r)
	return r, err
}
