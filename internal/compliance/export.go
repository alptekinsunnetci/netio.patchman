package compliance

import (
	"archive/zip"
	"encoding/csv"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"time"

	"netio.patchman/internal/store"
)

// ExportSchema identifies the JSON export.
const ExportSchema = "netio.patchman/compliance-export/v1"

// Bundle is a stored version with everything its exports contain.
type Bundle struct {
	Report      store.ComplianceReport
	Version     store.ReportVersion
	Content     Report
	Assessments []store.ControlAssessment
	// Evidence is every item the version used, Controls their controls.
	Evidence []store.EvidenceItem
	Controls map[int64][]string
	// Redact hides the actor and details of audit log items (readers who
	// may not see the audit log).
	Redact bool
}

func (b Bundle) assessment(profile, control string) store.ControlAssessment {
	for _, a := range b.Assessments {
		if a.Profile == profile && a.Control == control {
			return a
		}
	}
	return store.ControlAssessment{Profile: profile, Control: control, ReviewStatus: store.ReviewNone}
}

func (b Bundle) redacted(e store.EvidenceItem) bool { return b.Redact && e.Kind == store.EvidenceAudit }

type exportVersion struct {
	Report      int64      `json:"report_id"`
	Number      int        `json:"version"`
	Status      string     `json:"status"`
	GeneratedAt time.Time  `json:"generated_at"`
	GeneratedBy string     `json:"generated_by"`
	Engine      string     `json:"engine"`
	SHA256      string     `json:"sha256"`
	FinalizedAt *time.Time `json:"finalized_at,omitempty"`
	FinalizedBy string     `json:"finalized_by,omitempty"`
	FinalSHA256 string     `json:"final_sha256,omitempty"`
}

type exportAssessment struct {
	Profile      string     `json:"profile"`
	Control      string     `json:"control"`
	Outcome      string     `json:"outcome"`
	Applicable   bool       `json:"applicable"`
	ReviewStatus string     `json:"review_status"`
	ReviewNote   string     `json:"review_note,omitempty"`
	ReviewedBy   string     `json:"reviewed_by,omitempty"`
	ReviewedAt   *time.Time `json:"reviewed_at,omitempty"`
}

type exportEvidence struct {
	ID          int64           `json:"id"`
	Kind        string          `json:"kind"`
	Source      string          `json:"source"`
	SourceRef   string          `json:"source_ref"`
	HostID      int64           `json:"host_id,omitempty"`
	Hostname    string          `json:"hostname,omitempty"`
	Platform    string          `json:"platform,omitempty"`
	Subject     string          `json:"subject,omitempty"`
	Actor       string          `json:"actor,omitempty"`
	Outcome     string          `json:"outcome,omitempty"`
	OccurredAt  time.Time       `json:"occurred_at"`
	CollectedAt time.Time       `json:"collected_at"`
	Payload     json.RawMessage `json:"payload,omitempty"`
	SHA256      string          `json:"sha256"`
	PrevSHA256  string          `json:"prev_sha256"`
	Redacted    bool            `json:"redacted,omitempty"`
	Controls    []string        `json:"controls"`
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

// WriteJSON writes the machine-readable export: the stored content
// verbatim, the assessments with their reviews and the evidence with hashes.
func WriteJSON(w io.Writer, b Bundle) error {
	v := b.Version
	out := struct {
		Schema      string             `json:"schema"`
		Version     exportVersion      `json:"version"`
		Report      json.RawMessage    `json:"report"`
		Assessments []exportAssessment `json:"assessments"`
		Evidence    []exportEvidence   `json:"evidence"`
	}{Schema: ExportSchema, Report: json.RawMessage(v.Content),
		Version: exportVersion{Report: v.ReportID, Number: v.Version, Status: v.Status, GeneratedAt: v.GeneratedAt.UTC(), GeneratedBy: v.GeneratedBy,
			Engine: v.Engine, SHA256: v.SHA256, FinalizedAt: timePtr(v.FinalizedAt), FinalizedBy: v.FinalizedBy, FinalSHA256: v.FinalSHA256}}
	for _, a := range b.Assessments {
		out.Assessments = append(out.Assessments, exportAssessment{Profile: a.Profile, Control: a.Control, Outcome: a.Outcome, Applicable: a.Applicable,
			ReviewStatus: a.ReviewStatus, ReviewNote: a.ReviewNote, ReviewedBy: a.ReviewedBy, ReviewedAt: timePtr(a.ReviewedAt)})
	}
	out.Evidence = []exportEvidence{}
	for _, e := range b.Evidence {
		x := exportEvidence{ID: e.ID, Kind: e.Kind, Source: e.Source, SourceRef: e.SourceRef, HostID: e.HostID, Hostname: e.Hostname, Platform: e.Platform,
			Subject: e.Subject, Actor: e.Actor, Outcome: e.Outcome, OccurredAt: e.OccurredAt.UTC(), CollectedAt: e.CollectedAt.UTC(),
			Payload: json.RawMessage(e.Payload), SHA256: e.SHA256, PrevSHA256: e.PrevSHA256, Controls: nonNilStrings(b.Controls[e.ID])}
		if b.redacted(e) {
			x.Actor, x.Payload, x.Redacted = "", nil, true
		}
		out.Evidence = append(out.Evidence, x)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// csvSheet writes one CSV file of the archive: UTF-8 with BOM, the
// locale's separator, formula-like cells prefixed with an apostrophe.
func csvSheet(z *zip.Writer, name string, comma rune, rows [][]string) error {
	f, err := z.Create(name)
	if err != nil {
		return err
	}
	if _, err := f.Write([]byte("\xEF\xBB\xBF")); err != nil {
		return err
	}
	cw := csv.NewWriter(f)
	cw.Comma = comma
	for _, rec := range rows {
		for i, v := range rec {
			if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
				rec[i] = "'" + v
			}
		}
		if err := cw.Write(rec); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// WriteCSVZip writes a ZIP with summary, controls, checks, gaps, assets and
// evidence as CSV files in the renderer's language.
func WriteCSVZip(w io.Writer, b Bundle, r Renderer) error {
	l := r.L
	comma := ';'
	if sep := []rune(l.T("csv.separator")); len(sep) == 1 {
		comma = sep[0]
	}
	c := b.Content
	z := zip.NewWriter(w)
	yes, no := l.T("common.yes"), l.T("common.no")
	yn := func(v bool) string {
		if v {
			return yes
		}
		return no
	}

	var profiles []string
	for _, p := range c.Profiles {
		profiles = append(profiles, r.ProfileName(p.ID)+" ("+p.Key()+")")
	}
	summary := [][]string{{l.T("compliance.csv.field"), l.T("compliance.csv.value")},
		{l.T("compliance.report.title_label"), c.Title},
		{l.T("compliance.report.version_label"), strconv.Itoa(b.Version.Version)},
		{l.T("compliance.report.status_label"), l.T("compliance.status." + b.Version.Status)},
		{l.T("compliance.report.period"), r.F.Date(c.PeriodFrom) + " – " + r.F.Date(c.PeriodTo.Add(-time.Second))},
		{l.T("compliance.report.profiles"), strings.Join(profiles, ", ")},
		{l.T("compliance.report.hosts"), strconv.Itoa(c.Summary.Hosts)},
		{l.T("compliance.report.generated_at"), r.F.DateTime(c.GeneratedAt)},
		{l.T("compliance.report.generated_by"), c.GeneratedBy},
		{"SHA-256", b.Version.SHA256},
	}
	if b.Version.FinalSHA256 != "" {
		summary = append(summary, []string{l.T("compliance.report.final_sha"), b.Version.FinalSHA256})
	}
	for _, wtext := range c.Summary.Warnings {
		summary = append(summary, []string{l.T("compliance.report.warning"), r.Text(wtext)})
	}
	summary = append(summary, []string{l.T("compliance.report.disclaimer_label"), r.Disclaimer()})
	if err := csvSheet(z, "summary.csv", comma, summary); err != nil {
		return err
	}

	controls := [][]string{{l.T("compliance.csv.profile"), l.T("compliance.csv.control"), l.T("compliance.csv.title"), l.T("compliance.csv.outcome"),
		l.T("compliance.csv.applicable"), l.T("compliance.csv.justification"), l.T("compliance.csv.checks"), l.T("compliance.csv.evidence"),
		l.T("compliance.csv.review"), l.T("compliance.csv.review_note"), l.T("compliance.csv.reviewed_by")}}
	for _, pa := range c.Controls {
		for _, ca := range pa.Controls {
			var checks []string
			for _, ch := range ca.Checks {
				checks = append(checks, r.CheckName(ch.Check)+": "+r.Outcome(ch.Outcome)+" ("+r.Relevance(ch.Relevance)+")")
			}
			a := b.assessment(pa.Profile, ca.ID)
			controls = append(controls, []string{r.ProfileName(pa.Profile) + " (" + pa.Profile + "@" + pa.Version + ")", ca.ID, r.ControlTitle(pa.Profile, ca.ID),
				r.Outcome(ca.Outcome), yn(ca.Applicable), ca.Justification, strings.Join(checks, "; "), strconv.Itoa(ca.Evidence),
				r.Review(a.ReviewStatus), a.ReviewNote, a.ReviewedBy})
		}
	}
	if err := csvSheet(z, "controls.csv", comma, controls); err != nil {
		return err
	}

	checks := [][]string{{l.T("compliance.csv.check"), l.T("compliance.csv.outcome"), l.T("compliance.csv.metrics"), l.T("compliance.csv.gaps"), l.T("compliance.csv.evidence")}}
	for _, ch := range c.Checks {
		var ms, gs []string
		for _, m := range ch.Metrics {
			n, v := r.Metric(m)
			ms = append(ms, n+": "+v)
		}
		for _, g := range ch.Gaps {
			gs = append(gs, r.Text(g))
		}
		checks = append(checks, []string{r.CheckLabel(ch.Check, ch.Platforms), r.Outcome(ch.Outcome), strings.Join(ms, "; "), strings.Join(gs, "; "), strconv.Itoa(ch.Evidence)})
	}
	if err := csvSheet(z, "checks.csv", comma, checks); err != nil {
		return err
	}

	gaps := [][]string{{l.T("compliance.csv.profile"), l.T("compliance.csv.control"), l.T("compliance.csv.title"), l.T("compliance.csv.outcome"),
		l.T("compliance.csv.gaps"), l.T("compliance.csv.recommendations")}}
	for _, g := range c.Gaps {
		var gs, rs []string
		for _, t := range g.Gaps {
			gs = append(gs, r.Text(t))
		}
		for _, t := range g.Recommendations {
			rs = append(rs, r.Text(t))
		}
		gaps = append(gaps, []string{r.ProfileName(g.Profile), g.Control, r.ControlTitle(g.Profile, g.Control), r.Outcome(g.Outcome), strings.Join(gs, "; "), strings.Join(rs, "; ")})
	}
	if err := csvSheet(z, "gaps.csv", comma, gaps); err != nil {
		return err
	}

	assets := [][]string{{l.T("compliance.csv.hostname"), l.T("compliance.csv.platform"), l.T("compliance.csv.os"), l.T("compliance.csv.os_version"),
		l.T("compliance.csv.agent"), l.T("compliance.csv.last_seen"), l.T("compliance.csv.groups"), l.T("compliance.csv.os_support")}}
	for _, a := range c.Inventory {
		sup := ""
		if a.OSSupport != "" {
			sup = l.T("eol.status." + a.OSSupport)
		}
		assets = append(assets, []string{a.Hostname, r.Platform(a.Platform), a.OSName, a.OSVersion, a.AgentVersion, r.F.DateTime(a.LastSeen),
			strings.Join(a.Groups, ", "), sup})
	}
	if err := csvSheet(z, "assets.csv", comma, assets); err != nil {
		return err
	}

	ev := [][]string{{"ID", l.T("compliance.csv.kind"), l.T("compliance.csv.occurred"), l.T("compliance.csv.hostname"), l.T("compliance.csv.platform"),
		l.T("compliance.csv.subject"), l.T("compliance.csv.outcome_raw"), l.T("compliance.csv.actor"), l.T("compliance.csv.controls"), "SHA-256"}}
	for _, e := range b.Evidence {
		actor := e.Actor
		if b.redacted(e) {
			actor = ""
		}
		var ctl []string
		for _, k := range b.Controls[e.ID] {
			ctl = append(ctl, r.ControlRef(k))
		}
		platform := ""
		if e.Platform != "" {
			platform = r.Platform(e.Platform)
		}
		ev = append(ev, []string{strconv.FormatInt(e.ID, 10), r.Kind(e.Kind), r.F.DateTime(e.OccurredAt), e.Hostname, platform, e.Subject, e.Outcome, actor,
			strings.Join(ctl, "; "), e.SHA256})
	}
	if err := csvSheet(z, "evidence.csv", comma, ev); err != nil {
		return err
	}
	return z.Close()
}
