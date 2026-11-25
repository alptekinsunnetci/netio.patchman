package web

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"netio.patchman/internal/compliance"
	"netio.patchman/internal/settings"
	"netio.patchman/internal/store"
	"netio.patchman/internal/timeutil"
)

// maxCompliancePeriodDays bounds a report's audit period.
const maxCompliancePeriodDays = 731

// outcomeClass maps an outcome to a pill style.
func outcomeClass(o string) string {
	switch o {
	case compliance.OutcomeSufficient:
		return "pill--succeeded"
	case compliance.OutcomePartial:
		return "pill--partial"
	case compliance.OutcomeDeviation:
		return "pill--failed"
	case compliance.OutcomeMissing:
		return "pill--warning"
	case compliance.OutcomeManualRequired:
		return "pill--queued"
	case compliance.OutcomeManualEvidence:
		return "pill--in_progress"
	}
	return "pill--expired"
}

// groupParam is the group preselected with ?group=.
func groupParam(r *http.Request) int64 {
	id, _ := strconv.ParseInt(r.URL.Query().Get("group"), 10, 64)
	return id
}

func (s *Server) renderer() compliance.Renderer { return compliance.Renderer{L: s.l, F: s.f} }

// userGroups returns the groups of a group-limited user (ok false: unlimited).
func userGroups(r *http.Request) ([]int64, bool) {
	sess := sessionFrom(r)
	if sess == nil {
		return nil, false
	}
	return sess.user.Scope()
}

func (s *Server) reportVisible(r *http.Request, rep store.ComplianceReport) bool {
	ids, limited := userGroups(r)
	return store.ReportVisibleTo(rep, ids, limited)
}

func (s *Server) cfg(r *http.Request) settings.Values {
	v, _ := settings.Load(r.Context(), s.st)
	return v
}

// enabledProfiles are the latest versions of the profiles enabled in the policies.
func enabledProfiles(cfg settings.Values) []compliance.Profile {
	on := map[string]bool{}
	for _, p := range cfg.ComplianceProfiles {
		on[p] = true
	}
	var out []compliance.Profile
	for _, p := range compliance.Profiles() {
		if on[p.ID] {
			out = append(out, p)
		}
	}
	return out
}

type outcomeCount struct {
	Outcome string
	N       int
}

func outcomeCounts(m map[string]int) []outcomeCount {
	var out []outcomeCount
	for _, o := range compliance.Outcomes {
		if m[o] > 0 {
			out = append(out, outcomeCount{o, m[o]})
		}
	}
	return out
}

// ---------- overview ----------

type reportListRow struct {
	store.ComplianceReport
	Profiles []string // names
	Scope    string
	Counts   []outcomeCount
	Gen      genStatus // background generation of a new version
}

func (s *Server) reportRows(r *http.Request, reports []store.ComplianceReport, withCounts int) []reportListRow {
	rd := s.renderer()
	groups := map[int64]string{}
	if gs, err := s.st.ListGroups(r.Context()); err == nil {
		for _, g := range gs {
			groups[g.ID] = g.Name
		}
	}
	var out []reportListRow
	for _, rep := range reports {
		if !s.reportVisible(r, rep) {
			continue
		}
		row := reportListRow{ComplianceReport: rep, Scope: s.l.T("compliance.scope.all"), Gen: s.gen.status(rep.ID)}
		for _, k := range rep.Profiles {
			id, _, _ := strings.Cut(k, "@")
			row.Profiles = append(row.Profiles, rd.ProfileName(id))
		}
		if rep.GroupID != 0 {
			row.Scope = s.l.T("compliance.scope.group", "name", groups[rep.GroupID])
		}
		if len(rep.Platforms) > 0 {
			var ps []string
			for _, p := range rep.Platforms {
				ps = append(ps, rd.Platform(p))
			}
			row.Scope += " · " + strings.Join(ps, ", ")
		}
		if len(out) < withCounts && rep.LatestVersion > 0 {
			if v, err := s.st.ReportVersionByNumber(r.Context(), rep.ID, rep.LatestVersion); err == nil {
				if c, err := compliance.Decode(v.Content); err == nil {
					total := map[string]int{}
					for _, p := range c.Summary.Profiles {
						for o, n := range p.Outcomes {
							total[o] += n
						}
					}
					row.Counts = outcomeCounts(total)
				}
			}
		}
		out = append(out, row)
	}
	return out
}

func (s *Server) complianceOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	reports, err := s.st.ListComplianceReports(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	rows := s.reportRows(r, reports, 6)
	if len(rows) > 6 {
		rows = rows[:6]
	}
	finals := 0
	for _, rep := range reports {
		if rep.HasFinal && s.reportVisible(r, rep) {
			finals++
		}
	}
	data := map[string]any{"Reports": rows, "Finals": finals, "Profiles": enabledProfiles(s.cfg(r))}
	if !s.limited(r) {
		counts, err := s.st.EvidenceKindCounts(ctx)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		total := 0
		var kinds []outcomeCount
		for _, k := range store.EvidenceKinds {
			if k == store.EvidenceAudit && !sessionFrom(r).user.IsAdmin() {
				continue
			}
			total += counts[k]
			kinds = append(kinds, outcomeCount{k, counts[k]})
		}
		start, _ := s.st.EvidenceStart(ctx)
		data["Kinds"], data["EvidenceTotal"], data["Start"] = kinds, total, start
	}
	d := s.page(r, s.l.T("compliance.title"), "compliance")
	d.Data = data
	s.render(w, r, http.StatusOK, "compliance", d)
}

// ---------- reports ----------

type platformOption struct {
	ID      string
	Checked bool
}

func (s *Server) complianceReports(w http.ResponseWriter, r *http.Request) {
	reports, err := s.st.ListComplianceReports(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	groups, err := s.st.ListGroups(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	loc := s.f.Location()
	y, m, day := timeutil.Now().In(loc).Date()
	today := time.Date(y, m, day, 0, 0, 0, 0, loc)
	var platforms []platformOption
	for _, p := range store.Platforms {
		platforms = append(platforms, platformOption{ID: p})
	}
	d := s.page(r, s.l.T("nav.compliance_reports"), "compliance_reports")
	d.Data = map[string]any{"Reports": s.reportRows(r, reports, 50), "Profiles": enabledProfiles(s.cfg(r)), "Groups": groups,
		"Limited": s.limited(r), "Platforms": platforms, "Presets": []string{"30d", "90d", "quarter", "12m", "year", "custom"},
		"From": today.AddDate(0, 0, -89).Format("2006-01-02"), "To": today.Format("2006-01-02"), "MaxDays": maxCompliancePeriodDays,
		"Group": groupParam(r)}
	s.render(w, r, http.StatusOK, "compliancereports", d)
}

// periodFor computes [from, to) in the display zone from a preset or dates.
func (s *Server) periodFor(preset, fromS, toS string) (time.Time, time.Time, bool) {
	loc := s.f.Location()
	y, m, day := timeutil.Now().In(loc).Date()
	today := time.Date(y, m, day, 0, 0, 0, 0, loc)
	end := today.AddDate(0, 0, 1)
	switch preset {
	case "30d":
		return today.AddDate(0, 0, -29), end, true
	case "90d":
		return today.AddDate(0, 0, -89), end, true
	case "12m":
		return today.AddDate(-1, 0, 1), end, true
	case "quarter":
		q := (int(m)-1)/3*3 + 1
		start := time.Date(y, time.Month(q), 1, 0, 0, 0, 0, loc).AddDate(0, -3, 0)
		return start, start.AddDate(0, 3, 0), true
	case "year":
		start := time.Date(y-1, 1, 1, 0, 0, 0, 0, loc)
		return start, start.AddDate(1, 0, 0), true
	}
	from, err1 := time.ParseInLocation("2006-01-02", fromS, loc)
	to, err2 := time.ParseInLocation("2006-01-02", toS, loc)
	if err1 != nil || err2 != nil || to.Before(from) {
		return time.Time{}, time.Time{}, false
	}
	to = to.AddDate(0, 0, 1)
	if to.Sub(from) > maxCompliancePeriodDays*24*time.Hour {
		return time.Time{}, time.Time{}, false
	}
	return from, to, true
}

func (s *Server) complianceReportCreate(w http.ResponseWriter, r *http.Request) {
	back := "/compliance/reports"
	title := strings.TrimSpace(r.PostFormValue("title"))
	if title == "" || len([]rune(title)) > 200 {
		s.redirect(w, r, back, "error", s.l.T("compliance.error.title"))
		return
	}
	enabled := map[string]bool{}
	for _, p := range enabledProfiles(s.cfg(r)) {
		enabled[p.Key()] = true
	}
	var profiles []string
	for _, k := range r.PostForm["profiles"] {
		if enabled[k] {
			profiles = append(profiles, k)
		}
	}
	if len(profiles) == 0 || len(profiles) != len(r.PostForm["profiles"]) {
		s.redirect(w, r, back, "error", s.l.T("compliance.error.profiles"))
		return
	}
	from, to, ok := s.periodFor(r.PostFormValue("preset"), r.PostFormValue("from"), r.PostFormValue("to"))
	if !ok {
		s.redirect(w, r, back, "error", s.l.T("compliance.error.period", "max", maxCompliancePeriodDays))
		return
	}
	groupID, _ := strconv.ParseInt(r.PostFormValue("group"), 10, 64)
	if groupID != 0 {
		if _, err := s.st.GroupByID(r.Context(), groupID); err != nil {
			s.redirect(w, r, back, "error", s.l.T("compliance.error.group"))
			return
		}
	}
	if ids, limited := userGroups(r); limited {
		allowed := false
		for _, g := range ids {
			allowed = allowed || g == groupID
		}
		if !allowed || groupID == 0 {
			s.redirect(w, r, back, "error", s.l.T("compliance.error.group_required"))
			return
		}
	}
	var platforms []string
	for _, p := range r.PostForm["platforms"] {
		if !store.ValidPlatform(p) {
			s.redirect(w, r, back, "error", s.l.T("compliance.error.platform"))
			return
		}
		platforms = append(platforms, p)
	}
	if len(platforms) == len(store.Platforms) {
		platforms = nil
	}
	note := strings.TrimSpace(r.PostFormValue("note"))
	if len([]rune(note)) > 2000 {
		note = string([]rune(note)[:2000])
	}
	u := sessionFrom(r).user
	rep := store.ComplianceReport{Title: title, Profiles: profiles, From: from.UTC(), To: to.UTC(), GroupID: groupID, Platforms: platforms, Note: note,
		CreatedByID: u.ID, CreatedBy: u.Email}
	id, err := s.st.CreateComplianceReport(r.Context(), rep)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	rep.ID = id
	details := "report_id=" + strconv.FormatInt(id, 10) + " profiles=" + strings.Join(profiles, ",")
	n, err := s.startVersion(r, rep, nil, s.auditEntry(r, "compliance.report_create", title, ""), func(int) string { return details })
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if n == 0 {
		s.redirect(w, r, "/compliance/reports", "info", s.l.T("compliance.report.generating", "title", title))
		return
	}
	s.redirect(w, r, reportURL(id, n), "success", s.l.T("compliance.report.created"))
}

// loadReport reads the report of the path and checks that the user may see it.
func (s *Server) loadReport(w http.ResponseWriter, r *http.Request) (store.ComplianceReport, bool) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	rep, err := s.st.ComplianceReportByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && !s.reportVisible(r, rep)) {
		s.errorPage(w, r, http.StatusNotFound, "error.not_found")
		return rep, false
	}
	if err != nil {
		s.serverError(w, r, err)
		return rep, false
	}
	return rep, true
}

// loadVersion reads the version of the path (or ?v=, default the latest).
func (s *Server) loadVersion(w http.ResponseWriter, r *http.Request, rep store.ComplianceReport) (store.ReportVersion, bool) {
	n, err := strconv.Atoi(r.PathValue("n"))
	if err != nil {
		n, _ = strconv.Atoi(r.URL.Query().Get("v"))
	}
	if n <= 0 {
		n = rep.LatestVersion
	}
	v, err := s.st.ReportVersionByNumber(r.Context(), rep.ID, n)
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, r, http.StatusNotFound, "error.not_found")
		return v, false
	}
	if err != nil {
		s.serverError(w, r, err)
		return v, false
	}
	return v, true
}

type ctlCheckRow struct {
	Label     string
	Relevance string
	Outcome   string
}

type ctlRow struct {
	ID, Title, Desc string
	Outcome         string
	Applicable      bool
	Justification   string
	Checks          []ctlCheckRow
	Manual          string
	ManualItems     int
	Evidence        int
	Review          store.ControlAssessment
}

type profileBlock struct {
	ID, Version, Name, Desc string
	Counts                  []outcomeCount
	Rows                    []ctlRow
}

type metricRow struct{ Name, Value string }

type checkRow struct {
	Label    string
	Outcome  string
	Metrics  []metricRow
	Gaps     []string
	Evidence int
}

type gapRow struct {
	Profile, Control, Title, Outcome string
	Gaps, Recs                       []string
}

type kvRow struct {
	Label string
	N     int
}

func sortedCounts(m map[string]int, label func(string) string) []kvRow {
	var out []kvRow
	for k, n := range m {
		out = append(out, kvRow{label(k), n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].N != out[j].N {
			return out[i].N > out[j].N
		}
		return out[i].Label < out[j].Label
	})
	return out
}

func (s *Server) complianceReport(w http.ResponseWriter, r *http.Request) {
	rep, ok := s.loadReport(w, r)
	if !ok {
		return
	}
	gen := s.gen.status(rep.ID)
	if rep.LatestVersion == 0 {
		switch {
		case gen.Running:
			s.redirect(w, r, "/compliance/reports", "info", s.l.T("compliance.report.generating", "title", rep.Title))
		case gen.Err != "":
			s.redirect(w, r, "/compliance/reports", "error", s.l.T("compliance.report.generate_failed"))
		default:
			s.errorPage(w, r, http.StatusNotFound, "error.not_found")
		}
		return
	}
	v, ok := s.loadVersion(w, r, rep)
	if !ok {
		return
	}
	ctx := r.Context()
	content, err := compliance.Decode(v.Content)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	versions, err := s.st.ReportVersions(ctx, rep.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	assessments, err := s.st.ControlAssessments(ctx, v.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	review := map[string]store.ControlAssessment{}
	for _, a := range assessments {
		review[a.Profile+":"+a.Control] = a
	}
	rd := s.renderer()
	var blocks []profileBlock
	for i, pa := range content.Controls {
		b := profileBlock{ID: pa.Profile, Version: pa.Version, Name: rd.ProfileName(pa.Profile), Desc: s.l.T("compliance.profile." + pa.Profile + ".desc")}
		if i < len(content.Summary.Profiles) {
			b.Counts = outcomeCounts(content.Summary.Profiles[i].Outcomes)
		}
		for _, ca := range pa.Controls {
			row := ctlRow{ID: ca.ID, Title: rd.ControlTitle(pa.Profile, ca.ID), Desc: rd.ControlDesc(pa.Profile, ca.ID), Outcome: ca.Outcome,
				Applicable: ca.Applicable, Justification: ca.Justification, ManualItems: ca.ManualItems, Evidence: ca.Evidence, Review: review[pa.Profile+":"+ca.ID]}
			if ca.Manual != "" {
				row.Manual = s.l.T("compliance.manual." + ca.Manual)
			}
			for _, cc := range ca.Checks {
				var ps []string
				for _, ch := range content.Checks {
					if ch.Key == cc.Key {
						ps = ch.Platforms
					}
				}
				row.Checks = append(row.Checks, ctlCheckRow{Label: rd.CheckLabel(cc.Check, ps), Relevance: rd.Relevance(cc.Relevance), Outcome: cc.Outcome})
			}
			b.Rows = append(b.Rows, row)
		}
		blocks = append(blocks, b)
	}
	var checks []checkRow
	for _, ch := range content.Checks {
		row := checkRow{Label: rd.CheckLabel(ch.Check, ch.Platforms), Outcome: ch.Outcome, Evidence: ch.Evidence}
		for _, m := range ch.Metrics {
			n, val := rd.Metric(m)
			row.Metrics = append(row.Metrics, metricRow{n, val})
		}
		for _, g := range ch.Gaps {
			row.Gaps = append(row.Gaps, rd.Text(g))
		}
		checks = append(checks, row)
	}
	var gaps []gapRow
	for _, g := range content.Gaps {
		row := gapRow{Profile: rd.ProfileName(g.Profile), Control: g.Control, Title: rd.ControlTitle(g.Profile, g.Control), Outcome: g.Outcome}
		for _, t := range g.Gaps {
			row.Gaps = append(row.Gaps, rd.Text(t))
		}
		for _, t := range g.Recommendations {
			row.Recs = append(row.Recs, rd.Text(t))
		}
		gaps = append(gaps, row)
	}
	var warnings []string
	for _, t := range content.Summary.Warnings {
		warnings = append(warnings, rd.Text(t))
	}
	var platforms []kvRow
	for _, p := range store.Platforms {
		if n := content.Summary.ByPlatform[p]; n > 0 {
			platforms = append(platforms, kvRow{rd.Platform(p), n})
		}
	}
	scope := s.l.T("compliance.scope.all")
	if content.Scope.GroupName != "" {
		scope = s.l.T("compliance.scope.group", "name", content.Scope.GroupName)
	}
	var scopePlatforms []string
	for _, p := range content.Scope.Platforms {
		scopePlatforms = append(scopePlatforms, rd.Platform(p))
	}
	inventory := content.Inventory
	if len(inventory) > 500 {
		inventory = inventory[:500]
	}
	evidence := content.Evidence.Items
	if len(evidence) > 100 {
		evidence = evidence[:100]
	}
	u := sessionFrom(r).user
	d := s.page(r, rep.Title, "compliance_reports")
	d.Data = map[string]any{"Report": rep, "V": v, "C": content, "Versions": versions, "Blocks": blocks, "Checks": checks, "Gaps": gaps,
		"Warnings": warnings, "Platforms": platforms, "Scope": scope, "ScopePlatforms": strings.Join(scopePlatforms, ", "),
		"Inventory": inventory, "InventoryTotal": len(content.Inventory), "Evidence": evidence,
		"ByType":   sortedCounts(content.Changes.ByType, func(k string) string { return s.l.T("job.type." + k) }),
		"ByOrigin": sortedCounts(content.Changes.ByOrigin, func(k string) string { return s.l.T("compliance.origin." + k) }),
		"ByAction": sortedCounts(content.Audit.ByAction, func(k string) string { return s.l.T("audit.action." + k) }),
		"MeanFix":  rd.Number(content.Vulnerabilities.MeanFixDays), "Disclaimer": rd.Disclaimer(),
		"CanReview": u.IsAdmin() && !v.Final(), "CanRegenerate": u.CanOperate(), "Latest": v.Version == rep.LatestVersion,
		"PeriodEnd": content.PeriodTo.Add(-time.Second), "Reviews": []string{store.ReviewNone, store.ReviewAccepted, store.ReviewGap}, "Gen": gen}
	s.render(w, r, http.StatusOK, "compliancereport", d)
}

func (s *Server) complianceRegenerate(w http.ResponseWriter, r *http.Request) {
	rep, ok := s.loadReport(w, r)
	if !ok {
		return
	}
	var prev []store.ControlAssessment
	if rep.LatestVersion > 0 {
		v, err := s.st.ReportVersionByNumber(r.Context(), rep.ID, rep.LatestVersion)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		if prev, err = s.st.ControlAssessments(r.Context(), v.ID); err != nil {
			s.serverError(w, r, err)
			return
		}
	}
	n, err := s.startVersion(r, rep, prev, s.auditEntry(r, "compliance.report_regenerate", rep.Title, ""), func(n int) string {
		return "report_id=" + strconv.FormatInt(rep.ID, 10) + " version=" + strconv.Itoa(n)
	})
	back := reportURL(rep.ID, 0)
	if rep.LatestVersion == 0 {
		back = "/compliance/reports"
	}
	switch {
	case errors.Is(err, errGenBusy):
		s.redirect(w, r, back, "info", s.l.T("compliance.report.busy"))
	case err != nil:
		s.serverError(w, r, err)
	case n == 0:
		s.redirect(w, r, back, "info", s.l.T("compliance.report.generating", "title", rep.Title))
	default:
		s.redirect(w, r, reportURL(rep.ID, n), "success", s.l.T("compliance.report.regenerated", "n", n))
	}
}

func (s *Server) complianceReview(w http.ResponseWriter, r *http.Request) {
	rep, ok := s.loadReport(w, r)
	if !ok {
		return
	}
	v, ok := s.loadVersion(w, r, rep)
	if !ok {
		return
	}
	profile, control := r.PostFormValue("profile"), r.PostFormValue("control")
	back := "/compliance/reports/" + strconv.FormatInt(rep.ID, 10) + "?v=" + strconv.Itoa(v.Version) + "#c-" + profile + "-" + control
	err := s.st.ReviewControl(r.Context(), v.ID, profile, control, r.PostFormValue("status"), r.PostFormValue("note"), sessionFrom(r).user.Email)
	switch {
	case errors.Is(err, store.ErrReportFinal):
		s.redirect(w, r, back, "error", s.l.T("compliance.error.final"))
		return
	case errors.Is(err, store.ErrNotFound):
		s.errorPage(w, r, http.StatusNotFound, "error.not_found")
		return
	case err != nil:
		s.redirect(w, r, back, "error", s.l.T("compliance.error.review"))
		return
	}
	s.audit(r, "compliance.review", rep.Title, "report_id="+strconv.FormatInt(rep.ID, 10)+" version="+strconv.Itoa(v.Version)+
		" control="+profile+":"+control+" status="+r.PostFormValue("status"))
	s.redirect(w, r, back, "success", s.l.T("compliance.review.saved"))
}

func (s *Server) complianceFinalize(w http.ResponseWriter, r *http.Request) {
	rep, ok := s.loadReport(w, r)
	if !ok {
		return
	}
	v, ok := s.loadVersion(w, r, rep)
	if !ok {
		return
	}
	back := "/compliance/reports/" + strconv.FormatInt(rep.ID, 10) + "?v=" + strconv.Itoa(v.Version)
	assessments, err := s.st.ControlAssessments(r.Context(), v.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	err = s.st.FinalizeVersion(r.Context(), v.ID, sessionFrom(r).user.Email, compliance.FinalDigest(v.SHA256, assessments))
	if errors.Is(err, store.ErrReportFinal) {
		s.redirect(w, r, back, "error", s.l.T("compliance.error.final"))
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "compliance.report_finalize", rep.Title, "report_id="+strconv.FormatInt(rep.ID, 10)+" version="+strconv.Itoa(v.Version))
	s.redirect(w, r, back, "success", s.l.T("compliance.report.finalized_msg"))
}

func (s *Server) complianceDelete(w http.ResponseWriter, r *http.Request) {
	rep, ok := s.loadReport(w, r)
	if !ok {
		return
	}
	err := s.st.DeleteComplianceReport(r.Context(), rep.ID)
	if errors.Is(err, store.ErrReportFinal) {
		s.redirect(w, r, "/compliance/reports/"+strconv.FormatInt(rep.ID, 10), "error", s.l.T("compliance.error.delete_final"))
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "compliance.report_delete", rep.Title, "report_id="+strconv.FormatInt(rep.ID, 10))
	s.redirect(w, r, "/compliance/reports", "success", s.l.T("compliance.report.deleted"))
}

// bundle loads what an export of a version contains.
func (s *Server) bundle(r *http.Request, rep store.ComplianceReport, v store.ReportVersion) (compliance.Bundle, error) {
	ctx := r.Context()
	b := compliance.Bundle{Report: rep, Version: v, Redact: !sessionFrom(r).user.IsAdmin()}
	var err error
	if b.Content, err = compliance.Decode(v.Content); err != nil {
		return b, err
	}
	if b.Assessments, err = s.st.ControlAssessments(ctx, v.ID); err != nil {
		return b, err
	}
	if b.Evidence, err = s.st.EvidenceItems(ctx, store.EvidenceFilter{VersionID: v.ID}); err != nil {
		return b, err
	}
	b.Controls, err = s.st.VersionEvidenceControls(ctx, v.ID)
	return b, err
}

func (s *Server) complianceExport(w http.ResponseWriter, r *http.Request) {
	rep, ok := s.loadReport(w, r)
	if !ok {
		return
	}
	v, ok := s.loadVersion(w, r, rep)
	if !ok {
		return
	}
	format := r.URL.Query().Get("format")
	b, err := s.bundle(r, rep, v)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	name := "netio-patchman-compliance-" + strconv.FormatInt(rep.ID, 10) + "-v" + strconv.Itoa(v.Version)
	var buf bytes.Buffer
	var ctype string
	switch format {
	case "json":
		ctype, name = "application/json; charset=utf-8", name+".json"
		err = compliance.WriteJSON(&buf, b)
	case "csv":
		ctype, name = "application/zip", name+"-csv.zip"
		err = compliance.WriteCSVZip(&buf, b, s.renderer())
	case "pdf":
		ctype, name = "application/pdf", name+".pdf"
		err = compliance.WritePDF(&buf, b, s.renderer())
	default:
		s.errorPage(w, r, http.StatusNotFound, "error.not_found")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "compliance.export", rep.Title, "report_id="+strconv.FormatInt(rep.ID, 10)+" version="+strconv.Itoa(v.Version)+" format="+format)
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = buf.WriteTo(w)
}

// ---------- evidence ----------

type controlOption struct {
	Key, Label string
}

func (s *Server) controlOptions(cfg settings.Values) []controlOption {
	rd := s.renderer()
	var out []controlOption
	for _, p := range enabledProfiles(cfg) {
		for _, c := range p.Controls {
			out = append(out, controlOption{Key: p.ID + ":" + c.ID, Label: rd.ProfileName(p.ID) + " · " + c.ID + " " + rd.ControlTitle(p.ID, c.ID)})
		}
	}
	return out
}

func (s *Server) evidenceFilter(r *http.Request) store.EvidenceFilter {
	q := r.URL.Query()
	f := store.EvidenceFilter{Platform: q.Get("platform"), Query: q.Get("q")}
	if k := q.Get("kind"); k != "" {
		f.Kinds = []string{k}
	}
	if !store.ValidPlatform(f.Platform) {
		f.Platform = ""
	}
	loc := s.f.Location()
	if t, err := time.ParseInLocation("2006-01-02", q.Get("from"), loc); err == nil {
		f.From = t
	}
	if t, err := time.ParseInLocation("2006-01-02", q.Get("to"), loc); err == nil {
		f.To = t.AddDate(0, 0, 1)
	}
	f.VersionID, _ = strconv.ParseInt(q.Get("version"), 10, 64)
	f.Control = q.Get("control")
	if !sessionFrom(r).user.IsAdmin() {
		if len(f.Kinds) == 1 && f.Kinds[0] == store.EvidenceAudit {
			f.Kinds = []string{"-"}
		}
		if len(f.Kinds) == 0 {
			for _, k := range store.EvidenceKinds {
				if k != store.EvidenceAudit {
					f.Kinds = append(f.Kinds, k)
				}
			}
		}
	}
	return f
}

func (s *Server) complianceEvidence(w http.ResponseWriter, r *http.Request) {
	f := s.evidenceFilter(r)
	pg := pageNumber(r)
	items, total, err := s.st.ListEvidence(r.Context(), f, store.Page{Number: pg, Size: pageSize})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	kinds := store.EvidenceKinds
	if !sessionFrom(r).user.IsAdmin() {
		kinds = nil
		for _, k := range store.EvidenceKinds {
			if k != store.EvidenceAudit {
				kinds = append(kinds, k)
			}
		}
	}
	q := r.URL.Query()
	cfg := s.cfg(r)
	loc := s.f.Location()
	d := s.page(r, s.l.T("nav.compliance_evidence"), "compliance_evidence")
	d.Data = map[string]any{"Items": items, "Pager": newPager(r, pg, total), "Total": total, "Kinds": kinds, "Platforms": store.Platforms,
		"Q": q, "CanAdd": sessionFrom(r).user.CanOperate() && !s.limited(r), "Controls": s.controlOptions(cfg),
		"Today": timeutil.Now().In(loc).Format("2006-01-02"), "Version": f.VersionID, "Control": f.Control}
	s.render(w, r, http.StatusOK, "complianceevidence", d)
}

func (s *Server) complianceEvidenceAdd(w http.ResponseWriter, r *http.Request) {
	back := "/compliance/evidence"
	if s.limited(r) {
		s.errorPage(w, r, http.StatusForbidden, "error.forbidden")
		return
	}
	title := strings.TrimSpace(r.PostFormValue("title"))
	reference := strings.TrimSpace(r.PostFormValue("reference"))
	desc := strings.TrimSpace(r.PostFormValue("description"))
	if title == "" || len([]rune(title)) > 200 || len([]rune(reference)) > 500 || len([]rune(desc)) > 2000 {
		s.redirect(w, r, back, "error", s.l.T("compliance.error.evidence"))
		return
	}
	valid := map[string]bool{}
	for _, c := range s.controlOptions(s.cfg(r)) {
		valid[c.Key] = true
	}
	var controls []string
	for _, c := range r.PostForm["controls"] {
		if !valid[c] {
			s.redirect(w, r, back, "error", s.l.T("compliance.error.evidence_controls"))
			return
		}
		controls = append(controls, c)
	}
	if len(controls) == 0 {
		s.redirect(w, r, back, "error", s.l.T("compliance.error.evidence_controls"))
		return
	}
	at := timeutil.Now()
	if v := r.PostFormValue("date"); v != "" {
		t, err := time.ParseInLocation("2006-01-02", v, s.f.Location())
		if err != nil || t.After(at) {
			s.redirect(w, r, back, "error", s.l.T("compliance.error.evidence_date"))
			return
		}
		at = t
	}
	var rnd [12]byte
	_, _ = rand.Read(rnd[:])
	payload, _ := json.Marshal(map[string]any{"title": title, "reference": reference, "description": desc, "controls": controls,
		"document_date": at.In(s.f.Location()).Format("2006-01-02")})
	u := sessionFrom(r).user
	if _, err := s.st.AddEvidence(r.Context(), []store.EvidenceItem{{Kind: store.EvidenceManual, Source: store.SourceUser,
		SourceRef: "manual:" + hex.EncodeToString(rnd[:]), Subject: title, Actor: u.Email, Outcome: "recorded", OccurredAt: at.UTC(),
		Payload: string(payload)}}); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "compliance.evidence_add", title, "controls="+strings.Join(controls, ","))
	s.redirect(w, r, back+"?kind=manual", "success", s.l.T("compliance.evidence.added"))
}

type payloadRow struct{ Key, Value string }

func (s *Server) complianceEvidenceItem(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	e, err := s.st.EvidenceByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && e.Kind == store.EvidenceAudit && !sessionFrom(r).user.IsAdmin()) {
		s.errorPage(w, r, http.StatusNotFound, "error.not_found")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	uses, err := s.st.EvidenceUses(r.Context(), id)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	var visible []store.EvidenceUse
	reports := map[int64]bool{}
	for _, u := range uses {
		ok, seen := reports[u.ReportID]
		if !seen {
			if rep, err := s.st.ComplianceReportByID(r.Context(), u.ReportID); err == nil {
				ok = s.reportVisible(r, rep)
			}
			reports[u.ReportID] = ok
		}
		if ok {
			visible = append(visible, u)
		}
	}
	rd := s.renderer()
	type useRow struct {
		store.EvidenceUse
		Ref, Relevance string
	}
	var rows []useRow
	for _, u := range visible {
		rows = append(rows, useRow{u, rd.ProfileName(u.Profile) + " · " + u.Control + " " + rd.ControlTitle(u.Profile, u.Control), rd.Relevance(u.Relevance)})
	}
	var payload []payloadRow
	m := e.PayloadMap()
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		val := m[k]
		var text string
		switch x := val.(type) {
		case string:
			text = x
		default:
			b, _ := json.Marshal(x)
			text = string(b)
		}
		if k == "controls" {
			if list, ok := val.([]any); ok {
				var names []string
				for _, c := range list {
					if cs, ok := c.(string); ok {
						names = append(names, rd.ControlRef(cs))
					}
				}
				text = strings.Join(names, ", ")
			}
		}
		payload = append(payload, payloadRow{k, text})
	}
	d := s.page(r, s.l.T("compliance.evidence.item", "id", id), "compliance_evidence")
	d.Data = map[string]any{"E": e, "Uses": rows, "Payload": payload}
	s.render(w, r, http.StatusOK, "complianceitem", d)
}

// ---------- history ----------

func (s *Server) complianceHistory(w http.ResponseWriter, r *http.Request) {
	tab := r.URL.Query().Get("tab")
	admin := sessionFrom(r).user.IsAdmin()
	if (tab == "audit" || tab == "integrity") && !admin {
		tab = ""
	}
	if tab == "" {
		tab = "versions"
	}
	data := map[string]any{"Tab": tab}
	pg := pageNumber(r)
	switch tab {
	case "versions":
		versions, total, err := s.st.AllReportVersions(r.Context(), store.Page{Number: pg, Size: pageSize})
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		if s.limited(r) {
			reports := map[int64]bool{}
			var keep []store.ReportVersion
			for _, v := range versions {
				ok, seen := reports[v.ReportID]
				if !seen {
					if rep, err := s.st.ComplianceReportByID(r.Context(), v.ReportID); err == nil {
						ok = s.reportVisible(r, rep)
					}
					reports[v.ReportID] = ok
				}
				if ok {
					keep = append(keep, v)
				}
			}
			versions = keep
		}
		data["Versions"], data["Pager"] = versions, newPager(r, pg, total)
	case "audit":
		rows, total, err := s.st.ListAudit(r.Context(), store.Page{Number: pg, Size: pageSize})
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		data["Rows"], data["Pager"] = rows, newPager(r, pg, total)
	case "integrity":
		st, err := s.st.VerifyEvidence(r.Context())
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		data["Chain"] = st
		data["CheckedAt"] = timeutil.Now()
	}
	d := s.page(r, s.l.T("nav.compliance_history"), "compliance_history")
	d.Data = data
	s.render(w, r, http.StatusOK, "compliancehistory", d)
}

// ---------- policies ----------

type policyControl struct {
	ID, Title, Desc string
	Checks          []string
	Manual          string
	Setting         store.ControlSetting
	Applicable      bool
}

type policyProfile struct {
	ID, Key, Name, Desc string
	Enabled             bool
	Controls            []policyControl
}

func (s *Server) compliancePolicies(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfg(r)
	tab := r.URL.Query().Get("tab")
	if tab != "controls" {
		tab = "general"
	}
	stored, err := s.st.ControlSettings(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	on := map[string]bool{}
	for _, p := range cfg.ComplianceProfiles {
		on[p] = true
	}
	rd := s.renderer()
	var profiles []policyProfile
	for _, p := range compliance.Profiles() {
		pp := policyProfile{ID: p.ID, Key: p.Key(), Name: rd.ProfileName(p.ID), Desc: s.l.T("compliance.profile." + p.ID + ".desc"), Enabled: on[p.ID]}
		for _, c := range p.Controls {
			pc := policyControl{ID: c.ID, Title: rd.ControlTitle(p.ID, c.ID), Desc: rd.ControlDesc(p.ID, c.ID), Applicable: true}
			if st, ok := stored[p.ID+":"+c.ID]; ok {
				pc.Setting, pc.Applicable = st, st.Applicable
			}
			for _, ref := range c.Checks {
				pc.Checks = append(pc.Checks, rd.CheckLabel(ref.Check, ref.Platforms)+" · "+rd.Relevance(ref.Relevance))
			}
			if c.Manual != "" {
				pc.Manual = s.l.T("compliance.manual." + c.Manual)
			}
			pp.Controls = append(pp.Controls, pc)
		}
		profiles = append(profiles, pp)
	}
	d := s.page(r, s.l.T("nav.compliance_policies"), "compliance_policies")
	d.Data = map[string]any{"Tab": tab, "Cfg": cfg, "Profiles": profiles, "MinEvidenceDays": settings.MinEvidenceDays}
	s.render(w, r, http.StatusOK, "compliancepolicies", d)
}

func (s *Server) compliancePoliciesSave(w http.ResponseWriter, r *http.Request) {
	back := "/compliance/policies"
	var profiles []string
	for _, p := range compliance.Profiles() {
		for _, v := range r.PostForm["profiles"] {
			if v == p.ID {
				profiles = append(profiles, p.ID)
			}
		}
	}
	if len(profiles) == 0 {
		s.redirect(w, r, back, "error", s.l.T("compliance.error.profiles"))
		return
	}
	kv := map[string]string{settings.KeyComplianceProfiles: strings.Join(profiles, ",")}
	for _, f := range []struct {
		key    string
		lo, hi int
	}{
		{settings.KeyComplianceCoverageMin, 0, 100}, {settings.KeyCompliancePatchFailMax, 0, 100}, {settings.KeyComplianceCurrencyMin, 0, 100},
		{settings.KeyComplianceSLAMin, 0, 100}, {settings.KeyComplianceRebootMaxDays, 1, 365}, {settings.KeyComplianceEvidenceDays, settings.MinEvidenceDays, 3650},
	} {
		n, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue(strings.ReplaceAll(f.key, ".", "_"))))
		if err != nil || n < f.lo || n > f.hi {
			s.redirect(w, r, back, "error", s.l.T("compliance.error.threshold", "min", f.lo, "max", f.hi))
			return
		}
		kv[f.key] = strconv.Itoa(n)
	}
	if err := s.st.SaveSettings(r.Context(), kv); err != nil {
		s.serverError(w, r, err)
		return
	}
	var details []string
	for _, k := range []string{settings.KeyComplianceProfiles, settings.KeyComplianceCoverageMin, settings.KeyCompliancePatchFailMax,
		settings.KeyComplianceCurrencyMin, settings.KeyComplianceSLAMin, settings.KeyComplianceRebootMaxDays, settings.KeyComplianceEvidenceDays} {
		details = append(details, k+"="+kv[k])
	}
	s.audit(r, "compliance.policy", "", strings.Join(details, " "))
	s.redirect(w, r, back, "success", s.l.T("compliance.policies.saved"))
}

func (s *Server) complianceControlsSave(w http.ResponseWriter, r *http.Request) {
	back := "/compliance/policies?tab=controls"
	p, ok := compliance.Latest(r.PostFormValue("profile"))
	if !ok {
		s.redirect(w, r, back, "error", s.l.T("compliance.error.profiles"))
		return
	}
	stored, err := s.st.ControlSettings(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	by := sessionFrom(r).user.Email
	var changed []string
	for _, c := range p.Controls {
		applicable := r.PostFormValue("applicable_"+c.ID) == "1"
		just := strings.TrimSpace(r.PostFormValue("justification_" + c.ID))
		if !applicable && just == "" {
			s.redirect(w, r, back+"#p-"+p.ID, "error", s.l.T("compliance.error.justification", "control", c.ID))
			return
		}
		old, had := stored[p.ID+":"+c.ID]
		if (had && old.Applicable == applicable && old.Justification == just) || (!had && applicable && just == "") {
			continue
		}
		if err := s.st.SaveControlSetting(r.Context(), store.ControlSetting{Profile: p.ID, Control: c.ID, Applicable: applicable, Justification: just, UpdatedBy: by}); err != nil {
			s.serverError(w, r, err)
			return
		}
		changed = append(changed, c.ID+"="+strconv.FormatBool(applicable))
	}
	if len(changed) > 0 {
		s.audit(r, "compliance.applicability", p.ID, strings.Join(changed, " "))
	}
	s.redirect(w, r, back+"#p-"+p.ID, "success", s.l.T("compliance.policies.saved"))
}

// ---------- REST API ----------

func (s *Server) apiComplianceReports(w http.ResponseWriter, r *http.Request) {
	reports, err := s.st.ListComplianceReports(r.Context())
	if err != nil {
		s.apiError(w, http.StatusInternalServerError, "internal")
		return
	}
	type item struct {
		ID            int64     `json:"id"`
		Title         string    `json:"title"`
		Profiles      []string  `json:"profiles"`
		PeriodFrom    time.Time `json:"period_from"`
		PeriodTo      time.Time `json:"period_to"`
		GroupID       int64     `json:"group_id,omitempty"`
		Platforms     []string  `json:"platforms,omitempty"`
		Versions      int       `json:"versions"`
		LatestVersion int       `json:"latest_version"`
		LatestStatus  string    `json:"latest_status,omitempty"`
		CreatedBy     string    `json:"created_by"`
		CreatedAt     time.Time `json:"created_at"`
	}
	out := []item{}
	for _, rep := range reports {
		if !s.reportVisible(r, rep) {
			continue
		}
		out = append(out, item{ID: rep.ID, Title: rep.Title, Profiles: rep.Profiles, PeriodFrom: rep.From.UTC(), PeriodTo: rep.To.UTC(), GroupID: rep.GroupID,
			Platforms: rep.Platforms, Versions: rep.Versions, LatestVersion: rep.LatestVersion, LatestStatus: rep.LatestStatus, CreatedBy: rep.CreatedBy, CreatedAt: rep.CreatedAt.UTC()})
	}
	s.apiJSON(w, http.StatusOK, map[string]any{"reports": out})
}

func (s *Server) apiComplianceVersion(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	n, _ := strconv.Atoi(r.PathValue("n"))
	rep, err := s.st.ComplianceReportByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && !s.reportVisible(r, rep)) {
		s.apiError(w, http.StatusNotFound, "not_found")
		return
	}
	if err != nil {
		s.apiError(w, http.StatusInternalServerError, "internal")
		return
	}
	if n <= 0 {
		n = rep.LatestVersion
	}
	v, err := s.st.ReportVersionByNumber(r.Context(), rep.ID, n)
	if errors.Is(err, store.ErrNotFound) {
		s.apiError(w, http.StatusNotFound, "not_found")
		return
	}
	if err != nil {
		s.apiError(w, http.StatusInternalServerError, "internal")
		return
	}
	b, err := s.bundle(r, rep, v)
	if err != nil {
		s.apiError(w, http.StatusInternalServerError, "internal")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = compliance.WriteJSON(w, b)
}

func (s *Server) apiComplianceEvidence(w http.ResponseWriter, r *http.Request) {
	f := s.evidenceFilter(r)
	items, total, err := s.st.ListEvidence(r.Context(), f, store.Page{Number: pageNumber(r), Size: pageSize})
	if err != nil {
		s.apiError(w, http.StatusInternalServerError, "internal")
		return
	}
	type item struct {
		ID          int64           `json:"id"`
		Kind        string          `json:"kind"`
		Source      string          `json:"source"`
		HostID      int64           `json:"host_id,omitempty"`
		Hostname    string          `json:"hostname,omitempty"`
		Platform    string          `json:"platform,omitempty"`
		Subject     string          `json:"subject,omitempty"`
		Actor       string          `json:"actor,omitempty"`
		Outcome     string          `json:"outcome,omitempty"`
		OccurredAt  time.Time       `json:"occurred_at"`
		CollectedAt time.Time       `json:"collected_at"`
		Payload     json.RawMessage `json:"payload"`
		SHA256      string          `json:"sha256"`
		PrevSHA256  string          `json:"prev_sha256"`
	}
	out := make([]item, 0, len(items))
	for _, e := range items {
		out = append(out, item{ID: e.ID, Kind: e.Kind, Source: e.Source, HostID: e.HostID, Hostname: e.Hostname, Platform: e.Platform, Subject: e.Subject,
			Actor: e.Actor, Outcome: e.Outcome, OccurredAt: e.OccurredAt.UTC(), CollectedAt: e.CollectedAt.UTC(), Payload: json.RawMessage(e.Payload),
			SHA256: e.SHA256, PrevSHA256: e.PrevSHA256})
	}
	s.apiJSON(w, http.StatusOK, map[string]any{"evidence": out, "pagination": apiPageOf(r, total)})
}
