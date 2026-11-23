package compliance

import (
	_ "embed"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-pdf/fpdf"

	"netio.patchman/internal/store"
)

// DejaVu Sans (Bitstream Vera license, fonts/LICENSE) covers Latin,
// Turkish and Cyrillic; it is embedded so PDFs need no system fonts.
var (
	//go:embed fonts/DejaVuSans.ttf
	fontRegular []byte
	//go:embed fonts/DejaVuSans-Bold.ttf
	fontBold []byte
)

// pdfEvidenceRows bounds the evidence list in the PDF (the JSON and CSV
// exports hold every item).
const pdfEvidenceRows = 300

type pdfDoc struct {
	*fpdf.Fpdf
	r      Renderer
	bottom float64
}

const (
	pdfMargin = 15.0
	pdfWidth  = 210.0 - 2*pdfMargin
	lineH     = 4.6
)

func (d *pdfDoc) heading(text string) {
	if d.GetY() > d.bottom-30 {
		d.AddPage()
	}
	d.Ln(3)
	d.SetFont("dejavu", "B", 12.5)
	d.MultiCell(pdfWidth, 6.5, text, "", "L", false)
	d.SetDrawColor(180, 186, 194)
	d.Line(pdfMargin, d.GetY(), pdfMargin+pdfWidth, d.GetY())
	d.Ln(2)
	d.SetFont("dejavu", "", 9)
}

func (d *pdfDoc) sub(text string) {
	if d.GetY() > d.bottom-22 {
		d.AddPage()
	}
	d.Ln(1.5)
	d.SetFont("dejavu", "B", 10)
	d.MultiCell(pdfWidth, 5.5, text, "", "L", false)
	d.SetFont("dejavu", "", 9)
}

func (d *pdfDoc) para(text string) {
	d.SetFont("dejavu", "", 9)
	d.MultiCell(pdfWidth, lineH, text, "", "L", false)
	d.Ln(1)
}

func (d *pdfDoc) muted(text string) {
	d.SetTextColor(95, 102, 112)
	d.SetFont("dejavu", "", 8)
	d.MultiCell(pdfWidth, 4, text, "", "L", false)
	d.SetTextColor(20, 24, 31)
	d.SetFont("dejavu", "", 9)
	d.Ln(1)
}

// table draws rows with wrapped cells; widths are fractions of the page.
func (d *pdfDoc) table(head []string, widths []float64, rows [][]string) {
	ws := make([]float64, len(widths))
	for i, w := range widths {
		ws[i] = w * pdfWidth
	}
	var draw func(cells []string, bold bool)
	draw = func(cells []string, bold bool) {
		size := 8.0
		style := ""
		if bold {
			style = "B"
		}
		d.SetFont("dejavu", style, size)
		lines := make([][]string, len(cells))
		n := 1
		for i, c := range cells {
			lines[i] = d.SplitText(c, ws[i]-2)
			if len(lines[i]) == 0 {
				lines[i] = []string{""}
			}
			n = max(n, len(lines[i]))
		}
		h := float64(n)*4 + 1.6
		if d.GetY()+h > d.bottom {
			d.AddPage()
			if !bold && head != nil {
				// The header row repeats on the new page.
				draw(head, true)
				d.SetFont("dejavu", style, size)
			}
		}
		y := d.GetY()
		x := pdfMargin
		if bold {
			d.SetFillColor(236, 239, 243)
			d.Rect(pdfMargin, y, pdfWidth, h, "F")
		}
		for i := range cells {
			d.SetDrawColor(210, 214, 220)
			d.Rect(x, y, ws[i], h, "D")
			for j, ln := range lines[i] {
				d.SetXY(x+1, y+0.8+float64(j)*4)
				d.CellFormat(ws[i]-2, 4, ln, "", 0, "L", false, 0, "")
			}
			x += ws[i]
		}
		d.SetXY(pdfMargin, y+h)
	}
	if head != nil {
		draw(head, true)
	}
	for _, r := range rows {
		draw(r, false)
	}
	d.Ln(2)
	d.SetFont("dejavu", "", 9)
}

// WritePDF writes the printable report in the renderer's language.
func WritePDF(w io.Writer, b Bundle, r Renderer) error {
	l := r.L
	c := b.Content
	f := fpdf.New("P", "mm", "A4", "")
	f.AddUTF8FontFromBytes("dejavu", "", fontRegular)
	f.AddUTF8FontFromBytes("dejavu", "B", fontBold)
	f.SetMargins(pdfMargin, pdfMargin, pdfMargin)
	f.SetAutoPageBreak(true, 18)
	f.SetTitle(c.Title, true)
	f.SetCreator(c.Product+" "+c.ProductVersion, true)
	f.AliasNbPages("{nb}")
	d := &pdfDoc{Fpdf: f, r: r, bottom: 297 - 18}
	short := b.Version.SHA256
	if len(short) > 16 {
		short = short[:16]
	}
	f.SetFooterFunc(func() {
		f.SetY(-13)
		f.SetFont("dejavu", "", 7)
		f.SetTextColor(110, 116, 125)
		f.CellFormat(pdfWidth/2, 4, c.Product+" · "+c.Title+" · v"+strconv.Itoa(b.Version.Version)+" · SHA-256 "+short, "", 0, "L", false, 0, "")
		f.CellFormat(pdfWidth/2, 4, l.T("compliance.pdf.page", "n", strconv.Itoa(f.PageNo()), "total", "{nb}"), "", 0, "R", false, 0, "")
		f.SetTextColor(20, 24, 31)
	})
	f.AddPage()
	f.SetTextColor(20, 24, 31)

	// Cover.
	f.SetFont("dejavu", "", 9)
	f.SetTextColor(95, 102, 112)
	f.CellFormat(pdfWidth, 5, c.Product+" · "+l.T("compliance.title"), "", 1, "L", false, 0, "")
	f.SetTextColor(20, 24, 31)
	f.SetFont("dejavu", "B", 18)
	f.MultiCell(pdfWidth, 8, c.Title, "", "L", false)
	f.Ln(2)
	var profiles []string
	for _, p := range c.Profiles {
		profiles = append(profiles, r.ProfileName(p.ID)+" ("+p.Key()+")")
	}
	scope := l.T("compliance.scope.all")
	if c.Scope.GroupName != "" {
		scope = l.T("compliance.scope.group", "name", c.Scope.GroupName)
	}
	if len(c.Scope.Platforms) > 0 {
		var ps []string
		for _, p := range c.Scope.Platforms {
			ps = append(ps, r.Platform(p))
		}
		scope += " · " + strings.Join(ps, ", ")
	}
	meta := [][]string{
		{l.T("compliance.report.period"), r.F.Date(c.PeriodFrom) + " – " + r.F.Date(c.PeriodTo.Add(-time.Second))},
		{l.T("compliance.report.scope"), scope},
		{l.T("compliance.report.profiles"), strings.Join(profiles, "\n")},
		{l.T("compliance.report.version_label"), strconv.Itoa(b.Version.Version) + " · " + l.T("compliance.status."+b.Version.Status)},
		{l.T("compliance.report.generated_at"), r.F.DateTime(c.GeneratedAt) + " · " + c.GeneratedBy},
		{"SHA-256", b.Version.SHA256},
	}
	if b.Version.Final() {
		meta = append(meta, []string{l.T("compliance.report.finalized"), r.F.DateTime(b.Version.FinalizedAt) + " · " + b.Version.FinalizedBy})
		meta = append(meta, []string{l.T("compliance.report.final_sha"), b.Version.FinalSHA256})
	}
	if !c.CollectionStart.IsZero() {
		meta = append(meta, []string{l.T("compliance.report.collection_start"), r.F.DateTime(c.CollectionStart)})
	}
	d.table(nil, []float64{0.28, 0.72}, meta)
	if c.Note != "" {
		d.para(c.Note)
	}
	d.muted(r.Disclaimer())

	// 1. Executive summary.
	d.heading("1. " + l.T("compliance.section.summary"))
	for _, wtext := range c.Summary.Warnings {
		d.para("• " + r.Text(wtext))
	}
	var plat []string
	for _, p := range store.Platforms {
		if n := c.Summary.ByPlatform[p]; n > 0 {
			plat = append(plat, r.Platform(p)+": "+strconv.Itoa(n))
		}
	}
	d.para(l.T("compliance.summary.hosts", "n", strconv.Itoa(c.Summary.Hosts)) + " " + strings.Join(plat, " · "))
	head := []string{l.T("compliance.csv.profile")}
	widths := []float64{0.30}
	for _, o := range Outcomes {
		head = append(head, r.Outcome(o))
		widths = append(widths, 0.10)
	}
	var rows [][]string
	for _, ps := range c.Summary.Profiles {
		row := []string{r.ProfileName(ps.Profile)}
		for _, o := range Outcomes {
			row = append(row, strconv.Itoa(ps.Outcomes[o]))
		}
		rows = append(rows, row)
	}
	d.table(head, widths, rows)

	// 2. Scope and period.
	d.heading("2. " + l.T("compliance.section.scope"))
	d.para(l.T("compliance.scope.text", "from", r.F.Date(c.PeriodFrom), "to", r.F.Date(c.PeriodTo.Add(-time.Second)), "scope", scope))
	for _, p := range c.Profiles {
		d.para("• " + r.ProfileName(p.ID) + " (" + p.Key() + "): " + l.T("compliance.profile."+p.ID+".desc"))
	}

	// 3. Inventory.
	d.heading("3. " + l.T("compliance.section.inventory"))
	rows = nil
	for _, a := range c.Inventory {
		sup := ""
		if a.OSSupport != "" {
			sup = l.T("eol.status." + a.OSSupport)
		}
		rows = append(rows, []string{a.Hostname, r.Platform(a.Platform), strings.TrimSpace(a.OSName + " " + a.OSVersion), a.AgentVersion, r.F.Date(a.LastSeen), sup})
	}
	if len(rows) == 0 {
		d.para(l.T("compliance.empty.inventory"))
	} else {
		d.table([]string{l.T("compliance.csv.hostname"), l.T("compliance.csv.platform"), l.T("compliance.csv.os"), l.T("compliance.csv.agent"),
			l.T("compliance.csv.last_seen"), l.T("compliance.csv.os_support")}, []float64{0.22, 0.14, 0.28, 0.1, 0.12, 0.14}, rows)
	}

	// 4. Updates by platform.
	d.heading("4. " + l.T("compliance.section.updates"))
	rows = nil
	for _, u := range c.Updates {
		rows = append(rows, []string{r.Platform(u.Platform), strconv.Itoa(u.Hosts), strconv.Itoa(u.HostsWithSecurity), strconv.Itoa(u.SecurityUpdates),
			strconv.Itoa(u.Updates), strconv.Itoa(u.RebootPending), strconv.Itoa(u.UpdateJobsSucceeded), strconv.Itoa(u.UpdateJobsFailed)})
	}
	if len(rows) == 0 {
		d.para(l.T("compliance.empty.updates"))
	} else {
		d.table([]string{l.T("compliance.csv.platform"), l.T("compliance.col.hosts"), l.T("compliance.col.hosts_security"), l.T("compliance.col.security_updates"),
			l.T("compliance.col.updates"), l.T("compliance.col.reboot"), l.T("compliance.col.jobs_ok"), l.T("compliance.col.jobs_failed")},
			[]float64{0.19, 0.1, 0.13, 0.12, 0.1, 0.12, 0.12, 0.12}, rows)
	}

	// 5. Vulnerability management.
	v := c.Vulnerabilities
	d.heading("5. " + l.T("compliance.section.vulnerabilities"))
	sev := func(s SeverityCounts) []string {
		return []string{strconv.Itoa(s.Critical), strconv.Itoa(s.High), strconv.Itoa(s.Medium), strconv.Itoa(s.Low), strconv.Itoa(s.KEV)}
	}
	d.table([]string{"", l.T("severity.critical"), l.T("severity.high"), l.T("severity.medium"), l.T("severity.low"), "KEV"},
		[]float64{0.3, 0.14, 0.14, 0.14, 0.14, 0.14},
		[][]string{append([]string{l.T("compliance.vuln.open_start")}, sev(v.OpenAtStart)...), append([]string{l.T("compliance.vuln.open_end")}, sev(v.OpenAtEnd)...)})
	d.para(l.T("compliance.vuln.resolved", "n", strconv.Itoa(v.Resolved), "days", r.Number(v.MeanFixDays), "kev", strconv.Itoa(v.KEVResolved)))
	if len(v.KEVOpen) > 0 {
		d.sub(l.T("compliance.vuln.kev_open"))
		rows = nil
		for _, k := range v.KEVOpen {
			rows = append(rows, []string{k.CVE, k.Title, k.DueDate, strconv.Itoa(k.Hosts)})
		}
		d.table([]string{"CVE", l.T("compliance.col.title"), l.T("compliance.col.due"), l.T("compliance.col.hosts")}, []float64{0.2, 0.52, 0.14, 0.14}, rows)
	}

	// 6. Patch compliance.
	p := c.Patch
	d.heading("6. " + l.T("compliance.section.patch"))
	d.para(l.T("compliance.patch.text", "jobs", strconv.Itoa(p.Jobs), "ok", strconv.Itoa(p.Succeeded), "partial", strconv.Itoa(p.Partial),
		"failed", strconv.Itoa(p.Failed), "packages", strconv.Itoa(p.Packages)))
	d.para(l.T("compliance.patch.clean", "clean", strconv.Itoa(p.HostsClean), "hosts", strconv.Itoa(p.Hosts)))

	// 7. SLA.
	d.heading("7. " + l.T("compliance.section.sla"))
	if !c.SLA.Enabled {
		d.para(l.T("compliance.sla.disabled"))
	} else {
		d.para(l.T("compliance.sla.days", "critical", strconv.Itoa(c.SLA.Days["critical"]), "high", strconv.Itoa(c.SLA.Days["high"]),
			"medium", strconv.Itoa(c.SLA.Days["medium"]), "low", strconv.Itoa(c.SLA.Days["low"])))
		d.para(l.T("compliance.sla.text", "resolved", strconv.Itoa(c.SLA.Resolved), "within", strconv.Itoa(c.SLA.WithinSLA), "late", strconv.Itoa(c.SLA.Late),
			"open", strconv.Itoa(c.SLA.OpenOverdue)))
	}

	// 8. EOL.
	d.heading("8. " + l.T("compliance.section.eol"))
	if len(c.EOL) == 0 {
		d.para(l.T("compliance.empty.eol"))
	} else {
		rows = nil
		for _, e := range c.EOL {
			rows = append(rows, []string{e.Hostname, r.Platform(e.Platform), e.OSName, l.T("eol.status." + e.Status)})
		}
		d.table([]string{l.T("compliance.csv.hostname"), l.T("compliance.csv.platform"), l.T("compliance.csv.os"), l.T("compliance.csv.os_support")},
			[]float64{0.28, 0.18, 0.36, 0.18}, rows)
	}

	// 9. Change management.
	ch := c.Changes
	d.heading("9. " + l.T("compliance.section.changes"))
	d.para(l.T("compliance.changes.text", "total", strconv.Itoa(ch.Total), "approvals", strconv.Itoa(ch.Approvals)))
	d.table([]string{l.T("compliance.col.type"), l.T("compliance.col.count")}, []float64{0.6, 0.4}, mapRows(ch.ByType, func(k string) string { return l.T("job.type." + k) }))
	d.table([]string{l.T("compliance.col.origin"), l.T("compliance.col.count")}, []float64{0.6, 0.4}, mapRows(ch.ByOrigin, func(k string) string { return l.T("compliance.origin." + k) }))

	// 10. Audit logs.
	a := c.Audit
	d.heading("10. " + l.T("compliance.section.audit"))
	chain := l.T("compliance.chain.ok", "n", strconv.Itoa(a.ChainItems))
	if !a.ChainOK {
		chain = l.T("compliance.chain.broken", "id", strconv.FormatInt(a.ChainBroken, 10))
	}
	d.para(l.T("compliance.audit.text", "n", strconv.Itoa(a.Events)) + " " + chain)
	d.table([]string{l.T("compliance.col.action"), l.T("compliance.col.count")}, []float64{0.7, 0.3}, mapRows(a.ByAction, func(k string) string { return l.T("audit.action." + k) }))

	// 11. Control assessments per profile.
	d.heading("11. " + l.T("compliance.section.controls"))
	d.muted(l.T("compliance.controls.note"))
	for _, pa := range c.Controls {
		d.sub(r.ProfileName(pa.Profile) + " (" + pa.Profile + "@" + pa.Version + ")")
		rows = nil
		for _, ca := range pa.Controls {
			var checks []string
			for _, cc := range ca.Checks {
				checks = append(checks, r.CheckName(cc.Check)+" · "+r.Relevance(cc.Relevance)+": "+r.Outcome(cc.Outcome))
			}
			if ca.Manual != "" {
				checks = append(checks, l.T("compliance.manual."+ca.Manual)+": "+strconv.Itoa(ca.ManualItems))
			}
			rev := b.assessment(pa.Profile, ca.ID)
			review := r.Review(rev.ReviewStatus)
			if rev.ReviewNote != "" {
				review += "\n" + rev.ReviewNote
			}
			if rev.ReviewedBy != "" {
				review += "\n" + rev.ReviewedBy
			}
			out := r.Outcome(ca.Outcome)
			if ca.Justification != "" {
				out += "\n" + ca.Justification
			}
			rows = append(rows, []string{ca.ID, r.ControlTitle(pa.Profile, ca.ID), out, strings.Join(checks, "\n"), strconv.Itoa(ca.Evidence), review})
		}
		d.table([]string{l.T("compliance.csv.control"), l.T("compliance.csv.title"), l.T("compliance.csv.outcome"), l.T("compliance.csv.checks"),
			l.T("compliance.csv.evidence"), l.T("compliance.csv.review")}, []float64{0.1, 0.22, 0.15, 0.3, 0.08, 0.15}, rows)
	}

	// 12. Evidence.
	d.heading("12. " + l.T("compliance.section.evidence"))
	d.para(l.T("compliance.evidence.total", "n", strconv.Itoa(len(b.Evidence))))
	items := append([]store.EvidenceItem{}, b.Evidence...)
	sort.Slice(items, func(i, j int) bool { return items[i].OccurredAt.After(items[j].OccurredAt) })
	rows = nil
	for _, e := range items[:min(len(items), pdfEvidenceRows)] {
		subj := e.Subject
		if e.Kind == store.EvidenceManual {
			if t, _ := e.PayloadMap()["title"].(string); t != "" {
				subj = t
			}
		}
		rows = append(rows, []string{strconv.FormatInt(e.ID, 10), r.Kind(e.Kind), r.F.DateTime(e.OccurredAt), e.Hostname, subj, e.SHA256[:min(16, len(e.SHA256))]})
	}
	if len(items) > pdfEvidenceRows {
		d.muted(l.T("compliance.evidence.truncated", "shown", strconv.Itoa(pdfEvidenceRows), "total", strconv.Itoa(len(items))))
	}
	if len(rows) > 0 {
		d.table([]string{"ID", l.T("compliance.csv.kind"), l.T("compliance.csv.occurred"), l.T("compliance.csv.hostname"), l.T("compliance.csv.subject"), "SHA-256"},
			[]float64{0.08, 0.17, 0.17, 0.18, 0.22, 0.18}, rows)
	}

	// 13. Missing evidence and recommendations.
	d.heading("13. " + l.T("compliance.section.gaps"))
	if len(c.Gaps) == 0 {
		d.para(l.T("compliance.empty.gaps"))
	}
	rows = nil
	for _, g := range c.Gaps {
		var gs, rs []string
		for _, t := range g.Gaps {
			gs = append(gs, r.Text(t))
		}
		for _, t := range g.Recommendations {
			rs = append(rs, r.Text(t))
		}
		rows = append(rows, []string{r.ProfileName(g.Profile) + "\n" + g.Control, r.Outcome(g.Outcome), strings.Join(gs, "\n"), strings.Join(rs, "\n")})
	}
	if len(rows) > 0 {
		d.table([]string{l.T("compliance.csv.control"), l.T("compliance.csv.outcome"), l.T("compliance.csv.gaps"), l.T("compliance.csv.recommendations")},
			[]float64{0.18, 0.14, 0.34, 0.34}, rows)
	}
	d.Ln(2)
	d.muted(r.Disclaimer())
	return f.Output(w)
}

func mapRows(m map[string]int, label func(string) string) [][]string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if m[keys[i]] != m[keys[j]] {
			return m[keys[i]] > m[keys[j]]
		}
		return keys[i] < keys[j]
	})
	rows := make([][]string, 0, len(keys))
	for _, k := range keys {
		rows = append(rows, []string{label(k), strconv.Itoa(m[k])})
	}
	return rows
}
