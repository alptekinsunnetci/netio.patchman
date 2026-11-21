package web

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"netio.patchman/internal/store"
	"netio.patchman/internal/timeutil"
)

// maxReportDays bounds the report period.
const maxReportDays = 366

// reportPeriod reads from/to (YYYY-MM-DD in the display time zone). The
// default is the last 30 days including today. to is exclusive in the result.
func (s *Server) reportPeriod(r *http.Request) (from, to time.Time, msg string) {
	loc := s.f.Location()
	y, m, d := timeutil.Now().In(loc).Date()
	today := time.Date(y, m, d, 0, 0, 0, 0, loc)
	from, to = today.AddDate(0, 0, -29), today
	q := r.URL.Query()
	parse := func(v string, dst *time.Time) {
		if v == "" {
			return
		}
		t, err := time.ParseInLocation("2006-01-02", v, loc)
		if err != nil {
			msg = s.l.T("report.error.date")
			return
		}
		*dst = t
	}
	parse(q.Get("from"), &from)
	parse(q.Get("to"), &to)
	if msg == "" && (to.Before(from) || to.Sub(from) > maxReportDays*24*time.Hour) {
		msg = s.l.T("report.error.range", "max", maxReportDays)
	}
	if msg != "" {
		from, to = today.AddDate(0, 0, -29), today
	}
	return from, to.AddDate(0, 0, 1), msg
}

func (s *Server) report(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	from, to, msg := s.reportPeriod(r)
	groups, err := s.st.ListGroups(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	var group *store.HostGroup
	if gid, _ := strconv.ParseInt(r.URL.Query().Get("group"), 10, 64); gid > 0 {
		for i := range groups {
			if groups[i].ID == gid {
				group = &groups[i]
			}
		}
	}
	gid := int64(0)
	if group != nil {
		gid = group.ID
	}
	var hosts []store.Host
	for pg := 1; ; pg++ {
		page, _, err := s.st.ListHosts(ctx, store.HostFilter{GroupID: gid, OfflineAfter: s.offlineAfter()}, store.Page{Number: pg, Size: 500})
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		hosts = append(hosts, page...)
		if len(page) < 500 {
			break
		}
	}
	online, reboot, secUpdates := 0, []store.Host{}, 0
	for _, h := range hosts {
		if h.Online(s.offlineAfter()) {
			online++
		}
		if h.RebootRequired {
			reboot = append(reboot, h)
		}
		secUpdates += h.SecurityUpdateCount
	}
	sev, kev, err := s.st.SeverityCountsFor(ctx, gid)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	flow, err := s.st.FindingFlow(ctx, from, to, gid)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	kevOpen, err := s.st.OpenKEV(ctx, gid)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	risks, riskTotal, err := s.st.ListFindings(ctx, store.FindingFilter{Status: store.StatusAcceptedRisk, GroupID: gid}, store.Page{Number: 1, Size: 500})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	jobs, err := s.st.JobCounts(ctx, from, to, gid)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	data := map[string]any{
		"From": from.Format("2006-01-02"), "To": to.AddDate(0, 0, -1).Format("2006-01-02"),
		"FromLabel": s.f.Date(from), "ToLabel": s.f.Date(to.AddDate(0, 0, -1)),
		"Groups": groups, "Group": group, "Hosts": hosts, "Online": online, "Reboot": reboot, "SecurityUpdates": secUpdates,
		"Sev": sev, "KEV": kev, "Flow": flow, "MeanFixDays": s.days(flow.MeanFix), "KEVOpen": kevOpen,
		"Today": timeutil.Now().UTC().Format("2006-01-02"),
		"Risks": risks, "RiskTotal": riskTotal, "Jobs": jobs, "JobStatuses": reportJobStatuses,
		"GeneratedAt": timeutil.Now(),
	}
	if group == nil {
		snaps, err := s.st.Snapshots(ctx, calendarDay(from), calendarDay(to.AddDate(0, 0, -1)))
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		data["Trend"] = s.buildTrends(snaps, from, to.AddDate(0, 0, -1))
	}
	d := s.page(r, s.l.T("report.title"), "reports")
	d.Error = msg
	d.Data = data
	s.render(w, r, http.StatusOK, "report", d)
}

var reportJobStatuses = []string{"succeeded", "partial", "failed", "timed_out", "expired", "cancelled", "queued", "dispatched"}

// days rounds a duration to days with one decimal and the locale's decimal
// separator ("" when zero).
func (s *Server) days(d time.Duration) string {
	if d <= 0 {
		return ""
	}
	return strings.Replace(strconv.FormatFloat(d.Hours()/24, 'f', 1, 64), ".", s.l.T("number.decimal"), 1)
}
