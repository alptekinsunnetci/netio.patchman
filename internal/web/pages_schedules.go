package web

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"netio.patchman/internal/protocol"
	"netio.patchman/internal/schedule"
	"netio.patchman/internal/store"
	"netio.patchman/internal/timeutil"
)

// weekdayOrder lists weekdays Monday first, as Turkish calendars do.
var weekdayOrder = []time.Weekday{time.Monday, time.Tuesday, time.Wednesday, time.Thursday, time.Friday, time.Saturday, time.Sunday}

func (s *Server) scheduler() *schedule.Runner {
	return &schedule.Runner{Store: s.st, Zone: s.f.Zone(), L: s.l, Logger: s.logger}
}

// scheduleDays describes a weekday mask ("Her gün", "Hafta içi", "Pzt, Çar").
func (s *Server) scheduleDays(mask int) string {
	switch mask & schedule.AllDays {
	case schedule.AllDays:
		return s.l.T("schedule.days.all")
	case schedule.Weekdays:
		return s.l.T("schedule.days.weekdays")
	case schedule.Weekend:
		return s.l.T("schedule.days.weekend")
	}
	var names []string
	for _, d := range weekdayOrder {
		if mask&(1<<uint(d)) != 0 {
			names = append(names, s.l.T("weekday.short."+strconv.Itoa(int(d))))
		}
	}
	return strings.Join(names, ", ")
}

func (s *Server) scheduleTarget(target, osID string, hostCount int) string {
	switch target {
	case store.TargetOS:
		return s.l.T("schedule.target.os_value", "os", osID)
	case store.TargetHosts:
		return s.l.T("schedule.target.hosts_value", "count", hostCount)
	}
	return s.l.T("schedule.target.all")
}

func (s *Server) allHosts(ctx context.Context) ([]store.Host, error) {
	var out []store.Host
	for pg := 1; ; pg++ {
		hosts, _, err := s.st.ListHosts(ctx, store.HostFilter{OfflineAfter: s.offlineAfter()}, store.Page{Number: pg, Size: 500})
		if err != nil {
			return nil, err
		}
		out = append(out, hosts...)
		if len(hosts) < 500 {
			return out, nil
		}
	}
}

func (s *Server) schedules(w http.ResponseWriter, r *http.Request) {
	rows, err := s.st.ListSchedules(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d := s.page(r, s.l.T("nav.schedules"), "schedules")
	d.Data = map[string]any{"Rows": rows}
	s.render(w, r, http.StatusOK, "schedules", d)
}

type dayOption struct {
	Value   int
	Label   string
	Checked bool
}

type hostOption struct {
	ID       int64
	Hostname string
	OS       string
	Checked  bool
}

// renderSchedule shows the create/edit form; sc.ID == 0 means a new schedule.
func (s *Server) renderSchedule(w http.ResponseWriter, r *http.Request, status int, sc store.Schedule, errMsg string) {
	ctx := r.Context()
	hosts, err := s.allHosts(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	osOpts, _ := s.st.OSOptions(ctx)
	selected := map[int64]bool{}
	for _, id := range sc.HostIDs {
		selected[id] = true
	}
	hostOpts := make([]hostOption, 0, len(hosts))
	for _, h := range hosts {
		hostOpts = append(hostOpts, hostOption{ID: h.ID, Hostname: h.Hostname, OS: h.OSName, Checked: selected[h.ID]})
	}
	days := make([]dayOption, 0, 7)
	for _, d := range weekdayOrder {
		days = append(days, dayOption{Value: int(d), Label: s.l.T("weekday." + strconv.Itoa(int(d))), Checked: sc.Days&(1<<uint(d)) != 0})
	}
	data := map[string]any{"S": sc, "Clock": schedule.Clock(sc.Minute), "Days": days, "Hosts": hostOpts, "OSOptions": osOpts,
		"JobTypes": schedule.JobTypes, "Timezone": s.f.Location().String(), "IsNew": sc.ID == 0}
	title := s.l.T("schedule.new_title")
	if sc.ID != 0 {
		title = sc.Name
		jobs, _, err := s.st.ListJobs(ctx, store.JobFilter{ScheduleID: sc.ID}, store.Page{Number: 1, Size: 20})
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		data["Jobs"] = jobs
		targets, err := s.st.ScheduleTargets(ctx, sc)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		pending, remoteOff := 0, 0
		for _, h := range targets {
			n := h.UpdateCount
			if sc.JobType == protocol.JobUpgradeSecurity {
				n = h.SecurityUpdateCount
			}
			if n > 0 {
				pending++
			}
			if !h.RemoteUpdates {
				remoteOff++
			}
		}
		data["Coverage"] = map[string]int{"Total": len(targets), "Pending": pending, "RemoteOff": remoteOff}
	}
	d := s.page(r, title, "schedules")
	d.Error = errMsg
	d.Data = data
	s.render(w, r, status, "schedule", d)
}

func (s *Server) scheduleNew(w http.ResponseWriter, r *http.Request) {
	// Sensible default: security updates every Sunday 03:00, 2-hour window.
	s.renderSchedule(w, r, http.StatusOK, store.Schedule{Enabled: true, JobType: protocol.JobUpgradeSecurity,
		Days: 1 << uint(time.Sunday), Minute: 3 * 60, WindowMinutes: 120, Target: store.TargetAll}, "")
}

func (s *Server) scheduleOr404(w http.ResponseWriter, r *http.Request) (store.Schedule, bool) {
	id, ok := pathID(r)
	if !ok {
		s.errorPage(w, r, http.StatusNotFound, "error.not_found")
		return store.Schedule{}, false
	}
	sc, err := s.st.ScheduleByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, r, http.StatusNotFound, "error.not_found")
		return sc, false
	}
	if err != nil {
		s.serverError(w, r, err)
		return sc, false
	}
	return sc, true
}

func (s *Server) scheduleDetail(w http.ResponseWriter, r *http.Request) {
	sc, ok := s.scheduleOr404(w, r)
	if !ok {
		return
	}
	s.renderSchedule(w, r, http.StatusOK, sc, "")
}

// parseScheduleForm reads the form into sc and returns validation messages.
func (s *Server) parseScheduleForm(r *http.Request, sc *store.Schedule) []string {
	_ = r.ParseForm()
	var bad []string
	sc.Name = strings.TrimSpace(r.PostFormValue("name"))
	sc.Enabled = r.PostFormValue("enabled") == "1"
	sc.JobType = r.PostFormValue("job_type")
	sc.Target = r.PostFormValue("target")
	sc.OSID = strings.TrimSpace(r.PostFormValue("os_id"))
	sc.HostIDs = formIDs(r, "host_ids")
	if sc.Name == "" {
		bad = append(bad, s.l.T("validation.required", "field", s.l.T("schedule.field.name")))
	} else if utf8.RuneCountInString(sc.Name) > 100 {
		bad = append(bad, s.l.T("schedule.error.name_length"))
	}
	if !schedule.ValidJobType(sc.JobType) {
		bad = append(bad, s.l.T("job.error.invalid_type"))
	}
	sc.Days = 0
	for _, v := range r.PostForm["days"] {
		if d, err := strconv.Atoi(v); err == nil && d >= 0 && d <= 6 {
			sc.Days |= 1 << uint(d)
		}
	}
	if sc.Days == 0 {
		bad = append(bad, s.l.T("schedule.error.days"))
	}
	if m, ok := schedule.ParseClock(r.PostFormValue("time")); ok {
		sc.Minute = m
	} else {
		bad = append(bad, s.l.T("schedule.error.time"))
	}
	win, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue("window_minutes")))
	sc.WindowMinutes = win
	if err != nil || win < schedule.MinWindowMinutes || win > schedule.MaxWindowMinutes {
		bad = append(bad, s.l.T("validation.range", "field", s.l.T("schedule.field.window"), "min", schedule.MinWindowMinutes, "max", schedule.MaxWindowMinutes))
	}
	switch sc.Target {
	case store.TargetAll:
		sc.OSID, sc.HostIDs = "", nil
	case store.TargetOS:
		sc.HostIDs = nil
		if sc.OSID == "" {
			bad = append(bad, s.l.T("schedule.error.os"))
		}
	case store.TargetHosts:
		sc.OSID = ""
		if len(sc.HostIDs) == 0 {
			bad = append(bad, s.l.T("schedule.error.hosts"))
		}
	default:
		bad = append(bad, s.l.T("schedule.error.target"))
	}
	sc.NextRunAt = time.Time{}
	if sc.Enabled && len(bad) == 0 {
		sc.NextRunAt = schedule.Next(sc.Days, sc.Minute, s.f.Location(), timeutil.Now())
	}
	return bad
}

func scheduleAuditDetails(sc store.Schedule) string {
	d := "type=" + sc.JobType + " days=" + strconv.Itoa(sc.Days) + " time=" + schedule.Clock(sc.Minute) +
		" window=" + strconv.Itoa(sc.WindowMinutes) + " target=" + sc.Target + " enabled=" + strconv.FormatBool(sc.Enabled)
	if sc.OSID != "" {
		d += " os=" + sc.OSID
	}
	if len(sc.HostIDs) > 0 {
		d += " hosts=" + strconv.Itoa(len(sc.HostIDs))
	}
	return d
}

func (s *Server) savedMessage(key string, sc store.Schedule) string {
	if !sc.Enabled {
		return s.l.T("schedule.saved_disabled")
	}
	return s.l.T(key, "next", s.f.Long(sc.NextRunAt))
}

func (s *Server) scheduleCreate(w http.ResponseWriter, r *http.Request) {
	var sc store.Schedule
	if bad := s.parseScheduleForm(r, &sc); len(bad) > 0 {
		s.renderSchedule(w, r, http.StatusBadRequest, sc, strings.Join(bad, " "))
		return
	}
	id, err := s.st.CreateSchedule(r.Context(), sc, sessionFrom(r).user.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "schedule.create", sc.Name, "schedule_id="+strconv.FormatInt(id, 10)+" "+scheduleAuditDetails(sc))
	s.redirect(w, r, "/schedules/"+strconv.FormatInt(id, 10), "success", s.savedMessage("schedule.created", sc))
}

func (s *Server) scheduleUpdate(w http.ResponseWriter, r *http.Request) {
	cur, ok := s.scheduleOr404(w, r)
	if !ok {
		return
	}
	sc := cur
	if bad := s.parseScheduleForm(r, &sc); len(bad) > 0 {
		s.renderSchedule(w, r, http.StatusBadRequest, sc, strings.Join(bad, " "))
		return
	}
	if err := s.st.UpdateSchedule(r.Context(), sc); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "schedule.update", sc.Name, "schedule_id="+strconv.FormatInt(sc.ID, 10)+" "+scheduleAuditDetails(sc))
	s.redirect(w, r, "/schedules/"+strconv.FormatInt(sc.ID, 10), "success", s.savedMessage("schedule.saved", sc))
}

func (s *Server) scheduleDelete(w http.ResponseWriter, r *http.Request) {
	sc, ok := s.scheduleOr404(w, r)
	if !ok {
		return
	}
	if err := s.st.DeleteSchedule(r.Context(), sc.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "schedule.delete", sc.Name, "schedule_id="+strconv.FormatInt(sc.ID, 10))
	s.redirect(w, r, "/schedules", "success", s.l.T("schedule.deleted", "name", sc.Name))
}

// scheduleRunNow runs a schedule immediately with a window starting now. The
// regular next run time is not changed.
func (s *Server) scheduleRunNow(w http.ResponseWriter, r *http.Request) {
	sc, ok := s.scheduleOr404(w, r)
	if !ok {
		return
	}
	back := "/schedules/" + strconv.FormatInt(sc.ID, 10)
	now := timeutil.Now()
	res, err := s.scheduler().Execute(r.Context(), sc, now.Add(sc.Window()))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if err := s.st.RecordScheduleRun(r.Context(), sc.ID, now, time.Time{}, res.Queued, res.Skipped); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "schedule.run_now", sc.Name, "schedule_id="+strconv.FormatInt(sc.ID, 10)+" queued="+strconv.Itoa(res.Queued)+" skipped="+strconv.Itoa(res.Skipped))
	if res.Queued == 0 {
		s.redirect(w, r, back, "info", s.l.T("schedule.run_now_none", "current", res.UpToDate, "skipped", res.Skipped))
		return
	}
	s.redirect(w, r, back, "success", s.l.T("schedule.run_now_done", "count", res.Queued, "skipped", res.Skipped, "current", res.UpToDate))
}
