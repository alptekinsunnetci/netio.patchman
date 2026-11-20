// Package schedule runs recurring update rules (maintenance windows).
//
// A schedule fires on selected weekdays at a wall-clock time in the server's
// display time zone and queues an update job on every targeted host that has
// pending updates. Jobs carry the end of the maintenance window; an agent
// that does not check in before then never receives the job (it expires),
// so updates are not applied outside the window. Servers are never rebooted.
package schedule

import (
	"context"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"netio.patchman/internal/i18n"
	"netio.patchman/internal/protocol"
	"netio.patchman/internal/store"
	"netio.patchman/internal/timeutil"
)

// Limits for the maintenance window length, in minutes.
const (
	MinWindowMinutes = 15
	MaxWindowMinutes = 24 * 60
)

// AllDays, Weekdays and Weekend are common weekday masks.
const (
	AllDays  = 0b1111111
	Weekdays = 0b0111110
	Weekend  = 0b1000001
)

// JobTypes lists the job types a schedule may run.
var JobTypes = []string{protocol.JobUpgradeSecurity, protocol.JobUpgradeAll}

// ValidJobType reports whether typ can be scheduled.
func ValidJobType(typ string) bool {
	for _, t := range JobTypes {
		if t == typ {
			return true
		}
	}
	return false
}

// Next returns the first run time strictly after `after` for the weekday
// mask and minute-of-day in loc, in UTC. It returns the zero time if no day
// is selected.
func Next(days, minute int, loc *time.Location, after time.Time) time.Time {
	if days&AllDays == 0 || minute < 0 || minute >= 24*60 {
		return time.Time{}
	}
	local := after.In(loc)
	for i := 0; i <= 7; i++ {
		d := local.AddDate(0, 0, i)
		c := time.Date(d.Year(), d.Month(), d.Day(), minute/60, minute%60, 0, 0, loc)
		if days&(1<<uint(c.Weekday())) != 0 && c.After(after) {
			return c.UTC()
		}
	}
	return time.Time{}
}

// ParseClock parses "HH:MM" into minutes after midnight.
func ParseClock(s string) (int, bool) {
	h, m, ok := strings.Cut(strings.TrimSpace(s), ":")
	if !ok || len(h) == 0 || len(h) > 2 || len(m) != 2 {
		return 0, false
	}
	hh, err1 := strconv.Atoi(h)
	mm, err2 := strconv.Atoi(m)
	if err1 != nil || err2 != nil || hh < 0 || hh > 23 || mm < 0 || mm > 59 {
		return 0, false
	}
	return hh*60 + mm, true
}

// Clock formats minutes after midnight as "HH:MM".
func Clock(minute int) string {
	return twoDigits(minute/60) + ":" + twoDigits(minute%60)
}

func twoDigits(n int) string {
	if n < 10 {
		return "0" + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}

// Result summarizes one run.
type Result struct {
	Queued    int // jobs created
	Skipped   int // remote updates disabled or a job of the type already active
	UpToDate  int // no pending updates of the scheduled kind
	Hostnames []string
}

// Runner executes due schedules.
type Runner struct {
	Store  *store.Store
	Zone   *timeutil.Zone // schedule times are wall-clock times in this zone
	L      i18n.Localizer
	Logger *slog.Logger
}

// Reschedule recomputes the next run of every enabled schedule, used after
// the time zone changed.
func (r *Runner) Reschedule(ctx context.Context, now time.Time) error {
	list, err := r.Store.ListSchedules(ctx)
	if err != nil {
		return err
	}
	for _, sc := range list {
		if !sc.Enabled {
			continue
		}
		if err := r.Store.SetScheduleNextRun(ctx, sc.ID, Next(sc.Days, sc.Minute, r.Zone.Location(), now)); err != nil {
			return err
		}
	}
	return nil
}

// Execute queues the schedule's job on its target hosts; jobs expire at until.
func (r *Runner) Execute(ctx context.Context, sc store.Schedule, until time.Time) (Result, error) {
	var res Result
	hosts, err := r.Store.ScheduleTargets(ctx, sc)
	if err != nil {
		return res, err
	}
	for _, h := range hosts {
		pending := h.UpdateCount
		if sc.JobType == protocol.JobUpgradeSecurity {
			pending = h.SecurityUpdateCount
		}
		if pending == 0 {
			res.UpToDate++
			continue
		}
		if !h.RemoteUpdates {
			res.Skipped++
			continue
		}
		active, err := r.Store.HasActiveJob(ctx, h.ID, sc.JobType)
		if err != nil {
			return res, err
		}
		if active {
			res.Skipped++
			continue
		}
		if _, err := r.Store.CreateScheduledJob(ctx, h.ID, sc.JobType, sc.ID, until); err != nil {
			return res, err
		}
		res.Queued++
		res.Hostnames = append(res.Hostnames, h.Hostname)
	}
	return res, nil
}

// Tick expires stale scheduled jobs and runs every due schedule.
func (r *Runner) Tick(ctx context.Context, now time.Time) {
	groups, err := r.Store.ExpireJobs(ctx, now)
	if err != nil {
		r.Logger.Warn(r.L.T("log.schedule.failed"), slog.String("error", err.Error()))
	}
	for _, g := range groups {
		link := "/jobs?status=" + store.JobExpired
		if g.ScheduleID != 0 {
			link = "/schedules/" + strconv.FormatInt(g.ScheduleID, 10)
		}
		_ = r.Store.AddNotification(ctx, store.LevelWarning, "schedule_expired", map[string]string{
			"name": g.ScheduleName, "count": strconv.Itoa(len(g.Hostnames)), "hosts": shortList(g.Hostnames),
		}, link)
		r.Logger.Warn(r.L.T("log.schedule.expired"), slog.String("schedule", g.ScheduleName), slog.Int("hosts", len(g.Hostnames)))
	}

	due, err := r.Store.DueSchedules(ctx, now)
	if err != nil {
		r.Logger.Warn(r.L.T("log.schedule.failed"), slog.String("error", err.Error()))
		return
	}
	for _, sc := range due {
		r.runDue(ctx, sc, now)
	}
}

func (r *Runner) runDue(ctx context.Context, sc store.Schedule, now time.Time) {
	link := "/schedules/" + strconv.FormatInt(sc.ID, 10)
	next := Next(sc.Days, sc.Minute, r.Zone.Location(), now)
	end := sc.NextRunAt.Add(sc.Window())
	if !now.Before(end) {
		// The server was not running during the whole window.
		if err := r.Store.SetScheduleNextRun(ctx, sc.ID, next); err != nil {
			r.Logger.Warn(r.L.T("log.schedule.failed"), slog.String("error", err.Error()))
			return
		}
		_ = r.Store.AddNotification(ctx, store.LevelWarning, "schedule_missed", map[string]string{"name": sc.Name}, link)
		r.Logger.Warn(r.L.T("log.schedule.missed"), slog.String("schedule", sc.Name), slog.Time("window_start", sc.NextRunAt))
		return
	}
	res, err := r.Execute(ctx, sc, end)
	if err != nil {
		r.Logger.Warn(r.L.T("log.schedule.failed"), slog.String("schedule", sc.Name), slog.String("error", err.Error()))
	}
	if err := r.Store.RecordScheduleRun(ctx, sc.ID, now, next, res.Queued, res.Skipped); err != nil {
		r.Logger.Warn(r.L.T("log.schedule.failed"), slog.String("error", err.Error()))
	}
	r.Logger.Info(r.L.T("log.schedule.ran"), slog.String("schedule", sc.Name), slog.String("type", sc.JobType),
		slog.Int("queued", res.Queued), slog.Int("skipped", res.Skipped), slog.Int("up_to_date", res.UpToDate), slog.Time("next_run", next))
	_ = r.Store.Audit(ctx, store.AuditEntry{Action: "schedule.run", Target: sc.Name,
		Details: "schedule_id=" + strconv.FormatInt(sc.ID, 10) + " type=" + sc.JobType + " queued=" + strconv.Itoa(res.Queued) + " skipped=" + strconv.Itoa(res.Skipped)})
	if res.Queued > 0 {
		_ = r.Store.AddNotification(ctx, store.LevelInfo, "schedule_ran", map[string]string{
			"name": sc.Name, "job_type": sc.JobType, "count": strconv.Itoa(res.Queued),
		}, link)
	}
}

func shortList(names []string) string {
	if len(names) > 10 {
		names = append(names[:10:10], "…")
	}
	return strings.Join(names, ", ")
}
