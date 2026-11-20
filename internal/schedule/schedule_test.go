package schedule

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"netio.patchman/internal/i18n"
	"netio.patchman/internal/protocol"
	"netio.patchman/internal/store"
	"netio.patchman/internal/timeutil"
)

func istanbul(t *testing.T) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation("Europe/Istanbul")
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

func TestNext(t *testing.T) {
	loc := istanbul(t)
	// Wednesday 2026-11-18 10:00 Istanbul (07:00 UTC).
	after := time.Date(2026, 11, 18, 10, 0, 0, 0, loc)
	sunday := 1 << uint(time.Sunday)
	cases := []struct {
		name   string
		days   int
		minute int
		want   time.Time
	}{
		{"later today", AllDays, 22 * 60, time.Date(2026, 11, 18, 22, 0, 0, 0, loc)},
		{"earlier today rolls to tomorrow", AllDays, 3 * 60, time.Date(2026, 11, 19, 3, 0, 0, 0, loc)},
		{"same minute is not next", AllDays, 10 * 60, time.Date(2026, 11, 19, 10, 0, 0, 0, loc)},
		{"sunday", sunday, 3 * 60, time.Date(2026, 11, 22, 3, 0, 0, 0, loc)},
		{"weekend", Weekend, 30, time.Date(2026, 11, 21, 0, 30, 0, 0, loc)},
		{"only wednesday, passed", 1 << uint(time.Wednesday), 9 * 60, time.Date(2026, 11, 25, 9, 0, 0, 0, loc)},
	}
	for _, c := range cases {
		got := Next(c.days, c.minute, loc, after)
		if !got.Equal(c.want) || got.Location() != time.UTC {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want.UTC())
		}
	}
	if !Next(0, 60, loc, after).IsZero() {
		t.Error("no days must give zero time")
	}
}

func TestParseClock(t *testing.T) {
	for in, want := range map[string]int{"03:00": 180, "3:05": 185, "23:59": 1439, "00:00": 0} {
		if got, ok := ParseClock(in); !ok || got != want {
			t.Errorf("ParseClock(%q) = %d %v", in, got, ok)
		}
	}
	for _, in := range []string{"", "24:00", "12:60", "1200", "aa:bb", "12:5"} {
		if _, ok := ParseClock(in); ok {
			t.Errorf("ParseClock(%q) accepted", in)
		}
	}
	if Clock(185) != "03:05" {
		t.Errorf("Clock(185) = %s", Clock(185))
	}
}

func addHost(t *testing.T, st *store.Store, name, osID string, remote bool, updates []protocol.Update) int64 {
	t.Helper()
	ctx := context.Background()
	if _, err := st.CreateEnrollmentToken(ctx, "t", "hash-"+name, "npe_", 0, time.Time{}, 0); err != nil {
		t.Fatal(err)
	}
	info := protocol.HostInfo{Hostname: name, MachineID: "m-" + name, OSID: osID, RemoteUpdates: remote}
	id, _, err := st.RegisterHost(ctx, "hash-"+name, info, "", "secret-"+name)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SaveReport(ctx, id, protocol.Report{Host: info, Updates: updates}, ""); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestRunnerWindow(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir()+"/s.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	loc := istanbul(t)
	r := &Runner{Store: st, Zone: timeutil.NewZone(loc), L: i18n.MustLoad().Localizer(i18n.DefaultLocale), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

	sec := []protocol.Update{{Name: "openssl", CurrentVersion: "1", AvailableVersion: "2", Security: true}}
	plain := []protocol.Update{{Name: "vim", CurrentVersion: "1", AvailableVersion: "2"}}
	web := addHost(t, st, "web-01", "ubuntu", true, sec)
	addHost(t, st, "db-01", "ubuntu", false, sec)   // remote updates disabled: skipped
	addHost(t, st, "app-01", "ubuntu", true, plain) // no security updates: up to date
	addHost(t, st, "rh-01", "almalinux", true, sec) // other OS: not targeted

	// Window starts at 03:00 Istanbul, 60 minutes.
	start := time.Date(2026, 11, 22, 3, 0, 0, 0, loc)
	sc := store.Schedule{Name: "Pazar gecesi", Enabled: true, JobType: protocol.JobUpgradeSecurity, Days: 1 << uint(time.Sunday),
		Minute: 180, WindowMinutes: 60, Target: store.TargetOS, OSID: "ubuntu", NextRunAt: start.UTC()}
	id, err := st.CreateSchedule(ctx, sc, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Not due yet.
	r.Tick(ctx, start.Add(-time.Minute))
	if jobs, _, _ := st.ListJobs(ctx, store.JobFilter{ScheduleID: id}, store.Page{Number: 1, Size: 10}); len(jobs) != 0 {
		t.Fatalf("ran early: %d jobs", len(jobs))
	}

	r.Tick(ctx, start.Add(30*time.Second))
	jobs, _, _ := st.ListJobs(ctx, store.JobFilter{ScheduleID: id}, store.Page{Number: 1, Size: 10})
	if len(jobs) != 1 || jobs[0].HostID != web || jobs[0].ScheduleName != "Pazar gecesi" || !jobs[0].ExpiresAt.Equal(start.Add(time.Hour)) {
		t.Fatalf("scheduled jobs: %+v", jobs)
	}
	got, _ := st.ScheduleByID(ctx, id)
	if got.LastQueued != 1 || got.LastSkipped != 1 || !got.NextRunAt.Equal(start.AddDate(0, 0, 7)) {
		t.Errorf("after run: queued=%d skipped=%d next=%v", got.LastQueued, got.LastSkipped, got.NextRunAt.In(loc))
	}
	// A second tick in the same window does not queue again.
	r.Tick(ctx, start.Add(2*time.Minute))
	if jobs, _, _ := st.ListJobs(ctx, store.JobFilter{ScheduleID: id}, store.Page{Number: 1, Size: 10}); len(jobs) != 1 {
		t.Errorf("ran twice: %d jobs", len(jobs))
	}

	// The agent stays offline: after the window the job expires and is never dispatched.
	r.Tick(ctx, start.Add(61*time.Minute))
	j, _ := st.JobByID(ctx, jobs[0].ID)
	if j.Status != store.JobExpired {
		t.Fatalf("status after window = %s", j.Status)
	}
	if d, _ := st.DispatchJobs(ctx, web); len(d) != 0 {
		t.Errorf("expired job dispatched: %+v", d)
	}
	notes, _, _ := st.ListNotifications(ctx, false, store.Page{Number: 1, Size: 10})
	kinds := map[string]bool{}
	for _, n := range notes {
		kinds[n.Kind] = true
	}
	if !kinds["schedule_ran"] || !kinds["schedule_expired"] {
		t.Errorf("notifications: %v", kinds)
	}

	// Server down for the whole next window: the run is skipped, not executed late.
	next := start.AddDate(0, 0, 7)
	r.Tick(ctx, next.Add(2*time.Hour))
	if jobs, _, _ := st.ListJobs(ctx, store.JobFilter{ScheduleID: id}, store.Page{Number: 1, Size: 10}); len(jobs) != 1 {
		t.Errorf("missed window executed late: %d jobs", len(jobs))
	}
	got, _ = st.ScheduleByID(ctx, id)
	if !got.NextRunAt.Equal(next.AddDate(0, 0, 7)) {
		t.Errorf("next after missed window = %v", got.NextRunAt.In(loc))
	}
}

func TestJobsExpireOnlyWhenQueued(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir()+"/s.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	host := addHost(t, st, "web-02", "debian", true, nil)
	id, _ := st.CreateSchedule(ctx, store.Schedule{Name: "x", Enabled: true, JobType: protocol.JobUpgradeAll, Days: AllDays, WindowMinutes: 60, Target: store.TargetAll}, 0)
	expires := time.Now().Add(time.Hour)
	jobID, err := st.CreateScheduledJob(ctx, host, protocol.JobUpgradeAll, id, expires)
	if err != nil {
		t.Fatal(err)
	}
	// Dispatched before the window ends: it keeps running past the window.
	if d, _ := st.DispatchJobs(ctx, host); len(d) != 1 {
		t.Fatalf("dispatch: %+v", d)
	}
	if g, _ := st.ExpireJobs(ctx, expires.Add(time.Minute)); len(g) != 0 {
		t.Errorf("dispatched job expired: %+v", g)
	}
	if j, _ := st.JobByID(ctx, jobID); j.Status != protocol.JobDispatched {
		t.Errorf("status = %s", j.Status)
	}
	// Deleting the schedule keeps job history.
	if err := st.DeleteSchedule(ctx, id); err != nil {
		t.Fatal(err)
	}
	if j, err := st.JobByID(ctx, jobID); err != nil || j.ScheduleID != 0 {
		t.Errorf("job after schedule delete: %+v %v", j, err)
	}
}
