package selfupdate

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func write(t *testing.T, path, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestManager(t *testing.T) {
	dir := t.TempDir()
	m := Manager{DataDir: dir}
	if _, ok := m.Updater(); ok {
		t.Fatal("updater without heartbeat")
	}
	if err := m.Request("admin@example.test"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("request without updater: %v", err)
	}
	// A stale heartbeat does not count.
	write(t, filepath.Join(dir, "update", "updater.json"), `{"version":"0.7.0","seen_at":`+strconv.FormatInt(time.Now().Add(-time.Minute).Unix(), 10)+`}`)
	if _, ok := m.Updater(); ok {
		t.Fatal("stale heartbeat")
	}
	write(t, filepath.Join(dir, "update", "updater.json"), `{"version":"0.7.0","seen_at":`+strconv.FormatInt(time.Now().Unix(), 10)+`}`)
	if u, ok := m.Updater(); !ok || u.Version != "0.7.0" {
		t.Fatalf("heartbeat: %+v %v", u, ok)
	}
	if err := m.Request("admin@example.test"); err != nil {
		t.Fatal(err)
	}
	if !m.Pending() {
		t.Fatal("request not pending")
	}
	if err := m.Request("admin@example.test"); !errors.Is(err, ErrBusy) {
		t.Fatalf("second request: %v", err)
	}
	// The updater takes the request and reports progress.
	_ = os.Remove(filepath.Join(dir, "update-request.json"))
	write(t, filepath.Join(dir, "update", "status.json"), `{"state":"running","step":"build","started_at":1700000000,"finished_at":0,"from":"0.6.1","to":"0.7.0"}`)
	st, ok := m.Status()
	if !ok || !st.Running() || st.Step != "build" || st.To != "0.7.0" || !st.FinishedAt.IsZero() {
		t.Fatalf("status: %+v", st)
	}
	if err := m.Request("x"); !errors.Is(err, ErrBusy) {
		t.Fatalf("request while running: %v", err)
	}
	write(t, filepath.Join(dir, "update", "status.json"), `{"state":"bogus"}`)
	if _, ok := m.Status(); ok {
		t.Error("invalid state accepted")
	}
	write(t, filepath.Join(dir, "update", "update.log"), strings.Repeat("line\n", 1000)+"last line\n")
	if l := m.Log(100); len(l) > 100 || !strings.HasSuffix(l, "last line\n") || strings.HasPrefix(l, "ine") {
		t.Errorf("log tail: %q", l)
	}
}

func TestProgress(t *testing.T) {
	dir := t.TempDir()
	m := Manager{DataDir: dir}
	if p := m.Progress(); p.Active || p.HasStatus {
		t.Fatalf("idle: %+v", p)
	}
	beat := func(at time.Time) {
		write(t, filepath.Join(dir, "update", "updater.json"), `{"version":"0.7.0","seen_at":`+strconv.FormatInt(at.Unix(), 10)+`}`)
	}
	status := func(state, step string, started, finished int64, from, to string) {
		write(t, filepath.Join(dir, "update", "status.json"), `{"state":"`+state+`","step":"`+step+`","started_at":`+
			strconv.FormatInt(started, 10)+`,"finished_at":`+strconv.FormatInt(finished, 10)+`,"from":"`+from+`","to":"`+to+`"}`)
	}
	beat(time.Now())
	status(StateSucceeded, "done", 1, 2, "0.5.0", "0.6.1")
	if err := m.Request("admin@example.test"); err != nil {
		t.Fatal(err)
	}
	if p := m.Progress(); !p.Active || p.Step != StepQueued || p.Stalled {
		t.Fatalf("queued: %+v", p)
	}
	// Taken by the updater, before its first status: still starting.
	_ = os.Remove(filepath.Join(dir, "update-request.json"))
	if p := m.Progress(); !p.Active || p.Step != StepQueued {
		t.Fatalf("taken: %+v", p)
	}
	now := time.Now().Unix()
	status(StateRunning, "restart", now-90, 0, "0.6.1", "0.7.0")
	beat(time.Now().Add(-time.Hour))
	p := m.Progress()
	if !p.Active || p.Step != "restart" || p.Stalled || p.Elapsed < 89*time.Second {
		t.Fatalf("running: %+v", p)
	}
	status(StateSucceeded, "done", now-90, now, "0.6.1", "0.7.0")
	if p := m.Progress(); p.Active || !p.FinishedWithin(time.Minute) || p.SameVersion() {
		t.Fatalf("finished: %+v", p)
	}
	// An hour later.
	write(t, filepath.Join(dir, requestedFile), strconv.FormatInt(now-7200, 10))
	status(StateFailed, "build", now-7200, now-3600, "0.7.0", "0.7.0")
	if p := m.Progress(); p.Active || p.FinishedWithin(time.Minute) || !p.SameVersion() {
		t.Fatalf("old result: %+v", p)
	}
	// A request nobody takes.
	write(t, filepath.Join(dir, "update-request.json"), `{}`)
	if p := m.Progress(); !p.Active || !p.Stalled {
		t.Fatalf("stalled: %+v", p)
	}
	if got := ProgressSteps(); len(got) != 6 || got[0] != StepQueued || got[5] != "health" {
		t.Errorf("steps: %v", got)
	}
}
