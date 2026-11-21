// Package selfupdate lets administrators update the netio.patchman server from
// the web interface. The server never touches Docker itself: it writes a
// request file into the shared data volume, and the optional "updater"
// container (docker-compose profile "updater", deploy/updater) runs fixed
// steps: git pull, database backup, image build, restart, health check. The
// updater reports its heartbeat and progress in files the server reads:
//
//	<data>/update-request.json   written by the server, removed by the updater
//	<data>/update/updater.json   {"version": "...", "seen_at": unix} every 5 s
//	<data>/update/status.json    {"state", "step", "started_at", "finished_at", "from", "to"}
//	<data>/update/update.log     command output of the last update
package selfupdate

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"netio.patchman/internal/timeutil"
)

// States of an update.
const (
	StateRunning   = "running"
	StateSucceeded = "succeeded"
	StateFailed    = "failed"
)

// Steps reported while running (also the catalog keys selfupdate.step.<id>).
var Steps = []string{"pull", "backup", "build", "restart", "health", "done"}

// heartbeatTimeout is how old the updater heartbeat may be.
const heartbeatTimeout = 30 * time.Second

// ErrBusy is returned when an update is already requested or running.
var ErrBusy = errors.New("selfupdate: update in progress")

// ErrUnavailable is returned when no updater is running.
var ErrUnavailable = errors.New("selfupdate: updater not running")

// Manager reads and writes the shared files.
type Manager struct {
	DataDir string
}

// Status is the progress of the last update.
type Status struct {
	State      string
	Step       string
	StartedAt  time.Time
	FinishedAt time.Time
	From, To   string
}

// Running reports whether the update is still going on.
func (s Status) Running() bool { return s.State == StateRunning }

// Updater is the updater's heartbeat.
type Updater struct {
	Version string
	SeenAt  time.Time
}

func (m Manager) path(parts ...string) string {
	return filepath.Join(append([]string{m.DataDir}, parts...)...)
}

func unix(v int64) time.Time {
	if v <= 0 {
		return time.Time{}
	}
	return time.Unix(v, 0).UTC()
}

// Updater returns the heartbeat; ok is false when no updater runs.
func (m Manager) Updater() (Updater, bool) {
	var raw struct {
		Version string `json:"version"`
		SeenAt  int64  `json:"seen_at"`
	}
	b, err := os.ReadFile(m.path("update", "updater.json"))
	if err != nil || json.Unmarshal(b, &raw) != nil {
		return Updater{}, false
	}
	u := Updater{Version: raw.Version, SeenAt: unix(raw.SeenAt)}
	return u, !u.SeenAt.IsZero() && timeutil.Now().Sub(u.SeenAt) < heartbeatTimeout
}

// Status returns the last update's progress; ok is false when none ran.
func (m Manager) Status() (Status, bool) {
	var raw struct {
		State      string `json:"state"`
		Step       string `json:"step"`
		StartedAt  int64  `json:"started_at"`
		FinishedAt int64  `json:"finished_at"`
		From       string `json:"from"`
		To         string `json:"to"`
	}
	b, err := os.ReadFile(m.path("update", "status.json"))
	if err != nil || json.Unmarshal(b, &raw) != nil {
		return Status{}, false
	}
	switch raw.State {
	case StateRunning, StateSucceeded, StateFailed:
	default:
		return Status{}, false
	}
	return Status{State: raw.State, Step: raw.Step, StartedAt: unix(raw.StartedAt), FinishedAt: unix(raw.FinishedAt), From: raw.From, To: raw.To}, true
}

// Pending reports whether a request waits for the updater.
func (m Manager) Pending() bool {
	_, err := os.Stat(m.path("update-request.json"))
	return err == nil
}

// Request asks the updater to update. by is recorded for the log only.
func (m Manager) Request(by string) error {
	if _, ok := m.Updater(); !ok {
		return ErrUnavailable
	}
	if st, ok := m.Status(); m.Pending() || (ok && st.Running()) {
		return ErrBusy
	}
	b, _ := json.Marshal(map[string]any{"requested_by": by, "requested_at": timeutil.Now().Unix()})
	tmp := m.path(".update-request.json.tmp")
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, m.path("update-request.json"))
}

// Log returns the end of the last update's output (at most max bytes).
func (m Manager) Log(max int) string {
	b, err := os.ReadFile(m.path("update", "update.log"))
	if err != nil {
		return ""
	}
	if len(b) > max {
		b = b[len(b)-max:]
		if i := strings.IndexByte(string(b), '\n'); i >= 0 {
			b = b[i+1:]
		}
	}
	return strings.ToValidUTF8(string(b), "")
}
