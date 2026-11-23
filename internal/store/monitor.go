package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"

	"netio.patchman/internal/protocol"
)

// Monitoring check keys of the built-in limits; defined checks use "c<id>".
const (
	MonitorMemory     = "memory"
	MonitorCPU        = "cpu"
	MonitorDiskPrefix = "disk:"
)

// MonitorFailures consecutive failed rounds are notified (one failed round
// may be a blip).
const MonitorFailures = 2

// MonitorResult is one evaluated check of a monitoring round.
type MonitorResult struct {
	Key     string
	CheckID int64
	Name    string // verbatim check name; "" for the built-in limits
	Type    string // check type, or "disk", "memory", "cpu" for the built-in limits
	OK      bool
	Value   string
	Message string
}

// Builtin reports whether the result comes from a built-in limit.
func (r MonitorResult) Builtin() bool { return r.CheckID == 0 }

// Target is the file system of a built-in disk limit ("" for the others).
func (r MonitorResult) Target() string {
	if !strings.HasPrefix(r.Key, MonitorDiskPrefix) {
		return ""
	}
	return strings.TrimPrefix(r.Key, MonitorDiskPrefix)
}

// HealthState is the stored state of a monitored check.
type HealthState struct {
	MonitorResult
	Fails     int
	Notified  bool
	Since     time.Time // when the check last changed between ok and failing
	CheckedAt time.Time
}

// HealthChange is a transition to notify: Down after MonitorFailures
// failed rounds, a recovery of a notified failure otherwise.
type HealthChange struct {
	HealthState
	Down bool
}

// SaveMonitoring stores a monitoring round of a host: the resource snapshot
// and the state of each check. Checks missing from the round are dropped.
// Changes between ok and failing are kept in the health history.
func (s *Store) SaveMonitoring(ctx context.Context, hostID int64, res *protocol.Resources, results []MonitorResult) ([]HealthChange, error) {
	var changes []HealthChange
	err := s.tx(ctx, func(tx *Tx) error {
		changes = nil
		var id int64
		if err := tx.QueryRowContext(ctx, `SELECT id FROM hosts WHERE id = ? FOR UPDATE`, hostID).Scan(&id); err != nil {
			return err
		}
		prev, err := healthStates(ctx, tx, ` WHERE host_id = ?`, hostID)
		if err != nil {
			return err
		}
		old := map[string]HealthState{}
		for _, p := range prev {
			old[p.Key] = p
		}
		n := now()
		seen := map[string]bool{}
		var history [][]any
		for _, r := range results {
			if r.Key == "" || seen[r.Key] {
				continue
			}
			seen[r.Key] = true
			p, had := old[r.Key]
			st := HealthState{MonitorResult: r, CheckedAt: fromTS(n), Since: fromTS(n), Notified: had && p.Notified}
			if !r.OK {
				st.Fails = 1
				if had {
					st.Fails = p.Fails + 1
				}
			}
			if had && p.OK == r.OK {
				st.Since = p.Since
			}
			switch {
			case !r.OK && st.Fails >= MonitorFailures && !st.Notified:
				st.Notified = true
				changes = append(changes, HealthChange{HealthState: st, Down: true})
			case r.OK && st.Notified:
				st.Notified = false
				changes = append(changes, HealthChange{HealthState: st})
			}
			if (had && p.OK != r.OK) || (!had && !r.OK) {
				// The built-in limits keep their file system as the name.
				name := r.Name
				if r.Builtin() && r.Type == "disk" {
					name = r.Target()
				}
				history = append(history, []any{hostID, 0, r.CheckID, truncate(name, 200), truncate(r.Type, 20), HealthMonitor, boolInt(r.OK),
					truncate(r.Value, 500), truncate(r.Message, 500), 0, n})
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO host_health_state (host_id, check_key, check_id, check_name, check_type, ok, value, message, fails, notified, since, checked_at)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT (host_id, check_key) DO UPDATE SET check_id = excluded.check_id, check_name = excluded.check_name, check_type = excluded.check_type,
				ok = excluded.ok, value = excluded.value, message = excluded.message, fails = excluded.fails, notified = excluded.notified,
				since = excluded.since, checked_at = excluded.checked_at`,
				hostID, truncate(r.Key, 250), r.CheckID, truncate(r.Name, 200), truncate(r.Type, 20), boolInt(r.OK), truncate(r.Value, 500), truncate(r.Message, 500),
				st.Fails, boolInt(st.Notified), st.Since.Unix(), n); err != nil {
				return err
			}
		}
		for _, p := range prev {
			if !seen[p.Key] {
				if _, err := tx.ExecContext(ctx, `DELETE FROM host_health_state WHERE host_id = ? AND check_key = ?`, hostID, p.Key); err != nil {
					return err
				}
			}
		}
		if len(history) > 0 {
			if err := insertRows(ctx, tx, `INSERT INTO health_results (host_id, job_id, check_id, check_name, check_type, phase, ok, value, message, duration_ms, created_at)`, "", 11, history); err != nil {
				return err
			}
		}
		if res != nil {
			b, _ := json.Marshal(res)
			if _, err := tx.ExecContext(ctx, `UPDATE hosts SET resources = ?, resources_at = ? WHERE id = ?`, string(b), n, hostID); err != nil {
				return err
			}
			m := SampleOf(*res)
			m.At = fromTS(n)
			if err := insertSample(ctx, tx, hostID, m); err != nil {
				return err
			}
		}
		return nil
	})
	return changes, err
}

// rowsQueryer is a DB or a Tx.
type rowsQueryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func healthStates(ctx context.Context, q rowsQueryer, where string, args ...any) ([]HealthState, error) {
	rows, err := q.QueryContext(ctx, `SELECT host_id, check_key, check_id, check_name, check_type, ok, value, message, fails, notified, since, checked_at
		FROM host_health_state`+where+` ORDER BY ok, CASE WHEN check_id = 0 THEN 1 ELSE 0 END, lower(check_name), check_key`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HealthState
	for rows.Next() {
		var st HealthState
		var host int64
		var ok, notified int
		var since, at int64
		if err := rows.Scan(&host, &st.Key, &st.CheckID, &st.Name, &st.Type, &ok, &st.Value, &st.Message, &st.Fails, &notified, &since, &at); err != nil {
			return nil, err
		}
		st.OK, st.Notified, st.Since, st.CheckedAt = ok == 1, notified == 1, fromTS(since), fromTS(at)
		out = append(out, st)
	}
	return out, rows.Err()
}

// HostHealthStates returns the monitored checks of a host, failing first.
func (s *Store) HostHealthStates(ctx context.Context, hostID int64) ([]HealthState, error) {
	where, args := andScope(ctx, ` WHERE host_id = ?`, []any{hostID}, "host_id")
	return healthStates(ctx, s.db, where, args...)
}

// HostResources returns the latest resource snapshot of a host (nil when
// the agent never sent one).
func (s *Store) HostResources(ctx context.Context, hostID int64) (*protocol.Resources, time.Time, error) {
	where, args := andScope(ctx, ` WHERE id = ?`, []any{hostID}, "id")
	var raw string
	var at int64
	if err := s.db.QueryRowContext(ctx, `SELECT resources, resources_at FROM hosts`+where, args...).Scan(&raw, &at); err != nil {
		return nil, time.Time{}, err
	}
	if raw == "" {
		return nil, time.Time{}, nil
	}
	var r protocol.Resources
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		return nil, time.Time{}, nil
	}
	return &r, fromTS(at), nil
}

// FleetResources returns the resource snapshots taken after since, by host.
func (s *Store) FleetResources(ctx context.Context, since time.Time) (map[int64]protocol.Resources, error) {
	where, args := andScope(ctx, ` WHERE resources <> '' AND resources_at >= ?`, []any{since.Unix()}, "id")
	rows, err := s.db.QueryContext(ctx, `SELECT id, resources FROM hosts`+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]protocol.Resources{}
	for rows.Next() {
		var id int64
		var raw string
		if err := rows.Scan(&id, &raw); err != nil {
			return nil, err
		}
		var r protocol.Resources
		if json.Unmarshal([]byte(raw), &r) == nil {
			out[id] = r
		}
	}
	return out, rows.Err()
}

// FailingHealth counts the failing monitored checks per host.
func (s *Store) FailingHealth(ctx context.Context) (map[int64]int, error) {
	where, args := andScope(ctx, ` WHERE ok = 0`, nil, "host_id")
	rows, err := s.db.QueryContext(ctx, `SELECT host_id, COUNT(*) FROM host_health_state`+where+` GROUP BY host_id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]int{}
	for rows.Next() {
		var id int64
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}

// MetricSample is one row of a host's resource history; percentages in
// tenths, -1 unknown. Disk is the fullest file system.
type MetricSample struct {
	At                            time.Time
	CPU, Load, Memory, Swap, Disk int
}

// SampleOf converts a snapshot to a history row.
func SampleOf(r protocol.Resources) MetricSample {
	tenths := func(v float64) int {
		if v < 0 {
			return -1
		}
		return int(v*10 + 0.5)
	}
	return MetricSample{CPU: tenths(r.CPU()), Load: tenths(r.LoadPercent()), Memory: tenths(r.MemoryPercent()), Swap: tenths(r.SwapPercent()), Disk: tenths(r.DiskMax())}
}

// RecordMetricSample stores one history row (imports, tests); a second
// row for the same second is ignored.
func (s *Store) RecordMetricSample(ctx context.Context, hostID int64, m MetricSample) error {
	return insertSample(ctx, s.db, hostID, m)
}

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func insertSample(ctx context.Context, x execer, hostID int64, m MetricSample) error {
	_, err := x.ExecContext(ctx, `INSERT INTO host_metrics (host_id, at, cpu, load, memory, swap, disk) VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (host_id, at) DO NOTHING`, hostID, m.At.Unix(), m.CPU, m.Load, m.Memory, m.Swap, m.Disk)
	return err
}

// HostMetrics returns a host's resource history since from, oldest first.
func (s *Store) HostMetrics(ctx context.Context, hostID int64, from time.Time) ([]MetricSample, error) {
	where, args := andScope(ctx, ` WHERE host_id = ? AND at >= ?`, []any{hostID, from.Unix()}, "host_id")
	rows, err := s.db.QueryContext(ctx, `SELECT at, cpu, load, memory, swap, disk FROM host_metrics`+where+` ORDER BY at`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MetricSample
	for rows.Next() {
		var m MetricSample
		var at int64
		if err := rows.Scan(&at, &m.CPU, &m.Load, &m.Memory, &m.Swap, &m.Disk); err != nil {
			return nil, err
		}
		m.At = fromTS(at)
		out = append(out, m)
	}
	return out, rows.Err()
}

// PruneHostMetrics deletes resource history older than d.
func (s *Store) PruneHostMetrics(ctx context.Context, d time.Duration) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM host_metrics WHERE at < ?`, now()-int64(d.Seconds()))
	return err
}
