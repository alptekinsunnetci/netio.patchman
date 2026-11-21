package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// JobExpired marks scheduled jobs the agent did not pick up before the
// maintenance window ended.
const JobExpired = "expired"

// Schedule targets.
const (
	TargetAll   = "all"
	TargetOS    = "os"
	TargetHosts = "hosts"
	// TargetGroup is stored as target 'all' with group_id set.
	TargetGroup = "group"
)

// Schedule is a recurring update rule (maintenance window).
type Schedule struct {
	ID            int64
	Name          string
	Enabled       bool
	JobType       string
	Days          int // weekday bitmask, bit 0 = Sunday
	Minute        int // minutes after midnight in the display time zone
	WindowMinutes int
	Target        string
	OSID          string
	HostIDs       []int64
	GroupID       int64
	GroupName     string
	// Reboot restarts hosts that report a pending reboot after their update
	// job, while the maintenance window is still open (opt-in).
	Reboot      bool
	NextRunAt   time.Time
	LastRunAt   time.Time
	LastQueued  int
	LastSkipped int
	CreatedBy   string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Window returns the maintenance window length.
func (sc Schedule) Window() time.Duration { return time.Duration(sc.WindowMinutes) * time.Minute }

const scheduleSelect = `SELECT sc.id, sc.name, sc.enabled, sc.job_type, sc.days, sc.minute, sc.window_minutes, sc.target, sc.os_id,
 sc.next_run_at, sc.last_run_at, sc.last_queued, sc.last_skipped, COALESCE(u.name, ''), sc.created_at, sc.updated_at,
 (SELECT COUNT(*) FROM schedule_hosts sh WHERE sh.schedule_id = sc.id), COALESCE(sc.group_id, 0), COALESCE(g.name, ''), sc.reboot
 FROM schedules sc LEFT JOIN users u ON u.id = sc.created_by LEFT JOIN host_groups g ON g.id = sc.group_id`

func scanSchedule(row interface{ Scan(...any) error }) (Schedule, int, error) {
	var sc Schedule
	var enabled, hostCount, reboot int
	var next, last, created, updated int64
	err := row.Scan(&sc.ID, &sc.Name, &enabled, &sc.JobType, &sc.Days, &sc.Minute, &sc.WindowMinutes, &sc.Target, &sc.OSID,
		&next, &last, &sc.LastQueued, &sc.LastSkipped, &sc.CreatedBy, &created, &updated, &hostCount, &sc.GroupID, &sc.GroupName, &reboot)
	if errors.Is(err, sql.ErrNoRows) {
		return sc, 0, ErrNotFound
	}
	if err != nil {
		return sc, 0, err
	}
	sc.Enabled, sc.Reboot = enabled == 1, reboot == 1
	if sc.GroupID != 0 && sc.Target == TargetAll {
		sc.Target = TargetGroup
	}
	sc.NextRunAt, sc.LastRunAt, sc.CreatedAt, sc.UpdatedAt = fromTS(next), fromTS(last), fromTS(created), fromTS(updated)
	return sc, hostCount, nil
}

// ScheduleRow is a schedule with the number of explicitly selected hosts.
type ScheduleRow struct {
	Schedule
	HostCount int
}

// ListSchedules returns all schedules ordered by name.
func (s *Store) ListSchedules(ctx context.Context) ([]ScheduleRow, error) {
	rows, err := s.db.QueryContext(ctx, scheduleSelect+` ORDER BY sc.name COLLATE NOCASE, sc.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ScheduleRow
	for rows.Next() {
		sc, n, err := scanSchedule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ScheduleRow{Schedule: sc, HostCount: n})
	}
	return out, rows.Err()
}

// ScheduleByID returns a schedule including its selected host IDs.
func (s *Store) ScheduleByID(ctx context.Context, id int64) (Schedule, error) {
	sc, _, err := scanSchedule(s.db.QueryRowContext(ctx, scheduleSelect+` WHERE sc.id = ?`, id))
	if err != nil {
		return sc, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT host_id FROM schedule_hosts WHERE schedule_id = ? ORDER BY host_id`, id)
	if err != nil {
		return sc, err
	}
	defer rows.Close()
	for rows.Next() {
		var h int64
		if err := rows.Scan(&h); err != nil {
			return sc, err
		}
		sc.HostIDs = append(sc.HostIDs, h)
	}
	return sc, rows.Err()
}

// dbTarget maps a schedule to its stored target and group_id (NULL unless
// the target is a group).
func dbTarget(sc Schedule) (string, any) {
	if sc.Target == TargetGroup {
		return TargetAll, nullID(sc.GroupID)
	}
	return sc.Target, nil
}

func setScheduleHosts(ctx context.Context, tx *sql.Tx, id int64, sc Schedule) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM schedule_hosts WHERE schedule_id = ?`, id); err != nil {
		return err
	}
	if sc.Target != TargetHosts {
		return nil
	}
	for _, h := range sc.HostIDs {
		// Hosts deleted meanwhile are ignored.
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO schedule_hosts (schedule_id, host_id) SELECT ?, id FROM hosts WHERE id = ?`, id, h); err != nil {
			return err
		}
	}
	return nil
}

// CreateSchedule stores a new schedule.
func (s *Store) CreateSchedule(ctx context.Context, sc Schedule, userID int64) (int64, error) {
	var id int64
	err := s.tx(ctx, func(tx *sql.Tx) error {
		n := now()
		target, group := dbTarget(sc)
		res, err := tx.ExecContext(ctx, `INSERT INTO schedules (name, enabled, job_type, days, minute, window_minutes, target, os_id, next_run_at, created_by, created_at, updated_at, group_id, reboot)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			sc.Name, boolInt(sc.Enabled), sc.JobType, sc.Days, sc.Minute, sc.WindowMinutes, target, sc.OSID, toTS(sc.NextRunAt), nullID(userID), n, n, group, boolInt(sc.Reboot))
		if err != nil {
			return err
		}
		if id, err = res.LastInsertId(); err != nil {
			return err
		}
		return setScheduleHosts(ctx, tx, id, sc)
	})
	return id, err
}

// UpdateSchedule replaces a schedule's definition and next run time.
func (s *Store) UpdateSchedule(ctx context.Context, sc Schedule) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		target, group := dbTarget(sc)
		res, err := tx.ExecContext(ctx, `UPDATE schedules SET name = ?, enabled = ?, job_type = ?, days = ?, minute = ?, window_minutes = ?, target = ?, os_id = ?,
			next_run_at = ?, updated_at = ?, group_id = ?, reboot = ? WHERE id = ?`,
			sc.Name, boolInt(sc.Enabled), sc.JobType, sc.Days, sc.Minute, sc.WindowMinutes, target, sc.OSID, toTS(sc.NextRunAt), now(), group, boolInt(sc.Reboot), sc.ID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return setScheduleHosts(ctx, tx, sc.ID, sc)
	})
}

// DeleteSchedule removes a schedule. Its queued jobs are cancelled; finished
// jobs keep their history (schedule_id becomes NULL).
func (s *Store) DeleteSchedule(ctx context.Context, id int64) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE jobs SET status = 'cancelled', finished_at = ? WHERE schedule_id = ? AND status = 'queued'`, now(), id); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `DELETE FROM schedules WHERE id = ?`, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// DueSchedules returns enabled schedules whose next run time has passed.
func (s *Store) DueSchedules(ctx context.Context, at time.Time) ([]Schedule, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM schedules WHERE enabled = 1 AND next_run_at > 0 AND next_run_at <= ? ORDER BY next_run_at, id`, at.Unix())
	if err != nil {
		return nil, err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	out := make([]Schedule, 0, len(ids))
	for _, id := range ids {
		sc, err := s.ScheduleByID(ctx, id)
		if err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, nil
}

// SetScheduleNextRun advances a schedule without recording a run (for
// example when the server was down for the whole window).
func (s *Store) SetScheduleNextRun(ctx context.Context, id int64, next time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE schedules SET next_run_at = ? WHERE id = ?`, toTS(next), id)
	return err
}

// RecordScheduleRun stores the outcome of a run. A zero next keeps the
// current next run time (manual runs).
func (s *Store) RecordScheduleRun(ctx context.Context, id int64, at, next time.Time, queued, skipped int) error {
	if next.IsZero() {
		_, err := s.db.ExecContext(ctx, `UPDATE schedules SET last_run_at = ?, last_queued = ?, last_skipped = ? WHERE id = ?`,
			at.Unix(), queued, skipped, id)
		return err
	}
	_, err := s.db.ExecContext(ctx, `UPDATE schedules SET last_run_at = ?, last_queued = ?, last_skipped = ?, next_run_at = ? WHERE id = ?`,
		at.Unix(), queued, skipped, toTS(next), id)
	return err
}

// ScheduleTargets returns the hosts a schedule applies to, with aggregates.
func (s *Store) ScheduleTargets(ctx context.Context, sc Schedule) ([]Host, error) {
	q := hostSelect
	var args []any
	switch sc.Target {
	case TargetAll:
	case TargetOS:
		q += ` WHERE h.os_id = ?`
		args = append(args, sc.OSID)
	case TargetHosts:
		q += ` WHERE h.id IN (SELECT host_id FROM schedule_hosts WHERE schedule_id = ?)`
		args = append(args, sc.ID)
	case TargetGroup:
		q += ` WHERE h.id IN (SELECT host_id FROM host_group_members WHERE group_id = ?)`
		args = append(args, sc.GroupID)
	default:
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY h.hostname COLLATE NOCASE`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Host
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// CreateScheduledJob queues a job on behalf of a schedule. The agent must
// pick it up before expiresAt, otherwise it is marked expired.
func (s *Store) CreateScheduledJob(ctx context.Context, hostID int64, typ string, scheduleID int64, expiresAt time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `INSERT INTO jobs (host_id, type, packages, params, status, created_by, created_at, schedule_id, expires_at)
		VALUES (?, ?, '[]', '{}', 'queued', NULL, ?, ?, ?)`, hostID, typ, now(), scheduleID, toTS(expiresAt))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ExpiredJobGroup summarizes jobs of one schedule that expired together.
type ExpiredJobGroup struct {
	ScheduleID   int64
	ScheduleName string
	Hostnames    []string
}

// ExpireJobs marks queued jobs whose window has ended as expired and groups
// them by schedule.
func (s *Store) ExpireJobs(ctx context.Context, at time.Time) ([]ExpiredJobGroup, error) {
	var groups []ExpiredJobGroup
	err := s.tx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT COALESCE(j.schedule_id, 0), COALESCE(sc.name, ''), h.hostname FROM jobs j
			JOIN hosts h ON h.id = j.host_id LEFT JOIN schedules sc ON sc.id = j.schedule_id
			WHERE j.status = 'queued' AND j.expires_at > 0 AND j.expires_at <= ? ORDER BY j.schedule_id, h.hostname`, at.Unix())
		if err != nil {
			return err
		}
		idx := map[int64]int{}
		for rows.Next() {
			var id int64
			var name, host string
			if err := rows.Scan(&id, &name, &host); err != nil {
				rows.Close()
				return err
			}
			i, ok := idx[id]
			if !ok {
				i = len(groups)
				idx[id] = i
				groups = append(groups, ExpiredJobGroup{ScheduleID: id, ScheduleName: name})
			}
			groups[i].Hostnames = append(groups[i].Hostnames, host)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		_, err = tx.ExecContext(ctx, `UPDATE jobs SET status = 'expired', finished_at = ?, exit_code = -1
			WHERE status = 'queued' AND expires_at > 0 AND expires_at <= ?`, now(), at.Unix())
		return err
	})
	return groups, err
}

// SchedulesForHost returns the names of enabled schedules that cover a host.
func (s *Store) SchedulesForHost(ctx context.Context, h Host) ([]ScheduleRow, error) {
	all, err := s.ListSchedules(ctx)
	if err != nil {
		return nil, err
	}
	var out []ScheduleRow
	for _, sc := range all {
		switch sc.Target {
		case TargetAll:
		case TargetOS:
			if !strings.EqualFold(sc.OSID, h.OSID) {
				continue
			}
		case TargetHosts:
			var n int
			if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schedule_hosts WHERE schedule_id = ? AND host_id = ?`, sc.ID, h.ID).Scan(&n); err != nil {
				return nil, err
			}
			if n == 0 {
				continue
			}
		case TargetGroup:
			member := false
			for _, g := range h.Groups {
				member = member || g.ID == sc.GroupID
			}
			if !member {
				continue
			}
		}
		out = append(out, sc)
	}
	return out, nil
}

func toTS(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

// QueueScheduledReboot queues a reboot job for a host that reported a pending
// reboot when its latest update job came from a schedule with the reboot
// option, finished (succeeded or partial) and its maintenance window is still
// open. It returns the new job ID, or 0 when nothing was queued. Each update
// job leads to at most one reboot.
func (s *Store) QueueScheduledReboot(ctx context.Context, hostID int64) (int64, error) {
	var rebootID int64
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var jobID, scheduleID, expires int64
		err := tx.QueryRowContext(ctx, `SELECT j.id, j.schedule_id, j.expires_at FROM jobs j JOIN schedules sc ON sc.id = j.schedule_id
			WHERE j.host_id = ? AND sc.reboot = 1 AND j.reboot_job_id = 0 AND j.type IN ('upgrade_security', 'upgrade_all')
			AND j.status IN ('succeeded', 'partial') AND j.expires_at > ? ORDER BY j.finished_at DESC LIMIT 1`, hostID, now()).
			Scan(&jobID, &scheduleID, &expires)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		// A reboot already waiting for this host is enough.
		var pending int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM jobs WHERE host_id = ? AND type = 'reboot' AND status IN ('queued', 'dispatched')`, hostID).Scan(&pending); err != nil {
			return err
		}
		if pending == 0 {
			res, err := tx.ExecContext(ctx, `INSERT INTO jobs (host_id, type, packages, params, status, created_by, created_at, schedule_id, expires_at)
				VALUES (?, 'reboot', '[]', '{}', 'queued', NULL, ?, ?, ?)`, hostID, now(), scheduleID, expires)
			if err != nil {
				return err
			}
			if rebootID, err = res.LastInsertId(); err != nil {
				return err
			}
		}
		mark := rebootID
		if mark == 0 {
			mark = -1
		}
		_, err = tx.ExecContext(ctx, `UPDATE jobs SET reboot_job_id = ? WHERE id = ?`, mark, jobID)
		return err
	})
	return rebootID, err
}
