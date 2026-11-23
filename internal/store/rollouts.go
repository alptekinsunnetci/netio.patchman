package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Rollout statuses.
const (
	RolloutRunning   = "running"
	RolloutPaused    = "paused"
	RolloutCompleted = "completed"
	RolloutFailed    = "failed" // stopped automatically
	RolloutCancelled = "cancelled"
)

// Rollout host statuses.
const (
	RolloutHostPending   = "pending"
	RolloutHostQueued    = "queued"
	RolloutHostSucceeded = "succeeded"
	RolloutHostFailed    = "failed"
	RolloutHostSkipped   = "skipped"
)

// ParamRolloutID is the server-side job parameter linking a job to its rollout.
const ParamRolloutID = "rollout_id"

// Rollout is a rolling update.
type Rollout struct {
	ID                int64
	Name              string
	JobType           string
	Packages          []string
	Status            string
	Stages            int
	CurrentStage      int
	Canary            int // hosts in the first stage (0: no canary)
	MaxParallel       int
	WaitMinutes       int
	MaxFailurePct     int
	RequireHealth     bool
	PauseAfterCanary  bool
	JobTimeoutMinutes int
	StageFinishedAt   time.Time
	AcceptedFailures  int
	AcceptedProcessed int
	Reason            string // catalog key suffix of the stop/pause reason
	CreatedByID       int64
	CreatedBy         string
	CreatedAt         time.Time
	FinishedAt        time.Time
	Counts            RolloutCounts
}

// RolloutCounts counts hosts by status.
type RolloutCounts struct {
	Total, Pending, Queued, Succeeded, Failed, Skipped int
}

// Done returns the hosts that finished (succeeded or failed).
func (c RolloutCounts) Done() int { return c.Succeeded + c.Failed }

// Active reports whether the rollout can still change hosts.
func (r Rollout) Active() bool { return r.Status == RolloutRunning || r.Status == RolloutPaused }

// RolloutHost is a host of a rollout.
type RolloutHost struct {
	HostID    int64
	Hostname  string
	Stage     int
	Position  int
	JobID     int64
	JobStatus string
	Status    string
	Note      string
}

const rolloutCols = `r.id, r.name, r.job_type, r.packages, r.status, r.stages, r.current_stage, r.canary, r.max_parallel, r.wait_minutes, r.max_failure_pct,
	r.require_health, r.pause_after_canary, r.job_timeout_minutes, r.stage_finished_at, r.accepted_failures, r.accepted_processed, r.reason,
	COALESCE(r.created_by, 0), COALESCE(u.name, ''), r.created_at, r.finished_at`

func scanRollout(row interface{ Scan(...any) error }) (Rollout, error) {
	var r Rollout
	var pkgs string
	var health, pause int
	var sf, ca, fa int64
	err := row.Scan(&r.ID, &r.Name, &r.JobType, &pkgs, &r.Status, &r.Stages, &r.CurrentStage, &r.Canary, &r.MaxParallel, &r.WaitMinutes, &r.MaxFailurePct,
		&health, &pause, &r.JobTimeoutMinutes, &sf, &r.AcceptedFailures, &r.AcceptedProcessed, &r.Reason, &r.CreatedByID, &r.CreatedBy, &ca, &fa)
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrNotFound
	}
	if err != nil {
		return r, err
	}
	_ = json.Unmarshal([]byte(pkgs), &r.Packages)
	r.RequireHealth, r.PauseAfterCanary = health == 1, pause == 1
	r.StageFinishedAt, r.CreatedAt, r.FinishedAt = fromTS(sf), fromTS(ca), fromTS(fa)
	return r, nil
}

// CreateRollout stores a rollout with its hosts by stage (stages[0] is the
// first stage, in order).
func (s *Store) CreateRollout(ctx context.Context, r Rollout, stages [][]int64) (int64, error) {
	var id int64
	err := s.tx(ctx, func(tx *Tx) error {
		pk, _ := json.Marshal(nonNil(r.Packages))
		var err error
		id, err = insertID(ctx, tx, `INSERT INTO rollouts (name, job_type, packages, status, stages, canary, max_parallel, wait_minutes, max_failure_pct,
			require_health, pause_after_canary, job_timeout_minutes, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			strings.TrimSpace(r.Name), r.JobType, string(pk), RolloutRunning, len(stages), r.Canary, r.MaxParallel, r.WaitMinutes, r.MaxFailurePct,
			boolInt(r.RequireHealth), boolInt(r.PauseAfterCanary), r.JobTimeoutMinutes, nullID(r.CreatedByID), now())
		if err != nil {
			return err
		}
		var rows [][]any
		pos := 0
		for st, hosts := range stages {
			for _, h := range hosts {
				rows = append(rows, []any{id, h, st, pos})
				pos++
			}
		}
		return insertRows(ctx, tx, `INSERT INTO rollout_hosts (rollout_id, host_id, stage, position)`, "", 4, rows)
	})
	return id, err
}

// RolloutByID returns a rollout with its host counts.
func (s *Store) RolloutByID(ctx context.Context, id int64) (Rollout, error) {
	r, err := scanRollout(s.db.QueryRowContext(ctx, `SELECT `+rolloutCols+` FROM rollouts r LEFT JOIN users u ON u.id = r.created_by WHERE r.id = ?`, id))
	if err != nil {
		return r, err
	}
	counts, err := s.rolloutCounts(ctx, []int64{id})
	r.Counts = counts[id]
	return r, err
}

func (s *Store) rolloutCounts(ctx context.Context, ids []int64) (map[int64]RolloutCounts, error) {
	out := map[int64]RolloutCounts{}
	if len(ids) == 0 {
		return out, nil
	}
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	rows, err := s.db.QueryContext(ctx, `SELECT rollout_id, status, COUNT(*) FROM rollout_hosts WHERE rollout_id IN (?`+strings.Repeat(",?", len(ids)-1)+`) GROUP BY rollout_id, status`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var st string
		var n int
		if err := rows.Scan(&id, &st, &n); err != nil {
			return nil, err
		}
		c := out[id]
		c.Total += n
		switch st {
		case RolloutHostPending:
			c.Pending += n
		case RolloutHostQueued:
			c.Queued += n
		case RolloutHostSucceeded:
			c.Succeeded += n
		case RolloutHostFailed:
			c.Failed += n
		case RolloutHostSkipped:
			c.Skipped += n
		}
		out[id] = c
	}
	return out, rows.Err()
}

// ListRollouts returns rollouts newest first.
func (s *Store) ListRollouts(ctx context.Context, p Page) ([]Rollout, int, error) {
	return s.rollouts(ctx, "", nil, p)
}

// RunningRollouts returns the rollouts the runner advances.
func (s *Store) RunningRollouts(ctx context.Context) ([]Rollout, error) {
	out, _, err := s.rollouts(ctx, ` WHERE r.status = ?`, []any{RolloutRunning}, Page{Number: 1, Size: 500})
	return out, err
}

func (s *Store) rollouts(ctx context.Context, where string, args []any, p Page) ([]Rollout, int, error) {
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM rollouts r`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+rolloutCols+` FROM rollouts r LEFT JOIN users u ON u.id = r.created_by`+where+` ORDER BY r.id DESC LIMIT ? OFFSET ?`,
		append(args, p.limit(), p.Offset())...)
	if err != nil {
		return nil, 0, err
	}
	var out []Rollout
	var ids []int64
	for rows.Next() {
		r, err := scanRollout(rows)
		if err != nil {
			rows.Close()
			return nil, 0, err
		}
		out = append(out, r)
		ids = append(ids, r.ID)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	counts, err := s.rolloutCounts(ctx, ids)
	for i := range out {
		out[i].Counts = counts[out[i].ID]
	}
	return out, total, err
}

// RolloutHosts returns a rollout's hosts in order with their job status.
func (s *Store) RolloutHosts(ctx context.Context, id int64) ([]RolloutHost, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT rh.host_id, h.hostname, rh.stage, rh.position, rh.job_id, COALESCE(j.status, ''), rh.status, rh.note
		FROM rollout_hosts rh JOIN hosts h ON h.id = rh.host_id LEFT JOIN jobs j ON j.id = rh.job_id
		WHERE rh.rollout_id = ? ORDER BY rh.stage, rh.position`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RolloutHost
	for rows.Next() {
		var h RolloutHost
		if err := rows.Scan(&h.HostID, &h.Hostname, &h.Stage, &h.Position, &h.JobID, &h.JobStatus, &h.Status, &h.Note); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// SetRolloutHost records a host's progress.
func (s *Store) SetRolloutHost(ctx context.Context, rolloutID, hostID int64, status string, jobID int64, note string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE rollout_hosts SET status = ?, job_id = CASE WHEN CAST(? AS BIGINT) > 0 THEN CAST(? AS BIGINT) ELSE job_id END, note = ?
		WHERE rollout_id = ? AND host_id = ?`, status, jobID, jobID, truncate(note, 200), rolloutID, hostID)
	return err
}

// SkipPendingRolloutHosts marks the hosts not started yet as skipped.
func (s *Store) SkipPendingRolloutHosts(ctx context.Context, rolloutID int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE rollout_hosts SET status = ? WHERE rollout_id = ? AND status = ?`, RolloutHostSkipped, rolloutID, RolloutHostPending)
	return err
}

// SaveRolloutState stores the progress fields of a rollout.
func (s *Store) SaveRolloutState(ctx context.Context, r Rollout) error {
	_, err := s.db.ExecContext(ctx, `UPDATE rollouts SET status = ?, current_stage = ?, stage_finished_at = ?, reason = ?, finished_at = ?,
		accepted_failures = ?, accepted_processed = ? WHERE id = ?`,
		r.Status, r.CurrentStage, ts(r.StageFinishedAt), r.Reason, ts(r.FinishedAt), r.AcceptedFailures, r.AcceptedProcessed, r.ID)
	return err
}

// CreateJobExpiring queues a job that is never dispatched after expires.
func (s *Store) CreateJobExpiring(ctx context.Context, hostID int64, typ string, packages []string, params map[string]string, userID int64, expires time.Time) (int64, error) {
	b, _ := json.Marshal(nonNil(packages))
	if params == nil {
		params = map[string]string{}
	}
	p, _ := json.Marshal(params)
	return insertID(ctx, s.db, `INSERT INTO jobs (host_id, type, packages, params, status, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, 'queued', ?, ?, ?)`,
		hostID, typ, string(b), string(p), nullID(userID), now(), ts(expires))
}

// RolloutStatusCounts counts rollouts by status.
func (s *Store) RolloutStatusCounts(ctx context.Context) (map[string]int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT status, COUNT(*) FROM rollouts GROUP BY status`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			return nil, err
		}
		out[st] = n
	}
	return out, rows.Err()
}
