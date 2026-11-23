package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"netio.patchman/internal/protocol"
)

// Health check scopes.
const (
	HealthScopeAll   = "all"
	HealthScopeGroup = "group"
	HealthScopeHost  = "host"
)

// HealthCheckDef is a stored health check definition.
type HealthCheckDef struct {
	protocol.HealthCheck
	Scope       string
	GroupID     int64
	GroupName   string
	HostID      int64
	Hostname    string
	WithUpdates bool
	Enabled     bool
	CreatedAt   time.Time
}

const healthCheckCols = `c.id, c.name, c.type, c.target, c.expect, c.contains, c.insecure, c.cpu, c.memory, c.disk, c.paths, c.timeout_seconds,
	c.scope, COALESCE(c.group_id, 0), COALESCE(g.name, ''), COALESCE(c.host_id, 0), COALESCE(h.hostname, ''), c.with_updates, c.enabled, c.created_at`

const healthCheckFrom = ` FROM health_checks c LEFT JOIN host_groups g ON g.id = c.group_id LEFT JOIN hosts h ON h.id = c.host_id`

func scanHealthCheck(row interface{ Scan(...any) error }) (HealthCheckDef, error) {
	var c HealthCheckDef
	var insecure, with, enabled int
	var paths string
	var created int64
	err := row.Scan(&c.ID, &c.Name, &c.Type, &c.Target, &c.Expect, &c.Contains, &insecure, &c.CPU, &c.Memory, &c.Disk, &paths, &c.TimeoutSeconds,
		&c.Scope, &c.GroupID, &c.GroupName, &c.HostID, &c.Hostname, &with, &enabled, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return c, ErrNotFound
	}
	if err != nil {
		return c, err
	}
	_ = json.Unmarshal([]byte(paths), &c.Paths)
	c.Insecure, c.WithUpdates, c.Enabled, c.CreatedAt = insecure == 1, with == 1, enabled == 1, fromTS(created)
	return c, nil
}

func healthArgs(c HealthCheckDef) []any {
	paths, _ := json.Marshal(nonNil(c.Paths))
	var group, host any
	switch c.Scope {
	case HealthScopeGroup:
		group = c.GroupID
	case HealthScopeHost:
		host = c.HostID
	}
	return []any{strings.TrimSpace(c.Name), c.Type, c.Target, c.Expect, c.Contains, boolInt(c.Insecure), c.CPU, c.Memory, c.Disk, string(paths), c.TimeoutSeconds,
		c.Scope, group, host, boolInt(c.WithUpdates), boolInt(c.Enabled)}
}

// CreateHealthCheck stores a definition.
func (s *Store) CreateHealthCheck(ctx context.Context, c HealthCheckDef) (int64, error) {
	return insertID(ctx, s.db, `INSERT INTO health_checks (name, type, target, expect, contains, insecure, cpu, memory, disk, paths, timeout_seconds,
		scope, group_id, host_id, with_updates, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, append(healthArgs(c), now())...)
}

// UpdateHealthCheck replaces a definition.
func (s *Store) UpdateHealthCheck(ctx context.Context, c HealthCheckDef) error {
	res, err := s.db.ExecContext(ctx, `UPDATE health_checks SET name = ?, type = ?, target = ?, expect = ?, contains = ?, insecure = ?, cpu = ?, memory = ?, disk = ?,
		paths = ?, timeout_seconds = ?, scope = ?, group_id = ?, host_id = ?, with_updates = ?, enabled = ? WHERE id = ?`, append(healthArgs(c), c.ID)...)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteHealthCheck removes a definition (its results stay in the history).
func (s *Store) DeleteHealthCheck(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM health_checks WHERE id = ?`, id)
	return err
}

// HealthCheckByID returns a definition.
func (s *Store) HealthCheckByID(ctx context.Context, id int64) (HealthCheckDef, error) {
	return scanHealthCheck(s.db.QueryRowContext(ctx, `SELECT `+healthCheckCols+healthCheckFrom+` WHERE c.id = ?`, id))
}

// ListHealthChecks returns all definitions by name.
func (s *Store) ListHealthChecks(ctx context.Context) ([]HealthCheckDef, error) {
	return s.healthChecks(ctx, ` ORDER BY lower(c.name), c.id`)
}

func (s *Store) healthChecks(ctx context.Context, tail string, args ...any) ([]HealthCheckDef, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+healthCheckCols+healthCheckFrom+tail, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HealthCheckDef
	for rows.Next() {
		c, err := scanHealthCheck(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ChecksForHost returns the enabled checks that apply to a host (all hosts,
// one of its groups, or the host itself); withUpdates keeps only those that
// run with update jobs.
func (s *Store) ChecksForHost(ctx context.Context, hostID int64, withUpdates bool) ([]protocol.HealthCheck, error) {
	cond := ` WHERE c.enabled = 1 AND (c.scope = 'all' OR (c.scope = 'host' AND c.host_id = ?)
		OR (c.scope = 'group' AND c.group_id IN (SELECT group_id FROM host_group_members WHERE host_id = ?)))`
	if withUpdates {
		cond += ` AND c.with_updates = 1`
	}
	defs, err := s.healthChecks(ctx, cond+` ORDER BY lower(c.name), c.id LIMIT ?`, hostID, hostID, protocol.MaxHealthChecks)
	if err != nil {
		return nil, err
	}
	out := make([]protocol.HealthCheck, len(defs))
	for i, d := range defs {
		out[i] = d.HealthCheck
	}
	return out, nil
}

// HealthResultRow is a stored check result.
type HealthResultRow struct {
	protocol.HealthResult
	HostID    int64
	JobID     int64
	Phase     string // "before", "after", "check"
	CreatedAt time.Time
}

// Health phases.
const (
	HealthBefore = "before"
	HealthAfter  = "after"
	HealthCheck  = "check"
)

// RecordHealth stores the results of a job's health report.
func (s *Store) RecordHealth(ctx context.Context, hostID, jobID int64, rep *protocol.HealthReport) error {
	if rep == nil {
		return nil
	}
	n := now()
	var rows [][]any
	add := func(phase string, list []protocol.HealthResult) {
		for _, r := range list {
			rows = append(rows, []any{hostID, jobID, r.ID, truncate(r.Name, 200), truncate(r.Type, 20), phase, boolInt(r.OK), truncate(r.Value, 500), truncate(r.Message, 500), r.DurationMS, n})
		}
	}
	add(HealthBefore, rep.Before)
	add(HealthAfter, rep.After)
	add(HealthCheck, rep.Checks)
	if len(rows) == 0 {
		return nil
	}
	return s.tx(ctx, func(tx *Tx) error {
		return insertRows(ctx, tx, `INSERT INTO health_results (host_id, job_id, check_id, check_name, check_type, phase, ok, value, message, duration_ms, created_at)`, "", 11, rows)
	})
}

// HostHealth returns a host's most recent check results, newest first.
func (s *Store) HostHealth(ctx context.Context, hostID int64, p Page) ([]HealthResultRow, int, error) {
	where, args := andScope(ctx, ` WHERE host_id = ?`, []any{hostID}, "host_id")
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM health_results`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, host_id, job_id, check_id, check_name, check_type, phase, ok, value, message, duration_ms, created_at
		FROM health_results`+where+` ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?`, append(args, p.limit(), p.Offset())...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []HealthResultRow
	for rows.Next() {
		var r HealthResultRow
		var id int64
		var ok int
		var at int64
		if err := rows.Scan(&id, &r.HostID, &r.JobID, &r.ID, &r.Name, &r.Type, &r.Phase, &ok, &r.Value, &r.Message, &r.DurationMS, &at); err != nil {
			return nil, 0, err
		}
		r.OK, r.CreatedAt = ok == 1, fromTS(at)
		out = append(out, r)
	}
	return out, total, rows.Err()
}

// LatestHostHealth returns the latest result of each check on a host.
func (s *Store) LatestHostHealth(ctx context.Context, hostID int64) ([]HealthResultRow, error) {
	rows, _, err := s.HostHealth(ctx, hostID, Page{Number: 1, Size: 500})
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []HealthResultRow
	for _, r := range rows {
		key := r.Name + "\x00" + r.Type
		if r.ID != 0 {
			key = "#" + itoa(r.ID)
		}
		if !seen[key] {
			seen[key] = true
			out = append(out, r)
		}
	}
	return out, nil
}

// PruneHealthResults deletes results older than d.
func (s *Store) PruneHealthResults(ctx context.Context, d time.Duration) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM health_results WHERE created_at < ?`, now()-int64(d.Seconds()))
	return err
}
