package store

import (
	"context"
	"database/sql"
	"math"
	"time"
)

// ---------- accepted risk expiry ----------

// ExpiredRisk is an accepted risk that reopened because its term ended.
type ExpiredRisk struct {
	CVEID    string
	HostID   int64
	Hostname string
	Package  string
}

// ExpireAcceptedRisks reopens accepted risks whose expiry is at or before at.
func (s *Store) ExpireAcceptedRisks(ctx context.Context, at time.Time) ([]ExpiredRisk, error) {
	var out []ExpiredRisk
	err := s.tx(ctx, func(tx *Tx) error {
		out = nil
		rows, err := tx.QueryContext(ctx, `SELECT f.id, f.cve_id, f.host_id, h.hostname, f.package_name FROM findings f JOIN hosts h ON h.id = f.host_id
			WHERE f.status = 'accepted_risk' AND f.status_expires_at > 0 AND f.status_expires_at <= ? ORDER BY f.cve_id, h.hostname`, at.Unix())
		if err != nil {
			return err
		}
		var ids []int64
		for rows.Next() {
			var id int64
			var e ExpiredRisk
			if err := rows.Scan(&id, &e.CVEID, &e.HostID, &e.Hostname, &e.Package); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
			out = append(out, e)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		for _, id := range ids {
			if _, err := tx.ExecContext(ctx, `UPDATE findings SET status = 'open', status_note = '', status_changed_by = NULL, status_expires_at = 0 WHERE id = ?`, id); err != nil {
				return err
			}
		}
		return nil
	})
	return out, err
}

// ---------- daily snapshots ----------

// Snapshot is the fleet state on one UTC day.
type Snapshot struct {
	Day             time.Time
	Hosts           int
	Sev             SeverityCounts
	KEV             int
	OpenFindings    int
	SecurityUpdates int
	RebootRequired  int
	// SecurityScore is the fleet average score, -1 when none was computed.
	SecurityScore int
}

// DayStart returns the UTC midnight of t.
func DayStart(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

// TakeSnapshot stores the current fleet state as the snapshot of at's UTC
// day, replacing an earlier one of the same day.
func (s *Store) TakeSnapshot(ctx context.Context, at time.Time) error {
	sev, kev, err := s.SeverityCountsFor(ctx, 0)
	if err != nil {
		return err
	}
	var hosts, open, sec, reboot int
	var avg sql.NullFloat64
	if err := s.db.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM hosts),
		(SELECT COUNT(*) FROM findings WHERE status IN `+activeStatuses+`),
		(SELECT COUNT(*) FROM host_updates WHERE security = 1),
		(SELECT COUNT(*) FROM hosts WHERE reboot_required = 1),
		(SELECT AVG(security_score) FROM hosts WHERE security_score >= 0)`).Scan(&hosts, &open, &sec, &reboot, &avg); err != nil {
		return err
	}
	score := -1
	if avg.Valid {
		score = int(math.Round(avg.Float64))
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO daily_snapshots (day, hosts, critical, high, medium, low, other, kev, open_findings, security_updates, reboot_required, taken_at, security_score)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (day) DO UPDATE SET hosts = excluded.hosts, critical = excluded.critical, high = excluded.high, medium = excluded.medium,
		low = excluded.low, other = excluded.other, kev = excluded.kev, open_findings = excluded.open_findings,
		security_updates = excluded.security_updates, reboot_required = excluded.reboot_required, taken_at = excluded.taken_at,
		security_score = excluded.security_score`,
		DayStart(at).Unix(), hosts, sev.Critical, sev.High, sev.Medium, sev.Low, sev.Other, kev, open, sec, reboot, now(), score)
	return err
}

// Snapshots returns the snapshots of the UTC days in [from, to], oldest first.
func (s *Store) Snapshots(ctx context.Context, from, to time.Time) ([]Snapshot, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT day, hosts, critical, high, medium, low, other, kev, open_findings, security_updates, reboot_required, security_score
		FROM daily_snapshots WHERE day >= ? AND day <= ? ORDER BY day`, DayStart(from).Unix(), DayStart(to).Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Snapshot
	for rows.Next() {
		var sn Snapshot
		var day int64
		if err := rows.Scan(&day, &sn.Hosts, &sn.Sev.Critical, &sn.Sev.High, &sn.Sev.Medium, &sn.Sev.Low, &sn.Sev.Other, &sn.KEV,
			&sn.OpenFindings, &sn.SecurityUpdates, &sn.RebootRequired, &sn.SecurityScore); err != nil {
			return nil, err
		}
		sn.Day = fromTS(day)
		out = append(out, sn)
	}
	return out, rows.Err()
}

// PruneSnapshots deletes snapshots older than d.
func (s *Store) PruneSnapshots(ctx context.Context, d time.Duration) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM daily_snapshots WHERE day < ?`, now()-int64(d.Seconds()))
	return err
}

// ---------- finding flow and report queries ----------

// groupCond restricts an alias (findings, jobs) to a group's hosts and to
// the scope of ctx.
func groupCond(ctx context.Context, alias string, groupID int64) (string, []any) {
	var cond string
	var args []any
	if groupID != 0 {
		cond = ` AND ` + alias + `.host_id IN (SELECT host_id FROM host_group_members WHERE group_id = ?)`
		args = []any{groupID}
	}
	if sc, sa := hostScope(ctx, alias+".host_id"); sc != "" {
		cond += ` AND ` + sc
		args = append(args, sa...)
	}
	return cond, args
}

// Flow counts findings opened and resolved in [from, to) and the mean time
// from detection to resolution of the resolved ones.
type Flow struct {
	Opened   int
	Resolved int
	MeanFix  time.Duration
	// Open findings detected before from that are still active.
	Backlog int
}

// FindingFlow computes the flow for a period, optionally for one group.
func (s *Store) FindingFlow(ctx context.Context, from, to time.Time, groupID int64) (Flow, error) {
	var fl Flow
	gc, ga := groupCond(ctx, "f", groupID)
	var mean sql.NullFloat64
	args := append([]any{from.Unix(), to.Unix()}, ga...)
	args = append(args, from.Unix(), to.Unix())
	args = append(args, ga...)
	args = append(args, from.Unix(), to.Unix())
	args = append(args, ga...)
	args = append(args, from.Unix())
	args = append(args, ga...)
	err := s.db.QueryRowContext(ctx, `SELECT
		(SELECT COUNT(*) FROM findings f WHERE f.first_detected_at >= ? AND f.first_detected_at < ?`+gc+`),
		(SELECT COUNT(*) FROM findings f WHERE f.status = 'resolved' AND f.resolved_at >= ? AND f.resolved_at < ?`+gc+`),
		(SELECT CAST(AVG(f.resolved_at - f.first_detected_at) AS DOUBLE PRECISION) FROM findings f WHERE f.status = 'resolved' AND f.resolved_at >= ? AND f.resolved_at < ?`+gc+`),
		(SELECT COUNT(*) FROM findings f WHERE f.status IN `+activeStatuses+` AND f.first_detected_at < ?`+gc+`)`, args...).
		Scan(&fl.Opened, &fl.Resolved, &mean, &fl.Backlog)
	if mean.Valid && mean.Float64 > 0 {
		fl.MeanFix = time.Duration(mean.Float64) * time.Second
	}
	return fl, err
}

// SeverityCountsFor counts CVEs with active findings by severity, and the
// KEV ones, for the fleet (groupID 0) or one group.
func (s *Store) SeverityCountsFor(ctx context.Context, groupID int64) (SeverityCounts, int, error) {
	if groupID == 0 {
		return s.FleetSeverityCounts(ctx)
	}
	var c SeverityCounts
	gc, ga := groupCond(ctx, "f", groupID)
	rows, err := s.db.QueryContext(ctx, `SELECT COALESCE(v.severity, 'unknown'), COUNT(DISTINCT f.cve_id) FROM findings f LEFT JOIN vulnerabilities v ON v.cve_id = f.cve_id
		WHERE f.status IN `+activeStatuses+gc+` GROUP BY 1`, ga...)
	if err != nil {
		return c, 0, err
	}
	for rows.Next() {
		var sev string
		var n int
		if err := rows.Scan(&sev, &n); err != nil {
			rows.Close()
			return c, 0, err
		}
		switch sev {
		case "critical":
			c.Critical = n
		case "high":
			c.High = n
		case "medium":
			c.Medium = n
		case "low":
			c.Low = n
		default:
			c.Other += n
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return c, 0, err
	}
	rows.Close()
	var kev int
	err = s.db.QueryRowContext(ctx, `SELECT COUNT(DISTINCT f.cve_id) FROM findings f JOIN kev k ON k.cve_id = f.cve_id WHERE f.status IN `+activeStatuses+gc, ga...).Scan(&kev)
	return c, kev, err
}

// KEVOpen is an actively exploited CVE that still has active findings.
type KEVOpen struct {
	CVEID     string
	Title     string
	DateAdded string // verbatim from the catalog (YYYY-MM-DD)
	DueDate   string
	HostCount int
	Hostnames []string
}

// Overdue reports whether CISA's remediation due date is before day
// (formatted YYYY-MM-DD in UTC).
func (k KEVOpen) Overdue(day string) bool { return k.DueDate != "" && k.DueDate < day }

// OpenKEV lists KEV CVEs with active findings, earliest due date first.
func (s *Store) OpenKEV(ctx context.Context, groupID int64) ([]KEVOpen, error) {
	gc, ga := groupCond(ctx, "f", groupID)
	rows, err := s.db.QueryContext(ctx, `SELECT f.cve_id, COALESCE(MAX(v.title), ''), MAX(k.date_added), MAX(k.due_date), COUNT(DISTINCT f.host_id), GROUP_CONCAT(DISTINCT h.hostname)
		FROM findings f JOIN kev k ON k.cve_id = f.cve_id JOIN hosts h ON h.id = f.host_id LEFT JOIN vulnerabilities v ON v.cve_id = f.cve_id
		WHERE f.status IN `+activeStatuses+gc+` GROUP BY f.cve_id ORDER BY MAX(k.due_date), f.cve_id`, ga...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []KEVOpen
	for rows.Next() {
		var k KEVOpen
		var hosts string
		if err := rows.Scan(&k.CVEID, &k.Title, &k.DateAdded, &k.DueDate, &k.HostCount, &hosts); err != nil {
			return nil, err
		}
		k.Hostnames = splitSorted(hosts)
		out = append(out, k)
	}
	return out, rows.Err()
}

// JobCounts counts jobs created in [from, to) by status, optionally for a group.
func (s *Store) JobCounts(ctx context.Context, from, to time.Time, groupID int64) (map[string]int, error) {
	gc, ga := groupCond(ctx, "j", groupID)
	rows, err := s.db.QueryContext(ctx, `SELECT j.status, COUNT(*) FROM jobs j WHERE j.created_at >= ? AND j.created_at < ?`+gc+` GROUP BY j.status`,
		append([]any{from.Unix(), to.Unix()}, ga...)...)
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
