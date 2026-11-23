package store

import (
	"context"
	"database/sql"
	"math"
	"time"

	"netio.patchman/internal/vuln"
)

// ScoreFinding is an open finding as the security score sees it.
type ScoreFinding struct {
	CVE      string
	Severity vuln.Severity
	KEV      bool
	EPSS     *float64
	Overdue  bool
}

// ScoreFindings returns the open findings of every host (no user scope:
// background computation).
func (s *Store) ScoreFindings(ctx context.Context, sla SLA) (map[int64][]ScoreFinding, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT f.host_id, f.cve_id, COALESCE(v.severity, 'unknown'), CASE WHEN k.cve_id IS NULL THEN 0 ELSE 1 END, e.score, `+sla.dueSQL("f", "v")+`
		FROM findings f LEFT JOIN vulnerabilities v ON v.cve_id = f.cve_id LEFT JOIN kev k ON k.cve_id = f.cve_id LEFT JOIN epss e ON e.cve_id = f.cve_id
		WHERE f.status IN `+activeStatuses)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	n := now()
	out := map[int64][]ScoreFinding{}
	for rows.Next() {
		var id, due int64
		var f ScoreFinding
		var sev string
		var kev int
		var epss sql.NullFloat64
		if err := rows.Scan(&id, &f.CVE, &sev, &kev, &epss, &due); err != nil {
			return nil, err
		}
		f.Severity, f.KEV, f.EPSS, f.Overdue = vuln.Severity(sev), kev == 1, nullFloat(epss), due > 0 && due < n
		out[id] = append(out[id], f)
	}
	return out, rows.Err()
}

// UncoveredSecurityUpdates counts per host the pending security updates
// whose package has no open finding (by name or source package). Updates
// that fix an open finding are already in the score through the CVE.
func (s *Store) UncoveredSecurityUpdates(ctx context.Context) (map[int64]int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT u.host_id, COUNT(*) FROM host_updates u WHERE u.security = 1 AND NOT EXISTS (
		SELECT 1 FROM findings f WHERE f.host_id = u.host_id AND f.status IN `+activeStatuses+` AND (f.package_name = u.name OR f.package_name IN (
			SELECT p.source_name FROM host_packages p WHERE p.host_id = u.host_id AND p.name = u.name AND p.source_name <> '')))
		GROUP BY u.host_id`)
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

// HostScore is a computed score with its JSON explanation.
type HostScore struct {
	Score  int
	Detail string
}

// SaveScores stores the scores of the hosts and records them as the
// scores of day (UTC). Hosts not in scores keep their values.
func (s *Store) SaveScores(ctx context.Context, day time.Time, scores map[int64]HostScore) error {
	d := DayStart(day).Unix()
	return s.tx(ctx, func(tx *Tx) error {
		rows := make([][]any, 0, len(scores))
		for id, sc := range scores {
			if _, err := tx.ExecContext(ctx, `UPDATE hosts SET security_score = ?, score_detail = ? WHERE id = ?`, sc.Score, sc.Detail, id); err != nil {
				return err
			}
			rows = append(rows, []any{id, d, sc.Score})
		}
		return insertRows(ctx, tx, `INSERT INTO host_scores (host_id, day, score)`, `ON CONFLICT (host_id, day) DO UPDATE SET score = excluded.score`, 3, rows)
	})
}

// HostScoreDetail returns a host's score and explanation (-1, "" before the
// first computation).
func (s *Store) HostScoreDetail(ctx context.Context, hostID int64) (int, string, error) {
	where, args := andScope(ctx, ` WHERE id = ?`, []any{hostID}, "id")
	var sc int
	var detail string
	err := s.db.QueryRowContext(ctx, `SELECT security_score, score_detail FROM hosts`+where, args...).Scan(&sc, &detail)
	if err == sql.ErrNoRows {
		return -1, "", ErrNotFound
	}
	return sc, detail, err
}

// DayScore is a score on one UTC day.
type DayScore struct {
	Day   time.Time
	Score int
}

// HostScoreHistory returns a host's daily scores in [from, to].
func (s *Store) HostScoreHistory(ctx context.Context, hostID int64, from, to time.Time) ([]DayScore, error) {
	return s.dayScores(ctx, `SELECT day, score FROM host_scores WHERE host_id = ? AND day >= ? AND day <= ? ORDER BY day`,
		hostID, DayStart(from).Unix(), DayStart(to).Unix())
}

// GroupScoreHistory returns the daily average score of a group's hosts.
func (s *Store) GroupScoreHistory(ctx context.Context, groupID int64, from, to time.Time) ([]DayScore, error) {
	return s.dayScores(ctx, `SELECT hs.day, AVG(hs.score) FROM host_scores hs JOIN host_group_members m ON m.host_id = hs.host_id
		WHERE m.group_id = ? AND hs.day >= ? AND hs.day <= ? GROUP BY hs.day ORDER BY hs.day`, groupID, DayStart(from).Unix(), DayStart(to).Unix())
}

func (s *Store) dayScores(ctx context.Context, q string, args ...any) ([]DayScore, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DayScore
	for rows.Next() {
		var day int64
		var v float64
		if err := rows.Scan(&day, &v); err != nil {
			return nil, err
		}
		out = append(out, DayScore{Day: fromTS(day), Score: int(math.Round(v))})
	}
	return out, rows.Err()
}

// ScoreStats summarizes the scores of a set of hosts.
type ScoreStats struct {
	Avg   int // -1 without scored hosts
	Min   int
	Hosts int // hosts with a score
}

// GroupScores returns the score statistics of every group (visible hosts).
func (s *Store) GroupScores(ctx context.Context) (map[int64]ScoreStats, error) {
	where, args := andScope(ctx, ` WHERE h.security_score >= 0`, nil, "h.id")
	rows, err := s.db.QueryContext(ctx, `SELECT m.group_id, AVG(h.security_score), MIN(h.security_score), COUNT(*) FROM host_group_members m JOIN hosts h ON h.id = m.host_id`+where+
		` GROUP BY m.group_id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]ScoreStats{}
	for rows.Next() {
		var id int64
		var avg float64
		var st ScoreStats
		if err := rows.Scan(&id, &avg, &st.Min, &st.Hosts); err != nil {
			return nil, err
		}
		st.Avg = int(math.Round(avg))
		out[id] = st
	}
	return out, rows.Err()
}

// FleetScore returns the score statistics of the visible hosts.
func (s *Store) FleetScore(ctx context.Context) (ScoreStats, error) {
	where, args := andScope(ctx, ` WHERE security_score >= 0`, nil, "id")
	var avg sql.NullFloat64
	var min sql.NullInt64
	var st ScoreStats
	if err := s.db.QueryRowContext(ctx, `SELECT AVG(security_score), MIN(security_score), COUNT(*) FROM hosts`+where, args...).Scan(&avg, &min, &st.Hosts); err != nil {
		return st, err
	}
	st.Avg, st.Min = -1, -1
	if avg.Valid {
		st.Avg, st.Min = int(math.Round(avg.Float64)), int(min.Int64)
	}
	return st, nil
}

// ScoreAlerts marks hosts that dropped below threshold since the last call
// and returns them; hosts at or above it are re-armed. threshold <= 0 only
// re-arms.
func (s *Store) ScoreAlerts(ctx context.Context, threshold int) ([]HostRef, error) {
	if _, err := s.db.ExecContext(ctx, `UPDATE hosts SET score_alerted = 0 WHERE score_alerted = 1 AND (security_score >= ? OR security_score < 0)`, max(threshold, 0)); err != nil {
		return nil, err
	}
	if threshold <= 0 {
		return nil, nil
	}
	var out []HostRef
	err := s.tx(ctx, func(tx *Tx) error {
		out = nil
		rows, err := tx.QueryContext(ctx, `SELECT id, hostname, security_score FROM hosts WHERE score_alerted = 0 AND security_score >= 0 AND security_score < ? ORDER BY id FOR UPDATE`, threshold)
		if err != nil {
			return err
		}
		for rows.Next() {
			var r HostRef
			var sc int
			if err := rows.Scan(&r.ID, &r.Hostname, &sc); err != nil {
				rows.Close()
				return err
			}
			r.Version = itoa(int64(sc))
			out = append(out, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, r := range out {
			if _, err := tx.ExecContext(ctx, `UPDATE hosts SET score_alerted = 1 WHERE id = ?`, r.ID); err != nil {
				return err
			}
		}
		return nil
	})
	return out, err
}

// PruneHostScores deletes daily scores older than d.
func (s *Store) PruneHostScores(ctx context.Context, d time.Duration) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM host_scores WHERE day < ?`, now()-int64(d.Seconds()))
	return err
}
