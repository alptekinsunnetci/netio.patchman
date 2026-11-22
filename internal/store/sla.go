package store

import (
	"context"
	"fmt"
)

// SLA is the remediation target in days by severity, counted from the first
// detection of a finding (0 = no target for that severity).
type SLA struct {
	Critical, High, Medium, Low int
}

// Enabled reports whether any severity has a target.
func (s SLA) Enabled() bool { return s.Critical > 0 || s.High > 0 || s.Medium > 0 || s.Low > 0 }

// dueSQL returns an SQL expression for a finding's due time (0 = none),
// given the findings alias f and the vulnerabilities alias v. The day counts
// are integers formatted into the expression.
func (s SLA) dueSQL(f, v string) string {
	part := func(days int) string {
		if days <= 0 {
			return "0"
		}
		return fmt.Sprintf("%s.first_detected_at + %d", f, days*86400)
	}
	return fmt.Sprintf("(CASE %s.severity WHEN 'critical' THEN %s WHEN 'high' THEN %s WHEN 'medium' THEN %s WHEN 'low' THEN %s ELSE 0 END)",
		v, part(s.Critical), part(s.High), part(s.Medium), part(s.Low))
}

// EPSSEntry is one EPSS score.
type EPSSEntry struct {
	CVEID      string
	Score      float64
	Percentile float64
}

// ReplaceEPSS replaces the stored EPSS scores.
func (s *Store) ReplaceEPSS(ctx context.Context, entries []EPSSEntry) error {
	// A CVE listed twice keeps its last entry.
	rows := make([][]any, 0, len(entries))
	idx := make(map[string]int, len(entries))
	for _, e := range entries {
		row := []any{e.CVEID, e.Score, e.Percentile}
		if i, ok := idx[e.CVEID]; ok {
			rows[i] = row
			continue
		}
		idx[e.CVEID] = len(rows)
		rows = append(rows, row)
	}
	return s.tx(ctx, func(tx *Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM epss`); err != nil {
			return err
		}
		return insertRows(ctx, tx, `INSERT INTO epss (cve_id, score, percentile)`, "", 3, rows)
	})
}

// EPSSCount returns the number of stored EPSS scores.
func (s *Store) EPSSCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM epss`).Scan(&n)
	return n, err
}

// OverdueCounts counts active findings past their SLA deadline and the
// distinct CVEs among them, within the scope of ctx.
func (s *Store) OverdueCounts(ctx context.Context, sla SLA) (findings, cves int, err error) {
	if !sla.Enabled() {
		return 0, 0, nil
	}
	due := sla.dueSQL("f", "v")
	where, args := andScope(ctx, ` WHERE f.status IN `+activeStatuses+` AND `+due+` > 0 AND `+due+` < ?`, []any{now()}, "f.host_id")
	err = s.db.QueryRowContext(ctx, `SELECT COUNT(*), COUNT(DISTINCT f.cve_id) FROM findings f JOIN vulnerabilities v ON v.cve_id = f.cve_id`+where, args...).
		Scan(&findings, &cves)
	return findings, cves, err
}

// OverdueHost is a host with findings that became overdue.
type OverdueHost struct {
	HostID   int64
	Hostname string
	Count    int
}

// ClaimOverdue marks active findings that passed their SLA deadline and were
// not reported yet, and returns them per host (for one notification).
func (s *Store) ClaimOverdue(ctx context.Context, sla SLA) ([]OverdueHost, error) {
	if !sla.Enabled() {
		return nil, nil
	}
	due := sla.dueSQL("f", "v")
	var out []OverdueHost
	err := s.tx(ctx, func(tx *Tx) error {
		out = nil
		n := now()
		rows, err := tx.QueryContext(ctx, `SELECT f.host_id, h.hostname, COUNT(*) FROM findings f JOIN vulnerabilities v ON v.cve_id = f.cve_id
			JOIN hosts h ON h.id = f.host_id WHERE f.sla_notified_at = 0 AND f.status IN `+activeStatuses+` AND `+due+` > 0 AND `+due+` < ?
			GROUP BY f.host_id, h.hostname ORDER BY h.hostname`, n)
		if err != nil {
			return err
		}
		for rows.Next() {
			var o OverdueHost
			if err := rows.Scan(&o.HostID, &o.Hostname, &o.Count); err != nil {
				rows.Close()
				return err
			}
			out = append(out, o)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE findings SET sla_notified_at = ? WHERE sla_notified_at = 0 AND status IN `+activeStatuses+`
			AND id IN (SELECT f.id FROM findings f JOIN vulnerabilities v ON v.cve_id = f.cve_id WHERE `+due+` > 0 AND `+due+` < ?)`, n, n)
		return err
	})
	return out, err
}
