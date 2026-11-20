package store

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
	"time"

	"netio.patchman/internal/vuln"
)

// ---------- OSV cache ----------

// OSVQueryKey identifies a package version in an ecosystem.
type OSVQueryKey struct {
	Ecosystem, Name, Version string
}

// OSVRef is a record ID with its last-modified stamp as returned by OSV.
type OSVRef struct {
	ID       string `json:"id"`
	Modified string `json:"modified"`
}

// OSVQueryResult is a cached OSV query.
type OSVQueryResult struct {
	Records   []OSVRef
	CheckedAt time.Time
}

// OSVQueries returns cached results for keys (missing keys are absent).
func (s *Store) OSVQueries(ctx context.Context, keys []OSVQueryKey) (map[OSVQueryKey]OSVQueryResult, error) {
	out := make(map[OSVQueryKey]OSVQueryResult, len(keys))
	stmt, err := s.db.PrepareContext(ctx, `SELECT record_ids, checked_at FROM osv_queries WHERE ecosystem = ? AND name = ? AND version = ?`)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()
	for _, k := range keys {
		var ids string
		var checked int64
		err := stmt.QueryRowContext(ctx, k.Ecosystem, k.Name, k.Version).Scan(&ids, &checked)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, err
		}
		var r OSVQueryResult
		_ = json.Unmarshal([]byte(ids), &r.Records)
		r.CheckedAt = fromTS(checked)
		out[k] = r
	}
	return out, nil
}

// SaveOSVQueries upserts query results.
func (s *Store) SaveOSVQueries(ctx context.Context, results map[OSVQueryKey][]OSVRef) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		stmt, err := tx.PrepareContext(ctx, `INSERT INTO osv_queries (ecosystem, name, version, record_ids, checked_at) VALUES (?, ?, ?, ?, ?)
			ON CONFLICT (ecosystem, name, version) DO UPDATE SET record_ids = excluded.record_ids, checked_at = excluded.checked_at`)
		if err != nil {
			return err
		}
		defer stmt.Close()
		n := now()
		for k, refs := range results {
			if refs == nil {
				refs = []OSVRef{}
			}
			b, _ := json.Marshal(refs)
			if _, err := stmt.ExecContext(ctx, k.Ecosystem, k.Name, k.Version, string(b), n); err != nil {
				return err
			}
		}
		return nil
	})
}

// OSVRecord returns a cached raw record.
func (s *Store) OSVRecord(ctx context.Context, id string) (modified string, data []byte, fetchedAt time.Time, err error) {
	var f int64
	err = s.db.QueryRowContext(ctx, `SELECT modified, data, fetched_at FROM osv_records WHERE id = ?`, id).Scan(&modified, &data, &f)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil, time.Time{}, ErrNotFound
	}
	if err != nil {
		return "", nil, time.Time{}, err
	}
	if data, err = gunzip(data); err != nil {
		return "", nil, time.Time{}, err
	}
	return modified, data, fromTS(f), nil
}

// SaveOSVRecord stores a record gzip-compressed (the scanner stores a
// compacted copy that keeps the fields it uses, with text verbatim).
// Records cached as plain JSON by earlier versions are still read.
func (s *Store) SaveOSVRecord(ctx context.Context, id, modified string, data []byte) error {
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	if _, err := zw.Write(data); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO osv_records (id, modified, fetched_at, data) VALUES (?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET modified = excluded.modified, fetched_at = excluded.fetched_at, data = excluded.data`,
		id, modified, now(), buf.Bytes())
	return err
}

func gunzip(data []byte) ([]byte, error) {
	if len(data) < 2 || data[0] != 0x1f || data[1] != 0x8b {
		return data, nil // plain JSON
	}
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	return io.ReadAll(io.LimitReader(zr, 64<<20))
}

// PruneOSVQueries removes cached queries for package versions no host has
// had for a while, keeping the cache bounded.
func (s *Store) PruneOSVQueries(ctx context.Context, olderThan time.Duration) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM osv_queries WHERE checked_at < ?`, now()-int64(olderThan.Seconds()))
	return err
}

// PruneOSVRecords removes cached raw records fetched before the cutoff. A
// record that is still referenced is simply fetched again when needed.
func (s *Store) PruneOSVRecords(ctx context.Context, olderThan time.Duration) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM osv_records WHERE fetched_at < ?`, now()-int64(olderThan.Seconds()))
	return err
}

// ---------- vulnerabilities ----------

// VulnRecord is a stored vulnerability plus bookkeeping.
type VulnRecord struct {
	vuln.Vulnerability
	FetchedAt time.Time
}

const vulnCols = `v.cve_id, v.title, v.description, v.description_lang, v.cvss_score, v.cvss_vector, v.cvss_version, v.severity,
 v.published_at, v.modified_at, v.fetched_at, v.source, v.refs,
 CASE WHEN k.cve_id IS NULL THEN 0 ELSE 1 END, COALESCE(k.date_added, ''), COALESCE(k.due_date, '')`

const vulnFrom = ` FROM vulnerabilities v LEFT JOIN kev k ON k.cve_id = v.cve_id`

func scanVuln(row interface{ Scan(...any) error }) (VulnRecord, error) {
	var r VulnRecord
	var score sql.NullFloat64
	var sev, refs string
	var pub, mod, fetched int64
	var kev int
	err := row.Scan(&r.CVEID, &r.Title, &r.Description, &r.DescriptionLang, &score, &r.CVSSVector, &r.CVSSVersion, &sev,
		&pub, &mod, &fetched, &r.Source, &refs, &kev, &r.KEVDateAdded, &r.KEVDueDate)
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrNotFound
	}
	if err != nil {
		return r, err
	}
	if score.Valid {
		v := score.Float64
		r.CVSSScore = &v
	}
	r.Severity = vuln.Severity(sev)
	r.PublishedAt, r.ModifiedAt, r.FetchedAt = fromTS(pub), fromTS(mod), fromTS(fetched)
	r.KnownExploited = kev == 1
	_ = json.Unmarshal([]byte(refs), &r.References)
	return r, nil
}

// Vulnerability returns a stored vulnerability with its advisories.
func (s *Store) Vulnerability(ctx context.Context, cveID string) (VulnRecord, error) {
	r, err := scanVuln(s.db.QueryRowContext(ctx, `SELECT `+vulnCols+vulnFrom+` WHERE v.cve_id = ?`, cveID))
	if err != nil {
		return r, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT a.id, a.title, a.url FROM vulnerability_advisories va JOIN advisories a ON a.id = va.advisory_id WHERE va.cve_id = ? ORDER BY a.id`, cveID)
	if err != nil {
		return r, err
	}
	defer rows.Close()
	for rows.Next() {
		var a vuln.Advisory
		if err := rows.Scan(&a.ID, &a.Title, &a.URL); err != nil {
			return r, err
		}
		r.Advisories = append(r.Advisories, a)
	}
	return r, rows.Err()
}

// VulnFetchedAt returns when each CVE was last fetched (absent if unknown).
func (s *Store) VulnFetchedAt(ctx context.Context, ids []string) (map[string]time.Time, error) {
	out := map[string]time.Time{}
	stmt, err := s.db.PrepareContext(ctx, `SELECT fetched_at FROM vulnerabilities WHERE cve_id = ?`)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()
	for _, id := range ids {
		var f int64
		err := stmt.QueryRowContext(ctx, id).Scan(&f)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out[id] = fromTS(f)
	}
	return out, nil
}

// UpsertVulnerability stores a vulnerability (verbatim fields).
func (s *Store) UpsertVulnerability(ctx context.Context, v vuln.Vulnerability) error {
	refs, _ := json.Marshal(nonNil(v.References))
	var score any
	if v.CVSSScore != nil {
		score = *v.CVSSScore
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO vulnerabilities (cve_id, title, description, description_lang, cvss_score, cvss_vector, cvss_version,
		severity, published_at, modified_at, fetched_at, source, refs) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (cve_id) DO UPDATE SET title = excluded.title, description = excluded.description, description_lang = excluded.description_lang,
		cvss_score = excluded.cvss_score, cvss_vector = excluded.cvss_vector, cvss_version = excluded.cvss_version, severity = excluded.severity,
		published_at = excluded.published_at, modified_at = excluded.modified_at, fetched_at = excluded.fetched_at, source = excluded.source, refs = excluded.refs`,
		v.CVEID, v.Title, v.Description, v.DescriptionLanguage(), score, v.CVSSVector, v.CVSSVersion, string(v.Severity),
		ts(v.PublishedAt), ts(v.ModifiedAt), now(), v.Source, string(refs))
	return err
}

// UpsertAdvisory stores an advisory and links it to CVEs.
func (s *Store) UpsertAdvisory(ctx context.Context, a vuln.Advisory, source string, cves []string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO advisories (id, title, url, source) VALUES (?, ?, ?, ?)
			ON CONFLICT (id) DO UPDATE SET title = excluded.title, url = excluded.url, source = excluded.source`, a.ID, a.Title, a.URL, source); err != nil {
			return err
		}
		for _, c := range cves {
			if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO vulnerability_advisories (cve_id, advisory_id) VALUES (?, ?)`, c, a.ID); err != nil {
				return err
			}
		}
		return nil
	})
}

// KEVEntry is a CISA KEV catalog entry.
type KEVEntry struct {
	CVEID, DateAdded, DueDate, Ransomware string
}

// ReplaceKEV replaces the KEV catalog.
func (s *Store) ReplaceKEV(ctx context.Context, entries []KEVEntry) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM kev`); err != nil {
			return err
		}
		stmt, err := tx.PrepareContext(ctx, `INSERT OR REPLACE INTO kev (cve_id, date_added, due_date, ransomware) VALUES (?, ?, ?, ?)`)
		if err != nil {
			return err
		}
		defer stmt.Close()
		for _, e := range entries {
			if _, err := stmt.ExecContext(ctx, e.CVEID, e.DateAdded, e.DueDate, e.Ransomware); err != nil {
				return err
			}
		}
		return nil
	})
}

// KEVCount returns the number of KEV entries.
func (s *Store) KEVCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM kev`).Scan(&n)
	return n, err
}

// ---------- findings ----------

// FindingStatus values mirror vuln.ResolutionStatus.
const (
	StatusOpen          = string(vuln.StatusOpen)
	StatusInProgress    = string(vuln.StatusInProgress)
	StatusResolved      = string(vuln.StatusResolved)
	StatusAcceptedRisk  = string(vuln.StatusAcceptedRisk)
	StatusFalsePositive = string(vuln.StatusFalsePositive)
)

// ValidManualStatus reports whether users may set the status by hand.
// "resolved" is set automatically when the package is no longer vulnerable.
func ValidManualStatus(s string) bool {
	return s == StatusOpen || s == StatusInProgress || s == StatusAcceptedRisk || s == StatusFalsePositive
}

// DetectedFinding is a scanner result for one host.
type DetectedFinding struct {
	CVEID            string
	PackageName      string
	InstalledVersion string
	FixedVersion     string
	RecordID         string
}

// ApplyFindings reconciles a host's findings with a fresh scan. Findings no
// longer detected become "resolved"; resolved findings detected again are
// reopened. It returns the number of new or reopened findings.
func (s *Store) ApplyFindings(ctx context.Context, hostID int64, detected []DetectedFinding) (int, error) {
	created := 0
	err := s.tx(ctx, func(tx *sql.Tx) error {
		type existing struct {
			id     int64
			status string
		}
		cur := map[[2]string]existing{}
		rows, err := tx.QueryContext(ctx, `SELECT id, cve_id, package_name, status FROM findings WHERE host_id = ?`, hostID)
		if err != nil {
			return err
		}
		for rows.Next() {
			var e existing
			var cve, pkg string
			if err := rows.Scan(&e.id, &cve, &pkg, &e.status); err != nil {
				rows.Close()
				return err
			}
			cur[[2]string{cve, pkg}] = e
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		n := now()
		seen := map[[2]string]bool{}
		for _, d := range detected {
			key := [2]string{d.CVEID, d.PackageName}
			if seen[key] {
				continue
			}
			seen[key] = true
			if e, ok := cur[key]; ok {
				if e.status == StatusResolved {
					created++
					_, err = tx.ExecContext(ctx, `UPDATE findings SET status = 'open', status_note = '', status_changed_by = NULL, installed_version = ?, fixed_version = ?,
						record_id = ?, first_detected_at = ?, last_checked_at = ?, resolved_at = 0, notified = 0 WHERE id = ?`,
						d.InstalledVersion, d.FixedVersion, d.RecordID, n, n, e.id)
				} else {
					_, err = tx.ExecContext(ctx, `UPDATE findings SET installed_version = ?, fixed_version = ?, record_id = ?, last_checked_at = ? WHERE id = ?`,
						d.InstalledVersion, d.FixedVersion, d.RecordID, n, e.id)
				}
			} else {
				created++
				_, err = tx.ExecContext(ctx, `INSERT INTO findings (host_id, cve_id, package_name, installed_version, fixed_version, record_id, status, first_detected_at, last_checked_at)
					VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?)`, hostID, d.CVEID, d.PackageName, d.InstalledVersion, d.FixedVersion, d.RecordID, n, n)
			}
			if err != nil {
				return err
			}
		}
		for key, e := range cur {
			if !seen[key] && e.status != StatusResolved {
				if _, err := tx.ExecContext(ctx, `UPDATE findings SET status = 'resolved', resolved_at = ?, last_checked_at = ? WHERE id = ?`, n, n, e.id); err != nil {
					return err
				}
			}
		}
		return nil
	})
	return created, err
}

// SetFindingStatus changes the status of findings (by ID) on behalf of a user.
func (s *Store) SetFindingStatus(ctx context.Context, ids []int64, status, note string, userID int64) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		for _, id := range ids {
			if _, err := tx.ExecContext(ctx, `UPDATE findings SET status = ?, status_note = ?, status_changed_by = ? WHERE id = ? AND status <> 'resolved'`,
				status, truncate(note, 1000), nullID(userID), id); err != nil {
				return err
			}
		}
		return nil
	})
}

// SetCVEStatus changes the status of all unresolved findings of a CVE.
func (s *Store) SetCVEStatus(ctx context.Context, cveID, status, note string, userID int64) (int64, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE findings SET status = ?, status_note = ?, status_changed_by = ? WHERE cve_id = ? AND status <> 'resolved'`,
		status, truncate(note, 1000), nullID(userID), cveID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// FindingRow is a finding joined with its host and vulnerability.
type FindingRow struct {
	ID               int64
	HostID           int64
	Hostname         string
	CVEID            string
	Title            string
	Severity         vuln.Severity
	CVSSScore        *float64
	KnownExploited   bool
	PackageName      string
	InstalledVersion string
	FixedVersion     string
	Status           string
	StatusNote       string
	FirstDetectedAt  time.Time
	LastCheckedAt    time.Time
	ResolvedAt       time.Time
}

// FindingFilter narrows finding lists.
type FindingFilter struct {
	HostID   int64
	CVEID    string
	Severity string
	Status   string // "" = active (open+in_progress), "all", or a specific status
	Search   string
	KEVOnly  bool
}

func findingWhere(f FindingFilter) (string, []any) {
	var conds []string
	var args []any
	if f.HostID != 0 {
		conds = append(conds, `f.host_id = ?`)
		args = append(args, f.HostID)
	}
	if f.CVEID != "" {
		conds = append(conds, `f.cve_id = ?`)
		args = append(args, f.CVEID)
	}
	switch f.Status {
	case "":
		conds = append(conds, `f.status IN `+activeStatuses)
	case "all":
	default:
		conds = append(conds, `f.status = ?`)
		args = append(args, f.Status)
	}
	if f.Severity != "" {
		conds = append(conds, `COALESCE(v.severity, 'unknown') = ?`)
		args = append(args, f.Severity)
	}
	if f.KEVOnly {
		conds = append(conds, `k.cve_id IS NOT NULL`)
	}
	if q := strings.TrimSpace(f.Search); q != "" {
		l := likeEscape(q)
		conds = append(conds, `(f.cve_id LIKE ? ESCAPE '\' OR f.package_name LIKE ? ESCAPE '\' OR v.title LIKE ? ESCAPE '\')`)
		args = append(args, l, l, l)
	}
	if len(conds) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

const findingFrom = ` FROM findings f JOIN hosts h ON h.id = f.host_id LEFT JOIN vulnerabilities v ON v.cve_id = f.cve_id LEFT JOIN kev k ON k.cve_id = f.cve_id`

const severityOrder = `CASE COALESCE(v.severity, 'unknown') WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END`

// ListFindings returns findings for a host or CVE.
func (s *Store) ListFindings(ctx context.Context, f FindingFilter, p Page) ([]FindingRow, int, error) {
	where, args := findingWhere(f)
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*)`+findingFrom+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT f.id, f.host_id, h.hostname, f.cve_id, COALESCE(v.title, ''), COALESCE(v.severity, 'unknown'), v.cvss_score,
		CASE WHEN k.cve_id IS NULL THEN 0 ELSE 1 END, f.package_name, f.installed_version, f.fixed_version, f.status, f.status_note,
		f.first_detected_at, f.last_checked_at, f.resolved_at`+findingFrom+where+
		` ORDER BY `+severityOrder+`, v.cvss_score DESC, f.cve_id DESC, h.hostname LIMIT ? OFFSET ?`, append(args, p.limit(), p.Offset())...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []FindingRow
	for rows.Next() {
		var r FindingRow
		var sev string
		var score sql.NullFloat64
		var kev int
		var fd, lc, rs int64
		if err := rows.Scan(&r.ID, &r.HostID, &r.Hostname, &r.CVEID, &r.Title, &sev, &score, &kev, &r.PackageName, &r.InstalledVersion,
			&r.FixedVersion, &r.Status, &r.StatusNote, &fd, &lc, &rs); err != nil {
			return nil, 0, err
		}
		r.Severity = vuln.Severity(sev)
		if score.Valid {
			v := score.Float64
			r.CVSSScore = &v
		}
		r.KnownExploited = kev == 1
		r.FirstDetectedAt, r.LastCheckedAt, r.ResolvedAt = fromTS(fd), fromTS(lc), fromTS(rs)
		out = append(out, r)
	}
	return out, total, rows.Err()
}

// VulnSummary aggregates active findings per CVE across the fleet.
type VulnSummary struct {
	CVEID           string
	Title           string
	Severity        vuln.Severity
	CVSSScore       *float64
	KnownExploited  bool
	HostCount       int
	Packages        []string
	FixAvailable    bool
	FirstDetectedAt time.Time
	LastCheckedAt   time.Time
}

// VulnFilter narrows the fleet vulnerability list.
type VulnFilter struct {
	Severity string
	Search   string
	KEVOnly  bool
	FixOnly  bool
	Status   string // "" active, or a specific status
}

// ListVulnSummaries returns CVEs with active findings, most severe first.
func (s *Store) ListVulnSummaries(ctx context.Context, f VulnFilter, p Page) ([]VulnSummary, int, error) {
	where, args := findingWhere(FindingFilter{Severity: f.Severity, Search: f.Search, KEVOnly: f.KEVOnly, Status: f.Status})
	having := ""
	if f.FixOnly {
		having = ` HAVING MAX(f.fixed_version <> '') = 1`
	}
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM (SELECT f.cve_id`+findingFrom+where+` GROUP BY f.cve_id`+having+`)`, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT f.cve_id, COALESCE(MAX(v.title), ''), COALESCE(MAX(v.severity), 'unknown'), MAX(v.cvss_score),
		MAX(CASE WHEN k.cve_id IS NULL THEN 0 ELSE 1 END), COUNT(DISTINCT f.host_id), GROUP_CONCAT(DISTINCT f.package_name),
		MAX(f.fixed_version <> ''), MIN(f.first_detected_at), MAX(f.last_checked_at)`+findingFrom+where+
		` GROUP BY f.cve_id`+having+` ORDER BY MIN(`+severityOrder+`), MAX(k.cve_id IS NOT NULL) DESC, MAX(v.cvss_score) DESC, COUNT(DISTINCT f.host_id) DESC, f.cve_id DESC LIMIT ? OFFSET ?`,
		append(args, p.limit(), p.Offset())...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []VulnSummary
	for rows.Next() {
		var r VulnSummary
		var sev, pkgs string
		var score sql.NullFloat64
		var kev, fix int
		var fd, lc int64
		if err := rows.Scan(&r.CVEID, &r.Title, &sev, &score, &kev, &r.HostCount, &pkgs, &fix, &fd, &lc); err != nil {
			return nil, 0, err
		}
		r.Severity = vuln.Severity(sev)
		if score.Valid {
			v := score.Float64
			r.CVSSScore = &v
		}
		r.KnownExploited, r.FixAvailable = kev == 1, fix == 1
		r.Packages = splitSorted(pkgs)
		r.FirstDetectedAt, r.LastCheckedAt = fromTS(fd), fromTS(lc)
		out = append(out, r)
	}
	return out, total, rows.Err()
}

func splitSorted(csv string) []string {
	if csv == "" {
		return nil
	}
	parts := strings.Split(csv, ",")
	sort.Strings(parts)
	return parts
}

// FleetSeverityCounts counts distinct CVEs with active findings by severity.
func (s *Store) FleetSeverityCounts(ctx context.Context) (SeverityCounts, int, error) {
	var c SeverityCounts
	rows, err := s.db.QueryContext(ctx, `SELECT COALESCE(v.severity, 'unknown'), COUNT(DISTINCT f.cve_id) FROM findings f LEFT JOIN vulnerabilities v ON v.cve_id = f.cve_id
		WHERE f.status IN `+activeStatuses+` GROUP BY 1`)
	if err != nil {
		return c, 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var sev string
		var n int
		if err := rows.Scan(&sev, &n); err != nil {
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
		return c, 0, err
	}
	rows.Close()
	var kev int
	err = s.db.QueryRowContext(ctx, `SELECT COUNT(DISTINCT f.cve_id) FROM findings f JOIN kev k ON k.cve_id = f.cve_id WHERE f.status IN `+activeStatuses).Scan(&kev)
	return c, kev, err
}

// PendingAlert is a CVE with findings not yet notified.
type PendingAlert struct {
	CVEID    string
	Severity vuln.Severity
	KEV      bool
}

// PendingAlerts returns CVEs whose active findings have not been notified.
func (s *Store) PendingAlerts(ctx context.Context) ([]PendingAlert, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT f.cve_id, COALESCE(MAX(v.severity), 'unknown'), MAX(CASE WHEN k.cve_id IS NULL THEN 0 ELSE 1 END)
		FROM findings f LEFT JOIN vulnerabilities v ON v.cve_id = f.cve_id LEFT JOIN kev k ON k.cve_id = f.cve_id
		WHERE f.notified = 0 AND f.status IN `+activeStatuses+` GROUP BY f.cve_id ORDER BY f.cve_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PendingAlert
	for rows.Next() {
		var a PendingAlert
		var sev string
		var kev int
		if err := rows.Scan(&a.CVEID, &sev, &kev); err != nil {
			return nil, err
		}
		a.Severity, a.KEV = vuln.Severity(sev), kev == 1
		out = append(out, a)
	}
	return out, rows.Err()
}

// MarkNotified marks all findings of the CVEs as notified.
func (s *Store) MarkNotified(ctx context.Context, cves []string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		for _, c := range cves {
			if _, err := tx.ExecContext(ctx, `UPDATE findings SET notified = 1 WHERE cve_id = ? AND notified = 0`, c); err != nil {
				return err
			}
		}
		return nil
	})
}

// AlertDetails returns the data for a CVE notification: affected host names,
// the most common package, installed and fixed versions, earliest detection.
type AlertDetails struct {
	Hostnames        []string
	PackageName      string
	InstalledVersion string
	FixedVersion     string
	FirstDetectedAt  time.Time
}

// AlertDetailsFor aggregates active findings of a CVE.
func (s *Store) AlertDetailsFor(ctx context.Context, cveID string) (AlertDetails, error) {
	var d AlertDetails
	rows, err := s.db.QueryContext(ctx, `SELECT h.hostname, f.package_name, f.installed_version, f.fixed_version, f.first_detected_at
		FROM findings f JOIN hosts h ON h.id = f.host_id WHERE f.cve_id = ? AND f.status IN `+activeStatuses+` ORDER BY h.hostname`, cveID)
	if err != nil {
		return d, err
	}
	defer rows.Close()
	hosts := map[string]bool{}
	pkgCount := map[string]int{}
	for rows.Next() {
		var host, pkg, inst, fixed string
		var fd int64
		if err := rows.Scan(&host, &pkg, &inst, &fixed, &fd); err != nil {
			return d, err
		}
		if !hosts[host] {
			hosts[host] = true
			d.Hostnames = append(d.Hostnames, host)
		}
		pkgCount[pkg]++
		if pkgCount[pkg] > pkgCount[d.PackageName] || d.PackageName == "" {
			d.PackageName, d.InstalledVersion, d.FixedVersion = pkg, inst, fixed
		}
		if t := fromTS(fd); d.FirstDetectedAt.IsZero() || t.Before(d.FirstDetectedAt) {
			d.FirstDetectedAt = t
		}
	}
	return d, rows.Err()
}

// PruneResolvedFindings deletes findings resolved before the cutoff.
func (s *Store) PruneResolvedFindings(ctx context.Context, olderThan time.Duration) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM findings WHERE status = 'resolved' AND resolved_at > 0 AND resolved_at < ?`, now()-int64(olderThan.Seconds()))
	return err
}
