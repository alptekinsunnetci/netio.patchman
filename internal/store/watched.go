package store

import (
	"context"
	"sort"
	"strings"

	"netio.patchman/internal/vuln"
)

// MaxWatchedPerUser bounds how many packages one user can watch.
const MaxWatchedPerUser = 100

// WatchedPackage summarizes a watched package across the visible fleet.
type WatchedPackage struct {
	Name string
	// Hosts that have it installed and how many distinct versions they run.
	HostCount    int
	VersionCount int
	// Hosts with a pending update for it, and how many of those are security updates.
	UpdateHosts   int
	SecurityHosts int
	// Active findings: distinct CVEs, affected hosts, worst severity, KEV.
	CVECount       int
	VulnHosts      int
	Severity       vuln.Severity
	KnownExploited bool
	// FindingPackage is the package name the findings are recorded under
	// (the source package on Debian/Ubuntu/Alpine), for search links.
	FindingPackage string
}

// HostWatchedPackage is a watched package installed on one host.
type HostWatchedPackage struct {
	Name             string
	Versions         []string // one per architecture
	AvailableVersion string   // "" = no pending update
	Security         bool
	CVECount         int
	Severity         vuln.Severity
	KnownExploited   bool
	FindingPackage   string
}

// WatchPackage adds a package name to a user's watch list.
func (s *Store) WatchPackage(ctx context.Context, userID int64, name string) error {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM watched_packages WHERE user_id = ?`, userID).Scan(&n); err != nil {
		return err
	}
	if n >= MaxWatchedPerUser {
		var exists int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM watched_packages WHERE user_id = ? AND name = ?`, userID, name).Scan(&exists); err != nil {
			return err
		}
		if exists == 0 {
			return ErrLimit
		}
		return nil
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO watched_packages (user_id, name, created_at) VALUES (?, ?, ?) ON CONFLICT DO NOTHING`, userID, name, now())
	return err
}

// UnwatchPackage removes a package name from a user's watch list.
func (s *Store) UnwatchPackage(ctx context.Context, userID int64, name string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM watched_packages WHERE user_id = ? AND name = ?`, userID, name)
	return err
}

// WatchedNames returns a user's watched package names, sorted.
func (s *Store) WatchedNames(ctx context.Context, userID int64) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name FROM watched_packages WHERE user_id = ? ORDER BY name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// CountHostWatched counts the user's watched packages installed on a host.
func (s *Store) CountHostWatched(ctx context.Context, userID, hostID int64) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(DISTINCT p.name) FROM host_packages p JOIN watched_packages w ON w.name = p.name
		WHERE w.user_id = ? AND p.host_id = ?`, userID, hostID).Scan(&n)
	return n, err
}

// watchedFindingJoin matches findings to installed packages: by binary name
// (RPM) or by the source package (Debian/Ubuntu/Alpine).
const watchedFindingJoin = ` FROM host_packages p JOIN findings f ON f.host_id = p.host_id
	AND (f.package_name = p.name OR (p.source_name <> '' AND f.package_name = p.source_name))
	LEFT JOIN vulnerabilities v ON v.cve_id = f.cve_id LEFT JOIN kev k ON k.cve_id = f.cve_id`

func inList(n int) string { return `(?` + strings.Repeat(",?", n-1) + `)` }

func anyArgs(names []string) []any {
	out := make([]any, len(names))
	for i, n := range names {
		out[i] = n
	}
	return out
}

var severityByRank = []vuln.Severity{vuln.SeverityCritical, vuln.SeverityHigh, vuln.SeverityMedium, vuln.SeverityLow, vuln.SeverityUnknown}

func severityFromRank(rank int) vuln.Severity {
	if rank < 0 || rank >= len(severityByRank) {
		return vuln.SeverityUnknown
	}
	return severityByRank[rank]
}

// WatchedSummary summarizes a user's watched packages over the hosts the
// context may see, in name order.
func (s *Store) WatchedSummary(ctx context.Context, userID int64) ([]WatchedPackage, error) {
	names, err := s.WatchedNames(ctx, userID)
	if err != nil || len(names) == 0 {
		return nil, err
	}
	byName := make(map[string]*WatchedPackage, len(names))
	out := make([]WatchedPackage, len(names))
	for i, n := range names {
		out[i] = WatchedPackage{Name: n, Severity: vuln.SeverityUnknown}
		byName[n] = &out[i]
	}
	in := inList(len(names))

	where, args := andScope(ctx, ` WHERE p.name IN `+in, anyArgs(names), "p.host_id")
	rows, err := s.db.QueryContext(ctx, `SELECT p.name, COUNT(DISTINCT p.host_id), COUNT(DISTINCT p.version) FROM host_packages p`+where+` GROUP BY p.name`, args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var n string
		var hosts, versions int
		if err := rows.Scan(&n, &hosts, &versions); err != nil {
			rows.Close()
			return nil, err
		}
		if w := byName[n]; w != nil {
			w.HostCount, w.VersionCount = hosts, versions
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	where, args = andScope(ctx, ` WHERE u.name IN `+in, anyArgs(names), "u.host_id")
	rows, err = s.db.QueryContext(ctx, `SELECT u.name, COUNT(*), COUNT(CASE WHEN u.security = 1 THEN 1 END) FROM host_updates u`+where+` GROUP BY u.name`, args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var n string
		var hosts, sec int
		if err := rows.Scan(&n, &hosts, &sec); err != nil {
			rows.Close()
			return nil, err
		}
		if w := byName[n]; w != nil {
			w.UpdateHosts, w.SecurityHosts = hosts, sec
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	where, args = andScope(ctx, ` WHERE p.name IN `+in+` AND f.status IN `+activeStatuses, anyArgs(names), "p.host_id")
	rows, err = s.db.QueryContext(ctx, `SELECT p.name, COUNT(DISTINCT f.cve_id), COUNT(DISTINCT f.host_id), MIN(`+severityOrder+`),
		MAX(CASE WHEN k.cve_id IS NULL THEN 0 ELSE 1 END), MIN(f.package_name)`+watchedFindingJoin+where+` GROUP BY p.name`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var n, pkg string
		var cves, hosts, rank, kev int
		if err := rows.Scan(&n, &cves, &hosts, &rank, &kev, &pkg); err != nil {
			return nil, err
		}
		if w := byName[n]; w != nil {
			w.CVECount, w.VulnHosts, w.Severity, w.KnownExploited, w.FindingPackage = cves, hosts, severityFromRank(rank), kev == 1, pkg
		}
	}
	return out, rows.Err()
}

// HostWatched returns the user's watched packages installed on a host, and
// how many watched packages the host does not have.
func (s *Store) HostWatched(ctx context.Context, userID, hostID int64) ([]HostWatchedPackage, int, error) {
	names, err := s.WatchedNames(ctx, userID)
	if err != nil || len(names) == 0 {
		return nil, 0, err
	}
	in := inList(len(names))
	args := append([]any{hostID}, anyArgs(names)...)
	byName := map[string]*HostWatchedPackage{}

	rows, err := s.db.QueryContext(ctx, `SELECT name, version, arch FROM host_packages WHERE host_id = ? AND name IN `+in+` ORDER BY name, arch`, args...)
	if err != nil {
		return nil, 0, err
	}
	for rows.Next() {
		var n, version, arch string
		if err := rows.Scan(&n, &version, &arch); err != nil {
			rows.Close()
			return nil, 0, err
		}
		w := byName[n]
		if w == nil {
			w = &HostWatchedPackage{Name: n, Severity: vuln.SeverityUnknown}
			byName[n] = w
		}
		if arch != "" && arch != "all" && arch != "noarch" {
			version += " (" + arch + ")"
		}
		w.Versions = append(w.Versions, version)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	if len(byName) == 0 {
		return nil, len(names), nil
	}

	rows, err = s.db.QueryContext(ctx, `SELECT name, available_version, security FROM host_updates WHERE host_id = ? AND name IN `+in, args...)
	if err != nil {
		return nil, 0, err
	}
	for rows.Next() {
		var n, avail string
		var sec int
		if err := rows.Scan(&n, &avail, &sec); err != nil {
			rows.Close()
			return nil, 0, err
		}
		if w := byName[n]; w != nil {
			w.AvailableVersion, w.Security = avail, sec == 1
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	rows, err = s.db.QueryContext(ctx, `SELECT p.name, COUNT(DISTINCT f.cve_id), MIN(`+severityOrder+`), MAX(CASE WHEN k.cve_id IS NULL THEN 0 ELSE 1 END), MIN(f.package_name)`+
		watchedFindingJoin+` WHERE p.host_id = ? AND p.name IN `+in+` AND f.status IN `+activeStatuses+` GROUP BY p.name`, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var n, pkg string
		var cves, rank, kev int
		if err := rows.Scan(&n, &cves, &rank, &kev, &pkg); err != nil {
			return nil, 0, err
		}
		if w := byName[n]; w != nil {
			w.CVECount, w.Severity, w.KnownExploited, w.FindingPackage = cves, severityFromRank(rank), kev == 1, pkg
		}
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	out := make([]HostWatchedPackage, 0, len(byName))
	for _, w := range byName {
		out = append(out, *w)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, len(names) - len(out), nil
}
