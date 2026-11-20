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

// SeverityCounts counts active findings (distinct CVEs) by severity.
type SeverityCounts struct {
	Critical, High, Medium, Low, Other int
}

// Total returns the sum.
func (c SeverityCounts) Total() int { return c.Critical + c.High + c.Medium + c.Low + c.Other }

// Host is a managed server.
type Host struct {
	ID             int64
	MachineID      string
	Hostname       string
	FQDN           string
	OSID           string
	OSVersionID    string
	OSName         string
	OSVersion      string
	Kernel         string
	Arch           string
	IPAddresses    []string
	PackageManager string
	Ecosystem      string // OSV ecosystems joined with "|", empty if unsupported
	AgentVersion   string
	RemoteUpdates  bool
	SelfUpdate     bool // the agent accepts automatic updates
	RebootRequired bool
	UptimeSeconds  int64
	EnrolledAt     time.Time
	LastSeenAt     time.Time
	LastReportAt   time.Time
	LastScanAt     time.Time
	ReportErrors   []string
	Notes          string

	// Aggregates filled by list/detail queries.
	PackageCount        int
	UpdateCount         int
	SecurityUpdateCount int
	Vulns               SeverityCounts
}

// Online reports whether the agent checked in within offlineAfter.
func (h Host) Online(offlineAfter time.Duration) bool {
	return !h.LastSeenAt.IsZero() && time.Since(h.LastSeenAt) < offlineAfter
}

// HostInfo returns the protocol view of the host.
func (h Host) HostInfo() protocol.HostInfo {
	return protocol.HostInfo{
		Hostname: h.Hostname, FQDN: h.FQDN, MachineID: h.MachineID, OSID: h.OSID,
		OSVersionID: h.OSVersionID, OSVersion: h.OSVersion, OSName: h.OSName,
		Kernel: h.Kernel, Arch: h.Arch, PackageManager: h.PackageManager,
	}
}

const activeStatuses = `('open','in_progress')`

const hostSelect = `SELECT h.id, h.machine_id, h.hostname, h.fqdn, h.os_id, h.os_version_id, h.os_name, h.os_version,
 h.kernel, h.arch, h.ip_addresses, h.package_manager, h.ecosystem, h.agent_version, h.remote_updates,
 h.reboot_required, h.uptime_seconds, h.enrolled_at, h.last_seen_at, h.last_report_at, h.last_scan_at,
 h.report_errors, h.notes, h.self_update,
 (SELECT COUNT(*) FROM host_packages p WHERE p.host_id = h.id) AS pkg_count,
 (SELECT COUNT(*) FROM host_updates u WHERE u.host_id = h.id) AS upd_count,
 (SELECT COUNT(*) FROM host_updates u WHERE u.host_id = h.id AND u.security = 1) AS sec_count,
 (SELECT COUNT(DISTINCT f.cve_id) FROM findings f JOIN vulnerabilities v ON v.cve_id = f.cve_id WHERE f.host_id = h.id AND f.status IN ` + activeStatuses + ` AND v.severity = 'critical') AS crit_count,
 (SELECT COUNT(DISTINCT f.cve_id) FROM findings f JOIN vulnerabilities v ON v.cve_id = f.cve_id WHERE f.host_id = h.id AND f.status IN ` + activeStatuses + ` AND v.severity = 'high') AS high_count,
 (SELECT COUNT(DISTINCT f.cve_id) FROM findings f JOIN vulnerabilities v ON v.cve_id = f.cve_id WHERE f.host_id = h.id AND f.status IN ` + activeStatuses + ` AND v.severity = 'medium') AS med_count,
 (SELECT COUNT(DISTINCT f.cve_id) FROM findings f JOIN vulnerabilities v ON v.cve_id = f.cve_id WHERE f.host_id = h.id AND f.status IN ` + activeStatuses + ` AND v.severity = 'low') AS low_count,
 (SELECT COUNT(DISTINCT f.cve_id) FROM findings f JOIN vulnerabilities v ON v.cve_id = f.cve_id WHERE f.host_id = h.id AND f.status IN ` + activeStatuses + ` AND v.severity NOT IN ('critical','high','medium','low')) AS other_count
 FROM hosts h`

func scanHost(row interface{ Scan(...any) error }) (Host, error) {
	var h Host
	var ips, errs string
	var remote, reboot, self int
	var enrolled, seen, report, scan int64
	err := row.Scan(&h.ID, &h.MachineID, &h.Hostname, &h.FQDN, &h.OSID, &h.OSVersionID, &h.OSName, &h.OSVersion,
		&h.Kernel, &h.Arch, &ips, &h.PackageManager, &h.Ecosystem, &h.AgentVersion, &remote,
		&reboot, &h.UptimeSeconds, &enrolled, &seen, &report, &scan, &errs, &h.Notes, &self,
		&h.PackageCount, &h.UpdateCount, &h.SecurityUpdateCount,
		&h.Vulns.Critical, &h.Vulns.High, &h.Vulns.Medium, &h.Vulns.Low, &h.Vulns.Other)
	if errors.Is(err, sql.ErrNoRows) {
		return h, ErrNotFound
	}
	if err != nil {
		return h, err
	}
	_ = json.Unmarshal([]byte(ips), &h.IPAddresses)
	_ = json.Unmarshal([]byte(errs), &h.ReportErrors)
	h.RemoteUpdates, h.RebootRequired, h.SelfUpdate = remote == 1, reboot == 1, self == 1
	h.EnrolledAt, h.LastSeenAt, h.LastReportAt, h.LastScanAt = fromTS(enrolled), fromTS(seen), fromTS(report), fromTS(scan)
	return h, nil
}

// HostFilter narrows the host list.
type HostFilter struct {
	Search       string
	Status       string // "", "online", "offline", "reboot", "vulnerable", "updates"
	OSID         string
	OfflineAfter time.Duration
}

// ListHosts returns hosts matching f, ordered by hostname, and the total count.
func (s *Store) ListHosts(ctx context.Context, f HostFilter, p Page) ([]Host, int, error) {
	where, args := hostWhere(f)
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM hosts h`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.QueryContext(ctx, hostSelect+where+` ORDER BY h.hostname COLLATE NOCASE LIMIT ? OFFSET ?`, append(args, p.limit(), p.Offset())...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Host
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, h)
	}
	return out, total, rows.Err()
}

func hostWhere(f HostFilter) (string, []any) {
	var conds []string
	var args []any
	if q := strings.TrimSpace(f.Search); q != "" {
		conds = append(conds, `(h.hostname LIKE ? ESCAPE '\' OR h.fqdn LIKE ? ESCAPE '\' OR h.ip_addresses LIKE ? ESCAPE '\' OR h.os_name LIKE ? ESCAPE '\')`)
		l := likeEscape(q)
		args = append(args, l, l, l, l)
	}
	if f.OSID != "" {
		conds = append(conds, `h.os_id = ?`)
		args = append(args, f.OSID)
	}
	cutoff := now() - int64(f.OfflineAfter.Seconds())
	switch f.Status {
	case "online":
		conds = append(conds, `h.last_seen_at >= ?`)
		args = append(args, cutoff)
	case "offline":
		conds = append(conds, `h.last_seen_at < ?`)
		args = append(args, cutoff)
	case "reboot":
		conds = append(conds, `h.reboot_required = 1`)
	case "vulnerable":
		conds = append(conds, `EXISTS (SELECT 1 FROM findings f WHERE f.host_id = h.id AND f.status IN `+activeStatuses+`)`)
	case "updates":
		conds = append(conds, `EXISTS (SELECT 1 FROM host_updates u WHERE u.host_id = h.id)`)
	}
	if len(conds) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

// HostByID returns a host with aggregates.
func (s *Store) HostByID(ctx context.Context, id int64) (Host, error) {
	return scanHost(s.db.QueryRowContext(ctx, hostSelect+` WHERE h.id = ?`, id))
}

// HostIDBySecret authenticates an agent by its secret hash.
func (s *Store) HostIDBySecret(ctx context.Context, secretHash string) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, `SELECT id FROM hosts WHERE agent_secret_hash = ?`, secretHash).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	return id, err
}

// OSOptions returns distinct (os_id, sample name) pairs for filters.
func (s *Store) OSOptions(ctx context.Context) ([][2]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT os_id, MIN(os_name) FROM hosts WHERE os_id <> '' GROUP BY os_id ORDER BY os_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][2]string
	for rows.Next() {
		var a, b string
		if err := rows.Scan(&a, &b); err != nil {
			return nil, err
		}
		out = append(out, [2]string{a, b})
	}
	return out, rows.Err()
}

// DeleteHost removes a host and all its data. The agent's secret stops working.
func (s *Store) DeleteHost(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM hosts WHERE id = ?`, id)
	return err
}

// SetHostNotes stores free-text notes.
func (s *Store) SetHostNotes(ctx context.Context, id int64, notes string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE hosts SET notes = ? WHERE id = ?`, truncate(notes, 4000), id)
	return err
}

// EnrollmentToken allows agents to register.
type EnrollmentToken struct {
	ID          int64
	Name        string
	TokenPrefix string
	CreatedBy   string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	MaxUses     int
	Uses        int
	RevokedAt   time.Time
}

// Usable reports whether the token can still enroll agents.
func (t EnrollmentToken) Usable() bool {
	if !t.RevokedAt.IsZero() {
		return false
	}
	if !t.ExpiresAt.IsZero() && time.Now().After(t.ExpiresAt) {
		return false
	}
	return t.MaxUses == 0 || t.Uses < t.MaxUses
}

// CreateEnrollmentToken stores a token hash.
func (s *Store) CreateEnrollmentToken(ctx context.Context, name, hash, prefix string, createdBy int64, expires time.Time, maxUses int) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO enrollment_tokens (name, token_hash, token_prefix, created_by, created_at, expires_at, max_uses) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		strings.TrimSpace(name), hash, prefix, nullID(createdBy), now(), ts(expires), maxUses)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ListEnrollmentTokens returns all tokens, newest first.
func (s *Store) ListEnrollmentTokens(ctx context.Context) ([]EnrollmentToken, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT t.id, t.name, t.token_prefix, COALESCE(u.name, ''), t.created_at, t.expires_at, t.max_uses, t.uses, t.revoked_at
		FROM enrollment_tokens t LEFT JOIN users u ON u.id = t.created_by ORDER BY t.id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EnrollmentToken
	for rows.Next() {
		var t EnrollmentToken
		var c, e, r int64
		if err := rows.Scan(&t.ID, &t.Name, &t.TokenPrefix, &t.CreatedBy, &c, &e, &t.MaxUses, &t.Uses, &r); err != nil {
			return nil, err
		}
		t.CreatedAt, t.ExpiresAt, t.RevokedAt = fromTS(c), fromTS(e), fromTS(r)
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeEnrollmentToken disables a token. Already enrolled agents keep working.
func (s *Store) RevokeEnrollmentToken(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE enrollment_tokens SET revoked_at = ? WHERE id = ? AND revoked_at = 0`, now(), id)
	return err
}

// ErrTokenInvalid is returned for unknown, revoked, expired or exhausted tokens.
var ErrTokenInvalid = errors.New("store: enrollment token invalid")

// RegisterHost consumes an enrollment token and creates the host, or
// re-enrolls an existing host with the same machine ID (rotating its secret).
func (s *Store) RegisterHost(ctx context.Context, tokenHash string, info protocol.HostInfo, ecosystem, secretHash string) (int64, bool, error) {
	var hostID int64
	var reenrolled bool
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var tokenID int64
		var expires, revoked int64
		var maxUses, uses int
		err := tx.QueryRowContext(ctx, `SELECT id, expires_at, revoked_at, max_uses, uses FROM enrollment_tokens WHERE token_hash = ?`, tokenHash).
			Scan(&tokenID, &expires, &revoked, &maxUses, &uses)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrTokenInvalid
		}
		if err != nil {
			return err
		}
		n := now()
		if revoked != 0 || (expires != 0 && expires <= n) || (maxUses > 0 && uses >= maxUses) {
			return ErrTokenInvalid
		}
		if _, err := tx.ExecContext(ctx, `UPDATE enrollment_tokens SET uses = uses + 1 WHERE id = ?`, tokenID); err != nil {
			return err
		}
		ips, _ := json.Marshal(nonNil(info.IPAddresses))
		if info.MachineID != "" {
			err := tx.QueryRowContext(ctx, `SELECT id FROM hosts WHERE machine_id = ? ORDER BY id LIMIT 1`, info.MachineID).Scan(&hostID)
			if err == nil {
				reenrolled = true
				_, err = tx.ExecContext(ctx, `UPDATE hosts SET agent_secret_hash = ?, enrollment_token = ?, last_seen_at = ?, offline_notified = 0 WHERE id = ?`,
					secretHash, tokenID, n, hostID)
				if err != nil {
					return err
				}
				return updateHostInfo(ctx, tx, hostID, info, ecosystem)
			}
			if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO hosts (machine_id, hostname, fqdn, os_id, os_version_id, os_name, os_version, kernel, arch,
			ip_addresses, package_manager, ecosystem, agent_version, remote_updates, self_update, uptime_seconds, agent_secret_hash, enrolled_at, enrollment_token, last_seen_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			info.MachineID, info.Hostname, info.FQDN, info.OSID, info.OSVersionID, info.OSName, info.OSVersion, info.Kernel, info.Arch,
			string(ips), info.PackageManager, ecosystem, info.AgentVersion, boolInt(info.RemoteUpdates), boolInt(info.SelfUpdate), info.UptimeSeconds, secretHash, n, tokenID, n)
		if err != nil {
			return err
		}
		hostID, err = res.LastInsertId()
		return err
	})
	return hostID, reenrolled, err
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func updateHostInfo(ctx context.Context, tx *sql.Tx, id int64, info protocol.HostInfo, ecosystem string) error {
	ips, _ := json.Marshal(nonNil(info.IPAddresses))
	_, err := tx.ExecContext(ctx, `UPDATE hosts SET hostname = ?, fqdn = ?, os_id = ?, os_version_id = ?, os_name = ?, os_version = ?,
		kernel = ?, arch = ?, ip_addresses = ?, package_manager = ?, ecosystem = ?, agent_version = ?, remote_updates = ?, self_update = ?,
		uptime_seconds = ?, last_seen_at = ?, offline_notified = 0 WHERE id = ?`,
		info.Hostname, info.FQDN, info.OSID, info.OSVersionID, info.OSName, info.OSVersion,
		info.Kernel, info.Arch, string(ips), info.PackageManager, ecosystem, info.AgentVersion, boolInt(info.RemoteUpdates), boolInt(info.SelfUpdate),
		info.UptimeSeconds, now(), id)
	return err
}

// Checkin records a heartbeat and returns whether the host was offline
// (already notified) before this check-in, and whether a report is due.
func (s *Store) Checkin(ctx context.Context, id int64, info protocol.HostInfo, ecosystem string, reportEvery time.Duration) (wasOfflineNotified, reportDue bool, err error) {
	err = s.tx(ctx, func(tx *sql.Tx) error {
		var notified int
		var lastReport int64
		if err := tx.QueryRowContext(ctx, `SELECT offline_notified, last_report_at FROM hosts WHERE id = ?`, id).Scan(&notified, &lastReport); err != nil {
			return err
		}
		wasOfflineNotified = notified == 1
		reportDue = lastReport == 0 || now()-lastReport >= int64(reportEvery.Seconds())
		return updateHostInfo(ctx, tx, id, info, ecosystem)
	})
	return
}

// SaveReport replaces the host's inventory and flags it for scanning.
func (s *Store) SaveReport(ctx context.Context, id int64, r protocol.Report, ecosystem string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if err := updateHostInfo(ctx, tx, id, r.Host, ecosystem); err != nil {
			return err
		}
		errs, _ := json.Marshal(nonNil(r.Errors))
		if _, err := tx.ExecContext(ctx, `UPDATE hosts SET reboot_required = ?, last_report_at = ?, needs_scan = 1, report_errors = ? WHERE id = ?`,
			boolInt(r.RebootRequired), now(), string(errs), id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM host_packages WHERE host_id = ?`, id); err != nil {
			return err
		}
		ins, err := tx.PrepareContext(ctx, `INSERT OR REPLACE INTO host_packages (host_id, name, arch, version, source_name, source_version) VALUES (?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return err
		}
		defer ins.Close()
		for _, p := range r.Packages {
			if p.Name == "" || p.Version == "" {
				continue
			}
			if _, err := ins.ExecContext(ctx, id, p.Name, p.Arch, p.Version, p.SourceName, p.SourceVersion); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM host_updates WHERE host_id = ?`, id); err != nil {
			return err
		}
		upd, err := tx.PrepareContext(ctx, `INSERT OR REPLACE INTO host_updates (host_id, name, current_version, available_version, repository, security) VALUES (?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return err
		}
		defer upd.Close()
		for _, u := range r.Updates {
			if u.Name == "" {
				continue
			}
			if _, err := upd.ExecContext(ctx, id, u.Name, u.CurrentVersion, u.AvailableVersion, u.Repository, boolInt(u.Security)); err != nil {
				return err
			}
		}
		return nil
	})
}

// HostPackages returns all packages of a host.
func (s *Store) HostPackages(ctx context.Context, id int64) ([]protocol.Package, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name, version, arch, source_name, source_version FROM host_packages WHERE host_id = ? ORDER BY name, arch`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []protocol.Package
	for rows.Next() {
		var p protocol.Package
		if err := rows.Scan(&p.Name, &p.Version, &p.Arch, &p.SourceName, &p.SourceVersion); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// SearchHostPackages pages through a host's packages with an optional search.
func (s *Store) SearchHostPackages(ctx context.Context, id int64, search string, p Page) ([]protocol.Package, int, error) {
	where := ` WHERE host_id = ?`
	args := []any{id}
	if q := strings.TrimSpace(search); q != "" {
		where += ` AND (name LIKE ? ESCAPE '\' OR source_name LIKE ? ESCAPE '\')`
		args = append(args, likeEscape(q), likeEscape(q))
	}
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM host_packages`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT name, version, arch, source_name, source_version FROM host_packages`+where+` ORDER BY name, arch LIMIT ? OFFSET ?`,
		append(args, p.limit(), p.Offset())...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []protocol.Package
	for rows.Next() {
		var pk protocol.Package
		if err := rows.Scan(&pk.Name, &pk.Version, &pk.Arch, &pk.SourceName, &pk.SourceVersion); err != nil {
			return nil, 0, err
		}
		out = append(out, pk)
	}
	return out, total, rows.Err()
}

// HostUpdates returns a host's pending updates, security first.
func (s *Store) HostUpdates(ctx context.Context, id int64) ([]protocol.Update, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name, current_version, available_version, repository, security FROM host_updates WHERE host_id = ? ORDER BY security DESC, name`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []protocol.Update
	for rows.Next() {
		var u protocol.Update
		var sec int
		if err := rows.Scan(&u.Name, &u.CurrentVersion, &u.AvailableVersion, &u.Repository, &sec); err != nil {
			return nil, err
		}
		u.Security = sec == 1
		out = append(out, u)
	}
	return out, rows.Err()
}

// HostsNeedingScan returns IDs of hosts flagged for scanning.
func (s *Store) HostsNeedingScan(ctx context.Context, limit int) ([]int64, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM hosts WHERE needs_scan = 1 ORDER BY last_scan_at LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// MarkAllForScan flags every host with an inventory for rescanning.
func (s *Store) MarkAllForScan(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `UPDATE hosts SET needs_scan = 1 WHERE last_report_at > 0`)
	return err
}

// MarkForScan flags one host for rescanning.
func (s *Store) MarkForScan(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE hosts SET needs_scan = 1 WHERE id = ? AND last_report_at > 0`, id)
	return err
}

// UpgradablePackagesFor returns the names of a host's pending updates that
// belong to pkg, where pkg is a binary or source package name (findings on
// Debian, Ubuntu and Alpine are keyed by source package).
func (s *Store) UpgradablePackagesFor(ctx context.Context, hostID int64, pkg string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT u.name FROM host_updates u
		WHERE u.host_id = ? AND (u.name = ? OR u.name IN (SELECT p.name FROM host_packages p WHERE p.host_id = ? AND p.source_name = ?))
		ORDER BY u.name`, hostID, pkg, hostID, pkg)
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

// AgentVersions counts hosts per agent version.
func (s *Store) AgentVersions(ctx context.Context) ([][2]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT agent_version, COUNT(*) FROM hosts GROUP BY agent_version ORDER BY agent_version DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][2]string
	for rows.Next() {
		var v, n string
		if err := rows.Scan(&v, &n); err != nil {
			return nil, err
		}
		out = append(out, [2]string{v, n})
	}
	return out, rows.Err()
}

// MarkScanned clears the scan flag.
func (s *Store) MarkScanned(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE hosts SET needs_scan = 0, last_scan_at = ? WHERE id = ?`, now(), id)
	return err
}

// HostsGoneOffline returns hosts not seen within offlineAfter that have not
// been notified yet, and marks them notified.
func (s *Store) HostsGoneOffline(ctx context.Context, offlineAfter time.Duration) ([]Host, error) {
	cutoff := now() - int64(offlineAfter.Seconds())
	rows, err := s.db.QueryContext(ctx, hostSelect+` WHERE h.offline_notified = 0 AND h.last_seen_at > 0 AND h.last_seen_at < ?`, cutoff)
	if err != nil {
		return nil, err
	}
	var out []Host
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, h)
	}
	rows.Close()
	for _, h := range out {
		if _, err := s.db.ExecContext(ctx, `UPDATE hosts SET offline_notified = 1 WHERE id = ?`, h.ID); err != nil {
			return nil, err
		}
	}
	return out, nil
}
