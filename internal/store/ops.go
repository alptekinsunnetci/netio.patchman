package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"netio.patchman/internal/protocol"
)

// JobTimedOut marks jobs whose agent never reported a result.
const JobTimedOut = "timed_out"

// Job is an update job.
type Job struct {
	ID           int64
	HostID       int64
	Hostname     string
	Type         string
	Packages     []string
	Params       map[string]string
	Status       string
	CreatedBy    string
	CreatedAt    time.Time
	DispatchedAt time.Time
	FinishedAt   time.Time
	ExitCode     int
	Output       string
	// Remaining lists targeted packages (or services) still pending after the job.
	Remaining []string
	// Set for jobs created by a schedule.
	ScheduleID   int64
	ScheduleName string
	ExpiresAt    time.Time
}

// Active reports whether the job has not finished yet.
func (j Job) Active() bool {
	return j.Status == protocol.JobQueued || j.Status == protocol.JobDispatched
}

// CreateJob queues a job for a host. userID 0 means a system-created job
// (for example an automatic agent update).
func (s *Store) CreateJob(ctx context.Context, hostID int64, typ string, packages []string, params map[string]string, userID int64) (int64, error) {
	b, _ := json.Marshal(nonNil(packages))
	if params == nil {
		params = map[string]string{}
	}
	p, _ := json.Marshal(params)
	res, err := s.db.ExecContext(ctx, `INSERT INTO jobs (host_id, type, packages, params, status, created_by, created_at) VALUES (?, ?, ?, ?, 'queued', ?, ?)`,
		hostID, typ, string(b), string(p), nullID(userID), now())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// HasActiveJob reports whether the host has a queued or dispatched job of the type.
func (s *Store) HasActiveJob(ctx context.Context, hostID int64, typ string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM jobs WHERE host_id = ? AND type = ? AND status IN ('queued','dispatched')`, hostID, typ).Scan(&n)
	return n > 0, err
}

// CountActiveJobs counts queued or dispatched jobs of a type across all hosts.
func (s *Store) CountActiveJobs(ctx context.Context, typ string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM jobs WHERE type = ? AND status IN ('queued','dispatched')`, typ).Scan(&n)
	return n, err
}

// LastFinishedJob returns the status and finish time of the host's most recent
// finished job of a type; status is "" if there is none.
func (s *Store) LastFinishedJob(ctx context.Context, hostID int64, typ string) (string, time.Time, error) {
	var status string
	var fin int64
	err := s.db.QueryRowContext(ctx, `SELECT status, finished_at FROM jobs WHERE host_id = ? AND type = ? AND finished_at > 0 ORDER BY finished_at DESC, id DESC LIMIT 1`,
		hostID, typ).Scan(&status, &fin)
	if errors.Is(err, sql.ErrNoRows) {
		return "", time.Time{}, nil
	}
	return status, fromTS(fin), err
}

// DispatchJobs returns queued jobs for a host and marks them dispatched.
func (s *Store) DispatchJobs(ctx context.Context, hostID int64) ([]protocol.Job, error) {
	var out []protocol.Job
	err := s.tx(ctx, func(tx *sql.Tx) error {
		// Scheduled jobs past their maintenance window are never dispatched.
		rows, err := tx.QueryContext(ctx, `SELECT id, type, packages, params FROM jobs WHERE host_id = ? AND status = 'queued'
			AND (expires_at = 0 OR expires_at > ?) ORDER BY id`, hostID, now())
		if err != nil {
			return err
		}
		for rows.Next() {
			var j protocol.Job
			var pk, params string
			if err := rows.Scan(&j.ID, &j.Type, &pk, &params); err != nil {
				rows.Close()
				return err
			}
			_ = json.Unmarshal([]byte(pk), &j.Packages)
			_ = json.Unmarshal([]byte(params), &j.Params)
			out = append(out, j)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		for _, j := range out {
			if _, err := tx.ExecContext(ctx, `UPDATE jobs SET status = 'dispatched', dispatched_at = ? WHERE id = ?`, now(), j.ID); err != nil {
				return err
			}
		}
		return nil
	})
	return out, err
}

// CompleteJob records a job result reported by the host's agent.
func (s *Store) CompleteJob(ctx context.Context, hostID, jobID int64, r protocol.JobResult) (Job, error) {
	status := protocol.JobFailed
	switch {
	case r.Succeeded && len(r.Remaining) > 0:
		status = protocol.JobPartial
	case r.Succeeded:
		status = protocol.JobSucceeded
	}
	var remaining []string
	for _, n := range r.Remaining {
		if len(remaining) < 500 && (protocol.ValidPackageName(n) || protocol.ValidServiceName(n)) {
			remaining = append(remaining, n)
		}
	}
	rem, _ := json.Marshal(nonNil(remaining))
	res, err := s.db.ExecContext(ctx, `UPDATE jobs SET status = ?, finished_at = ?, exit_code = ?, output = ?, remaining = ? WHERE id = ? AND host_id = ? AND status IN ('queued','dispatched')`,
		status, now(), r.ExitCode, truncate(r.Output, protocol.MaxOutputBytes), string(rem), jobID, hostID)
	if err != nil {
		return Job{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return Job{}, ErrNotFound
	}
	return s.JobByID(ctx, jobID)
}

// CancelJob cancels a job that has not been dispatched yet.
func (s *Store) CancelJob(ctx context.Context, id int64) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE jobs SET status = 'cancelled', finished_at = ? WHERE id = ? AND status = 'queued'`, now(), id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// TimeOutJobs marks dispatched jobs older than d as timed out and returns them.
func (s *Store) TimeOutJobs(ctx context.Context, d time.Duration) ([]Job, error) {
	cutoff := now() - int64(d.Seconds())
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM jobs WHERE status = 'dispatched' AND dispatched_at < ?`, cutoff)
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
	var out []Job
	for _, id := range ids {
		if _, err := s.db.ExecContext(ctx, `UPDATE jobs SET status = 'timed_out', finished_at = ?, exit_code = -1 WHERE id = ?`, now(), id); err != nil {
			return nil, err
		}
		j, err := s.JobByID(ctx, id)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, nil
}

const jobSelect = `SELECT j.id, j.host_id, h.hostname, j.type, j.packages, j.params, j.status, COALESCE(u.name, ''), j.created_at, j.dispatched_at, j.finished_at, j.exit_code, j.output, j.remaining,
 COALESCE(j.schedule_id, 0), COALESCE(sc.name, ''), j.expires_at
 FROM jobs j JOIN hosts h ON h.id = j.host_id LEFT JOIN users u ON u.id = j.created_by LEFT JOIN schedules sc ON sc.id = j.schedule_id`

func scanJob(row interface{ Scan(...any) error }, withOutput bool) (Job, error) {
	var j Job
	var pk, params, rem string
	var c, d, f, e int64
	err := row.Scan(&j.ID, &j.HostID, &j.Hostname, &j.Type, &pk, &params, &j.Status, &j.CreatedBy, &c, &d, &f, &j.ExitCode, &j.Output, &rem,
		&j.ScheduleID, &j.ScheduleName, &e)
	if errors.Is(err, sql.ErrNoRows) {
		return j, ErrNotFound
	}
	if err != nil {
		return j, err
	}
	_ = json.Unmarshal([]byte(pk), &j.Packages)
	_ = json.Unmarshal([]byte(params), &j.Params)
	_ = json.Unmarshal([]byte(rem), &j.Remaining)
	j.CreatedAt, j.DispatchedAt, j.FinishedAt, j.ExpiresAt = fromTS(c), fromTS(d), fromTS(f), fromTS(e)
	if !withOutput {
		j.Output = ""
	}
	return j, nil
}

// JobByID returns a job including output.
func (s *Store) JobByID(ctx context.Context, id int64) (Job, error) {
	where, args := andScope(ctx, ` WHERE j.id = ?`, []any{id}, "j.host_id")
	return scanJob(s.db.QueryRowContext(ctx, jobSelect+where, args...), true)
}

// JobFilter narrows job lists.
type JobFilter struct {
	HostID     int64
	ScheduleID int64
	Status     string
}

// ListJobs returns jobs newest first, without output.
func (s *Store) ListJobs(ctx context.Context, f JobFilter, p Page) ([]Job, int, error) {
	var conds []string
	var args []any
	if f.HostID != 0 {
		conds = append(conds, `j.host_id = ?`)
		args = append(args, f.HostID)
	}
	if f.ScheduleID != 0 {
		conds = append(conds, `j.schedule_id = ?`)
		args = append(args, f.ScheduleID)
	}
	if f.Status != "" {
		conds = append(conds, `j.status = ?`)
		args = append(args, f.Status)
	}
	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}
	where, args = andScope(ctx, where, args, "j.host_id")
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM jobs j`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.QueryContext(ctx, jobSelect+where+` ORDER BY j.id DESC LIMIT ? OFFSET ?`, append(args, p.limit(), p.Offset())...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Job
	for rows.Next() {
		j, err := scanJob(rows, false)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, j)
	}
	return out, total, rows.Err()
}

// PruneJobs deletes finished jobs older than d.
func (s *Store) PruneJobs(ctx context.Context, d time.Duration) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM jobs WHERE finished_at > 0 AND finished_at < ?`, now()-int64(d.Seconds()))
	return err
}

// ---------- notifications ----------

// Notification levels.
const (
	LevelCritical = "critical"
	LevelWarning  = "warning"
	LevelInfo     = "info"
)

// Notification is an in-app notification. Its text is rendered from the
// catalog key "notification.<Kind>" with Params at display time.
type Notification struct {
	ID        int64
	CreatedAt time.Time
	Level     string
	Kind      string
	Params    map[string]string
	Link      string
	ReadAt    time.Time
}

// AddNotification stores a notification.
func (s *Store) AddNotification(ctx context.Context, level, kind string, params map[string]string, link string) error {
	b, _ := json.Marshal(params)
	at := now()
	hostID, jobID := linkTarget(link)
	res, err := s.db.ExecContext(ctx, `INSERT INTO notifications (created_at, level, kind, params, link, host_id)
		VALUES (?, ?, ?, ?, ?, CASE WHEN ? > 0 THEN ? ELSE COALESCE((SELECT host_id FROM jobs WHERE id = ?), 0) END)`,
		at, level, kind, string(b), link, hostID, hostID, jobID)
	if err != nil {
		return err
	}
	if fn := s.notifyHook.Load(); fn != nil {
		id, _ := res.LastInsertId()
		(*fn)(Notification{ID: id, CreatedAt: fromTS(at), Level: level, Kind: kind, Params: params, Link: link})
	}
	return nil
}

// linkTarget returns the host or job id of a notification link
// ("/servers/12", "/jobs/40"), 0 when it names neither.
func linkTarget(link string) (hostID, jobID int64) {
	path, _, _ := strings.Cut(link, "?")
	for _, prefix := range []string{"/servers/", "/jobs/"} {
		if rest, ok := strings.CutPrefix(path, prefix); ok {
			id, err := strconv.ParseInt(strings.SplitN(rest, "/", 2)[0], 10, 64)
			if err != nil {
				return 0, 0
			}
			if prefix == "/servers/" {
				return id, 0
			}
			return 0, id
		}
	}
	return 0, 0
}

// notificationScope limits notifications to the hosts of the scope of ctx;
// limited users see only notifications about one of their hosts.
func notificationScope(ctx context.Context, where string, args []any) (string, []any) {
	if _, ok := ScopeFrom(ctx); !ok {
		return where, args
	}
	where, args = andScope(ctx, where, args, "host_id")
	return where + " AND host_id > 0", args
}

// ListNotifications returns notifications newest first.
func (s *Store) ListNotifications(ctx context.Context, unreadOnly bool, p Page) ([]Notification, int, error) {
	where := ""
	if unreadOnly {
		where = " WHERE read_at = 0"
	}
	var args []any
	where, args = notificationScope(ctx, where, args)
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM notifications`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, created_at, level, kind, params, link, read_at FROM notifications`+where+` ORDER BY id DESC LIMIT ? OFFSET ?`, append(args, p.limit(), p.Offset())...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Notification
	for rows.Next() {
		var n Notification
		var c, r int64
		var params string
		if err := rows.Scan(&n.ID, &c, &n.Level, &n.Kind, &params, &n.Link, &r); err != nil {
			return nil, 0, err
		}
		_ = json.Unmarshal([]byte(params), &n.Params)
		n.CreatedAt, n.ReadAt = fromTS(c), fromTS(r)
		out = append(out, n)
	}
	return out, total, rows.Err()
}

// UnreadNotifications returns the unread count.
func (s *Store) UnreadNotifications(ctx context.Context) (int, error) {
	var n int
	where, args := notificationScope(ctx, " WHERE read_at = 0", nil)
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM notifications`+where, args...).Scan(&n)
	return n, err
}

// MarkNotificationsRead marks one (id > 0) or all (id == 0) notifications read.
func (s *Store) MarkNotificationsRead(ctx context.Context, id int64) error {
	where, args := " WHERE read_at = 0", []any(nil)
	if id > 0 {
		where, args = " WHERE id = ? AND read_at = 0", []any{id}
	}
	where, args = notificationScope(ctx, where, args)
	_, err := s.db.ExecContext(ctx, `UPDATE notifications SET read_at = ?`+where, append([]any{now()}, args...)...)
	return err
}

// PruneNotifications deletes notifications older than d.
func (s *Store) PruneNotifications(ctx context.Context, d time.Duration) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM notifications WHERE created_at < ?`, now()-int64(d.Seconds()))
	return err
}

// PruneAudit deletes audit entries older than d.
func (s *Store) PruneAudit(ctx context.Context, d time.Duration) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM audit_log WHERE at < ?`, now()-int64(d.Seconds()))
	return err
}

// ---------- settings ----------

// Settings returns all stored settings.
func (s *Store) Settings(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key, value FROM settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

// SaveSettings upserts settings.
func (s *Store) SaveSettings(ctx context.Context, kv map[string]string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		for k, v := range kv {
			if _, err := tx.ExecContext(ctx, `INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value`, k, v); err != nil {
				return err
			}
		}
		return nil
	})
}

// DeleteSettings removes keys, so their defaults apply again.
func (s *Store) DeleteSettings(ctx context.Context, keys ...string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		for _, k := range keys {
			if _, err := tx.ExecContext(ctx, `DELETE FROM settings WHERE key = ?`, k); err != nil {
				return err
			}
		}
		return nil
	})
}

// ---------- fleet packages and dashboard ----------

// FleetUpdate aggregates a pending update across hosts.
type FleetUpdate struct {
	Name              string
	HostCount         int
	Security          bool
	CurrentVersions   []string
	AvailableVersions []string
}

// ListFleetUpdates aggregates pending updates by package.
func (s *Store) ListFleetUpdates(ctx context.Context, search string, securityOnly bool, p Page) ([]FleetUpdate, int, error) {
	var conds []string
	var args []any
	if q := strings.TrimSpace(search); q != "" {
		conds = append(conds, `name LIKE ? ESCAPE '\'`)
		args = append(args, likeEscape(q))
	}
	if securityOnly {
		conds = append(conds, `security = 1`)
	}
	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}
	where, args = andScope(ctx, where, args, "host_id")
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(DISTINCT name) FROM host_updates`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT name, COUNT(DISTINCT host_id), MAX(security), GROUP_CONCAT(DISTINCT current_version), GROUP_CONCAT(DISTINCT available_version)
		FROM host_updates`+where+` GROUP BY name ORDER BY MAX(security) DESC, COUNT(DISTINCT host_id) DESC, name LIMIT ? OFFSET ?`, append(args, p.limit(), p.Offset())...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []FleetUpdate
	for rows.Next() {
		var u FleetUpdate
		var sec int
		var cur, avail sql.NullString
		if err := rows.Scan(&u.Name, &u.HostCount, &sec, &cur, &avail); err != nil {
			return nil, 0, err
		}
		u.Security = sec == 1
		u.CurrentVersions, u.AvailableVersions = splitSorted(cur.String), splitSorted(avail.String)
		out = append(out, u)
	}
	return out, total, rows.Err()
}

// HostRef is a minimal host reference.
type HostRef struct {
	ID            int64
	Hostname      string
	RemoteUpdates bool
	Version       string
	Extra         string
}

// HostsWithUpdate returns hosts that have a pending update for a package.
func (s *Store) HostsWithUpdate(ctx context.Context, name string) ([]HostRef, error) {
	where, args := andScope(ctx, ` WHERE u.name = ?`, []any{name}, "h.id")
	return s.hostRefs(ctx, `SELECT h.id, h.hostname, h.remote_updates, u.current_version, u.available_version FROM host_updates u JOIN hosts h ON h.id = u.host_id`+
		where+` ORDER BY h.hostname`, args...)
}

// HostsWithPackage returns hosts that have a package installed.
func (s *Store) HostsWithPackage(ctx context.Context, name string) ([]HostRef, error) {
	where, args := andScope(ctx, ` WHERE p.name = ?`, []any{name}, "h.id")
	return s.hostRefs(ctx, `SELECT h.id, h.hostname, h.remote_updates, p.version, p.arch FROM host_packages p JOIN hosts h ON h.id = p.host_id`+
		where+` ORDER BY h.hostname, p.arch`, args...)
}

// HostsWithSecurityUpdates returns hosts that have at least one pending security update.
func (s *Store) HostsWithSecurityUpdates(ctx context.Context) ([]HostRef, error) {
	where, args := andScope(ctx, ` WHERE u.security = 1`, nil, "h.id")
	return s.hostRefs(ctx, `SELECT h.id, h.hostname, h.remote_updates, '', COUNT(*) FROM host_updates u JOIN hosts h ON h.id = u.host_id`+
		where+` GROUP BY h.id ORDER BY h.hostname`, args...)
}

func (s *Store) hostRefs(ctx context.Context, q string, args ...any) ([]HostRef, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HostRef
	for rows.Next() {
		var r HostRef
		var remote int
		if err := rows.Scan(&r.ID, &r.Hostname, &remote, &r.Version, &r.Extra); err != nil {
			return nil, err
		}
		r.RemoteUpdates = remote == 1
		out = append(out, r)
	}
	return out, rows.Err()
}

// InstalledPackage aggregates an installed package version across hosts.
type InstalledPackage struct {
	Name      string
	Version   string
	HostCount int
}

// SearchInstalled finds installed packages across the fleet.
func (s *Store) SearchInstalled(ctx context.Context, search string, p Page) ([]InstalledPackage, int, error) {
	q := strings.TrimSpace(search)
	if q == "" {
		return nil, 0, nil
	}
	where, args := andScope(ctx, ` WHERE name LIKE ? ESCAPE '\'`, []any{likeEscape(q)}, "host_id")
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM (SELECT 1 FROM host_packages`+where+` GROUP BY name, version)`, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT name, version, COUNT(DISTINCT host_id) FROM host_packages`+where+` GROUP BY name, version ORDER BY name, version LIMIT ? OFFSET ?`,
		append(args, p.limit(), p.Offset())...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []InstalledPackage
	for rows.Next() {
		var r InstalledPackage
		if err := rows.Scan(&r.Name, &r.Version, &r.HostCount); err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}

// FleetStats summarizes the fleet for the dashboard.
type FleetStats struct {
	Hosts          int
	Online         int
	Offline        int
	NeverSeen      int
	RebootRequired int
	// RebootOldest is the earliest pending reboot (zero if none).
	RebootOldest        time.Time
	HostsWithUpdates    int
	PendingUpdates      int
	SecurityUpdates     int
	HostsWithSecUpdates int
}

// FleetStats computes dashboard counters.
func (s *Store) FleetStats(ctx context.Context, offlineAfter time.Duration) (FleetStats, error) {
	var st FleetStats
	var oldest int64
	cutoff := now() - int64(offlineAfter.Seconds())
	hw, ha := andScope(ctx, "", nil, "id")
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(last_seen_at >= ?), 0), COALESCE(SUM(last_seen_at > 0 AND last_seen_at < ?), 0),
		COALESCE(SUM(last_seen_at = 0), 0), COALESCE(SUM(reboot_required), 0),
		COALESCE(MIN(CASE WHEN reboot_required = 1 AND reboot_required_since > 0 THEN reboot_required_since END), 0) FROM hosts`+hw, append([]any{cutoff, cutoff}, ha...)...).
		Scan(&st.Hosts, &st.Online, &st.Offline, &st.NeverSeen, &st.RebootRequired, &oldest)
	if err != nil {
		return st, err
	}
	st.RebootOldest = fromTS(oldest)
	uw, ua := andScope(ctx, "", nil, "host_id")
	err = s.db.QueryRowContext(ctx, `SELECT COUNT(DISTINCT host_id), COUNT(*), COALESCE(SUM(security), 0),
		COUNT(DISTINCT CASE WHEN security = 1 THEN host_id END) FROM host_updates`+uw, ua...).
		Scan(&st.HostsWithUpdates, &st.PendingUpdates, &st.SecurityUpdates, &st.HostsWithSecUpdates)
	return st, err
}

// TopVulnerableHosts returns hosts with the most critical/high findings.
func (s *Store) TopVulnerableHosts(ctx context.Context, limit int) ([]Host, error) {
	where, args := andScope(ctx, "", nil, "h.id")
	rows, err := s.db.QueryContext(ctx, hostSelect+where+` ORDER BY crit_count DESC, high_count DESC, sec_count DESC, h.hostname LIMIT ?`, append(args, limit)...)
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
		if h.Vulns.Total() == 0 && h.SecurityUpdateCount == 0 {
			continue
		}
		out = append(out, h)
	}
	return out, rows.Err()
}
