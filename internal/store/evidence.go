package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ---------- platforms ----------

// Platforms compliance reports break hosts down by.
const (
	PlatformLinux         = "linux"
	PlatformWindowsServer = "windows_server"
	PlatformWindows10     = "windows_10"
	PlatformWindows11     = "windows_11"
	PlatformWindowsOther  = "windows_other"
)

// Platforms lists the platforms in display order.
var Platforms = []string{PlatformLinux, PlatformWindowsServer, PlatformWindows10, PlatformWindows11, PlatformWindowsOther}

// ValidPlatform reports whether p is one of Platforms.
func ValidPlatform(p string) bool {
	for _, x := range Platforms {
		if x == p {
			return true
		}
	}
	return false
}

// PlatformOf classifies a host from what its agent reports. Windows agents
// put the product name in OSName ("Windows Server 2022 Standard",
// "Windows 11 Pro"; agents before 0.6.1 may still say "Windows 10" on build
// 22000 and later) and "major.minor.build" in OSVersionID.
func PlatformOf(osID, osName, osVersionID string) string {
	if osID != "windows" {
		return PlatformLinux
	}
	switch {
	case strings.HasPrefix(osName, "Windows Server"):
		return PlatformWindowsServer
	case strings.HasPrefix(osName, "Windows 11"):
		return PlatformWindows11
	case strings.HasPrefix(osName, "Windows 10"):
		parts := strings.Split(osVersionID, ".")
		if b, err := strconv.Atoi(parts[len(parts)-1]); err == nil && len(parts) == 3 && b >= 22000 {
			return PlatformWindows11
		}
		return PlatformWindows10
	}
	return PlatformWindowsOther
}

// Platform is the host's compliance platform (see PlatformOf).
func (h Host) Platform() string { return PlatformOf(h.OSID, h.OSName, h.OSVersionID) }

// ---------- evidence items ----------

// Evidence kinds.
const (
	EvidenceUpdateJob    = "update_job"         // package update or rollback applied on a host
	EvidenceChangeJob    = "change_job"         // other change: reboot, service restart, agent update, preview, check
	EvidenceVulnResolved = "vuln_resolved"      // a finding was resolved (by an update or a newer scan)
	EvidenceAudit        = "audit_event"        // a user or system action from the audit log
	EvidenceDrift        = "drift_detected"     // a host deviated from a server standard
	EvidenceBackup       = "backup_result"      // automatic or manual database backup
	EvidenceInventory    = "inventory_snapshot" // the daily host states of one UTC day
	EvidenceManual       = "manual"             // a document or record entered by a user
)

// EvidenceKinds lists the kinds in display order.
var EvidenceKinds = []string{EvidenceUpdateJob, EvidenceChangeJob, EvidenceVulnResolved, EvidenceAudit, EvidenceDrift,
	EvidenceBackup, EvidenceInventory, EvidenceManual}

// Evidence sources.
const (
	SourceAgent   = "agent"
	SourceScanner = "scanner"
	SourceSystem  = "system"
	SourceUser    = "user"
)

// EvidenceItem is one fact in the evidence repository. Items are never
// changed; SHA256 covers the content and PrevSHA256, the hash of the item
// before it, so a changed or removed item breaks the chain.
type EvidenceItem struct {
	ID          int64
	Kind        string
	Source      string
	SourceRef   string // the source row ("job:12"), unique per kind
	HostID      int64  // 0: not about one host
	Hostname    string
	Platform    string
	Subject     string // CVE, job type, audit action, package ... verbatim
	Actor       string // user email, "schedule:3", "rollout:2", "system"
	Outcome     string
	OccurredAt  time.Time
	CollectedAt time.Time
	Payload     string // JSON object
	SHA256      string
	PrevSHA256  string
}

// PayloadMap decodes the payload (empty map when invalid).
func (e EvidenceItem) PayloadMap() map[string]any {
	m := map[string]any{}
	_ = json.Unmarshal([]byte(e.Payload), &m)
	return m
}

// Retroactive reports whether the item was collected more than a day after
// it happened (taken over from data that existed before collection began).
func (e EvidenceItem) Retroactive() bool {
	return e.CollectedAt.Sub(e.OccurredAt) > 24*time.Hour
}

func cleanText(s string) string { return strings.ReplaceAll(strings.ToValidUTF8(s, "�"), "\x00", "") }

// payloadJSON encodes a payload; map keys are sorted, so equal content
// gives equal text.
func payloadJSON(m map[string]any) string {
	if len(m) == 0 {
		return "{}"
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "{}"
	}
	return cleanText(string(b))
}

// evidenceHash is the chained SHA-256 of an item's stored content.
func evidenceHash(e EvidenceItem) string {
	h := sha256.New()
	fmt.Fprintf(h, "netio.patchman/evidence/v1\n%s\n%s\n%s\n%s\n%d\n%s\n%s\n%s\n%s\n%s\n%d\n%d\n",
		e.PrevSHA256, e.Kind, e.Source, e.SourceRef, e.HostID, e.Hostname, e.Platform, e.Subject, e.Actor, e.Outcome,
		ts(e.OccurredAt), ts(e.CollectedAt))
	h.Write([]byte(e.Payload))
	return hex.EncodeToString(h.Sum(nil))
}

// Settings rows of the evidence repository (not system settings, so a
// configuration reset keeps them).
const (
	keyEvidenceHead   = "compliance.state.chain_head"
	keyEvidencePruned = "compliance.state.pruned_id"
	keyEvidenceStart  = "compliance.state.started_at"
	keyCursorJobs     = "compliance.state.jobs"
	keyCursorFindings = "compliance.state.findings"
	keyCursorAudit    = "compliance.state.audit"
	keyCursorDrift    = "compliance.state.drift"
	keyCursorBackupOK = "compliance.state.backup_ok"
	keyCursorBackupKO = "compliance.state.backup_failed"
	keyCursorDay      = "compliance.state.inventory_day"
)

// AddEvidence appends items that are not stored yet (same kind and source
// reference) to the chain and returns how many it added.
func (s *Store) AddEvidence(ctx context.Context, items []EvidenceItem) (int, error) {
	if len(items) == 0 {
		return 0, nil
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO settings (key, value) VALUES (?, '') ON CONFLICT (key) DO NOTHING`, keyEvidenceHead); err != nil {
		return 0, err
	}
	added := 0
	err := s.tx(ctx, func(tx *Tx) error {
		added = 0
		// The chain head row serializes writers (PostgreSQL row lock; SQLite
		// has a single writer).
		var head string
		if err := tx.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ? FOR UPDATE`, keyEvidenceHead).Scan(&head); err != nil {
			return err
		}
		fresh, err := unseenEvidence(ctx, tx, items)
		if err != nil {
			return err
		}
		if len(fresh) == 0 {
			return nil
		}
		collected := fromTS(now())
		// One statement per row keeps ids in chain order.
		for _, e := range fresh {
			e.CollectedAt = collected
			e.PrevSHA256 = head
			e.SHA256 = evidenceHash(e)
			if _, err := tx.ExecContext(ctx, `INSERT INTO evidence_items (kind, source, source_ref, host_id, hostname, platform, subject, actor, outcome,
				occurred_at, collected_at, payload, sha256, prev_sha256) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				e.Kind, e.Source, e.SourceRef, e.HostID, e.Hostname, e.Platform, e.Subject, e.Actor, e.Outcome,
				ts(e.OccurredAt), ts(e.CollectedAt), e.Payload, e.SHA256, e.PrevSHA256); err != nil {
				return err
			}
			head = e.SHA256
		}
		if _, err := tx.ExecContext(ctx, `UPDATE settings SET value = ? WHERE key = ?`, head, keyEvidenceHead); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT (key) DO NOTHING`,
			keyEvidenceStart, strconv.FormatInt(ts(collected), 10)); err != nil {
			return err
		}
		added = len(fresh)
		return nil
	})
	return added, err
}

// unseenEvidence normalizes items and drops those already stored or
// repeated in the batch.
func unseenEvidence(ctx context.Context, tx *Tx, items []EvidenceItem) ([]EvidenceItem, error) {
	seen := map[[2]string]bool{}
	for start := 0; start < len(items); start += 400 {
		chunk := items[start:min(start+400, len(items))]
		args := make([]any, len(chunk))
		for i, e := range chunk {
			args[i] = e.SourceRef
		}
		rows, err := tx.QueryContext(ctx, `SELECT kind, source_ref FROM evidence_items WHERE source_ref IN (?`+strings.Repeat(",?", len(chunk)-1)+`)`, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var k, ref string
			if err := rows.Scan(&k, &ref); err != nil {
				rows.Close()
				return nil, err
			}
			seen[[2]string{k, ref}] = true
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
	}
	var out []EvidenceItem
	for _, e := range items {
		key := [2]string{e.Kind, e.SourceRef}
		if seen[key] || e.SourceRef == "" {
			continue
		}
		seen[key] = true
		e.Kind, e.Source, e.SourceRef = cleanText(e.Kind), cleanText(e.Source), cleanText(e.SourceRef)
		e.Hostname, e.Platform, e.Subject = cleanText(e.Hostname), cleanText(e.Platform), cleanText(e.Subject)
		e.Actor, e.Outcome = cleanText(e.Actor), cleanText(e.Outcome)
		if e.Payload == "" {
			e.Payload = "{}"
		}
		e.Payload = cleanText(e.Payload)
		out = append(out, e)
	}
	return out, nil
}

const evidenceCols = `id, kind, source, source_ref, host_id, hostname, platform, subject, actor, outcome, occurred_at, collected_at, payload, sha256, prev_sha256`

func scanEvidence(row interface{ Scan(...any) error }) (EvidenceItem, error) {
	var e EvidenceItem
	var occ, col int64
	err := row.Scan(&e.ID, &e.Kind, &e.Source, &e.SourceRef, &e.HostID, &e.Hostname, &e.Platform, &e.Subject, &e.Actor, &e.Outcome,
		&occ, &col, &e.Payload, &e.SHA256, &e.PrevSHA256)
	e.OccurredAt, e.CollectedAt = fromTS(occ), fromTS(col)
	return e, err
}

// EvidenceFilter selects evidence items.
type EvidenceFilter struct {
	Kinds    []string
	From, To time.Time // occurred_at in [From, To); zero = open
	HostID   int64
	Platform string
	Query    string // substring of hostname, subject or actor
	// HostsOnly leaves out items not about a host (audit log, backups),
	// which only administrators see.
	HostsOnly bool
	// VersionID limits to the items a report version used.
	VersionID int64
	Control   string // with VersionID: "profile:control"
}

func (f EvidenceFilter) where(ctx context.Context) (string, []any) {
	var conds []string
	var args []any
	if len(f.Kinds) > 0 {
		conds = append(conds, `e.kind IN (?`+strings.Repeat(",?", len(f.Kinds)-1)+`)`)
		for _, k := range f.Kinds {
			args = append(args, k)
		}
	}
	if !f.From.IsZero() {
		conds, args = append(conds, `e.occurred_at >= ?`), append(args, ts(f.From))
	}
	if !f.To.IsZero() {
		conds, args = append(conds, `e.occurred_at < ?`), append(args, ts(f.To))
	}
	if f.HostID != 0 {
		conds, args = append(conds, `e.host_id = ?`), append(args, f.HostID)
	}
	if f.Platform != "" {
		conds, args = append(conds, `e.platform = ?`), append(args, f.Platform)
	}
	if q := strings.TrimSpace(f.Query); q != "" {
		like := "%" + likeEscape(q) + "%"
		conds = append(conds, `(e.hostname LIKE ? ESCAPE '\' OR e.subject LIKE ? ESCAPE '\' OR e.actor LIKE ? ESCAPE '\')`)
		args = append(args, like, like, like)
	}
	if f.VersionID != 0 {
		c := `e.id IN (SELECT ae.evidence_id FROM assessment_evidence ae WHERE ae.version_id = ?`
		args = append(args, f.VersionID)
		if p, ctl, ok := strings.Cut(f.Control, ":"); ok {
			c += ` AND ae.profile = ? AND ae.control = ?`
			args = append(args, p, ctl)
		}
		conds = append(conds, c+`)`)
	}
	if _, limited := ScopeFrom(ctx); limited || f.HostsOnly {
		conds = append(conds, `e.host_id <> 0`)
	}
	if sc, sa := hostScope(ctx, "e.host_id"); sc != "" {
		conds, args = append(conds, sc), append(args, sa...)
	}
	if len(conds) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

// ListEvidence returns a page of evidence items, newest first.
func (s *Store) ListEvidence(ctx context.Context, f EvidenceFilter, p Page) ([]EvidenceItem, int, error) {
	where, args := f.where(ctx)
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM evidence_items e`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+prefixCols("e.", evidenceCols)+` FROM evidence_items e`+where+` ORDER BY e.occurred_at DESC, e.id DESC LIMIT ? OFFSET ?`,
		append(args, p.Size, p.Offset())...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []EvidenceItem
	for rows.Next() {
		e, err := scanEvidence(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}

// EvidenceItems returns every item matching f, oldest first.
func (s *Store) EvidenceItems(ctx context.Context, f EvidenceFilter) ([]EvidenceItem, error) {
	where, args := f.where(ctx)
	rows, err := s.db.QueryContext(ctx, `SELECT `+prefixCols("e.", evidenceCols)+` FROM evidence_items e`+where+` ORDER BY e.occurred_at, e.id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EvidenceItem
	for rows.Next() {
		e, err := scanEvidence(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// EvidenceByID returns one item (ErrNotFound outside the scope of ctx).
func (s *Store) EvidenceByID(ctx context.Context, id int64) (EvidenceItem, error) {
	where, args := EvidenceFilter{}.where(ctx)
	if where == "" {
		where = " WHERE e.id = ?"
	} else {
		where += " AND e.id = ?"
	}
	e, err := scanEvidence(s.db.QueryRowContext(ctx, `SELECT `+prefixCols("e.", evidenceCols)+` FROM evidence_items e`+where, append(args, id)...))
	if errors.Is(err, sql.ErrNoRows) {
		return e, ErrNotFound
	}
	return e, err
}

// EvidenceUse is a report control an item was used for.
type EvidenceUse struct {
	ReportID  int64
	Title     string
	Version   int
	Status    string
	Profile   string
	Control   string
	Relevance string
}

// EvidenceUses lists the report controls an item was used for, newest first.
func (s *Store) EvidenceUses(ctx context.Context, id int64) ([]EvidenceUse, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT r.id, r.title, v.version, v.status, ae.profile, ae.control, ae.relevance
		FROM assessment_evidence ae JOIN compliance_report_versions v ON v.id = ae.version_id JOIN compliance_reports r ON r.id = v.report_id
		WHERE ae.evidence_id = ? ORDER BY v.id DESC, ae.profile, ae.control`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EvidenceUse
	for rows.Next() {
		var u EvidenceUse
		if err := rows.Scan(&u.ReportID, &u.Title, &u.Version, &u.Status, &u.Profile, &u.Control, &u.Relevance); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// EvidenceStart is when evidence collection began (zero before the first item).
func (s *Store) EvidenceStart(ctx context.Context) (time.Time, error) {
	v, err := s.settingValue(ctx, keyEvidenceStart)
	if err != nil {
		return time.Time{}, err
	}
	n, _ := strconv.ParseInt(v, 10, 64)
	return fromTS(n), nil
}

func (s *Store) settingValue(ctx context.Context, key string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

func (s *Store) setSettingValue(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// ChainStatus is the result of an integrity check of the evidence chain.
type ChainStatus struct {
	Items    int
	OK       bool
	BrokenID int64  // first item that failed
	Reason   string // "content", "link", "head"
	Head     string
	First    time.Time // collection time of the oldest item
	Last     time.Time
}

// VerifyEvidence recomputes every item's hash and checks the links between
// consecutive items and the stored head. Items below the pruning boundary
// (old items kept for final reports) are only checked for content.
func (s *Store) VerifyEvidence(ctx context.Context) (ChainStatus, error) {
	st := ChainStatus{OK: true}
	head, err := s.settingValue(ctx, keyEvidenceHead)
	if err != nil {
		return st, err
	}
	pv, err := s.settingValue(ctx, keyEvidencePruned)
	if err != nil {
		return st, err
	}
	pruned, _ := strconv.ParseInt(pv, 10, 64)
	st.Head = head
	rows, err := s.db.QueryContext(ctx, `SELECT `+evidenceCols+` FROM evidence_items ORDER BY id`)
	if err != nil {
		return st, err
	}
	defer rows.Close()
	prev, linked := "", false
	fail := func(id int64, reason string) {
		if st.OK {
			st.OK, st.BrokenID, st.Reason = false, id, reason
		}
	}
	for rows.Next() {
		e, err := scanEvidence(rows)
		if err != nil {
			return st, err
		}
		st.Items++
		if st.First.IsZero() {
			st.First = e.CollectedAt
		}
		st.Last = e.CollectedAt
		if evidenceHash(e) != e.SHA256 {
			fail(e.ID, "content")
		}
		if e.ID > pruned {
			// The first item above the boundary may follow a pruned one.
			if linked && e.PrevSHA256 != prev {
				fail(e.ID, "link")
			}
			if !linked && pruned == 0 && e.PrevSHA256 != "" {
				fail(e.ID, "link")
			}
			linked = true
		}
		prev = e.SHA256
	}
	if err := rows.Err(); err != nil {
		return st, err
	}
	if prev != head {
		fail(0, "head")
	}
	return st, nil
}

// PruneEvidence removes items collected before now-d, except those a final
// report version uses, and moves the pruning boundary.
func (s *Store) PruneEvidence(ctx context.Context, d time.Duration) error {
	cutoff := now() - int64(d.Seconds())
	var maxID sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `SELECT MAX(id) FROM evidence_items WHERE collected_at < ?`, cutoff).Scan(&maxID); err != nil || !maxID.Valid {
		return err
	}
	return s.tx(ctx, func(tx *Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM evidence_items WHERE id <= ? AND id NOT IN (SELECT ae.evidence_id FROM assessment_evidence ae
			JOIN compliance_report_versions v ON v.id = ae.version_id WHERE v.status = 'final')`, maxID.Int64); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM evidence_host_states WHERE day < ?`, cutoff); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value`,
			keyEvidencePruned, strconv.FormatInt(maxID.Int64, 10))
		return err
	})
}

// ---------- collection ----------

// BackupState is the last backup result (from the backup.* settings).
type BackupState struct {
	LastAt      time.Time
	LastErrorAt time.Time
	LastError   string
}

// CollectEvidence copies new facts from jobs, resolved findings, the audit
// log, drift findings, backups and the daily host states into the evidence
// repository. Each source keeps a cursor; at most limit rows per source are
// read per call. It returns how many items it added.
func (s *Store) CollectEvidence(ctx context.Context, sla SLA, backup BackupState, limit int) (int, error) {
	total := 0
	for _, step := range []func(context.Context, SLA, BackupState, int) ([]EvidenceItem, func() error, error){
		s.jobEvidence, s.findingEvidence, s.auditEvidence, s.driftEvidence, s.backupEvidence, s.inventoryEvidence,
	} {
		items, commit, err := step(ctx, sla, backup, limit)
		if err != nil {
			return total, err
		}
		n, err := s.AddEvidence(ctx, items)
		if err != nil {
			return total, err
		}
		total += n
		if commit != nil {
			if err := commit(); err != nil {
				return total, err
			}
		}
	}
	return total, nil
}

// cursor is a (time, id) position in a source.
type cursor struct{ at, id int64 }

func (s *Store) loadCursor(ctx context.Context, key string) cursor {
	v, _ := s.settingValue(ctx, key)
	a, b, _ := strings.Cut(v, ":")
	at, _ := strconv.ParseInt(a, 10, 64)
	id, _ := strconv.ParseInt(b, 10, 64)
	return cursor{at, id}
}

// nextCursor: a full batch continues exactly after its last row; a partial
// batch rereads the last two minutes next time, so rows committed late with
// an earlier time are not missed (stored ones are skipped).
func (s *Store) nextCursor(ctx context.Context, key string, last cursor, n, limit int) func() error {
	return func() error {
		c := last
		if n < limit {
			c = cursor{max(0, last.at-120), 0}
		}
		return s.setSettingValue(ctx, key, strconv.FormatInt(c.at, 10)+":"+strconv.FormatInt(c.id, 10))
	}
}

func originOf(createdBy int64, email string, scheduleID, rolloutID int64) (origin, actor string) {
	switch {
	case rolloutID != 0:
		return "rollout", "rollout:" + strconv.FormatInt(rolloutID, 10)
	case scheduleID != 0:
		return "schedule", "schedule:" + strconv.FormatInt(scheduleID, 10)
	case createdBy != 0 || email != "":
		return "user", email
	}
	return "system", "system"
}

// updateJob reports whether a job changed packages (or rolled them back).
func updateJob(typ string, params map[string]string) bool {
	switch typ {
	case "upgrade_security", "upgrade_all", "upgrade_packages":
		return true
	case "rollback":
		return params["mode"] == "apply"
	}
	return false
}

func (s *Store) jobEvidence(ctx context.Context, _ SLA, _ BackupState, limit int) ([]EvidenceItem, func() error, error) {
	c := s.loadCursor(ctx, keyCursorJobs)
	rows, err := s.db.QueryContext(ctx, `SELECT j.id, j.host_id, h.hostname, h.os_id, h.os_name, h.os_version_id, j.type, j.packages, j.params, j.status,
		COALESCE(j.created_by, 0), COALESCE(u.email, ''), j.created_at, j.dispatched_at, j.finished_at, j.exit_code, j.remaining, COALESCE(j.schedule_id, 0),
		COALESCE((SELECT MIN(rh.rollout_id) FROM rollout_hosts rh WHERE rh.job_id = j.id), 0)
		FROM jobs j JOIN hosts h ON h.id = j.host_id LEFT JOIN users u ON u.id = j.created_by
		WHERE j.finished_at > 0 AND j.type <> 'refresh' AND (j.finished_at > ? OR (j.finished_at = ? AND j.id > ?))
		ORDER BY j.finished_at, j.id LIMIT ?`, c.at, c.at, c.id, limit)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var out []EvidenceItem
	last := c
	for rows.Next() {
		var id, hostID, createdBy, created, dispatched, finished, scheduleID, rolloutID int64
		var exit int
		var hostname, osID, osName, osVer, typ, pk, params, status, email, remaining string
		if err := rows.Scan(&id, &hostID, &hostname, &osID, &osName, &osVer, &typ, &pk, &params, &status, &createdBy, &email,
			&created, &dispatched, &finished, &exit, &remaining, &scheduleID, &rolloutID); err != nil {
			return nil, nil, err
		}
		last = cursor{finished, id}
		var packages, rem []string
		var pm map[string]string
		_ = json.Unmarshal([]byte(pk), &packages)
		_ = json.Unmarshal([]byte(remaining), &rem)
		_ = json.Unmarshal([]byte(params), &pm)
		origin, actor := originOf(createdBy, email, scheduleID, rolloutID)
		kind := EvidenceChangeJob
		if updateJob(typ, pm) {
			kind = EvidenceUpdateJob
		}
		source := SourceAgent
		if status == "timed_out" || status == "expired" || status == "cancelled" {
			source = SourceSystem
		}
		payload := map[string]any{"job_id": id, "type": typ, "status": status, "exit_code": exit, "origin": origin,
			"package_count": len(packages), "remaining_count": len(rem), "created_at": created, "dispatched_at": dispatched, "finished_at": finished}
		if len(packages) > 0 {
			payload["packages"] = packages[:min(len(packages), 100)]
		}
		if scheduleID != 0 {
			payload["schedule_id"] = scheduleID
		}
		if rolloutID != 0 {
			payload["rollout_id"] = rolloutID
		}
		if pv := pm["preview_job"]; pv != "" {
			payload["approved_preview"] = pv
		}
		if m := pm["mode"]; m != "" && typ == "rollback" {
			payload["mode"] = m
		}
		out = append(out, EvidenceItem{Kind: kind, Source: source, SourceRef: "job:" + strconv.FormatInt(id, 10), HostID: hostID, Hostname: hostname,
			Platform: PlatformOf(osID, osName, osVer), Subject: typ, Actor: actor, Outcome: status, OccurredAt: fromTS(finished), Payload: payloadJSON(payload)})
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	return out, s.nextCursor(ctx, keyCursorJobs, last, len(out), limit), nil
}

func (s *Store) findingEvidence(ctx context.Context, sla SLA, _ BackupState, limit int) ([]EvidenceItem, func() error, error) {
	c := s.loadCursor(ctx, keyCursorFindings)
	rows, err := s.db.QueryContext(ctx, `SELECT f.id, f.host_id, h.hostname, h.os_id, h.os_name, h.os_version_id, f.cve_id, f.package_name,
		COALESCE(v.severity, 'unknown'), f.first_detected_at, f.resolved_at, `+sla.dueSQL("f", "v")+`, COALESCE(k.due_date, ''), CASE WHEN k.cve_id IS NULL THEN 0 ELSE 1 END
		FROM findings f JOIN hosts h ON h.id = f.host_id LEFT JOIN vulnerabilities v ON v.cve_id = f.cve_id LEFT JOIN kev k ON k.cve_id = f.cve_id
		WHERE f.status = 'resolved' AND f.resolved_at > 0 AND (f.resolved_at > ? OR (f.resolved_at = ? AND f.id > ?))
		ORDER BY f.resolved_at, f.id LIMIT ?`, c.at, c.at, c.id, limit)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var out []EvidenceItem
	last := c
	for rows.Next() {
		var id, hostID, detected, resolved, due int64
		var kev int
		var hostname, osID, osName, osVer, cve, pkg, sev, kevDue string
		if err := rows.Scan(&id, &hostID, &hostname, &osID, &osName, &osVer, &cve, &pkg, &sev, &detected, &resolved, &due, &kevDue, &kev); err != nil {
			return nil, nil, err
		}
		last = cursor{resolved, id}
		outcome := "no_sla"
		if due > 0 {
			outcome = "within_sla"
			if resolved > due {
				outcome = "overdue"
			}
		}
		payload := map[string]any{"cve": cve, "package": pkg, "severity": sev, "first_detected_at": detected, "resolved_at": resolved, "due_at": due, "kev": kev == 1}
		if kevDue != "" {
			payload["kev_due"] = kevDue
		}
		out = append(out, EvidenceItem{Kind: EvidenceVulnResolved, Source: SourceScanner,
			SourceRef: "finding:" + strconv.FormatInt(id, 10) + ":" + strconv.FormatInt(resolved, 10), HostID: hostID, Hostname: hostname,
			Platform: PlatformOf(osID, osName, osVer), Subject: cve, Actor: "system", Outcome: outcome, OccurredAt: fromTS(resolved), Payload: payloadJSON(payload)})
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	return out, s.nextCursor(ctx, keyCursorFindings, last, len(out), limit), nil
}

func (s *Store) auditEvidence(ctx context.Context, _ SLA, _ BackupState, limit int) ([]EvidenceItem, func() error, error) {
	c := s.loadCursor(ctx, keyCursorAudit)
	rows, err := s.db.QueryContext(ctx, `SELECT id, at, user_email, action, target, details, ip FROM audit_log WHERE id > ? ORDER BY id LIMIT ?`, c.id, limit)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var out []EvidenceItem
	last := c
	for rows.Next() {
		var id, at int64
		var email, action, target, details, ip string
		if err := rows.Scan(&id, &at, &email, &action, &target, &details, &ip); err != nil {
			return nil, nil, err
		}
		last = cursor{at, id}
		actor := email
		if actor == "" {
			actor = "system"
		}
		outcome := ""
		if strings.HasSuffix(action, "_failed") {
			outcome = "failed"
		}
		out = append(out, EvidenceItem{Kind: EvidenceAudit, Source: SourceSystem, SourceRef: "audit:" + strconv.FormatInt(id, 10),
			Subject: action, Actor: actor, Outcome: outcome, OccurredAt: fromTS(at),
			Payload: payloadJSON(map[string]any{"target": target, "details": details, "ip": ip})})
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	// The audit log only grows, so its cursor is the last id.
	return out, func() error {
		return s.setSettingValue(ctx, keyCursorAudit, strconv.FormatInt(last.at, 10)+":"+strconv.FormatInt(last.id, 10))
	}, nil
}

func (s *Store) driftEvidence(ctx context.Context, _ SLA, _ BackupState, limit int) ([]EvidenceItem, func() error, error) {
	// Cursor "first_seen:host:rule": a deviation is identified by host and rule.
	v, _ := s.settingValue(ctx, keyCursorDrift)
	var at, host, rule int64
	if parts := strings.Split(v, ":"); len(parts) == 3 {
		at, _ = strconv.ParseInt(parts[0], 10, 64)
		host, _ = strconv.ParseInt(parts[1], 10, 64)
		rule, _ = strconv.ParseInt(parts[2], 10, 64)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT d.host_id, h.hostname, h.os_id, h.os_name, h.os_version_id, d.rule_id, r.kind, r.subject_type, r.subject, r.value,
		s.name, d.detail, d.first_seen
		FROM drift_findings d JOIN hosts h ON h.id = d.host_id JOIN standard_rules r ON r.id = d.rule_id JOIN standards s ON s.id = r.standard_id
		WHERE d.first_seen > ? OR (d.first_seen = ? AND (d.host_id > ? OR (d.host_id = ? AND d.rule_id > ?)))
		ORDER BY d.first_seen, d.host_id, d.rule_id LIMIT ?`, at, at, host, host, rule, limit)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var out []EvidenceItem
	lastAt, lastHost, lastRule := at, host, rule
	for rows.Next() {
		var hostID, ruleID, first int64
		var hostname, osID, osName, osVer, kind, subjType, subj, value, std, detail string
		if err := rows.Scan(&hostID, &hostname, &osID, &osName, &osVer, &ruleID, &kind, &subjType, &subj, &value, &std, &detail, &first); err != nil {
			return nil, nil, err
		}
		lastAt, lastHost, lastRule = first, hostID, ruleID
		out = append(out, EvidenceItem{Kind: EvidenceDrift, Source: SourceSystem,
			SourceRef: fmt.Sprintf("drift:%d:%d:%d", hostID, ruleID, first), HostID: hostID, Hostname: hostname,
			Platform: PlatformOf(osID, osName, osVer), Subject: subj, Actor: "system", Outcome: "detected", OccurredAt: fromTS(first),
			Payload: payloadJSON(map[string]any{"standard": std, "rule_kind": kind, "subject_type": subjType, "value": value, "detail": detail})})
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	return out, func() error {
		// As with jobs: a partial batch rereads the last two minutes.
		if len(out) < limit {
			lastAt, lastHost, lastRule = max(0, lastAt-120), 0, 0
		}
		return s.setSettingValue(ctx, keyCursorDrift, fmt.Sprintf("%d:%d:%d", lastAt, lastHost, lastRule))
	}, nil
}

func (s *Store) backupEvidence(ctx context.Context, _ SLA, b BackupState, _ int) ([]EvidenceItem, func() error, error) {
	var out []EvidenceItem
	if !b.LastAt.IsZero() {
		out = append(out, EvidenceItem{Kind: EvidenceBackup, Source: SourceSystem, SourceRef: "backup:ok:" + strconv.FormatInt(ts(b.LastAt), 10),
			Subject: "database", Actor: "system", Outcome: "succeeded", OccurredAt: b.LastAt, Payload: "{}"})
	}
	if !b.LastErrorAt.IsZero() {
		out = append(out, EvidenceItem{Kind: EvidenceBackup, Source: SourceSystem, SourceRef: "backup:failed:" + strconv.FormatInt(ts(b.LastErrorAt), 10),
			Subject: "database", Actor: "system", Outcome: "failed", OccurredAt: b.LastErrorAt,
			Payload: payloadJSON(map[string]any{"error": truncate(b.LastError, 500)})})
	}
	return out, nil, nil
}

// inventoryEvidence seals every finished UTC day of host states with one
// item holding the hash of that day's rows.
func (s *Store) inventoryEvidence(ctx context.Context, _ SLA, _ BackupState, limit int) ([]EvidenceItem, func() error, error) {
	c := s.loadCursor(ctx, keyCursorDay)
	today := DayStart(fromTS(now())).Unix()
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT day FROM evidence_host_states WHERE day > ? AND day < ? ORDER BY day LIMIT ?`, c.at, today, min(limit, 400))
	if err != nil {
		return nil, nil, err
	}
	var days []int64
	for rows.Next() {
		var d int64
		if err := rows.Scan(&d); err != nil {
			rows.Close()
			return nil, nil, err
		}
		days = append(days, d)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, nil, err
	}
	rows.Close()
	var out []EvidenceItem
	for _, d := range days {
		states, err := s.hostStatesOfDay(ctx, d)
		if err != nil {
			return nil, nil, err
		}
		h := sha256.New()
		platforms := map[string]int{}
		for _, st := range states {
			fmt.Fprintf(h, "%d|%s|%s|%s|%s|%s|%s|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%s|%d\n", st.HostID, st.Hostname, st.Platform, st.OSName, st.OSVersion,
				st.AgentVersion, st.GroupIDs, ts(st.LastSeenAt), st.Updates, st.SecurityUpdates, st.Critical, st.High, st.Medium, st.Low,
				st.KEV, st.KEVOverdue, st.SLAOverdue, ts(st.RebootRequiredSince), st.OSEOL, b2i(st.Monitored))
			platforms[st.Platform]++
		}
		pl := map[string]any{}
		for k, v := range platforms {
			pl[k] = v
		}
		out = append(out, EvidenceItem{Kind: EvidenceInventory, Source: SourceSystem, SourceRef: "inventory:" + strconv.FormatInt(d, 10),
			Subject: time.Unix(d, 0).UTC().Format("2006-01-02"), Actor: "system", Outcome: "recorded", OccurredAt: fromTS(d + 86400 - 1),
			Payload: payloadJSON(map[string]any{"day": d, "hosts": len(states), "platforms": pl, "states_sha256": hex.EncodeToString(h.Sum(nil))})})
	}
	last := c
	if len(days) > 0 {
		last.at = days[len(days)-1]
	}
	return out, func() error { return s.setSettingValue(ctx, keyCursorDay, strconv.FormatInt(last.at, 10)+":0") }, nil
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ---------- daily host states ----------

// HostState is a host's state on one UTC day.
type HostState struct {
	Day                 time.Time
	HostID              int64
	Hostname            string
	Platform            string
	OSName              string
	OSVersion           string
	AgentVersion        string
	GroupIDs            string // ",1,4,"
	LastSeenAt          time.Time
	Updates             int
	SecurityUpdates     int
	Critical, High      int
	Medium, Low         int
	KEV                 int
	KEVOverdue          int
	SLAOverdue          int
	RebootRequiredSince time.Time // zero: no reboot pending
	OSEOL               string    // eol.Status* of the operating system, "" without a calendar
	Monitored           bool      // resource usage reported recently
}

// InGroup reports whether the host was a member of the group that day.
func (h HostState) InGroup(id int64) bool {
	return strings.Contains(h.GroupIDs, ","+strconv.FormatInt(id, 10)+",")
}

// TakeHostStates writes the current state of every host as the state of
// at's UTC day (replacing an earlier one of that day). osEOL is the support
// status of each host's operating system.
func (s *Store) TakeHostStates(ctx context.Context, at time.Time, sla SLA, osEOL map[int64]string) error {
	day := DayStart(at).Unix()
	nowTS := at.UTC().Unix()
	todayStr := at.UTC().Format("2006-01-02")
	type agg struct{ crit, high, med, low, kev, kevOver, slaOver int }
	aggs := map[int64]*agg{}
	get := func(id int64) *agg {
		a := aggs[id]
		if a == nil {
			a = &agg{}
			aggs[id] = a
		}
		return a
	}
	rows, err := s.db.QueryContext(ctx, `SELECT f.host_id, COALESCE(v.severity, 'unknown'), COUNT(DISTINCT f.cve_id) FROM findings f
		LEFT JOIN vulnerabilities v ON v.cve_id = f.cve_id WHERE f.status IN `+activeStatuses+` GROUP BY f.host_id, COALESCE(v.severity, 'unknown')`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id int64
		var sev string
		var n int
		if err := rows.Scan(&id, &sev, &n); err != nil {
			rows.Close()
			return err
		}
		a := get(id)
		switch sev {
		case "critical":
			a.crit = n
		case "high":
			a.high = n
		case "medium":
			a.med = n
		case "low":
			a.low = n
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	rows, err = s.db.QueryContext(ctx, `SELECT f.host_id, COUNT(DISTINCT f.cve_id), COUNT(DISTINCT CASE WHEN k.due_date <> '' AND k.due_date < ? THEN f.cve_id END)
		FROM findings f JOIN kev k ON k.cve_id = f.cve_id WHERE f.status IN `+activeStatuses+` GROUP BY f.host_id`, todayStr)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id int64
		var n, over int
		if err := rows.Scan(&id, &n, &over); err != nil {
			rows.Close()
			return err
		}
		a := get(id)
		a.kev, a.kevOver = n, over
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	if sla.Enabled() {
		due := sla.dueSQL("f", "v")
		rows, err = s.db.QueryContext(ctx, `SELECT f.host_id, COUNT(*) FROM findings f LEFT JOIN vulnerabilities v ON v.cve_id = f.cve_id
			WHERE f.status IN `+activeStatuses+` AND `+due+` > 0 AND `+due+` < ? GROUP BY f.host_id`, nowTS)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id int64
			var n int
			if err := rows.Scan(&id, &n); err != nil {
				rows.Close()
				return err
			}
			get(id).slaOver = n
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
	}
	groups := map[int64][]int64{}
	rows, err = s.db.QueryContext(ctx, `SELECT host_id, group_id FROM host_group_members ORDER BY host_id, group_id`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var h, g int64
		if err := rows.Scan(&h, &g); err != nil {
			rows.Close()
			return err
		}
		groups[h] = append(groups[h], g)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	rows, err = s.db.QueryContext(ctx, `SELECT h.id, h.hostname, h.os_id, h.os_name, h.os_version, h.os_version_id, h.agent_version, h.last_seen_at,
		h.reboot_required, h.reboot_required_since, h.resources_at,
		(SELECT COUNT(*) FROM host_updates u WHERE u.host_id = h.id), (SELECT COUNT(*) FROM host_updates u WHERE u.host_id = h.id AND u.security = 1)
		FROM hosts h ORDER BY h.id`)
	if err != nil {
		return err
	}
	var batch [][]any
	for rows.Next() {
		var id, seen, rebootSince, resAt int64
		var reboot, updates, sec int
		var hostname, osID, osName, osVersion, osVerID, agentVer string
		if err := rows.Scan(&id, &hostname, &osID, &osName, &osVersion, &osVerID, &agentVer, &seen, &reboot, &rebootSince, &resAt, &updates, &sec); err != nil {
			rows.Close()
			return err
		}
		a := get(id)
		gids := ""
		if g := groups[id]; len(g) > 0 {
			parts := make([]string, len(g))
			for i, x := range g {
				parts[i] = strconv.FormatInt(x, 10)
			}
			gids = "," + strings.Join(parts, ",") + ","
		}
		since := int64(0)
		if reboot == 1 {
			since = rebootSince
			if since == 0 {
				since = nowTS
			}
		}
		monitored := 0
		if resAt > 0 && nowTS-resAt <= 3600 {
			monitored = 1
		}
		batch = append(batch, []any{day, id, cleanText(hostname), PlatformOf(osID, osName, osVerID), cleanText(osName), cleanText(osVersion), cleanText(agentVer), gids, seen,
			updates, sec, a.crit, a.high, a.med, a.low, a.kev, a.kevOver, a.slaOver, since, osEOL[id], monitored, nowTS})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	if len(batch) == 0 {
		return nil
	}
	return s.tx(ctx, func(tx *Tx) error {
		return insertRows(ctx, tx, `INSERT INTO evidence_host_states (day, host_id, hostname, platform, os_name, os_version, agent_version, group_ids, last_seen_at,
			updates, security_updates, critical, high, medium, low, kev, kev_overdue, sla_overdue, reboot_required_since, os_eol, monitored, taken_at)`,
			`ON CONFLICT (day, host_id) DO UPDATE SET hostname = excluded.hostname, platform = excluded.platform, os_name = excluded.os_name,
			os_version = excluded.os_version, agent_version = excluded.agent_version, group_ids = excluded.group_ids, last_seen_at = excluded.last_seen_at,
			updates = excluded.updates, security_updates = excluded.security_updates, critical = excluded.critical, high = excluded.high,
			medium = excluded.medium, low = excluded.low, kev = excluded.kev, kev_overdue = excluded.kev_overdue, sla_overdue = excluded.sla_overdue,
			reboot_required_since = excluded.reboot_required_since, os_eol = excluded.os_eol, monitored = excluded.monitored, taken_at = excluded.taken_at`,
			22, batch)
	})
}

const hostStateCols = `day, host_id, hostname, platform, os_name, os_version, agent_version, group_ids, last_seen_at, updates, security_updates,
	critical, high, medium, low, kev, kev_overdue, sla_overdue, reboot_required_since, os_eol, monitored`

func scanHostState(row interface{ Scan(...any) error }) (HostState, error) {
	var h HostState
	var day, seen, since int64
	var mon int
	err := row.Scan(&day, &h.HostID, &h.Hostname, &h.Platform, &h.OSName, &h.OSVersion, &h.AgentVersion, &h.GroupIDs, &seen, &h.Updates, &h.SecurityUpdates,
		&h.Critical, &h.High, &h.Medium, &h.Low, &h.KEV, &h.KEVOverdue, &h.SLAOverdue, &since, &h.OSEOL, &mon)
	h.Day, h.LastSeenAt, h.RebootRequiredSince, h.Monitored = fromTS(day), fromTS(seen), fromTS(since), mon == 1
	return h, err
}

func (s *Store) hostStatesOfDay(ctx context.Context, day int64) ([]HostState, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+hostStateCols+` FROM evidence_host_states WHERE day = ? ORDER BY host_id`, day)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HostState
	for rows.Next() {
		h, err := scanHostState(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// HostStates returns the daily states of the UTC days overlapping [from, to),
// optionally only of the current members of a group, oldest first. The
// scope of ctx applies.
func (s *Store) HostStates(ctx context.Context, from, to time.Time, groupID int64) ([]HostState, error) {
	where := ` WHERE day >= ? AND day < ?`
	args := []any{DayStart(from).Unix(), to.UTC().Unix()}
	if groupID != 0 {
		where += ` AND host_id IN (SELECT host_id FROM host_group_members WHERE group_id = ?)`
		args = append(args, groupID)
	}
	where, args = andScope(ctx, where, args, "host_id")
	rows, err := s.db.QueryContext(ctx, `SELECT `+hostStateCols+` FROM evidence_host_states`+where+` ORDER BY day, host_id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HostState
	for rows.Next() {
		h, err := scanHostState(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// prefixCols prefixes every column of a comma separated list.
func prefixCols(p, cols string) string {
	parts := strings.Split(cols, ",")
	for i, c := range parts {
		parts[i] = p + strings.TrimSpace(c)
	}
	return strings.Join(parts, ", ")
}
