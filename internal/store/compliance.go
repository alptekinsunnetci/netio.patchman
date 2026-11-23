package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
)

// Report version states.
const (
	ReportDraft = "draft"
	ReportFinal = "final"
)

// Review states of a control assessment.
const (
	ReviewNone     = "not_reviewed"
	ReviewAccepted = "accepted"
	ReviewGap      = "gap"
)

// ErrReportFinal is returned when a final version would change.
var ErrReportFinal = errors.New("report version is final")

// ComplianceReport is a report definition; its content lives in versions.
type ComplianceReport struct {
	ID          int64
	Title       string
	Profiles    []string // "isms@1"
	From, To    time.Time
	GroupID     int64 // 0: all hosts
	Platforms   []string
	Note        string
	CreatedByID int64
	CreatedBy   string
	CreatedAt   time.Time
	// Filled by lists.
	Versions      int
	LatestVersion int
	LatestStatus  string
	LatestAt      time.Time
	HasFinal      bool
}

type reportScope struct {
	Group     int64    `json:"group,omitempty"`
	Platforms []string `json:"platforms,omitempty"`
}

// CreateComplianceReport stores a report definition.
func (s *Store) CreateComplianceReport(ctx context.Context, r ComplianceReport) (int64, error) {
	prof, _ := json.Marshal(nonNil(r.Profiles))
	scope, _ := json.Marshal(reportScope{Group: r.GroupID, Platforms: r.Platforms})
	var by any
	if r.CreatedByID != 0 {
		by = r.CreatedByID
	}
	return insertID(ctx, s.db, `INSERT INTO compliance_reports (title, profiles, period_from, period_to, scope, note, created_by, created_by_email, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, cleanText(r.Title), string(prof), ts(r.From), ts(r.To), string(scope), cleanText(r.Note), by, r.CreatedBy, now())
}

const reportCols = `r.id, r.title, r.profiles, r.period_from, r.period_to, r.scope, r.note, COALESCE(r.created_by, 0), r.created_by_email, r.created_at,
	(SELECT COUNT(*) FROM compliance_report_versions v WHERE v.report_id = r.id),
	COALESCE((SELECT MAX(v.version) FROM compliance_report_versions v WHERE v.report_id = r.id), 0),
	(SELECT COUNT(*) FROM compliance_report_versions v WHERE v.report_id = r.id AND v.status = 'final')`

func scanReport(row interface{ Scan(...any) error }) (ComplianceReport, error) {
	var r ComplianceReport
	var prof, scope string
	var from, to, created int64
	var finals int
	err := row.Scan(&r.ID, &r.Title, &prof, &from, &to, &scope, &r.Note, &r.CreatedByID, &r.CreatedBy, &created, &r.Versions, &r.LatestVersion, &finals)
	if err != nil {
		return r, err
	}
	_ = json.Unmarshal([]byte(prof), &r.Profiles)
	var sc reportScope
	_ = json.Unmarshal([]byte(scope), &sc)
	r.GroupID, r.Platforms = sc.Group, sc.Platforms
	r.From, r.To, r.CreatedAt, r.HasFinal = fromTS(from), fromTS(to), fromTS(created), finals > 0
	return r, nil
}

func (s *Store) fillLatest(ctx context.Context, r *ComplianceReport) error {
	if r.LatestVersion == 0 {
		return nil
	}
	var at int64
	err := s.db.QueryRowContext(ctx, `SELECT status, generated_at FROM compliance_report_versions WHERE report_id = ? AND version = ?`, r.ID, r.LatestVersion).
		Scan(&r.LatestStatus, &at)
	r.LatestAt = fromTS(at)
	return err
}

// ListComplianceReports returns all reports, newest first.
func (s *Store) ListComplianceReports(ctx context.Context) ([]ComplianceReport, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+reportCols+` FROM compliance_reports r ORDER BY r.id DESC`)
	if err != nil {
		return nil, err
	}
	var out []ComplianceReport
	for rows.Next() {
		r, err := scanReport(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	for i := range out {
		if err := s.fillLatest(ctx, &out[i]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// ComplianceReportByID returns one report.
func (s *Store) ComplianceReportByID(ctx context.Context, id int64) (ComplianceReport, error) {
	r, err := scanReport(s.db.QueryRowContext(ctx, `SELECT `+reportCols+` FROM compliance_reports r WHERE r.id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrNotFound
	}
	if err != nil {
		return r, err
	}
	return r, s.fillLatest(ctx, &r)
}

// DeleteComplianceReport removes a report that has no final version.
func (s *Store) DeleteComplianceReport(ctx context.Context, id int64) error {
	return s.tx(ctx, func(tx *Tx) error {
		var finals int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM compliance_report_versions WHERE report_id = ? AND status = 'final'`, id).Scan(&finals); err != nil {
			return err
		}
		if finals > 0 {
			return ErrReportFinal
		}
		res, err := tx.ExecContext(ctx, `DELETE FROM compliance_reports WHERE id = ?`, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// ReportVersion is one generated version of a report.
type ReportVersion struct {
	ID          int64
	ReportID    int64
	Version     int
	Status      string
	GeneratedAt time.Time
	GeneratedBy string
	Engine      string
	Content     string // report model (JSON); empty in lists
	SHA256      string
	FinalizedAt time.Time
	FinalizedBy string
	FinalSHA256 string
	// ReportTitle is filled by AllReportVersions.
	ReportTitle string
}

// Final reports whether the version can no longer change.
func (v ReportVersion) Final() bool { return v.Status == ReportFinal }

// ControlAssessment is the result for one control of a version: the
// automated outcome and the manual review, kept apart.
type ControlAssessment struct {
	Profile      string
	Control      string
	Outcome      string
	Applicable   bool
	ReviewStatus string
	ReviewNote   string
	ReviewedBy   string
	ReviewedAt   time.Time
}

// AssessmentEvidence maps an evidence item to a control of a version.
type AssessmentEvidence struct {
	Profile    string
	Control    string
	EvidenceID int64
	Relevance  string
}

// AddReportVersion stores a new draft version with its assessments and
// evidence mapping and returns its number and id.
func (s *Store) AddReportVersion(ctx context.Context, v ReportVersion, assessments []ControlAssessment, mapping []AssessmentEvidence) (int, int64, error) {
	var number int
	var id int64
	err := s.tx(ctx, func(tx *Tx) error {
		number, id = 0, 0
		// Locks the report so two generations do not get the same number.
		var rid int64
		if err := tx.QueryRowContext(ctx, `SELECT id FROM compliance_reports WHERE id = ? FOR UPDATE`, v.ReportID).Scan(&rid); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) + 1 FROM compliance_report_versions WHERE report_id = ?`, v.ReportID).Scan(&number); err != nil {
			return err
		}
		var err error
		id, err = insertID(ctx, tx, `INSERT INTO compliance_report_versions (report_id, version, status, generated_at, generated_by, engine, content, sha256)
			VALUES (?, ?, 'draft', ?, ?, ?, ?, ?)`, v.ReportID, number, ts(v.GeneratedAt), v.GeneratedBy, v.Engine, v.Content, v.SHA256)
		if err != nil {
			return err
		}
		rows := make([][]any, len(assessments))
		for i, a := range assessments {
			rs := a.ReviewStatus
			if rs == "" {
				rs = ReviewNone
			}
			rows[i] = []any{id, a.Profile, a.Control, a.Outcome, b2i(a.Applicable), rs, cleanText(a.ReviewNote), a.ReviewedBy, ts(a.ReviewedAt)}
		}
		if err := insertRows(ctx, tx, `INSERT INTO control_assessments (version_id, profile, control, outcome, applicable, review_status, review_note, reviewed_by, reviewed_at)`,
			"", 9, rows); err != nil {
			return err
		}
		seen := map[AssessmentEvidence]bool{}
		mrows := make([][]any, 0, len(mapping))
		for _, m := range mapping {
			k := AssessmentEvidence{Profile: m.Profile, Control: m.Control, EvidenceID: m.EvidenceID}
			if seen[k] {
				continue
			}
			seen[k] = true
			mrows = append(mrows, []any{id, m.Profile, m.Control, m.EvidenceID, m.Relevance})
		}
		return insertRows(ctx, tx, `INSERT INTO assessment_evidence (version_id, profile, control, evidence_id, relevance)`, "", 5, mrows)
	})
	return number, id, err
}

const versionCols = `v.id, v.report_id, v.version, v.status, v.generated_at, v.generated_by, v.engine, v.sha256, v.finalized_at, v.finalized_by, v.final_sha256`

func scanVersion(row interface{ Scan(...any) error }, extra ...any) (ReportVersion, error) {
	var v ReportVersion
	var gen, fin int64
	dest := append([]any{&v.ID, &v.ReportID, &v.Version, &v.Status, &gen, &v.GeneratedBy, &v.Engine, &v.SHA256, &fin, &v.FinalizedBy, &v.FinalSHA256}, extra...)
	err := row.Scan(dest...)
	v.GeneratedAt, v.FinalizedAt = fromTS(gen), fromTS(fin)
	return v, err
}

// ReportVersions lists a report's versions (without content), newest first.
func (s *Store) ReportVersions(ctx context.Context, reportID int64) ([]ReportVersion, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+versionCols+` FROM compliance_report_versions v WHERE v.report_id = ? ORDER BY v.version DESC`, reportID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ReportVersion
	for rows.Next() {
		v, err := scanVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// AllReportVersions lists the versions of every report, newest first.
func (s *Store) AllReportVersions(ctx context.Context, p Page) ([]ReportVersion, int, error) {
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM compliance_report_versions`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+versionCols+`, r.title FROM compliance_report_versions v JOIN compliance_reports r ON r.id = v.report_id
		ORDER BY v.generated_at DESC, v.id DESC LIMIT ? OFFSET ?`, p.Size, p.Offset())
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []ReportVersion
	for rows.Next() {
		var title string
		v, err := scanVersion(rows, &title)
		if err != nil {
			return nil, 0, err
		}
		v.ReportTitle = title
		out = append(out, v)
	}
	return out, total, rows.Err()
}

// ReportVersionByNumber returns a version with its content.
func (s *Store) ReportVersionByNumber(ctx context.Context, reportID int64, number int) (ReportVersion, error) {
	var content string
	v, err := scanVersion(s.db.QueryRowContext(ctx, `SELECT `+versionCols+`, v.content FROM compliance_report_versions v WHERE v.report_id = ? AND v.version = ?`,
		reportID, number), &content)
	if errors.Is(err, sql.ErrNoRows) {
		return v, ErrNotFound
	}
	v.Content = content
	return v, err
}

// ControlAssessments returns the assessments of a version.
func (s *Store) ControlAssessments(ctx context.Context, versionID int64) ([]ControlAssessment, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT profile, control, outcome, applicable, review_status, review_note, reviewed_by, reviewed_at
		FROM control_assessments WHERE version_id = ? ORDER BY profile, control`, versionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ControlAssessment
	for rows.Next() {
		var a ControlAssessment
		var app int
		var at int64
		if err := rows.Scan(&a.Profile, &a.Control, &a.Outcome, &app, &a.ReviewStatus, &a.ReviewNote, &a.ReviewedBy, &at); err != nil {
			return nil, err
		}
		a.Applicable, a.ReviewedAt = app == 1, fromTS(at)
		out = append(out, a)
	}
	return out, rows.Err()
}

// VersionEvidenceCounts counts the distinct evidence items per control of
// a version ("profile:control" -> n) and in total.
func (s *Store) VersionEvidenceCounts(ctx context.Context, versionID int64) (map[string]int, int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT profile, control, COUNT(*) FROM assessment_evidence WHERE version_id = ? GROUP BY profile, control`, versionID)
	if err != nil {
		return nil, 0, err
	}
	out := map[string]int{}
	for rows.Next() {
		var p, c string
		var n int
		if err := rows.Scan(&p, &c, &n); err != nil {
			rows.Close()
			return nil, 0, err
		}
		out[p+":"+c] = n
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, 0, err
	}
	rows.Close()
	var total int
	err = s.db.QueryRowContext(ctx, `SELECT COUNT(DISTINCT evidence_id) FROM assessment_evidence WHERE version_id = ?`, versionID).Scan(&total)
	return out, total, err
}

// VersionEvidenceControls maps every evidence item of a version to the
// controls ("profile:control") it was used for.
func (s *Store) VersionEvidenceControls(ctx context.Context, versionID int64) (map[int64][]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT evidence_id, profile, control FROM assessment_evidence WHERE version_id = ? ORDER BY evidence_id, profile, control`, versionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64][]string{}
	for rows.Next() {
		var id int64
		var p, c string
		if err := rows.Scan(&id, &p, &c); err != nil {
			return nil, err
		}
		out[id] = append(out[id], p+":"+c)
	}
	return out, rows.Err()
}

func (s *Store) draftVersion(ctx context.Context, tx *Tx, versionID int64) error {
	var status string
	err := tx.QueryRowContext(ctx, `SELECT status FROM compliance_report_versions WHERE id = ? FOR UPDATE`, versionID).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if status != ReportDraft {
		return ErrReportFinal
	}
	return nil
}

// ReviewControl records the manual review of a control on a draft version.
func (s *Store) ReviewControl(ctx context.Context, versionID int64, profile, control, status, note, by string) error {
	switch status {
	case ReviewNone, ReviewAccepted, ReviewGap:
	default:
		return errors.New("invalid review status")
	}
	return s.tx(ctx, func(tx *Tx) error {
		if err := s.draftVersion(ctx, tx, versionID); err != nil {
			return err
		}
		at := now()
		if status == ReviewNone {
			by, at = "", 0
		}
		res, err := tx.ExecContext(ctx, `UPDATE control_assessments SET review_status = ?, review_note = ?, reviewed_by = ?, reviewed_at = ?
			WHERE version_id = ? AND profile = ? AND control = ?`, status, truncate(cleanText(strings.TrimSpace(note)), 2000), by, at, versionID, profile, control)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// FinalizeVersion makes a draft version final; finalSHA covers its content
// and reviews.
func (s *Store) FinalizeVersion(ctx context.Context, versionID int64, by, finalSHA string) error {
	return s.tx(ctx, func(tx *Tx) error {
		if err := s.draftVersion(ctx, tx, versionID); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE compliance_report_versions SET status = 'final', finalized_at = ?, finalized_by = ?, final_sha256 = ? WHERE id = ?`,
			now(), by, finalSHA, versionID)
		return err
	})
}

// ControlSetting is the applicability of a control in this installation.
type ControlSetting struct {
	Profile       string
	Control       string
	Applicable    bool
	Justification string
	UpdatedBy     string
	UpdatedAt     time.Time
}

// ControlSettings returns the stored settings by "profile:control".
func (s *Store) ControlSettings(ctx context.Context) (map[string]ControlSetting, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT profile, control, applicable, justification, updated_by, updated_at FROM compliance_control_settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]ControlSetting{}
	for rows.Next() {
		var c ControlSetting
		var app int
		var at int64
		if err := rows.Scan(&c.Profile, &c.Control, &app, &c.Justification, &c.UpdatedBy, &at); err != nil {
			return nil, err
		}
		c.Applicable, c.UpdatedAt = app == 1, fromTS(at)
		out[c.Profile+":"+c.Control] = c
	}
	return out, rows.Err()
}

// SaveControlSetting stores the applicability of a control.
func (s *Store) SaveControlSetting(ctx context.Context, c ControlSetting) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO compliance_control_settings (profile, control, applicable, justification, updated_by, updated_at)
		VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (profile, control) DO UPDATE SET applicable = excluded.applicable,
		justification = excluded.justification, updated_by = excluded.updated_by, updated_at = excluded.updated_at`,
		c.Profile, c.Control, b2i(c.Applicable), truncate(cleanText(strings.TrimSpace(c.Justification)), 1000), c.UpdatedBy, now())
	return err
}

// EvidenceKindCounts counts the stored evidence items by kind.
func (s *Store) EvidenceKindCounts(ctx context.Context) (map[string]int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT kind, COUNT(*) FROM evidence_items GROUP BY kind`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			return nil, err
		}
		out[k] = n
	}
	return out, rows.Err()
}

// ---------- live facts used by the compliance checks ----------

func idList(col string, ids []int64) (string, []any) {
	if len(ids) == 0 {
		return "1 = 0", nil
	}
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	return col + ` IN (?` + strings.Repeat(",?", len(ids)-1) + `)`, args
}

// RiskStats summarizes the currently accepted risks of some hosts.
type RiskStats struct {
	Accepted  int
	NoExpiry  int
	NoNote    int
	Expiring  int // within 30 days
	HostCount int
}

// AcceptedRiskStats summarizes accepted risks on the given hosts.
func (s *Store) AcceptedRiskStats(ctx context.Context, hostIDs []int64) (RiskStats, error) {
	var r RiskStats
	cond, args := idList("host_id", hostIDs)
	soon := now() + 30*86400
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*), COUNT(CASE WHEN status_expires_at = 0 THEN 1 END), COUNT(CASE WHEN status_note = '' THEN 1 END),
		COUNT(CASE WHEN status_expires_at > 0 AND status_expires_at < ? THEN 1 END), COUNT(DISTINCT host_id)
		FROM findings WHERE status = 'accepted_risk' AND `+cond, append([]any{soon}, args...)...).Scan(&r.Accepted, &r.NoExpiry, &r.NoNote, &r.Expiring, &r.HostCount)
	return r, err
}

// DriftStats counts the server standards and the open deviations of some hosts.
func (s *Store) DriftStats(ctx context.Context, hostIDs []int64) (standards, deviations, hosts int, err error) {
	if err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM standards WHERE enabled = 1`).Scan(&standards); err != nil {
		return
	}
	cond, args := idList("host_id", hostIDs)
	err = s.db.QueryRowContext(ctx, `SELECT COUNT(*), COUNT(DISTINCT host_id) FROM drift_findings WHERE `+cond, args...).Scan(&deviations, &hosts)
	return
}

// AdminMFAStats counts active administrators and those without an authenticator.
func (s *Store) AdminMFAStats(ctx context.Context) (admins, withoutMFA int, err error) {
	err = s.db.QueryRowContext(ctx, `SELECT COUNT(*), COUNT(CASE WHEN totp_secret = '' THEN 1 END) FROM users WHERE role = 'admin' AND disabled = 0`).
		Scan(&admins, &withoutMFA)
	return
}

// ReportVisibleTo reports whether a group-limited user may see a report:
// it must cover one of the user's groups.
func ReportVisibleTo(r ComplianceReport, groupIDs []int64, limited bool) bool {
	if !limited {
		return true
	}
	for _, g := range groupIDs {
		if g == r.GroupID && g != 0 {
			return true
		}
	}
	return false
}

// FormatProfileKey joins a profile and a control ("isms@1", "ISMS-01").
func FormatProfileKey(profile, control string) string { return profile + ":" + control }

// ParseInt64s parses ids from strings, skipping invalid ones.
func ParseInt64s(vals []string) []int64 {
	var out []int64
	for _, v := range vals {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			out = append(out, n)
		}
	}
	return out
}
