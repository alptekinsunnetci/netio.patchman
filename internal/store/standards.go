package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// Standard is a set of software rules for a group (GroupID 0: all hosts).
type Standard struct {
	ID          int64
	Name        string
	Description string
	GroupID     int64
	GroupName   string
	Enabled     bool
	CreatedAt   time.Time
	Rules       []StandardRule
	Deviations  int // hosts x rules currently deviating
}

// StandardRule is one rule (see package drift for the kinds).
type StandardRule struct {
	ID          int64
	StandardID  int64
	Kind        string
	SubjectType string
	Subject     string
	Value       string
}

const standardCols = `s.id, s.name, s.description, COALESCE(s.group_id, 0), COALESCE(g.name, ''), s.enabled, s.created_at`

func scanStandard(row interface{ Scan(...any) error }) (Standard, error) {
	var st Standard
	var enabled int
	var created int64
	err := row.Scan(&st.ID, &st.Name, &st.Description, &st.GroupID, &st.GroupName, &enabled, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return st, ErrNotFound
	}
	st.Enabled, st.CreatedAt = enabled == 1, fromTS(created)
	return st, err
}

// SaveStandard creates (ID 0) or updates a standard and replaces its rules.
func (s *Store) SaveStandard(ctx context.Context, st Standard) (int64, error) {
	id := st.ID
	err := s.tx(ctx, func(tx *Tx) error {
		var group any
		if st.GroupID > 0 {
			group = st.GroupID
		}
		var err error
		if st.ID == 0 {
			id, err = insertID(ctx, tx, `INSERT INTO standards (name, description, group_id, enabled, created_at) VALUES (?, ?, ?, ?, ?)`,
				strings.TrimSpace(st.Name), truncate(st.Description, 500), group, boolInt(st.Enabled), now())
			if err != nil {
				return err
			}
		} else {
			res, err := tx.ExecContext(ctx, `UPDATE standards SET name = ?, description = ?, group_id = ?, enabled = ? WHERE id = ?`,
				strings.TrimSpace(st.Name), truncate(st.Description, 500), group, boolInt(st.Enabled), st.ID)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n == 0 {
				return ErrNotFound
			}
		}
		// Rules that did not change keep their id (and their open deviations).
		keep := map[int64]bool{}
		for _, r := range st.Rules {
			if r.ID > 0 {
				keep[r.ID] = true
			}
		}
		rows, err := tx.QueryContext(ctx, `SELECT id FROM standard_rules WHERE standard_id = ?`, id)
		if err != nil {
			return err
		}
		var drop []int64
		for rows.Next() {
			var rid int64
			if err := rows.Scan(&rid); err != nil {
				rows.Close()
				return err
			}
			if !keep[rid] {
				drop = append(drop, rid)
			}
		}
		rows.Close()
		for _, rid := range drop {
			if _, err := tx.ExecContext(ctx, `DELETE FROM standard_rules WHERE id = ?`, rid); err != nil {
				return err
			}
		}
		for _, r := range st.Rules {
			if r.ID > 0 {
				if _, err := tx.ExecContext(ctx, `UPDATE standard_rules SET kind = ?, subject_type = ?, subject = ?, value = ? WHERE id = ? AND standard_id = ?`,
					r.Kind, r.SubjectType, r.Subject, truncate(r.Value, 500), r.ID, id); err != nil {
					return err
				}
				continue
			}
			if _, err := insertID(ctx, tx, `INSERT INTO standard_rules (standard_id, kind, subject_type, subject, value) VALUES (?, ?, ?, ?, ?)`,
				id, r.Kind, r.SubjectType, r.Subject, truncate(r.Value, 500)); err != nil {
				return err
			}
		}
		return nil
	})
	return id, err
}

// DeleteStandard removes a standard with its rules and deviations.
func (s *Store) DeleteStandard(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM standards WHERE id = ?`, id)
	return err
}

// StandardByID returns a standard with its rules.
func (s *Store) StandardByID(ctx context.Context, id int64) (Standard, error) {
	st, err := scanStandard(s.db.QueryRowContext(ctx, `SELECT `+standardCols+` FROM standards s LEFT JOIN host_groups g ON g.id = s.group_id WHERE s.id = ?`, id))
	if err != nil {
		return st, err
	}
	st.Rules, err = s.standardRules(ctx, ` WHERE standard_id = ?`, id)
	return st, err
}

func (s *Store) standardRules(ctx context.Context, where string, args ...any) ([]StandardRule, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, standard_id, kind, subject_type, subject, value FROM standard_rules`+where+` ORDER BY id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []StandardRule
	for rows.Next() {
		var r StandardRule
		if err := rows.Scan(&r.ID, &r.StandardID, &r.Kind, &r.SubjectType, &r.Subject, &r.Value); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListStandards returns every standard with its rules and deviation count
// (deviations of the hosts the context may see).
func (s *Store) ListStandards(ctx context.Context) ([]Standard, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+standardCols+` FROM standards s LEFT JOIN host_groups g ON g.id = s.group_id ORDER BY lower(s.name), s.id`)
	if err != nil {
		return nil, err
	}
	var out []Standard
	idx := map[int64]int{}
	for rows.Next() {
		st, err := scanStandard(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		idx[st.ID] = len(out)
		out = append(out, st)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rules, err := s.standardRules(ctx, "")
	if err != nil {
		return nil, err
	}
	for _, r := range rules {
		if i, ok := idx[r.StandardID]; ok {
			out[i].Rules = append(out[i].Rules, r)
		}
	}
	where, args := andScope(ctx, "", nil, "d.host_id")
	crow, err := s.db.QueryContext(ctx, `SELECT r.standard_id, COUNT(*) FROM drift_findings d JOIN standard_rules r ON r.id = d.rule_id`+where+` GROUP BY r.standard_id`, args...)
	if err != nil {
		return nil, err
	}
	defer crow.Close()
	for crow.Next() {
		var id int64
		var n int
		if err := crow.Scan(&id, &n); err != nil {
			return nil, err
		}
		if i, ok := idx[id]; ok {
			out[i].Deviations = n
		}
	}
	return out, crow.Err()
}

// DriftHost is a host's data for the standards check (background, no scope).
type DriftHost struct {
	ID             int64
	Hostname       string
	PackageManager string
	Groups         []int64
	Packages       map[string][]string // only packages named by package rules
	Software       []SoftwareItem
}

// DriftInputs returns the enabled standards' rules and every host's facts.
func (s *Store) DriftInputs(ctx context.Context) ([]Standard, []DriftHost, error) {
	all, err := s.ListStandards(ctx)
	if err != nil {
		return nil, nil, err
	}
	var stds []Standard
	names := map[string]bool{}
	for _, st := range all {
		if !st.Enabled || len(st.Rules) == 0 {
			continue
		}
		stds = append(stds, st)
		for _, r := range st.Rules {
			if r.SubjectType == "package" {
				names[r.Subject] = true
			}
		}
	}
	if len(stds) == 0 {
		return nil, nil, nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, hostname, package_manager FROM hosts ORDER BY id`)
	if err != nil {
		return nil, nil, err
	}
	var hosts []DriftHost
	idx := map[int64]int{}
	for rows.Next() {
		var h DriftHost
		if err := rows.Scan(&h.ID, &h.Hostname, &h.PackageManager); err != nil {
			rows.Close()
			return nil, nil, err
		}
		h.Packages = map[string][]string{}
		idx[h.ID] = len(hosts)
		hosts = append(hosts, h)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	host := func(id int64) *DriftHost {
		if i, ok := idx[id]; ok {
			return &hosts[i]
		}
		return nil
	}
	// Group memberships.
	grows, err := s.db.QueryContext(ctx, `SELECT host_id, group_id FROM host_group_members`)
	if err != nil {
		return nil, nil, err
	}
	for grows.Next() {
		var hid, gid int64
		if err := grows.Scan(&hid, &gid); err != nil {
			grows.Close()
			return nil, nil, err
		}
		if h := host(hid); h != nil {
			h.Groups = append(h.Groups, gid)
		}
	}
	grows.Close()
	if err := grows.Err(); err != nil {
		return nil, nil, err
	}
	// Packages named by package rules.
	if len(names) > 0 {
		args := make([]any, 0, len(names))
		for n := range names {
			args = append(args, n)
		}
		prows, err := s.db.QueryContext(ctx, `SELECT host_id, name, version FROM host_packages WHERE name IN `+inList(len(args)), args...)
		if err != nil {
			return nil, nil, err
		}
		for prows.Next() {
			var hid int64
			var name, ver string
			if err := prows.Scan(&hid, &name, &ver); err != nil {
				prows.Close()
				return nil, nil, err
			}
			if h := host(hid); h != nil {
				h.Packages[name] = append(h.Packages[name], ver)
			}
		}
		prows.Close()
		if err := prows.Err(); err != nil {
			return nil, nil, err
		}
	}
	srows, err := s.db.QueryContext(ctx, `SELECT host_id, software, cycle, version, package, package_version, running, service FROM host_software ORDER BY host_id, software, cycle`)
	if err != nil {
		return nil, nil, err
	}
	defer srows.Close()
	for srows.Next() {
		var hid int64
		var it SoftwareItem
		if err := srows.Scan(&hid, &it.Software, &it.Cycle, &it.Version, &it.Package, &it.PackageVersion, &it.Running, &it.Service); err != nil {
			return nil, nil, err
		}
		if h := host(hid); h != nil {
			h.Software = append(h.Software, it)
		}
	}
	if err := srows.Err(); err != nil {
		return nil, nil, err
	}
	return stds, hosts, nil
}

// DriftKey names one deviation.
type DriftKey struct {
	HostID, RuleID int64
}

// NewDrift is a deviation seen for the first time.
type NewDrift struct {
	HostID   int64
	Hostname string
	RuleID   int64
	Standard string
}

// SyncDrift replaces the stored deviations with found (host, rule ->
// observed value) and returns the new ones.
func (s *Store) SyncDrift(ctx context.Context, found map[DriftKey]string) ([]DriftKey, error) {
	var fresh []DriftKey
	err := s.tx(ctx, func(tx *Tx) error {
		fresh = nil
		existing := map[DriftKey]string{}
		rows, err := tx.QueryContext(ctx, `SELECT host_id, rule_id, detail FROM drift_findings`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var k DriftKey
			var d string
			if err := rows.Scan(&k.HostID, &k.RuleID, &d); err != nil {
				rows.Close()
				return err
			}
			existing[k] = d
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		n := now()
		var insert [][]any
		for k, d := range found {
			old, ok := existing[k]
			switch {
			case !ok:
				fresh = append(fresh, k)
				insert = append(insert, []any{k.HostID, k.RuleID, truncate(d, 500), n})
			case old != d:
				if _, err := tx.ExecContext(ctx, `UPDATE drift_findings SET detail = ? WHERE host_id = ? AND rule_id = ?`, truncate(d, 500), k.HostID, k.RuleID); err != nil {
					return err
				}
			}
		}
		for k := range existing {
			if _, ok := found[k]; !ok {
				if _, err := tx.ExecContext(ctx, `DELETE FROM drift_findings WHERE host_id = ? AND rule_id = ?`, k.HostID, k.RuleID); err != nil {
					return err
				}
			}
		}
		return insertRows(ctx, tx, `INSERT INTO drift_findings (host_id, rule_id, detail, first_seen)`, "", 4, insert)
	})
	return fresh, err
}

// DriftRow is a deviation on the report.
type DriftRow struct {
	HostID      int64
	Hostname    string
	StandardID  int64
	Standard    string
	Rule        StandardRule
	Found       string
	FirstSeen   time.Time
	HasUpdate   bool   // a pending update exists for the rule's package
	UpdateName  string // the package to upgrade
	RemoteJobOK bool   // remote updates are on for the host
}

// DriftFilter narrows the deviation list.
type DriftFilter struct {
	StandardID, HostID, GroupID int64
}

// ListDrift returns current deviations of the hosts the context may see.
func (s *Store) ListDrift(ctx context.Context, f DriftFilter, p Page) ([]DriftRow, int, error) {
	var conds []string
	var args []any
	if f.StandardID > 0 {
		conds = append(conds, `r.standard_id = ?`)
		args = append(args, f.StandardID)
	}
	if f.HostID > 0 {
		conds = append(conds, `d.host_id = ?`)
		args = append(args, f.HostID)
	}
	if f.GroupID > 0 {
		conds = append(conds, `d.host_id IN (SELECT host_id FROM host_group_members WHERE group_id = ?)`)
		args = append(args, f.GroupID)
	}
	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}
	where, args = andScope(ctx, where, args, "d.host_id")
	from := ` FROM drift_findings d JOIN standard_rules r ON r.id = d.rule_id JOIN standards st ON st.id = r.standard_id JOIN hosts h ON h.id = d.host_id`
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*)`+from+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT d.host_id, h.hostname, st.id, st.name, r.id, r.kind, r.subject_type, r.subject, r.value, d.detail, d.first_seen, h.remote_updates,
		(SELECT COUNT(*) FROM host_updates u WHERE u.host_id = d.host_id AND u.name = r.subject),
		(SELECT MIN(s2.package) FROM host_software s2 JOIN host_updates u2 ON u2.host_id = s2.host_id AND u2.name = s2.package WHERE s2.host_id = d.host_id AND s2.software = r.subject)`+
		from+where+` ORDER BY lower(h.hostname), h.hostname, st.name, r.id LIMIT ? OFFSET ?`, append(args, p.limit(), p.Offset())...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []DriftRow
	for rows.Next() {
		var d DriftRow
		var first int64
		var remote, pkgUpd int
		var swUpd sql.NullString
		if err := rows.Scan(&d.HostID, &d.Hostname, &d.StandardID, &d.Standard, &d.Rule.ID, &d.Rule.Kind, &d.Rule.SubjectType, &d.Rule.Subject, &d.Rule.Value,
			&d.Found, &first, &remote, &pkgUpd, &swUpd); err != nil {
			return nil, 0, err
		}
		d.FirstSeen, d.RemoteJobOK = fromTS(first), remote == 1
		switch {
		case d.Rule.SubjectType == "package" && pkgUpd > 0:
			d.HasUpdate, d.UpdateName = true, d.Rule.Subject
		case d.Rule.SubjectType == "software" && swUpd.Valid:
			d.HasUpdate, d.UpdateName = true, swUpd.String
		}
		out = append(out, d)
	}
	return out, total, rows.Err()
}
