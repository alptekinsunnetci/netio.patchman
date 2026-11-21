package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// HostGroup is a named set of hosts (for example "üretim" or "veritabanı").
// A host can belong to several groups.
type HostGroup struct {
	ID          int64
	Name        string
	Description string
	CreatedAt   time.Time
	HostCount   int
}

// GroupRef is a group as shown next to a host.
type GroupRef struct {
	ID   int64
	Name string
}

// MaxGroupName is the longest accepted group name in characters.
const MaxGroupName = 60

// ListGroups returns all groups with their member counts, ordered by name.
func (s *Store) ListGroups(ctx context.Context) ([]HostGroup, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT g.id, g.name, g.description, g.created_at,
		(SELECT COUNT(*) FROM host_group_members m WHERE m.group_id = g.id)
		FROM host_groups g ORDER BY g.name COLLATE NOCASE`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HostGroup
	for rows.Next() {
		var g HostGroup
		var c int64
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &c, &g.HostCount); err != nil {
			return nil, err
		}
		g.CreatedAt = fromTS(c)
		out = append(out, g)
	}
	return out, rows.Err()
}

// GroupByID returns a group with its member count.
func (s *Store) GroupByID(ctx context.Context, id int64) (HostGroup, error) {
	var g HostGroup
	var c int64
	err := s.db.QueryRowContext(ctx, `SELECT g.id, g.name, g.description, g.created_at,
		(SELECT COUNT(*) FROM host_group_members m WHERE m.group_id = g.id)
		FROM host_groups g WHERE g.id = ?`, id).Scan(&g.ID, &g.Name, &g.Description, &c, &g.HostCount)
	if errors.Is(err, sql.ErrNoRows) {
		return g, ErrNotFound
	}
	g.CreatedAt = fromTS(c)
	return g, err
}

func uniqueErr(err error) error {
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return ErrDuplicate
	}
	return err
}

// nameTaken reports whether another group has the name. SQLite's NOCASE
// folds ASCII only, so "Üretim" and "üretim" are compared here.
func (s *Store) nameTaken(ctx context.Context, name string, exceptID int64) (bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name FROM host_groups`)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var n string
		if err := rows.Scan(&id, &n); err != nil {
			return false, err
		}
		if id != exceptID && strings.EqualFold(n, strings.TrimSpace(name)) {
			return true, nil
		}
	}
	return false, rows.Err()
}

// CreateGroup stores a new group.
func (s *Store) CreateGroup(ctx context.Context, name, description string) (int64, error) {
	if taken, err := s.nameTaken(ctx, name, 0); err != nil || taken {
		if taken {
			return 0, ErrDuplicate
		}
		return 0, err
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO host_groups (name, description, created_at) VALUES (?, ?, ?)`,
		strings.TrimSpace(name), truncate(strings.TrimSpace(description), 500), now())
	if err != nil {
		return 0, uniqueErr(err)
	}
	return res.LastInsertId()
}

// UpdateGroup renames a group or changes its description.
func (s *Store) UpdateGroup(ctx context.Context, id int64, name, description string) error {
	if taken, err := s.nameTaken(ctx, name, id); err != nil || taken {
		if taken {
			return ErrDuplicate
		}
		return err
	}
	res, err := s.db.ExecContext(ctx, `UPDATE host_groups SET name = ?, description = ? WHERE id = ?`,
		strings.TrimSpace(name), truncate(strings.TrimSpace(description), 500), id)
	if err != nil {
		return uniqueErr(err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteGroup removes a group. Schedules that targeted it are disabled and
// switched to an empty host selection, so they never fall back to every host.
func (s *Store) DeleteGroup(ctx context.Context, id int64) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE schedules SET enabled = 0, next_run_at = 0, target = 'hosts', group_id = NULL, updated_at = ? WHERE group_id = ?`, now(), id); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `DELETE FROM host_groups WHERE id = ?`, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// AddHostsToGroup adds hosts to a group and returns how many were added.
func (s *Store) AddHostsToGroup(ctx context.Context, groupID int64, hostIDs []int64) (int, error) {
	added := 0
	err := s.tx(ctx, func(tx *sql.Tx) error {
		for _, h := range hostIDs {
			res, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO host_group_members (group_id, host_id)
				SELECT ?, id FROM hosts WHERE id = ? AND EXISTS (SELECT 1 FROM host_groups WHERE id = ?)`, groupID, h, groupID)
			if err != nil {
				return err
			}
			n, _ := res.RowsAffected()
			added += int(n)
		}
		return nil
	})
	return added, err
}

// RemoveHostsFromGroup removes hosts from a group and returns how many were removed.
func (s *Store) RemoveHostsFromGroup(ctx context.Context, groupID int64, hostIDs []int64) (int, error) {
	removed := 0
	err := s.tx(ctx, func(tx *sql.Tx) error {
		for _, h := range hostIDs {
			res, err := tx.ExecContext(ctx, `DELETE FROM host_group_members WHERE group_id = ? AND host_id = ?`, groupID, h)
			if err != nil {
				return err
			}
			n, _ := res.RowsAffected()
			removed += int(n)
		}
		return nil
	})
	return removed, err
}

// SetHostGroups replaces the groups of one host.
func (s *Store) SetHostGroups(ctx context.Context, hostID int64, groupIDs []int64) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM host_group_members WHERE host_id = ?`, hostID); err != nil {
			return err
		}
		for _, g := range groupIDs {
			if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO host_group_members (group_id, host_id)
				SELECT id, ? FROM host_groups WHERE id = ?`, hostID, g); err != nil {
				return err
			}
		}
		return nil
	})
}

// fillGroups sets Groups on each host with one query.
func (s *Store) fillGroups(ctx context.Context, hosts []Host) error {
	if len(hosts) == 0 {
		return nil
	}
	idx := make(map[int64]int, len(hosts))
	args := make([]any, 0, len(hosts))
	marks := make([]string, 0, len(hosts))
	for i, h := range hosts {
		idx[h.ID] = i
		args = append(args, h.ID)
		marks = append(marks, "?")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT m.host_id, g.id, g.name FROM host_group_members m JOIN host_groups g ON g.id = m.group_id
		WHERE m.host_id IN (`+strings.Join(marks, ",")+`) ORDER BY g.name COLLATE NOCASE`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var hostID int64
		var g GroupRef
		if err := rows.Scan(&hostID, &g.ID, &g.Name); err != nil {
			return err
		}
		if i, ok := idx[hostID]; ok {
			hosts[i].Groups = append(hosts[i].Groups, g)
		}
	}
	return rows.Err()
}
