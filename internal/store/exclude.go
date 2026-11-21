package store

import (
	"context"
	"strings"
)

// SetHostExclude stores a host's package exclusion patterns.
func (s *Store) SetHostExclude(ctx context.Context, id int64, patterns []string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE hosts SET exclude_packages = ? WHERE id = ?`, strings.Join(patterns, ", "), id)
	return err
}

// SetGroupExclude stores a group's package exclusion patterns.
func (s *Store) SetGroupExclude(ctx context.Context, id int64, patterns []string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE host_groups SET exclude_packages = ? WHERE id = ?`, strings.Join(patterns, ", "), id)
	return err
}

// HostExcludes returns the exclusion lists of a host and of its groups,
// joined (the fleet-wide list is a setting).
func (s *Store) HostExcludes(ctx context.Context, hostID int64) (string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT exclude_packages FROM hosts WHERE id = ?
		UNION ALL SELECT g.exclude_packages FROM host_groups g JOIN host_group_members m ON m.group_id = g.id WHERE m.host_id = ?`, hostID, hostID)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var parts []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return "", err
		}
		if v != "" {
			parts = append(parts, v)
		}
	}
	return strings.Join(parts, ", "), rows.Err()
}
