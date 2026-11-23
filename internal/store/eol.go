package store

import (
	"context"
)

// SaveEOLProduct stores a fetched support calendar (verbatim JSON).
func (s *Store) SaveEOLProduct(ctx context.Context, product, data string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO eol_data (product, data, fetched_at) VALUES (?, ?, ?)
		ON CONFLICT (product) DO UPDATE SET data = excluded.data, fetched_at = excluded.fetched_at`, product, data, now())
	return err
}

// EOLProducts returns the stored support calendars by product.
func (s *Store) EOLProducts(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT product, data FROM eol_data`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var p, d string
		if err := rows.Scan(&p, &d); err != nil {
			return nil, err
		}
		out[p] = d
	}
	return out, rows.Err()
}

// MarkEOLNotice records that a notification was sent for a release and
// kind; it reports false when one was sent before.
func (s *Store) MarkEOLNotice(ctx context.Context, product, cycle, kind string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `INSERT INTO eol_notices (product, cycle, kind, notified_at) VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING`,
		product, cycle, kind, now())
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// EOLHost is a host's operating system and software for the support
// calendar assessment.
type EOLHost struct {
	ID             int64
	Hostname       string
	OSID           string
	OSVersionID    string
	OSName         string
	Kernel         string
	PackageManager string
	Software       []SoftwareItem
}

// EOLHosts returns the hosts the context may see with their software,
// ordered by hostname; groupID > 0 limits them to one group.
func (s *Store) EOLHosts(ctx context.Context, groupID int64) ([]EOLHost, error) {
	where, args := "", []any(nil)
	if groupID > 0 {
		where, args = ` WHERE h.id IN (SELECT host_id FROM host_group_members WHERE group_id = ?)`, []any{groupID}
	}
	where, args = andScope(ctx, where, args, "h.id")
	rows, err := s.db.QueryContext(ctx, `SELECT h.id, h.hostname, h.os_id, h.os_version_id, h.os_name, h.kernel, h.package_manager FROM hosts h`+where+
		` ORDER BY lower(h.hostname), h.hostname, h.id`, args...)
	if err != nil {
		return nil, err
	}
	var out []EOLHost
	idx := map[int64]int{}
	for rows.Next() {
		var h EOLHost
		if err := rows.Scan(&h.ID, &h.Hostname, &h.OSID, &h.OSVersionID, &h.OSName, &h.Kernel, &h.PackageManager); err != nil {
			rows.Close()
			return nil, err
		}
		idx[h.ID] = len(out)
		out = append(out, h)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	swhere, sargs := andScope(ctx, "", nil, "s.host_id")
	srows, err := s.db.QueryContext(ctx, `SELECT s.host_id, s.software, s.cycle, s.version, s.package, s.package_version, s.running, s.service FROM host_software s`+swhere+
		` ORDER BY s.host_id, s.software, s.cycle`, sargs...)
	if err != nil {
		return nil, err
	}
	defer srows.Close()
	for srows.Next() {
		var id int64
		var it SoftwareItem
		if err := srows.Scan(&id, &it.Software, &it.Cycle, &it.Version, &it.Package, &it.PackageVersion, &it.Running, &it.Service); err != nil {
			return nil, err
		}
		if i, ok := idx[id]; ok {
			out[i].Software = append(out[i].Software, it)
		}
	}
	return out, srows.Err()
}
