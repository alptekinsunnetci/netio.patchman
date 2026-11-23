package store

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	"netio.patchman/internal/pkgver"
	"netio.patchman/internal/protocol"
	"netio.patchman/internal/vuln"
)

// saveServices stores the report's service list. A report without one
// clears it only for agents that do not report services at all; an agent
// that could not read them this time keeps the last list.
func saveServices(ctx context.Context, tx *Tx, hostID int64, r protocol.Report) error {
	switch {
	case r.Services != nil:
		if _, err := tx.ExecContext(ctx, `DELETE FROM host_services WHERE host_id = ?`, hostID); err != nil {
			return err
		}
		rows := make([][]any, 0, len(r.Services))
		seen := map[string]bool{}
		for _, s := range r.Services {
			if len(rows) >= protocol.MaxServices || seen[s.Name] || !protocol.ValidServiceName(s.Name) {
				continue
			}
			seen[s.Name] = true
			state := s.State
			if state != protocol.ServiceRunning && state != protocol.ServiceFailed {
				state = protocol.ServiceStopped
			}
			rows = append(rows, []any{hostID, s.Name, state, boolInt(s.Enabled)})
		}
		if err := insertRows(ctx, tx, `INSERT INTO host_services (host_id, name, state, enabled)`, "", 4, rows); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE hosts SET services_known = 1 WHERE id = ?`, hostID)
		return err
	case !r.Host.Supports(protocol.CapServices):
		if _, err := tx.ExecContext(ctx, `DELETE FROM host_services WHERE host_id = ?`, hostID); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE hosts SET services_known = 0 WHERE id = ?`, hostID)
		return err
	}
	return nil
}

// HostServices returns a host's services and whether they are known.
func (s *Store) HostServices(ctx context.Context, hostID int64) ([]protocol.Service, bool, error) {
	var known int
	where, args := andScope(ctx, ` WHERE id = ?`, []any{hostID}, "id")
	if err := s.db.QueryRowContext(ctx, `SELECT services_known FROM hosts`+where, args...).Scan(&known); err != nil {
		return nil, false, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT name, state, enabled FROM host_services WHERE host_id = ? ORDER BY name`, hostID)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	var out []protocol.Service
	for rows.Next() {
		var sv protocol.Service
		var enabled int
		if err := rows.Scan(&sv.Name, &sv.State, &enabled); err != nil {
			return nil, false, err
		}
		sv.Enabled = enabled == 1
		out = append(out, sv)
	}
	return out, known == 1, rows.Err()
}

// SoftwareItem is a product release detected on a host (see package software).
type SoftwareItem struct {
	Software       string
	Cycle          string
	Version        string
	Package        string
	PackageVersion string
	Running        int // 1 yes, 0 no, -1 unknown
	Service        string
}

// Software event types.
const (
	SoftwareInstalled  = "installed"
	SoftwareRemoved    = "removed"
	SoftwareUpgraded   = "upgraded"
	SoftwareDowngraded = "downgraded"
)

// SoftwareEvent is a change of a host's software. Versions are the full
// package versions, verbatim.
type SoftwareEvent struct {
	ID         int64
	HostID     int64
	Hostname   string
	Software   string
	Cycle      string
	Event      string
	OldVersion string
	NewVersion string
	CreatedAt  time.Time
}

// SyncSoftware replaces a host's detected software and records what was
// installed, removed or changed. The first inventory of a host records no
// events (nothing changed, it was only seen for the first time).
func (s *Store) SyncSoftware(ctx context.Context, hostID int64, pm string, items []SoftwareItem) ([]SoftwareEvent, error) {
	var events []SoftwareEvent
	err := s.tx(ctx, func(tx *Tx) error {
		events = nil
		var synced int64
		var hostname string
		if err := tx.QueryRowContext(ctx, `SELECT software_synced_at, hostname FROM hosts WHERE id = ? FOR UPDATE`, hostID).Scan(&synced, &hostname); err != nil {
			return err
		}
		type old struct {
			pkgVersion string
			firstSeen  int64
		}
		existing := map[[2]string]old{}
		rows, err := tx.QueryContext(ctx, `SELECT software, cycle, package_version, first_seen_at FROM host_software WHERE host_id = ?`, hostID)
		if err != nil {
			return err
		}
		for rows.Next() {
			var sw, cycle, pv string
			var fs int64
			if err := rows.Scan(&sw, &cycle, &pv, &fs); err != nil {
				rows.Close()
				return err
			}
			existing[[2]string{sw, cycle}] = old{pv, fs}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		n := now()
		record := synced > 0
		seen := map[[2]string]bool{}
		var insert [][]any
		for _, it := range items {
			key := [2]string{it.Software, it.Cycle}
			if seen[key] {
				continue
			}
			seen[key] = true
			first := n
			if o, ok := existing[key]; ok {
				first = o.firstSeen
				if record && o.pkgVersion != it.PackageVersion {
					ev := SoftwareUpgraded
					if pkgver.Compare(pm, it.PackageVersion, o.pkgVersion) < 0 {
						ev = SoftwareDowngraded
					}
					events = append(events, SoftwareEvent{HostID: hostID, Hostname: hostname, Software: it.Software, Cycle: it.Cycle, Event: ev, OldVersion: o.pkgVersion, NewVersion: it.PackageVersion})
				}
			} else if record {
				events = append(events, SoftwareEvent{HostID: hostID, Hostname: hostname, Software: it.Software, Cycle: it.Cycle, Event: SoftwareInstalled, NewVersion: it.PackageVersion})
			}
			insert = append(insert, []any{hostID, it.Software, it.Cycle, truncate(it.Version, 100), it.Package, truncate(it.PackageVersion, 200), it.Running, it.Service, first, n})
		}
		if record {
			for key, o := range existing {
				if !seen[key] {
					events = append(events, SoftwareEvent{HostID: hostID, Hostname: hostname, Software: key[0], Cycle: key[1], Event: SoftwareRemoved, OldVersion: o.pkgVersion})
				}
			}
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM host_software WHERE host_id = ?`, hostID); err != nil {
			return err
		}
		if err := insertRows(ctx, tx, `INSERT INTO host_software (host_id, software, cycle, version, package, package_version, running, service, first_seen_at, updated_at)`, "", 10, insert); err != nil {
			return err
		}
		sort.Slice(events, func(i, j int) bool {
			if events[i].Software != events[j].Software {
				return events[i].Software < events[j].Software
			}
			return events[i].Cycle < events[j].Cycle
		})
		for i := range events {
			e := &events[i]
			e.CreatedAt = fromTS(n)
			id, err := insertID(ctx, tx, `INSERT INTO software_events (host_id, software, cycle, event, old_version, new_version, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
				hostID, e.Software, e.Cycle, e.Event, e.OldVersion, e.NewVersion, n)
			if err != nil {
				return err
			}
			e.ID = id
		}
		if synced == 0 {
			_, err = tx.ExecContext(ctx, `UPDATE hosts SET software_synced_at = ? WHERE id = ?`, n, hostID)
		}
		return err
	})
	return events, err
}

// softwareFindingJoin reaches the active findings of a product: through all
// binary packages built from the same source as the product's package
// (RPM records findings per binary, Debian per source package).
const softwareFindingJoin = ` JOIN host_packages p ON p.host_id = s.host_id AND p.name = s.package
	JOIN host_packages p2 ON p2.host_id = s.host_id AND (p2.name = p.name OR (p.source_name <> '' AND p2.source_name = p.source_name))
	JOIN findings f ON f.host_id = s.host_id AND (f.package_name = p2.name OR (p2.source_name <> '' AND f.package_name = p2.source_name))
	LEFT JOIN vulnerabilities v ON v.cve_id = f.cve_id LEFT JOIN kev k ON k.cve_id = f.cve_id`

// HostSoftwareRow is a product release on a host with its open findings.
type HostSoftwareRow struct {
	SoftwareItem
	HostID         int64
	Hostname       string
	OSName         string
	FirstSeenAt    time.Time
	UpdatedAt      time.Time
	CVECount       int
	Severity       vuln.Severity
	KnownExploited bool
}

// HostSoftware returns the products found on a host.
func (s *Store) HostSoftware(ctx context.Context, hostID int64) ([]HostSoftwareRow, error) {
	return s.softwareRows(ctx, ` WHERE s.host_id = ?`, []any{hostID}, ` ORDER BY s.software, s.cycle`)
}

// SoftwareHosts returns the hosts running a product, optionally one cycle.
func (s *Store) SoftwareHosts(ctx context.Context, software, cycle string) ([]HostSoftwareRow, error) {
	where, args := ` WHERE s.software = ?`, []any{software}
	if cycle != "" {
		where += ` AND s.cycle = ?`
		args = append(args, cycle)
	}
	return s.softwareRows(ctx, where, args, ` ORDER BY lower(h.hostname), h.hostname, s.cycle`)
}

func (s *Store) softwareRows(ctx context.Context, where string, args []any, order string) ([]HostSoftwareRow, error) {
	where, args = andScope(ctx, where, args, "s.host_id")
	rows, err := s.db.QueryContext(ctx, `SELECT s.host_id, h.hostname, h.os_name, s.software, s.cycle, s.version, s.package, s.package_version, s.running, s.service,
		s.first_seen_at, s.updated_at FROM host_software s JOIN hosts h ON h.id = s.host_id`+where+order, args...)
	if err != nil {
		return nil, err
	}
	var out []HostSoftwareRow
	for rows.Next() {
		var r HostSoftwareRow
		var fs, up int64
		if err := rows.Scan(&r.HostID, &r.Hostname, &r.OSName, &r.Software, &r.Cycle, &r.Version, &r.Package, &r.PackageVersion, &r.Running, &r.Service, &fs, &up); err != nil {
			rows.Close()
			return nil, err
		}
		r.FirstSeenAt, r.UpdatedAt, r.Severity = fromTS(fs), fromTS(up), vuln.SeverityUnknown
		out = append(out, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil || len(out) == 0 {
		return out, err
	}
	// Open findings per (host, product, cycle).
	idx := map[[3]string]int{}
	for i, r := range out {
		idx[[3]string{itoa(r.HostID), r.Software, r.Cycle}] = i
	}
	frows, err := s.db.QueryContext(ctx, `SELECT s.host_id, s.software, s.cycle, COUNT(DISTINCT f.cve_id), MIN(`+severityOrder+`), MAX(CASE WHEN k.cve_id IS NULL THEN 0 ELSE 1 END)
		FROM host_software s JOIN hosts h ON h.id = s.host_id`+softwareFindingJoin+where+` AND f.status IN `+activeStatuses+` GROUP BY s.host_id, s.software, s.cycle`, args...)
	if err != nil {
		return nil, err
	}
	defer frows.Close()
	for frows.Next() {
		var hid int64
		var sw, cycle string
		var cves, rank, kev int
		if err := frows.Scan(&hid, &sw, &cycle, &cves, &rank, &kev); err != nil {
			return nil, err
		}
		if i, ok := idx[[3]string{itoa(hid), sw, cycle}]; ok {
			out[i].CVECount, out[i].Severity, out[i].KnownExploited = cves, severityFromRank(rank), kev == 1
		}
	}
	return out, frows.Err()
}

// SoftwareCycle counts hosts per release cycle of a product.
type SoftwareCycle struct {
	Cycle string
	Hosts int
}

// SoftwareSummary aggregates a product over the visible fleet.
type SoftwareSummary struct {
	Software string
	Hosts    int
	Running  int
	Cycles   []SoftwareCycle
	// Distinct open CVEs on the product's packages and the worst severity.
	CVECount       int
	Severity       vuln.Severity
	KnownExploited bool
}

// SoftwareSummaries returns every detected product with host counts.
func (s *Store) SoftwareSummaries(ctx context.Context) ([]SoftwareSummary, error) {
	where, args := andScope(ctx, "", nil, "s.host_id")
	rows, err := s.db.QueryContext(ctx, `SELECT s.software, s.cycle, COUNT(DISTINCT s.host_id), COUNT(CASE WHEN s.running = 1 THEN 1 END)
		FROM host_software s`+where+` GROUP BY s.software, s.cycle ORDER BY s.software, s.cycle`, args...)
	if err != nil {
		return nil, err
	}
	byID := map[string]*SoftwareSummary{}
	var order []string
	for rows.Next() {
		var sw, cycle string
		var hosts, running int
		if err := rows.Scan(&sw, &cycle, &hosts, &running); err != nil {
			rows.Close()
			return nil, err
		}
		sum := byID[sw]
		if sum == nil {
			sum = &SoftwareSummary{Software: sw, Severity: vuln.SeverityUnknown}
			byID[sw] = sum
			order = append(order, sw)
		}
		sum.Cycles = append(sum.Cycles, SoftwareCycle{Cycle: cycle, Hosts: hosts})
		sum.Running += running
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Hosts per product (a host with two cycles counts once).
	hrows, err := s.db.QueryContext(ctx, `SELECT s.software, COUNT(DISTINCT s.host_id) FROM host_software s`+where+` GROUP BY s.software`, args...)
	if err != nil {
		return nil, err
	}
	for hrows.Next() {
		var sw string
		var n int
		if err := hrows.Scan(&sw, &n); err != nil {
			hrows.Close()
			return nil, err
		}
		if sum := byID[sw]; sum != nil {
			sum.Hosts = n
		}
	}
	hrows.Close()
	if err := hrows.Err(); err != nil {
		return nil, err
	}
	fwhere, fargs := andScope(ctx, ` WHERE f.status IN `+activeStatuses, nil, "s.host_id")
	frows, err := s.db.QueryContext(ctx, `SELECT s.software, COUNT(DISTINCT f.cve_id), MIN(`+severityOrder+`), MAX(CASE WHEN k.cve_id IS NULL THEN 0 ELSE 1 END)
		FROM host_software s`+softwareFindingJoin+fwhere+` GROUP BY s.software`, fargs...)
	if err != nil {
		return nil, err
	}
	defer frows.Close()
	for frows.Next() {
		var sw string
		var cves, rank, kev int
		if err := frows.Scan(&sw, &cves, &rank, &kev); err != nil {
			return nil, err
		}
		if sum := byID[sw]; sum != nil {
			sum.CVECount, sum.Severity, sum.KnownExploited = cves, severityFromRank(rank), kev == 1
		}
	}
	if err := frows.Err(); err != nil {
		return nil, err
	}
	out := make([]SoftwareSummary, 0, len(order))
	for _, id := range order {
		sum := byID[id]
		sort.Slice(sum.Cycles, func(i, j int) bool {
			return pkgver.CompareRPM(sum.Cycles[i].Cycle, sum.Cycles[j].Cycle) > 0
		})
		out = append(out, *sum)
	}
	return out, nil
}

// SoftwareEventFilter narrows the change history.
type SoftwareEventFilter struct {
	HostID   int64
	Software string
	Event    string
}

// ListSoftwareEvents returns software changes, newest first.
func (s *Store) ListSoftwareEvents(ctx context.Context, f SoftwareEventFilter, p Page) ([]SoftwareEvent, int, error) {
	var conds []string
	var args []any
	if f.HostID != 0 {
		conds = append(conds, `e.host_id = ?`)
		args = append(args, f.HostID)
	}
	if f.Software != "" {
		conds = append(conds, `e.software = ?`)
		args = append(args, f.Software)
	}
	if f.Event != "" {
		conds = append(conds, `e.event = ?`)
		args = append(args, f.Event)
	}
	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}
	where, args = andScope(ctx, where, args, "e.host_id")
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM software_events e`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT e.id, e.host_id, h.hostname, e.software, e.cycle, e.event, e.old_version, e.new_version, e.created_at
		FROM software_events e JOIN hosts h ON h.id = e.host_id`+where+` ORDER BY e.created_at DESC, e.id DESC LIMIT ? OFFSET ?`, append(args, p.limit(), p.Offset())...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []SoftwareEvent
	for rows.Next() {
		var e SoftwareEvent
		var at int64
		if err := rows.Scan(&e.ID, &e.HostID, &e.Hostname, &e.Software, &e.Cycle, &e.Event, &e.OldVersion, &e.NewVersion, &at); err != nil {
			return nil, 0, err
		}
		e.CreatedAt = fromTS(at)
		out = append(out, e)
	}
	return out, total, rows.Err()
}

// PruneSoftwareEvents deletes change history older than d.
func (s *Store) PruneSoftwareEvents(ctx context.Context, d time.Duration) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM software_events WHERE created_at < ?`, now()-int64(d.Seconds()))
	return err
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
