package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"netio.patchman/internal/protocol"
	"netio.patchman/internal/vuln"
)

// populate fills every table of s with representative data, including
// values that need care in a transfer: non-ASCII text, NULL scores, gzip
// blobs next to plain JSON, foreign keys in both directions.
func populate(t *testing.T, s *Store) {
	t.Helper()
	ctx := context.Background()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	admin, err := s.CreateUser(ctx, User{Email: "Yönetici@Example.test", Name: "Şule Çağlar", PasswordHash: "h", Role: RoleAdmin})
	must(err)
	op, err := s.CreateUser(ctx, User{Email: "op@example.test", Name: "Operatör", PasswordHash: "h", Role: RoleOperator})
	must(err)
	must(s.EnableTOTP(ctx, admin, "JBSWY3DPEHPK3PXP", 5, []string{"r1", "r2"}, ""))
	must(s.CreateSession(ctx, Session{TokenHash: "sess", UserID: admin, CSRFToken: "c", ExpiresAt: time.Now().Add(time.Hour)}, "192.0.2.1", "Mozilla"))
	_, err = s.CreateEnrollmentToken(ctx, "kayıt", "tok", "npe_", admin, time.Time{}, 0)
	must(err)
	var hosts []int64
	for i, name := range []string{"web-01", "veritabanı-02", "win-03"} {
		id, _, err := s.RegisterHost(ctx, "tok", protocol.HostInfo{Hostname: name, MachineID: fmt.Sprint("m", i), OSID: "debian", Virtualization: "kvm",
			IPAddresses: []string{"192.0.2.1" + strconv.Itoa(i)}}, "Debian:12", fmt.Sprint("secret", i))
		must(err)
		hosts = append(hosts, id)
		rep := protocol.Report{Host: protocol.HostInfo{Hostname: name, MachineID: fmt.Sprint("m", i), OSID: "debian"}, RebootRequired: i == 1,
			Packages: []protocol.Package{{Name: "openssl", Version: "3.0.11-1", Arch: "amd64", SourceName: "openssl", SourceVersion: "3.0.11-1"},
				{Name: "libssl3", Version: "3.0.11-1", Arch: "amd64", SourceName: "openssl", SourceVersion: "3.0.11-1"}},
			Updates: []protocol.Update{{Name: "openssl", CurrentVersion: "3.0.11-1", AvailableVersion: "3.0.13-1", Security: true, CVEs: []string{"CVE-2026-0001"}},
				{Name: "libssl3", CurrentVersion: "3.0.11-1", AvailableVersion: "3.0.13-1", Title: "Güncelleme ü"}},
			KernelPatch: &protocol.KernelPatch{Provider: protocol.Livepatch, CVEs: []string{"CVE-2026-0009"}}}
		must(s.SaveReport(ctx, id, rep, "Debian:12"))
		_, err = s.ApplyFindings(ctx, id, []DetectedFinding{{CVEID: "CVE-2026-0001", PackageName: "openssl", InstalledVersion: "3.0.11-1", FixedVersion: "3.0.13-1"},
			{CVEID: "CVE-2026-0002", PackageName: "openssl", InstalledVersion: "3.0.11-1"}})
		must(err)
	}
	score := 9.8
	must(s.UpsertVulnerability(ctx, vuln.Vulnerability{CVEID: "CVE-2026-0001", Title: "Açık <b>verbatim</b>", Description: "çok satırlı\nmetin", CVSSScore: &score,
		CVSSVector: "CVSS:3.1/AV:N", Severity: vuln.SeverityCritical, Source: "osv", References: []string{"https://example.test/a"}, PublishedAt: time.Unix(1700000000, 0)}))
	must(s.UpsertVulnerability(ctx, vuln.Vulnerability{CVEID: "CVE-2026-0002", Title: "no score", Severity: vuln.SeverityUnknown}))
	must(s.UpsertAdvisory(ctx, vuln.Advisory{ID: "DSA-1", Title: "openssl", URL: "https://example.test/dsa"}, "debian", []string{"CVE-2026-0001", "CVE-2026-0002"}))
	must(s.ReplaceKEV(ctx, []KEVEntry{{CVEID: "CVE-2026-0001", DateAdded: "2026-01-02", DueDate: "2026-01-23", Ransomware: "Known"}}))
	must(s.ReplaceEPSS(ctx, []EPSSEntry{{CVEID: "CVE-2026-0001", Score: 0.97512, Percentile: 0.99981}, {CVEID: "CVE-2026-0002", Score: 1e-5, Percentile: 0.01}}))
	must(s.SaveOSVQueries(ctx, map[OSVQueryKey][]OSVRef{{Ecosystem: "Debian:12", Name: "openssl", Version: "3.0.11-1"}: {{ID: "DSA-1", Modified: "m"}}}))
	must(s.SaveOSVRecord(ctx, "DSA-1", "m", []byte(`{"id":"DSA-1","details":"ü"}`)))
	if _, err := s.db.Exec(`INSERT INTO osv_records (id, modified, fetched_at, data) VALUES ('LEGACY-1', 'm', 1, '{"id":"LEGACY-1"}')`); err != nil {
		t.Fatal(err)
	}
	must(s.SaveMSRCKB(ctx, "5034439", []byte(`{"cves":["CVE-2026-0003"]}`)))
	g, err := s.CreateGroup(ctx, "Üretim", "canlı")
	must(err)
	_, err = s.AddHostsToGroup(ctx, g, hosts[:2])
	must(err)
	must(s.SetGroupExclude(ctx, g, []string{"kernel*"}))
	must(s.SetHostExclude(ctx, hosts[0], []string{"mysql-*"}))
	must(s.SetUserGroups(ctx, op, true, []int64{g}))
	sc, err := s.CreateSchedule(ctx, Schedule{Name: "Gece", Enabled: true, JobType: protocol.JobUpgradeSecurity, Days: 127, Minute: 120, WindowMinutes: 60,
		Target: TargetHosts, HostIDs: hosts[:1], NextRunAt: time.Now().Add(time.Hour), Reboot: true}, admin)
	must(err)
	_, err = s.CreateSchedule(ctx, Schedule{Name: "Grup", Enabled: true, JobType: protocol.JobUpgradeAll, Days: 1, Minute: 0, WindowMinutes: 30,
		Target: TargetGroup, GroupID: g}, 0)
	must(err)
	j, err := s.CreateScheduledJob(ctx, hosts[0], protocol.JobUpgradeSecurity, sc, time.Now().Add(time.Hour))
	must(err)
	_, err = s.CompleteJob(ctx, hosts[0], j, protocol.JobResult{Succeeded: true, Output: "çıktı\n"})
	must(err)
	_, err = s.CreateJob(ctx, hosts[1], protocol.JobUpgradePackages, []string{"openssl"}, map[string]string{"exclude": "kernel*"}, op)
	must(err)
	must(s.AddNotification(ctx, LevelWarning, "job_finished", map[string]string{"host": "web-01"}, fmt.Sprintf("/jobs/%d", j)))
	must(s.AddNotification(ctx, LevelInfo, "server_update", nil, ""))
	must(s.SaveSettings(ctx, map[string]string{"updates.exclude": "kernel*", "sla.critical_days": "7"}))
	must(s.Audit(ctx, AuditEntry{UserID: admin, UserEmail: "yönetici@example.test", Action: "user.create", Target: "op", IP: "192.0.2.1"}))
	must(s.Audit(ctx, AuditEntry{Action: "system", Details: "cli"}))
	_, err = s.CreateAPIToken(ctx, admin, "grafana", "apihash", "npat_ab", true, time.Time{})
	must(err)
	must(s.WatchPackage(ctx, op, "openssl"))
	_, err = s.CreateChannel(ctx, Channel{Name: "Slack", Type: ChannelSlack, URL: "https://hooks.example.test/x", MinLevel: LevelWarning, Enabled: true})
	must(err)
	must(s.TakeSnapshot(ctx, time.Now()))
}

// dump returns every table's rows as sorted, type-normalized strings.
func dump(t *testing.T, s *Store) map[string][]string {
	t.Helper()
	ctx := context.Background()
	tables, err := s.tableInfos(ctx, s.db.raw)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	for _, tb := range tables {
		cols := append([]string(nil), tb.cols...)
		sort.Strings(cols)
		q := make([]string, len(cols))
		for i, c := range cols {
			q[i] = quoteIdent(c)
		}
		rows, err := s.db.raw.QueryContext(ctx, `SELECT `+strings.Join(q, ", ")+` FROM `+quoteIdent(tb.name))
		if err != nil {
			t.Fatal(err)
		}
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		for rows.Next() {
			if err := rows.Scan(ptrs...); err != nil {
				t.Fatal(err)
			}
			parts := make([]string, len(cols))
			for i, v := range vals {
				switch x := v.(type) {
				case nil:
					parts[i] = cols[i] + "=NULL"
				case []byte:
					parts[i] = cols[i] + "=" + string(x)
				case float64:
					parts[i] = cols[i] + "=" + strconv.FormatFloat(x, 'g', -1, 64)
				default:
					parts[i] = fmt.Sprintf("%s=%v", cols[i], x)
				}
			}
			out[tb.name] = append(out[tb.name], strings.Join(parts, "|"))
		}
		rows.Close()
		sort.Strings(out[tb.name])
	}
	return out
}

func compareDumps(t *testing.T, want, got map[string][]string) {
	t.Helper()
	if len(want) != len(got) {
		t.Fatalf("tables: %d, want %d", len(got), len(want))
	}
	empty := 0
	for name, rows := range want {
		if len(rows) == 0 {
			empty++
		}
		if strings.Join(rows, "\n") != strings.Join(got[name], "\n") {
			t.Errorf("table %s differs:\nwant %q\ngot  %q", name, rows, got[name])
		}
	}
	if empty > 0 {
		var names []string
		for name, rows := range want {
			if len(rows) == 0 {
				names = append(names, name)
			}
		}
		t.Errorf("populate left tables empty: %v", names)
	}
}

func sqliteFile(t *testing.T) (*Store, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "netio-patchman.db")
	s, err := OpenSQLite(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	return s, p
}

// TestTransferRoundTrip imports a SQLite database into a second database
// (PostgreSQL when PATCHMAN_TEST_DATABASE_URL is set, else SQLite), backs
// it up and checks that every row of every table survived both steps.
func TestTransferRoundTrip(t *testing.T) {
	ctx := context.Background()
	src, path := sqliteFile(t)
	populate(t, src)
	want := dump(t, src)
	src.Close()

	dst := openTest(t)
	res, err := dst.ImportSQLite(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if res.Tables != len(want) || res.Rows == 0 || res.Sanitized != 0 {
		t.Errorf("result: %+v", res)
	}
	compareDumps(t, want, dump(t, dst))

	// The target database works normally afterwards; ids continue after the
	// imported ones (PostgreSQL identity sequences are moved on).
	id, err := dst.CreateUser(ctx, User{Email: "new@example.test", Name: "n", PasswordHash: "h", Role: RoleViewer})
	if err != nil || id != 3 {
		t.Fatalf("new user after import: %d %v", id, err)
	}
	if _, err := dst.CreateUser(ctx, User{Email: "yÖnetici@example.TEST", Name: "dup", PasswordHash: "h", Role: RoleViewer}); err != nil {
		// Only ASCII case is folded (as in SQLite): "Ö" differs from "ö".
		t.Errorf("non-ASCII case: %v", err)
	}
	if _, err := dst.CreateUser(ctx, User{Email: "OP@example.test", Name: "dup", PasswordHash: "h", Role: RoleViewer}); !errors.Is(err, ErrDuplicate) {
		t.Errorf("duplicate email accepted: %v", err)
	}
	u, err := dst.UserByEmail(ctx, "yönetici@EXAMPLE.test")
	if err != nil || u.ID != 1 || !u.MFAEnabled() {
		t.Errorf("user lookup after import: %+v %v", u, err)
	}

	// The source file is unchanged and a second import is refused.
	if _, err := dst.ImportSQLite(ctx, path); !errors.Is(err, ErrNotEmpty) {
		t.Errorf("second import: %v", err)
	}

	// A backup of the target is a SQLite file with the same data.
	if _, err := dst.DB().Exec(`DELETE FROM users WHERE id > 2`); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(t.TempDir(), "backup.db")
	if err := dst.Backup(ctx, backup); err != nil {
		t.Fatal(err)
	}
	b, err := OpenSQLite(ctx, backup)
	if err != nil {
		t.Fatal(err)
	}
	compareDumps(t, want, dump(t, b))
	b.Close()
	if _, err := os.Stat(backup + "-wal"); err == nil {
		t.Error("backup left a write-ahead log")
	}

	// Restore replaces everything with the backup.
	populated, _ := dst.CreateGroup(ctx, "geçici", "")
	if populated == 0 {
		t.Fatal("group not created")
	}
	if _, err := dst.Restore(ctx, backup); err != nil {
		t.Fatal(err)
	}
	compareDumps(t, want, dump(t, dst))
}

func TestImportRejectsOtherSchema(t *testing.T) {
	ctx := context.Background()
	src, path := sqliteFile(t)
	if _, err := src.db.Exec(`CREATE TABLE extra (x INTEGER)`); err != nil {
		t.Fatal(err)
	}
	src.Close()
	dst := openTest(t)
	if _, err := dst.ImportSQLite(ctx, path); !errors.Is(err, ErrSchemaMismatch) {
		t.Fatalf("got %v", err)
	}
	if empty, err := dst.Empty(ctx); err != nil || !empty {
		t.Errorf("target changed: %v %v", empty, err)
	}
}

func TestImportSanitizesText(t *testing.T) {
	ctx := context.Background()
	if !openTest(t).Postgres() {
		t.Skip("PostgreSQL only (set PATCHMAN_TEST_DATABASE_URL)")
	}
	src, path := sqliteFile(t)
	if _, err := src.db.Exec(`INSERT INTO settings (key, value) VALUES ('bad', CAST(X'61FF00' AS TEXT))`); err != nil {
		t.Fatal(err)
	}
	src.Close()
	dst := openTest(t)
	res, err := dst.ImportSQLite(ctx, path)
	if err != nil || res.Sanitized != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	kv, _ := dst.Settings(ctx)
	if kv["bad"] != "a�" {
		t.Errorf("value %q", kv["bad"])
	}
}

// TestImportHandlesOrphans: rows that refer to missing rows (a SQLite file
// written with foreign keys off) follow the delete rule of their key.
func TestImportHandlesOrphans(t *testing.T) {
	ctx := context.Background()
	if !openTest(t).Postgres() {
		t.Skip("PostgreSQL only (set PATCHMAN_TEST_DATABASE_URL)")
	}
	src, path := sqliteFile(t)
	host := registerHost(t, src, "m1")
	if _, err := src.ApplyFindings(ctx, host, []DetectedFinding{{CVEID: "CVE-2026-0001", PackageName: "p", InstalledVersion: "1"}}); err != nil {
		t.Fatal(err)
	}
	src.db.raw.SetMaxOpenConns(1)
	for _, q := range []string{
		`PRAGMA foreign_keys = OFF`,
		`INSERT INTO host_packages (host_id, name, version) VALUES (999, 'orphan', '1')`, // CASCADE: removed
		`INSERT INTO host_group_members (group_id, host_id) VALUES (77, 1)`,              // CASCADE: removed
		`UPDATE findings SET status_changed_by = 555`,                                    // SET NULL
	} {
		if _, err := src.db.raw.Exec(q); err != nil {
			t.Fatal(q, err)
		}
	}
	src.Close()
	dst := openTest(t)
	res, err := dst.ImportSQLite(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if res.Orphans != 3 {
		t.Errorf("orphans: %d", res.Orphans)
	}
	var n int
	_ = dst.db.QueryRow(`SELECT COUNT(*) FROM findings WHERE status_changed_by IS NULL`).Scan(&n)
	if n != 1 {
		t.Errorf("finding not unlinked")
	}
	// The foreign keys are back in place.
	if _, err := dst.db.Exec(`INSERT INTO host_packages (host_id, name, version) VALUES (999, 'x', '1')`); err == nil {
		t.Error("foreign key missing after import")
	}
}

// TestPostgresSchemaMatchesSQLite checks that both migration sets produce
// the same tables and columns.
func TestPostgresSchemaMatchesSQLite(t *testing.T) {
	ctx := context.Background()
	pg := openTest(t)
	if !pg.Postgres() {
		t.Skip("PostgreSQL only (set PATCHMAN_TEST_DATABASE_URL)")
	}
	lite, _ := sqliteFile(t)
	defer lite.Close()
	a, err := lite.tableInfos(ctx, lite.db.raw)
	if err != nil {
		t.Fatal(err)
	}
	b, err := pg.tableInfos(ctx, pg.db.raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sameSchema(a, b); err != nil {
		t.Fatal(err)
	}
	va, _ := lite.SchemaVersion(ctx)
	vb, _ := pg.SchemaVersion(ctx)
	if va != vb {
		t.Fatalf("schema versions: sqlite %d, postgres %d", va, vb)
	}
}

// TestMigrationSetsAligned: every SQLite migration has a PostgreSQL
// counterpart (or is covered by the baseline).
func TestMigrationSetsAligned(t *testing.T) {
	versions := func(dir string) (map[int]string, int) {
		entries, err := migrationFiles(dir)
		if err != nil {
			t.Fatal(err)
		}
		m := map[int]string{}
		top := 0
		for _, e := range entries {
			v, err := migrationVersion(e.Name())
			if err != nil {
				t.Fatal(err)
			}
			m[v] = e.Name()
			top = max(top, v)
		}
		return m, top
	}
	lite, liteTop := versions("migrations")
	pg, pgTop := versions("migrations/postgres")
	if liteTop != pgTop {
		t.Fatalf("newest migration: sqlite %d, postgres %d", liteTop, pgTop)
	}
	baseline := 0
	for v, name := range pg {
		if strings.Contains(name, "_baseline") {
			baseline = max(baseline, v)
		}
	}
	for v := range lite {
		if _, ok := pg[v]; !ok && v > baseline {
			t.Errorf("migration %d has no PostgreSQL file", v)
		}
	}
	if _, err := fs.Stat(migrationFS, "migrations/postgres"); err != nil {
		t.Fatal(err)
	}
}

func TestRewritePostgres(t *testing.T) {
	for in, want := range map[string]string{
		`SELECT a FROM t WHERE x = ? AND y LIKE ? ESCAPE '\' AND z = '?'`:          `SELECT a FROM t WHERE x = $1 AND y ILIKE $2 ESCAPE '\' AND z = '?'`,
		`SELECT GROUP_CONCAT(DISTINCT f.name), COUNT(*) FROM f WHERE id IN (?, ?)`: `SELECT string_agg(DISTINCT f.name, ','), COUNT(*) FROM f WHERE id IN ($1, $2)`,
		`SELECT 'it''s ?', ?`:                          `SELECT 'it''s ?', $1`,
		`SELECT id FROM hosts WHERE id = ? FOR UPDATE`: `SELECT id FROM hosts WHERE id = $1 FOR UPDATE`,
	} {
		if got := rewritePostgres(in); got != want {
			t.Errorf("rewrite(%q)\n got %q\nwant %q", in, got, want)
		}
	}
	lite := &DB{}
	if got := lite.q(`SELECT id FROM hosts WHERE id = ? FOR UPDATE`); got != `SELECT id FROM hosts WHERE id = ?` {
		t.Errorf("sqlite: %q", got)
	}
}

var _ = sql.ErrNoRows
