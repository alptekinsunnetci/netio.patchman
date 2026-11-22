// Package store is the persistence layer. It runs on PostgreSQL (the
// default of the Docker installation) or on an embedded SQLite file.
//
// Timestamps are stored as UTC unix seconds; 0 means "never". Vulnerability
// text is stored verbatim as received from its source.
package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite" // pure Go SQLite driver
)

// SQLite migrations are migrations/NNNN_*.sql, PostgreSQL migrations
// migrations/postgres/NNNN_*.sql. Both sets describe the same schema: a new
// schema change adds one file to each. The PostgreSQL baseline file
// (NNNN_baseline.sql) records versions 1..NNNN at once.
//
//go:embed migrations/*.sql migrations/postgres/*.sql
var migrationFS embed.FS

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("store: not found")

// Store wraps the database handle.
type Store struct {
	db *DB
	// schema is the PostgreSQL schema of a test database ("" otherwise).
	schema string
	// notifyHook is called after AddNotification (see OnNotification).
	notifyHook atomic.Pointer[func(Notification)]
}

// IsPostgresURL reports whether dsn selects PostgreSQL.
func IsPostgresURL(dsn string) bool {
	return strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://")
}

// Open opens the database: a postgres:// (or postgresql://) URL selects
// PostgreSQL, anything else is a SQLite file path (created if needed).
// Pending migrations are applied.
func Open(ctx context.Context, dsn string) (*Store, error) {
	if IsPostgresURL(dsn) {
		return openPostgres(ctx, dsn, "")
	}
	// Tests run against PostgreSQL when PATCHMAN_TEST_DATABASE_URL is set:
	// every SQLite path then maps to its own schema there.
	if testing.Testing() {
		if u := os.Getenv("PATCHMAN_TEST_DATABASE_URL"); u != "" {
			return openPostgresTest(ctx, u, dsn)
		}
	}
	return OpenSQLite(ctx, dsn)
}

// OpenSQLite opens (creating if needed) a SQLite database file and applies
// pending migrations.
func OpenSQLite(ctx context.Context, path string) (*Store, error) {
	if path != ":memory:" {
		abs, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		path = filepath.ToSlash(abs)
	}
	q := url.Values{}
	// auto_vacuum only takes effect on a new database (before the first table
	// is created); ReclaimSpace then returns freed pages to the file system.
	q.Add("_pragma", "auto_vacuum(INCREMENTAL)")
	q.Add("_pragma", "busy_timeout(10000)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "synchronous(NORMAL)")
	q.Add("_txlock", "immediate")
	dsn := "file:" + path + "?" + q.Encode()
	if path == ":memory:" {
		// A shared in-memory database for tests; one connection keeps it alive.
		dsn = "file::memory:?" + q.Encode()
	}
	raw, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if path == ":memory:" {
		raw.SetMaxOpenConns(1)
	} else {
		raw.SetMaxOpenConns(8)
	}
	s := &Store{db: &DB{raw: raw}}
	if err := s.migrateSQLite(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	return s, nil
}

func openPostgres(ctx context.Context, dsn, schema string) (*Store, error) {
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("store: %s", RedactURL(dsn))
	}
	if schema != "" {
		cfg.RuntimeParams["search_path"] = schema
	}
	if cfg.RuntimeParams["application_name"] == "" {
		cfg.RuntimeParams["application_name"] = "netio-patchman"
	}
	raw := stdlib.OpenDB(*cfg)
	raw.SetMaxOpenConns(20)
	raw.SetMaxIdleConns(10)
	raw.SetConnMaxLifetime(30 * time.Minute)
	if err := raw.PingContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	s := &Store{db: &DB{raw: raw, pg: true}, schema: schema}
	if err := s.migratePostgres(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	return s, nil
}

// openPostgresTest opens a schema of the test database for a SQLite path:
// the same path gives the same schema, ":memory:" a new one each time.
func openPostgresTest(ctx context.Context, dsn, path string) (*Store, error) {
	key := path
	if path == ":memory:" {
		key = path + strconv.FormatInt(time.Now().UnixNano(), 10)
	}
	sum := sha256.Sum256([]byte(key))
	schema := "t_" + hex.EncodeToString(sum[:8])
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	_, err = admin.ExecContext(ctx, `CREATE SCHEMA IF NOT EXISTS `+schema)
	admin.Close()
	if err != nil {
		return nil, err
	}
	return openPostgres(ctx, dsn, schema)
}

// RedactURL removes the password from a database URL for display and logs.
func RedactURL(dsn string) string {
	u, err := url.Parse(dsn)
	if err != nil {
		return "postgres://?"
	}
	if u.User != nil {
		u.User = url.User(u.User.Username())
	}
	q := u.Query()
	if q.Has("password") {
		q.Del("password")
		u.RawQuery = q.Encode()
	}
	return u.String()
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// DB exposes the handle for packages that need ad-hoc queries in tests.
func (s *Store) DB() *DB { return s.db }

// Postgres reports whether the store runs on PostgreSQL.
func (s *Store) Postgres() bool { return s.db.pg }

// ReclaimSpace returns free pages to the file system (SQLite incremental
// auto-vacuum; a no-op on databases created without it). PostgreSQL's
// autovacuum does this on its own.
func (s *Store) ReclaimSpace(ctx context.Context) error {
	if s.db.pg {
		return nil
	}
	_, err := s.db.ExecContext(ctx, "PRAGMA incremental_vacuum")
	return err
}

// Backup writes a consistent copy of the database to dest as a SQLite file,
// whichever database is in use, so backups can be opened anywhere and
// restored into either database (see Restore). dest must not exist.
func (s *Store) Backup(ctx context.Context, dest string) error {
	if !s.db.pg {
		_, err := s.db.ExecContext(ctx, "VACUUM INTO ?", dest)
		return err
	}
	_, err := s.exportSQLite(ctx, dest)
	return err
}

func migrationFiles(dir string) ([]fs.DirEntry, error) {
	entries, err := fs.ReadDir(migrationFS, dir)
	if err != nil {
		return nil, err
	}
	var out []fs.DirEntry
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out, nil
}

func migrationVersion(name string) (int, error) {
	num, _, _ := strings.Cut(name, "_")
	v, err := strconv.Atoi(num)
	if err != nil {
		return 0, fmt.Errorf("store: bad migration name %s", name)
	}
	return v, nil
}

// SchemaVersion returns the newest applied migration.
func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	var v int
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&v)
	return v, err
}

func (s *Store) migrateSQLite(ctx context.Context) error {
	if _, err := s.db.raw.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL)`); err != nil {
		return fmt.Errorf("store: create schema_migrations: %w", err)
	}
	entries, err := migrationFiles("migrations")
	if err != nil {
		return err
	}
	for _, e := range entries {
		version, err := migrationVersion(e.Name())
		if err != nil {
			return err
		}
		var exists int
		if err := s.db.raw.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, version).Scan(&exists); err != nil {
			return err
		}
		if exists > 0 {
			continue
		}
		body, err := fs.ReadFile(migrationFS, "migrations/"+e.Name())
		if err != nil {
			return err
		}
		err = s.tx(ctx, func(tx *Tx) error {
			if _, err := tx.tx.ExecContext(ctx, string(body)); err != nil {
				return fmt.Errorf("store: migration %s: %w", e.Name(), err)
			}
			_, err := tx.tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)`, version, now())
			return err
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// migrateLockID serializes migrations of processes sharing a PostgreSQL
// database (the server and a CLI command started next to it).
const migrateLockID = 7_164_090_001

func (s *Store) migratePostgres(ctx context.Context) error {
	entries, err := migrationFiles("migrations/postgres")
	if err != nil {
		return err
	}
	// PostgreSQL has transactional DDL: all pending migrations apply together
	// or not at all.
	return s.tx(ctx, func(tx *Tx) error {
		if _, err := tx.tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, migrateLockID); err != nil {
			return err
		}
		if _, err := tx.tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version BIGINT PRIMARY KEY, applied_at BIGINT NOT NULL)`); err != nil {
			return fmt.Errorf("store: create schema_migrations: %w", err)
		}
		var current int
		if err := tx.tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&current); err != nil {
			return err
		}
		for _, e := range entries {
			version, err := migrationVersion(e.Name())
			if err != nil {
				return err
			}
			if version <= current {
				continue
			}
			body, err := fs.ReadFile(migrationFS, "migrations/postgres/"+e.Name())
			if err != nil {
				return err
			}
			if _, err := tx.tx.ExecContext(ctx, string(body)); err != nil {
				return fmt.Errorf("store: migration postgres/%s: %w", e.Name(), err)
			}
			first := version
			if strings.Contains(e.Name(), "_baseline") {
				first = current + 1
			}
			for v := first; v <= version; v++ {
				if _, err := tx.tx.ExecContext(ctx, `INSERT INTO schema_migrations (version, applied_at) VALUES ($1, $2)`, v, now()); err != nil {
					return err
				}
			}
			current = version
		}
		return nil
	})
}

// tx runs fn in a transaction. On PostgreSQL a transaction that failed on a
// deadlock or serialization conflict is run again, so fn must not keep
// results of a failed attempt (reset what it collects at its start).
func (s *Store) tx(ctx context.Context, fn func(*Tx) error) error {
	for attempt := 1; ; attempt++ {
		err := s.tx1(ctx, fn)
		if err == nil || !s.db.pg || attempt >= 5 || !retryable(err) {
			return err
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(time.Duration(attempt*attempt) * 20 * time.Millisecond):
		}
	}
}

func (s *Store) tx1(ctx context.Context, fn func(*Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// now is replaceable in tests.
var now = func() int64 { return time.Now().UTC().Unix() }

// ts converts a time to unix seconds; zero time becomes 0.
func ts(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UTC().Unix()
}

// fromTS converts unix seconds to a UTC time; 0 becomes the zero time.
func fromTS(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.Unix(v, 0).UTC()
}

// nullID maps 0 ("no user", e.g. system or CLI actions) to SQL NULL so that
// foreign keys to users stay valid.
func nullID(id int64) any {
	if id == 0 {
		return nil
	}
	return id
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Page describes pagination input.
type Page struct {
	Number int // 1-based
	Size   int
}

// Offset returns the SQL offset.
func (p Page) Offset() int {
	if p.Number < 1 {
		return 0
	}
	return (p.Number - 1) * p.limit()
}

func (p Page) limit() int {
	if p.Size <= 0 || p.Size > 500 {
		return 50
	}
	return p.Size
}

// likeEscape escapes LIKE wildcards in user input; use with ESCAPE '\'.
func likeEscape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return "%" + r.Replace(s) + "%"
}
