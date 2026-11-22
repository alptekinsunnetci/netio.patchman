package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// Data transfer between databases: the one-time import of a SQLite
// database into PostgreSQL, backups of a PostgreSQL database (written as
// SQLite files, like the backups of a SQLite database) and restores. Every
// table is copied column by column inside one transaction on the target, row
// counts are compared before the commit, and a failure leaves the target
// unchanged.

// ErrNotEmpty is returned when an import target already holds data.
var ErrNotEmpty = errors.New("store: target database is not empty")

// ErrSchemaMismatch is returned when the source and target schemas differ
// (for example a backup taken by a newer version).
var ErrSchemaMismatch = errors.New("store: schema mismatch")

// TransferResult describes a completed copy.
type TransferResult struct {
	Tables int
	Rows   int64
	// Counts holds the rows copied per table.
	Counts map[string]int64
	// Sanitized counts text values PostgreSQL cannot store as they were
	// (invalid UTF-8 or NUL bytes); they were stored with those bytes
	// replaced or removed.
	Sanitized int64
	// Orphans counts rows that referred to a missing row (PostgreSQL target
	// only): removed or unlinked by the delete rule of their foreign key.
	Orphans  int64
	Duration time.Duration
}

type tableInfo struct {
	name  string
	cols  []string
	types map[string]string // PostgreSQL data types by column (target only)
	ident bool              // has an identity id column (PostgreSQL)
}

// tableInfos lists the data tables (without schema_migrations) and columns.
func (s *Store) tableInfos(ctx context.Context, q interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}) ([]tableInfo, error) {
	var names []string
	var listQ string
	if s.db.pg {
		listQ = `SELECT table_name FROM information_schema.tables WHERE table_schema = current_schema()
			AND table_type = 'BASE TABLE' AND table_name <> 'schema_migrations' ORDER BY table_name`
	} else {
		listQ = `SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
			AND name <> 'schema_migrations' ORDER BY name`
	}
	rows, err := q.QueryContext(ctx, listQ)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return nil, err
		}
		names = append(names, n)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]tableInfo, 0, len(names))
	for _, n := range names {
		t := tableInfo{name: n, types: map[string]string{}}
		var colQ string
		if s.db.pg {
			colQ = `SELECT column_name, data_type, is_identity FROM information_schema.columns
				WHERE table_schema = current_schema() AND table_name = $1 ORDER BY ordinal_position`
		} else {
			colQ = `SELECT name, type, '' FROM pragma_table_info(?) ORDER BY cid`
		}
		rows, err := q.QueryContext(ctx, colQ, n)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var c, typ, ident string
			if err := rows.Scan(&c, &typ, &ident); err != nil {
				rows.Close()
				return nil, err
			}
			t.cols = append(t.cols, c)
			t.types[c] = strings.ToLower(typ)
			if c == "id" && ident == "YES" {
				t.ident = true
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

// sameSchema checks that src and dst have the same tables and columns and
// returns the target's tables.
func sameSchema(src, dst []tableInfo) ([]tableInfo, error) {
	srcBy := map[string]tableInfo{}
	for _, t := range src {
		srcBy[t.name] = t
	}
	if len(src) != len(dst) {
		return nil, fmt.Errorf("%w: %d tables in the source, %d in the target", ErrSchemaMismatch, len(src), len(dst))
	}
	for _, t := range dst {
		st, ok := srcBy[t.name]
		if !ok {
			return nil, fmt.Errorf("%w: table %s missing in the source", ErrSchemaMismatch, t.name)
		}
		if len(st.cols) != len(t.cols) {
			return nil, fmt.Errorf("%w: table %s has %d columns in the source, %d in the target", ErrSchemaMismatch, t.name, len(st.cols), len(t.cols))
		}
		have := map[string]bool{}
		for _, c := range st.cols {
			have[c] = true
		}
		for _, c := range t.cols {
			if !have[c] {
				return nil, fmt.Errorf("%w: column %s.%s missing in the source", ErrSchemaMismatch, t.name, c)
			}
		}
	}
	return dst, nil
}

// Empty reports whether no data table has a row.
func (s *Store) Empty(ctx context.Context) (bool, error) {
	tables, err := s.tableInfos(ctx, s.db.raw)
	if err != nil {
		return false, err
	}
	for _, t := range tables {
		var one int
		err := s.db.raw.QueryRowContext(ctx, `SELECT 1 FROM `+quoteIdent(t.name)+` LIMIT 1`).Scan(&one)
		if err == nil {
			return false, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return false, err
		}
	}
	return true, nil
}

func quoteIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

// sourceCopy makes a consistent, migrated working copy of a SQLite file:
// the file is checked, copied with VACUUM INTO (which also takes in a
// write-ahead log left by an unclean shutdown) and the copy is brought to
// the current schema. The original file is not changed. The returned
// cleanup closes and removes the copy.
func sourceCopy(ctx context.Context, path string) (*Store, func(), error) {
	if _, err := os.Stat(path); err != nil {
		return nil, nil, err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, nil, err
	}
	raw, err := sql.Open("sqlite", "file:"+filepath.ToSlash(abs)+"?_pragma=busy_timeout(10000)")
	if err != nil {
		return nil, nil, err
	}
	defer raw.Close()
	var check string
	if err := raw.QueryRowContext(ctx, `PRAGMA quick_check`).Scan(&check); err != nil {
		return nil, nil, fmt.Errorf("store: %s: %w", path, err)
	}
	if check != "ok" {
		return nil, nil, fmt.Errorf("store: %s failed the integrity check: %s", path, check)
	}
	name := ".netio-patchman-transfer-" + strconv.FormatInt(time.Now().UnixNano(), 10) + ".db"
	var tmp string
	for _, dir := range []string{filepath.Dir(abs), os.TempDir()} {
		tmp = filepath.Join(dir, name)
		if _, err = raw.ExecContext(ctx, `VACUUM INTO ?`, tmp); err == nil {
			break
		}
		_ = os.Remove(tmp)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("store: copy %s: %w", path, err)
	}
	src, err := OpenSQLite(ctx, tmp)
	if err != nil {
		removeSQLite(tmp)
		return nil, nil, err
	}
	return src, func() { src.Close(); removeSQLite(tmp) }, nil
}

func removeSQLite(path string) {
	for _, p := range []string{path, path + "-wal", path + "-shm", path + "-journal"} {
		_ = os.Remove(p)
	}
}

// ImportSQLite copies a SQLite database file into this store, which must be
// empty (ErrNotEmpty otherwise). The file itself is not changed.
func (s *Store) ImportSQLite(ctx context.Context, path string) (TransferResult, error) {
	src, cleanup, err := sourceCopy(ctx, path)
	if err != nil {
		return TransferResult{}, err
	}
	defer cleanup()
	return transfer(ctx, src, s, false)
}

// Restore replaces all data of this store with a backup (a SQLite file, as
// written by Backup). The backup file itself is not changed.
func (s *Store) Restore(ctx context.Context, path string) (TransferResult, error) {
	src, cleanup, err := sourceCopy(ctx, path)
	if err != nil {
		return TransferResult{}, err
	}
	defer cleanup()
	return transfer(ctx, src, s, true)
}

// exportSQLite writes the data of this (PostgreSQL) store into a new SQLite
// file at dest, from one consistent snapshot.
func (s *Store) exportSQLite(ctx context.Context, dest string) (TransferResult, error) {
	if _, err := os.Stat(dest); err == nil {
		return TransferResult{}, fmt.Errorf("store: %s already exists", dest)
	}
	dst, err := OpenSQLite(ctx, dest)
	if err != nil {
		return TransferResult{}, err
	}
	// A new file that is deleted on any failure needs no journal: one
	// connection, no rollback journal, no syncing until the end.
	dst.db.raw.SetMaxOpenConns(1)
	for _, p := range []string{`PRAGMA journal_mode=OFF`, `PRAGMA synchronous=OFF`} {
		if _, err := dst.db.raw.ExecContext(ctx, p); err != nil {
			dst.Close()
			removeSQLite(dest)
			return TransferResult{}, err
		}
	}
	res, err := transfer(ctx, s, dst, false)
	if err == nil {
		// A self-contained file: no write-ahead log next to it.
		_, err = dst.db.raw.ExecContext(ctx, `PRAGMA journal_mode=DELETE`)
	}
	if cerr := dst.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		// Written without syncing: flush the file to disk once.
		var f *os.File
		if f, err = os.OpenFile(dest, os.O_RDWR, 0); err == nil {
			err = f.Sync()
			if cerr := f.Close(); err == nil {
				err = cerr
			}
		}
	}
	if err != nil {
		removeSQLite(dest)
	}
	return res, err
}

// rowSource reads a table from the source transaction.
type rowSource struct {
	rows *sql.Rows
	vals []any
	ptrs []any
	err  error
	conv func(i int, v any) (any, error)
}

func newRowSource(rows *sql.Rows, n int, conv func(i int, v any) (any, error)) *rowSource {
	rs := &rowSource{rows: rows, vals: make([]any, n), ptrs: make([]any, n), conv: conv}
	for i := range rs.vals {
		rs.ptrs[i] = &rs.vals[i]
	}
	return rs
}

func (r *rowSource) Next() bool {
	if r.err != nil || !r.rows.Next() {
		return false
	}
	if err := r.rows.Scan(r.ptrs...); err != nil {
		r.err = err
		return false
	}
	for i, v := range r.vals {
		if r.conv != nil {
			cv, err := r.conv(i, v)
			if err != nil {
				r.err = err
				return false
			}
			r.vals[i] = cv
		} else if b, ok := v.([]byte); ok {
			// Scan reuses driver buffers; keep a copy.
			r.vals[i] = append([]byte(nil), b...)
		}
	}
	return true
}

func (r *rowSource) Values() ([]any, error) { return r.vals, nil }

func (r *rowSource) Err() error {
	if r.err != nil {
		return r.err
	}
	return r.rows.Err()
}

// transfer copies every table of src into dst. replace empties dst first;
// otherwise dst must be empty.
func transfer(ctx context.Context, src, dst *Store, replace bool) (TransferResult, error) {
	start := time.Now()
	res := TransferResult{Counts: map[string]int64{}}
	sv, err := src.SchemaVersion(ctx)
	if err != nil {
		return res, err
	}
	dv, err := dst.SchemaVersion(ctx)
	if err != nil {
		return res, err
	}
	if sv != dv {
		return res, fmt.Errorf("%w: source schema version %d, target %d", ErrSchemaMismatch, sv, dv)
	}

	// One consistent snapshot of the source.
	opts := &sql.TxOptions{ReadOnly: true}
	if src.db.pg {
		opts.Isolation = sql.LevelRepeatableRead
	} else {
		opts = nil // modernc: BEGIN IMMEDIATE, which also blocks writers
	}
	stx, err := src.db.raw.BeginTx(ctx, opts)
	if err != nil {
		return res, err
	}
	defer stx.Rollback()
	srcTables, err := src.tableInfos(ctx, stx)
	if err != nil {
		return res, err
	}
	dstTables, err := dst.tableInfos(ctx, dst.db.raw)
	if err != nil {
		return res, err
	}
	tables, err := sameSchema(srcTables, dstTables)
	if err != nil {
		return res, err
	}
	srcCounts := map[string]int64{}
	for _, t := range tables {
		var n int64
		if err := stx.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+quoteIdent(t.name)).Scan(&n); err != nil {
			return res, err
		}
		srcCounts[t.name] = n
	}
	read := func(t tableInfo) (*sql.Rows, error) {
		cols := make([]string, len(t.cols))
		for i, c := range t.cols {
			cols[i] = quoteIdent(c)
		}
		return stx.QueryContext(ctx, `SELECT `+strings.Join(cols, ", ")+` FROM `+quoteIdent(t.name))
	}
	if dst.db.pg {
		err = dst.loadPostgres(ctx, tables, read, srcCounts, replace, &res)
	} else {
		err = dst.loadSQLite(ctx, tables, read, srcCounts, replace, &res)
	}
	if err != nil {
		return res, err
	}
	res.Tables = len(tables)
	res.Duration = time.Since(start)
	return res, nil
}

// importLockID keeps two processes from loading the same database at once.
const importLockID = 7_164_090_002

func (s *Store) loadPostgres(ctx context.Context, tables []tableInfo, read func(tableInfo) (*sql.Rows, error),
	srcCounts map[string]int64, replace bool, res *TransferResult) error {
	conn, err := s.db.raw.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	return conn.Raw(func(dc any) error {
		pc := dc.(*stdlib.Conn).Conn()
		tx, err := pc.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx)
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, importLockID); err != nil {
			return err
		}
		names := make([]string, len(tables))
		for i, t := range tables {
			names[i] = quoteIdent(t.name)
		}
		if replace {
			if _, err := tx.Exec(ctx, `TRUNCATE `+strings.Join(names, ", ")+` RESTART IDENTITY CASCADE`); err != nil {
				return err
			}
		} else {
			for _, t := range tables {
				var one int
				err := tx.QueryRow(ctx, `SELECT 1 FROM `+quoteIdent(t.name)+` LIMIT 1`).Scan(&one)
				if err == nil {
					return fmt.Errorf("%w: table %s has rows", ErrNotEmpty, t.name)
				}
				if !errors.Is(err, pgx.ErrNoRows) {
					return err
				}
			}
		}
		// Row-by-row foreign key checks are slow for millions of rows: the
		// constraints are dropped for the copy and added again afterwards,
		// which validates all rows at once (still inside the transaction, so
		// a failure restores everything).
		type fk struct{ table, name, def, parent, onDelete, col, parentCol string }
		var fks []fk
		rows, err := tx.Query(ctx, `SELECT conrelid::regclass::text, conname, pg_get_constraintdef(oid), confrelid::regclass::text, confdeltype::text,
			(SELECT attname FROM pg_attribute WHERE attrelid = conrelid AND attnum = conkey[1]),
			(SELECT attname FROM pg_attribute WHERE attrelid = confrelid AND attnum = confkey[1])
			FROM pg_constraint WHERE contype = 'f' AND connamespace = current_schema()::regnamespace AND cardinality(conkey) = 1
			ORDER BY conrelid::regclass::text, conname`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var f fk
			if err := rows.Scan(&f.table, &f.name, &f.def, &f.parent, &f.onDelete, &f.col, &f.parentCol); err != nil {
				rows.Close()
				return err
			}
			fks = append(fks, f)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, f := range fks {
			if _, err := tx.Exec(ctx, `ALTER TABLE `+f.table+` DROP CONSTRAINT `+quoteIdent(f.name)); err != nil {
				return err
			}
		}
		for _, t := range tables {
			rows, err := read(t)
			if err != nil {
				return err
			}
			conv := func(i int, v any) (any, error) {
				cv, changed, err := toPostgres(v, t.types[t.cols[i]])
				if err != nil {
					return nil, fmt.Errorf("store: %s.%s: %w", t.name, t.cols[i], err)
				}
				if changed {
					res.Sanitized++
				}
				return cv, nil
			}
			n, err := tx.CopyFrom(ctx, pgx.Identifier{t.name}, t.cols, newRowSource(rows, len(t.cols), conv))
			rows.Close()
			if err != nil {
				return fmt.Errorf("store: copy %s: %w", t.name, err)
			}
			var got int64
			if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM `+quoteIdent(t.name)).Scan(&got); err != nil {
				return err
			}
			if got != srcCounts[t.name] || n != got {
				return fmt.Errorf("store: %s: %d rows in the source, %d copied", t.name, srcCounts[t.name], got)
			}
			res.Counts[t.name] = got
			res.Rows += got
			if t.ident {
				if _, err := tx.Exec(ctx, `SELECT setval(pg_get_serial_sequence($1, 'id'), COALESCE(MAX(id), 0) + 1, false) FROM `+quoteIdent(t.name), t.name); err != nil {
					return err
				}
			}
		}
		// Rows whose parent row no longer exists (possible in SQLite files
		// written with foreign keys off) are treated as the delete rule of
		// the key says: removed (CASCADE) or unlinked (SET NULL). Removing a
		// row can orphan others, so repeat until nothing changes.
		for round := 0; round < 10; round++ {
			var changed int64
			for _, f := range fks {
				orphan := quoteIdent(f.col) + ` IS NOT NULL AND NOT EXISTS (SELECT 1 FROM ` + f.parent + ` p WHERE p.` + quoteIdent(f.parentCol) + ` = c.` + quoteIdent(f.col) + `)`
				var q string
				switch f.onDelete {
				case "c":
					q = `DELETE FROM ` + f.table + ` c WHERE c.` + orphan
				case "n":
					q = `UPDATE ` + f.table + ` c SET ` + quoteIdent(f.col) + ` = NULL WHERE c.` + orphan
				default:
					continue
				}
				tag, err := tx.Exec(ctx, q)
				if err != nil {
					return err
				}
				changed += tag.RowsAffected()
			}
			res.Orphans += changed
			if changed == 0 {
				break
			}
		}
		for _, f := range fks {
			if _, err := tx.Exec(ctx, `ALTER TABLE `+f.table+` ADD CONSTRAINT `+quoteIdent(f.name)+` `+f.def); err != nil {
				return fmt.Errorf("store: foreign key %s: %w", f.name, err)
			}
		}
		return tx.Commit(ctx)
	})
}

func (s *Store) loadSQLite(ctx context.Context, tables []tableInfo, read func(tableInfo) (*sql.Rows, error),
	srcCounts map[string]int64, replace bool, res *TransferResult) error {
	tx, err := s.db.raw.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `PRAGMA defer_foreign_keys = ON`); err != nil {
		return err
	}
	for _, t := range tables {
		if replace {
			if _, err := tx.ExecContext(ctx, `DELETE FROM `+quoteIdent(t.name)); err != nil {
				return err
			}
			continue
		}
		var one int
		err := tx.QueryRowContext(ctx, `SELECT 1 FROM `+quoteIdent(t.name)+` LIMIT 1`).Scan(&one)
		if err == nil {
			return fmt.Errorf("%w: table %s has rows", ErrNotEmpty, t.name)
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
	}
	for _, t := range tables {
		cols := make([]string, len(t.cols))
		for i, c := range t.cols {
			cols[i] = quoteIdent(c)
		}
		// Multi-row inserts of up to 3000 values (one prepared statement per
		// full batch).
		per := max(1, 3000/len(cols))
		one := "(?" + strings.Repeat(", ?", len(cols)-1) + ")"
		head := `INSERT INTO ` + quoteIdent(t.name) + ` (` + strings.Join(cols, ", ") + `) VALUES `
		full, err := tx.PrepareContext(ctx, head+one+strings.Repeat(", "+one, per-1))
		if err != nil {
			return err
		}
		rows, err := read(t)
		if err != nil {
			full.Close()
			return err
		}
		rs := newRowSource(rows, len(cols), nil)
		var n int64
		batch := make([]any, 0, per*len(cols))
		flush := func() error {
			if len(batch) == 0 {
				return nil
			}
			var err error
			if len(batch) == per*len(cols) {
				_, err = full.ExecContext(ctx, batch...)
			} else {
				k := len(batch) / len(cols)
				_, err = tx.ExecContext(ctx, head+one+strings.Repeat(", "+one, k-1), batch...)
			}
			batch = batch[:0]
			return err
		}
		for rs.Next() {
			batch = append(batch, rs.vals...)
			n++
			if len(batch) == per*len(cols) {
				if err := flush(); err != nil {
					rows.Close()
					full.Close()
					return fmt.Errorf("store: copy %s: %w", t.name, err)
				}
			}
		}
		err = rs.Err()
		if err == nil {
			err = flush()
		}
		rows.Close()
		full.Close()
		if err != nil {
			return fmt.Errorf("store: copy %s: %w", t.name, err)
		}
		var got int64
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+quoteIdent(t.name)).Scan(&got); err != nil {
			return err
		}
		if got != srcCounts[t.name] || n != got {
			return fmt.Errorf("store: %s: %d rows in the source, %d copied", t.name, srcCounts[t.name], got)
		}
		res.Counts[t.name] = got
		res.Rows += got
	}
	var violations int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM pragma_foreign_key_check`).Scan(&violations); err != nil {
		return err
	}
	if violations > 0 {
		return fmt.Errorf("store: foreign keys: %d rows reference missing rows", violations)
	}
	return tx.Commit()
}

// toPostgres converts a SQLite value (SQLite columns accept any type) to the
// PostgreSQL column type. changed reports a sanitized text value.
func toPostgres(v any, pgType string) (out any, changed bool, err error) {
	if v == nil {
		return nil, false, nil
	}
	switch pgType {
	case "bigint", "integer", "smallint":
		switch x := v.(type) {
		case int64:
			return x, false, nil
		case float64:
			if x != float64(int64(x)) {
				return nil, false, fmt.Errorf("non-integer value %v", x)
			}
			return int64(x), false, nil
		case bool:
			if x {
				return int64(1), false, nil
			}
			return int64(0), false, nil
		case string:
			n, err := strconv.ParseInt(strings.TrimSpace(x), 10, 64)
			return n, false, err
		case []byte:
			n, err := strconv.ParseInt(strings.TrimSpace(string(x)), 10, 64)
			return n, false, err
		}
	case "double precision", "real", "numeric":
		switch x := v.(type) {
		case float64:
			return x, false, nil
		case int64:
			return float64(x), false, nil
		case string:
			f, err := strconv.ParseFloat(strings.TrimSpace(x), 64)
			return f, false, err
		case []byte:
			f, err := strconv.ParseFloat(strings.TrimSpace(string(x)), 64)
			return f, false, err
		}
	case "bytea":
		switch x := v.(type) {
		case []byte:
			return append([]byte(nil), x...), false, nil
		case string:
			return []byte(x), false, nil
		}
	case "text", "character varying":
		var s string
		switch x := v.(type) {
		case string:
			s = x
		case []byte:
			s = string(x)
		case int64:
			return strconv.FormatInt(x, 10), false, nil
		case float64:
			return strconv.FormatFloat(x, 'g', -1, 64), false, nil
		default:
			return nil, false, fmt.Errorf("unexpected %T", v)
		}
		clean := s
		if !utf8.ValidString(clean) {
			clean = strings.ToValidUTF8(clean, "�")
		}
		if strings.IndexByte(clean, 0) >= 0 {
			clean = strings.ReplaceAll(clean, "\x00", "")
		}
		return clean, clean != s, nil
	}
	return nil, false, fmt.Errorf("unexpected %T for %s", v, pgType)
}
