package store

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5/pgconn"
)

// Queries are written once, in SQL that SQLite and PostgreSQL both accept,
// with "?" placeholders. DB rewrites them for PostgreSQL:
//
//   - "?" becomes "$1", "$2", ... (outside string literals)
//   - " LIKE " becomes " ILIKE " (SQLite's LIKE ignores ASCII case)
//   - GROUP_CONCAT(x) becomes string_agg(x, ',')
//
// and drops " FOR UPDATE" for SQLite, where a write transaction already
// holds the database lock. Everything else must be portable: ON CONFLICT
// instead of INSERT OR IGNORE/REPLACE, RETURNING id instead of
// LastInsertId, lower(col) instead of COLLATE NOCASE, CASE instead of
// boolean arithmetic, CAST(? AS BIGINT) where PostgreSQL cannot infer a
// parameter type, NULLS LAST on nullable sort keys and aliases on
// subqueries in FROM.

// DB is a database handle that adapts queries to the database in use.
type DB struct {
	raw *sql.DB
	pg  bool
	// rewritten caches converted queries by their source text.
	rewritten sync.Map
}

// Tx is a transaction on a DB.
type Tx struct {
	tx *sql.Tx
	db *DB
}

func (d *DB) q(query string) string {
	if v, ok := d.rewritten.Load(query); ok {
		return v.(string)
	}
	var out string
	if d.pg {
		out = rewritePostgres(query)
	} else {
		out = strings.ReplaceAll(query, " FOR UPDATE", "")
	}
	// Long generated statements (multi-row inserts) are not kept.
	if len(query) < 4096 {
		d.rewritten.Store(query, out)
	}
	return out
}

// Raw returns the underlying handle (for driver-specific work).
func (d *DB) Raw() *sql.DB { return d.raw }

// Postgres reports whether the database is PostgreSQL.
func (d *DB) Postgres() bool { return d.pg }

// ExecContext runs a statement.
func (d *DB) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return d.raw.ExecContext(ctx, d.q(query), args...)
}

// QueryContext runs a query.
func (d *DB) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return d.raw.QueryContext(ctx, d.q(query), args...)
}

// QueryRowContext runs a query that returns at most one row.
func (d *DB) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return d.raw.QueryRowContext(ctx, d.q(query), args...)
}

// PrepareContext prepares a statement.
func (d *DB) PrepareContext(ctx context.Context, query string) (*sql.Stmt, error) {
	return d.raw.PrepareContext(ctx, d.q(query))
}

// Exec runs a statement (tests).
func (d *DB) Exec(query string, args ...any) (sql.Result, error) {
	return d.ExecContext(context.Background(), query, args...)
}

// QueryRow runs a single-row query (tests).
func (d *DB) QueryRow(query string, args ...any) *sql.Row {
	return d.QueryRowContext(context.Background(), query, args...)
}

// PingContext checks the connection.
func (d *DB) PingContext(ctx context.Context) error { return d.raw.PingContext(ctx) }

// Close closes the handle.
func (d *DB) Close() error { return d.raw.Close() }

// BeginTx starts a transaction.
func (d *DB) BeginTx(ctx context.Context, opts *sql.TxOptions) (*Tx, error) {
	tx, err := d.raw.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &Tx{tx: tx, db: d}, nil
}

// ExecContext runs a statement in the transaction.
func (t *Tx) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return t.tx.ExecContext(ctx, t.db.q(query), args...)
}

// QueryContext runs a query in the transaction.
func (t *Tx) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return t.tx.QueryContext(ctx, t.db.q(query), args...)
}

// QueryRowContext runs a single-row query in the transaction.
func (t *Tx) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return t.tx.QueryRowContext(ctx, t.db.q(query), args...)
}

// PrepareContext prepares a statement in the transaction.
func (t *Tx) PrepareContext(ctx context.Context, query string) (*sql.Stmt, error) {
	return t.tx.PrepareContext(ctx, t.db.q(query))
}

// Commit commits the transaction.
func (t *Tx) Commit() error { return t.tx.Commit() }

// Rollback aborts the transaction.
func (t *Tx) Rollback() error { return t.tx.Rollback() }

// queryer is a DB or a Tx.
type queryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// insertID runs an INSERT and returns the new row's id (RETURNING works in
// both databases; the PostgreSQL driver has no LastInsertId).
func insertID(ctx context.Context, q queryer, query string, args ...any) (int64, error) {
	var id int64
	err := q.QueryRowContext(ctx, query+" RETURNING id", args...).Scan(&id)
	return id, err
}

// insertRows inserts rows of width values each with multi-row INSERT
// statements (far fewer round trips than one statement per row). head is
// "INSERT INTO t (a, b, ...)", tail an optional ON CONFLICT clause; rows
// must not conflict with each other.
func insertRows(ctx context.Context, tx *Tx, head, tail string, width int, rows [][]any) error {
	// Below the parameter limits of both databases (SQLite 32766, PostgreSQL 65535).
	per := max(1, 3000/width)
	one := "(?" + strings.Repeat(", ?", width-1) + ")"
	for len(rows) > 0 {
		n := min(per, len(rows))
		var b strings.Builder
		b.Grow(len(head) + len(tail) + n*(len(one)+2) + 8)
		b.WriteString(head)
		b.WriteString(" VALUES ")
		args := make([]any, 0, n*width)
		for i := 0; i < n; i++ {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(one)
			args = append(args, rows[i]...)
		}
		if tail != "" {
			b.WriteString(" ")
			b.WriteString(tail)
		}
		if _, err := tx.ExecContext(ctx, b.String(), args...); err != nil {
			return err
		}
		rows = rows[n:]
	}
	return nil
}

// rewritePostgres converts a portable query to PostgreSQL syntax.
func rewritePostgres(query string) string {
	var b strings.Builder
	b.Grow(len(query) + 16)
	n := 0
	inString := false
	for i := 0; i < len(query); i++ {
		c := query[i]
		switch {
		case c == '\'':
			inString = !inString
			b.WriteByte(c)
		case inString:
			b.WriteByte(c)
		case c == '?':
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
		case c == ' ' && strings.HasPrefix(query[i:], " LIKE "):
			b.WriteString(" ILIKE ")
			i += len(" LIKE ") - 1
		case (c == 'G' || c == 'g') && strings.HasPrefix(strings.ToUpper(query[i:min(i+13, len(query))]), "GROUP_CONCAT(") && (i == 0 || !isIdent(query[i-1])):
			// Find the matching parenthesis.
			start := i + len("GROUP_CONCAT(")
			depth, j := 1, start
			for ; j < len(query) && depth > 0; j++ {
				switch query[j] {
				case '(':
					depth++
				case ')':
					depth--
				}
			}
			inner := rewritePostgresInner(query[start:j-1], &n)
			b.WriteString("string_agg(")
			b.WriteString(inner)
			b.WriteString(", ',')")
			i = j - 1
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// rewritePostgresInner rewrites the argument of GROUP_CONCAT, continuing
// the placeholder numbering.
func rewritePostgresInner(s string, n *int) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '?' {
			*n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(*n))
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isIdent(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// uniqueErr maps unique constraint violations of either database to ErrDuplicate.
func uniqueErr(err error) error {
	if isUniqueViolation(err) {
		return ErrDuplicate
	}
	return err
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code == "23505"
	}
	return strings.Contains(err.Error(), "UNIQUE")
}

// retryable reports whether a PostgreSQL transaction failed because of a
// deadlock or a serialization conflict and may simply be run again.
func retryable(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && (pe.Code == "40001" || pe.Code == "40P01")
}
