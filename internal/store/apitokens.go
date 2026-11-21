package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// APIToken is a REST API key. It acts as its user (role and group limit);
// read-only keys cannot change anything.
type APIToken struct {
	ID         int64
	UserID     int64
	UserEmail  string
	Name       string
	Prefix     string // the first characters of the key, shown in lists
	ReadOnly   bool
	CreatedAt  time.Time
	ExpiresAt  time.Time // zero: no expiry
	LastUsedAt time.Time
	RevokedAt  time.Time
}

// Active reports whether the key can be used.
func (t APIToken) Active() bool {
	return t.RevokedAt.IsZero() && (t.ExpiresAt.IsZero() || time.Now().Before(t.ExpiresAt))
}

// MaxAPITokensPerUser bounds how many keys one user can have.
const MaxAPITokensPerUser = 20

// CreateAPIToken stores a key by its SHA-256 hash.
func (s *Store) CreateAPIToken(ctx context.Context, userID int64, name, hash, prefix string, readOnly bool, expires time.Time) (int64, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM api_tokens WHERE user_id = ? AND revoked_at = 0`, userID).Scan(&n); err != nil {
		return 0, err
	}
	if n >= MaxAPITokensPerUser {
		return 0, ErrLimit
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO api_tokens (user_id, name, token_hash, prefix, read_only, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		userID, truncate(strings.TrimSpace(name), 100), hash, prefix, boolInt(readOnly), now(), ts(expires))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ErrLimit is returned when a per-user limit is reached.
var ErrLimit = errors.New("store: limit reached")

const apiTokenCols = `t.id, t.user_id, u.email, t.name, t.prefix, t.read_only, t.created_at, t.expires_at, t.last_used_at, t.revoked_at`

func scanAPIToken(row interface{ Scan(...any) error }) (APIToken, error) {
	var t APIToken
	var ro int
	var c, e, l, r int64
	err := row.Scan(&t.ID, &t.UserID, &t.UserEmail, &t.Name, &t.Prefix, &ro, &c, &e, &l, &r)
	if errors.Is(err, sql.ErrNoRows) {
		return t, ErrNotFound
	}
	t.ReadOnly = ro == 1
	t.CreatedAt, t.ExpiresAt, t.LastUsedAt, t.RevokedAt = fromTS(c), fromTS(e), fromTS(l), fromTS(r)
	return t, err
}

// ListAPITokens returns a user's keys (userID 0: every user's), newest first.
func (s *Store) ListAPITokens(ctx context.Context, userID int64) ([]APIToken, error) {
	q := `SELECT ` + apiTokenCols + ` FROM api_tokens t JOIN users u ON u.id = t.user_id`
	var args []any
	if userID != 0 {
		q += ` WHERE t.user_id = ?`
		args = append(args, userID)
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY t.revoked_at <> 0, t.id DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIToken
	for rows.Next() {
		t, err := scanAPIToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeAPIToken revokes a key of a user (userID 0: any user's).
func (s *Store) RevokeAPIToken(ctx context.Context, id, userID int64) (APIToken, error) {
	q := `SELECT ` + apiTokenCols + ` FROM api_tokens t JOIN users u ON u.id = t.user_id WHERE t.id = ?`
	args := []any{id}
	if userID != 0 {
		q += ` AND t.user_id = ?`
		args = append(args, userID)
	}
	t, err := scanAPIToken(s.db.QueryRowContext(ctx, q, args...))
	if err != nil {
		return t, err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE api_tokens SET revoked_at = ? WHERE id = ? AND revoked_at = 0`, now(), id)
	return t, err
}

// APITokenUser returns an active key by hash and its enabled user, and
// records the use (at most once a minute).
func (s *Store) APITokenUser(ctx context.Context, hash string) (APIToken, User, error) {
	t, err := scanAPIToken(s.db.QueryRowContext(ctx, `SELECT `+apiTokenCols+` FROM api_tokens t JOIN users u ON u.id = t.user_id WHERE t.token_hash = ?`, hash))
	if err != nil {
		return t, User{}, err
	}
	if !t.Active() {
		return t, User{}, ErrNotFound
	}
	u, err := s.UserByID(ctx, t.UserID)
	if err != nil {
		return t, u, err
	}
	if u.Disabled {
		return t, u, ErrNotFound
	}
	if n := now(); n-ts(t.LastUsedAt) >= 60 {
		_, _ = s.db.ExecContext(ctx, `UPDATE api_tokens SET last_used_at = ? WHERE id = ?`, n, t.ID)
	}
	return t, u, nil
}
