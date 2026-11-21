package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// Roles.
const (
	RoleAdmin    = "admin"    // everything, including users and settings
	RoleOperator = "operator" // view + start update jobs + change finding status
	RoleViewer   = "viewer"   // read-only
)

// ValidRole reports whether r is a known role.
func ValidRole(r string) bool { return r == RoleAdmin || r == RoleOperator || r == RoleViewer }

// User is a dashboard user.
type User struct {
	ID                int64
	Email             string
	Name              string
	PasswordHash      string
	Role              string
	Disabled          bool
	CreatedAt         time.Time
	LastLoginAt       time.Time
	PasswordChangedAt time.Time
	// TOTPSecret is the base32 key of an enabled authenticator ("" = off).
	TOTPSecret    string
	TOTPEnabledAt time.Time
	// Locale is the user's interface language ("" = server default).
	Locale string
}

// SetUserLocale stores the user's interface language.
func (s *Store) SetUserLocale(ctx context.Context, id int64, locale string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET locale = ? WHERE id = ?`, locale, id)
	return err
}

// MFAEnabled reports whether the user signs in with a second factor.
func (u User) MFAEnabled() bool { return u.TOTPSecret != "" }

// CanOperate reports whether the user may start jobs and change findings.
func (u User) CanOperate() bool { return u.Role == RoleAdmin || u.Role == RoleOperator }

// IsAdmin reports whether the user is an administrator.
func (u User) IsAdmin() bool { return u.Role == RoleAdmin }

const userCols = `id, email, name, password_hash, role, disabled, created_at, last_login_at, password_changed_at, totp_secret, totp_enabled_at, locale`

func scanUser(row interface{ Scan(...any) error }) (User, error) {
	var u User
	var disabled int
	var created, lastLogin, changed, totpAt int64
	err := row.Scan(&u.ID, &u.Email, &u.Name, &u.PasswordHash, &u.Role, &disabled, &created, &lastLogin, &changed, &u.TOTPSecret, &totpAt, &u.Locale)
	if errors.Is(err, sql.ErrNoRows) {
		return u, ErrNotFound
	}
	u.Disabled = disabled == 1
	u.CreatedAt, u.LastLoginAt, u.PasswordChangedAt, u.TOTPEnabledAt = fromTS(created), fromTS(lastLogin), fromTS(changed), fromTS(totpAt)
	return u, err
}

// EnableTOTP turns on two-factor authentication with a verified secret and
// replaces the recovery codes (SHA-256 hashes). The verified step counts as
// used. Other sessions of the user are ended.
func (s *Store) EnableTOTP(ctx context.Context, id int64, secret string, usedStep int64, recoveryHashes []string, keepSessionHash string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE users SET totp_secret = ?, totp_enabled_at = ?, totp_last_step = ? WHERE id = ?`, secret, now(), usedStep, id); err != nil {
			return err
		}
		if err := replaceRecoveryCodes(ctx, tx, id, recoveryHashes); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ? AND token_hash <> ?`, id, keepSessionHash)
		return err
	})
}

// ReplaceRecoveryCodes stores a new set of recovery code hashes.
func (s *Store) ReplaceRecoveryCodes(ctx context.Context, id int64, hashes []string) error {
	return s.tx(ctx, func(tx *sql.Tx) error { return replaceRecoveryCodes(ctx, tx, id, hashes) })
}

func replaceRecoveryCodes(ctx context.Context, tx *sql.Tx, id int64, hashes []string) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_recovery_codes WHERE user_id = ?`, id); err != nil {
		return err
	}
	for _, h := range hashes {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO user_recovery_codes (user_id, code_hash) VALUES (?, ?)`, id, h); err != nil {
			return err
		}
	}
	return nil
}

// DisableTOTP turns off two-factor authentication, removes recovery codes and
// ends the user's sessions except keepSessionHash ("" ends all).
func (s *Store) DisableTOTP(ctx context.Context, id int64, keepSessionHash string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE users SET totp_secret = '', totp_enabled_at = 0, totp_last_step = 0 WHERE id = ?`, id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM user_recovery_codes WHERE user_id = ?`, id); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ? AND token_hash <> ?`, id, keepSessionHash)
		return err
	})
}

// UseTOTPStep records a verified time step. It returns false when the step
// (or a later one) was already used, which rejects replayed codes.
func (s *Store) UseTOTPStep(ctx context.Context, id, step int64) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET totp_last_step = ? WHERE id = ? AND totp_secret <> '' AND totp_last_step < ?`, step, id, step)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// UseRecoveryCode consumes a recovery code by its hash.
func (s *Store) UseRecoveryCode(ctx context.Context, id int64, hash string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM user_recovery_codes WHERE user_id = ? AND code_hash = ?`, id, hash)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// RecoveryCodesLeft returns the number of unused recovery codes.
func (s *Store) RecoveryCodesLeft(ctx context.Context, id int64) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_recovery_codes WHERE user_id = ?`, id).Scan(&n)
	return n, err
}

// CountUsers returns the number of users.
func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// CountActiveAdmins returns the number of enabled administrators.
func (s *Store) CountActiveAdmins(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = 0`).Scan(&n)
	return n, err
}

// CreateUser inserts a user and returns its ID.
func (s *Store) CreateUser(ctx context.Context, u User) (int64, error) {
	n := now()
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO users (email, name, password_hash, role, disabled, created_at, password_changed_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		strings.TrimSpace(u.Email), strings.TrimSpace(u.Name), u.PasswordHash, u.Role, boolInt(u.Disabled), n, n)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return 0, ErrDuplicate
		}
		return 0, err
	}
	return res.LastInsertId()
}

// ErrDuplicate is returned on unique constraint violations.
var ErrDuplicate = errors.New("store: duplicate")

// UserByID returns a user.
func (s *Store) UserByID(ctx context.Context, id int64) (User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id = ?`, id))
}

// UserByEmail returns a user by email (case-insensitive).
func (s *Store) UserByEmail(ctx context.Context, email string) (User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE email = ?`, strings.TrimSpace(email)))
}

// ListUsers returns all users ordered by name.
func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+userCols+` FROM users ORDER BY name COLLATE NOCASE, email`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// ActiveAdminEmails returns emails of enabled administrators.
func (s *Store) ActiveAdminEmails(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT email FROM users WHERE role = 'admin' AND disabled = 0 ORDER BY email`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var e string
		if err := rows.Scan(&e); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// UpdateUser changes name, role and disabled state. Disabling a user also
// ends their sessions.
func (s *Store) UpdateUser(ctx context.Context, id int64, name, role string, disabled bool) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE users SET name = ?, role = ?, disabled = ? WHERE id = ?`, strings.TrimSpace(name), role, boolInt(disabled), id); err != nil {
			return err
		}
		if disabled {
			_, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, id)
			return err
		}
		return nil
	})
}

// SetPassword replaces a user's password hash and ends all their sessions
// except keepSession (pass "" to end all).
func (s *Store) SetPassword(ctx context.Context, id int64, hash, keepSessionHash string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE users SET password_hash = ?, password_changed_at = ? WHERE id = ?`, hash, now(), id); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ? AND token_hash <> ?`, id, keepSessionHash)
		return err
	})
}

// DeleteUser removes a user.
func (s *Store) DeleteUser(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	return err
}

// TouchLogin records a successful login.
func (s *Store) TouchLogin(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET last_login_at = ? WHERE id = ?`, now(), id)
	return err
}

// Session is a login session. The raw token is only in the cookie.
type Session struct {
	TokenHash  string
	UserID     int64
	CSRFToken  string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastSeenAt time.Time
}

// CreateSession stores a session.
func (s *Store) CreateSession(ctx context.Context, sess Session, ip, userAgent string) error {
	n := now()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (token_hash, user_id, csrf_token, created_at, expires_at, last_seen_at, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		sess.TokenHash, sess.UserID, sess.CSRFToken, n, ts(sess.ExpiresAt), n, ip, truncate(userAgent, 300))
	return err
}

// SessionWithUser returns a valid (unexpired) session and its enabled user.
func (s *Store) SessionWithUser(ctx context.Context, tokenHash string) (Session, User, error) {
	var sess Session
	var created, expires, seen int64
	err := s.db.QueryRowContext(ctx,
		`SELECT token_hash, user_id, csrf_token, created_at, expires_at, last_seen_at FROM sessions WHERE token_hash = ? AND expires_at > ?`,
		tokenHash, now()).Scan(&sess.TokenHash, &sess.UserID, &sess.CSRFToken, &created, &expires, &seen)
	if errors.Is(err, sql.ErrNoRows) {
		return sess, User{}, ErrNotFound
	}
	if err != nil {
		return sess, User{}, err
	}
	sess.CreatedAt, sess.ExpiresAt, sess.LastSeenAt = fromTS(created), fromTS(expires), fromTS(seen)
	u, err := s.UserByID(ctx, sess.UserID)
	if err != nil {
		return sess, u, err
	}
	if u.Disabled {
		return sess, u, ErrNotFound
	}
	return sess, u, nil
}

// TouchSession extends a session's sliding expiry.
func (s *Store) TouchSession(ctx context.Context, tokenHash string, expires time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET last_seen_at = ?, expires_at = ? WHERE token_hash = ?`, now(), ts(expires), tokenHash)
	return err
}

// DeleteSession ends a session.
func (s *Store) DeleteSession(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, tokenHash)
	return err
}

// DeleteExpiredSessions removes expired sessions.
func (s *Store) DeleteExpiredSessions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, now())
	return err
}

// AuditEntry is an audit log record.
type AuditEntry struct {
	ID        int64
	At        time.Time
	UserID    int64
	UserEmail string
	Action    string // stable English identifier, e.g. "user.create"
	Target    string
	Details   string
	IP        string
}

// Audit appends an audit log record. Errors are returned but callers usually
// only log them.
func (s *Store) Audit(ctx context.Context, e AuditEntry) error {
	var uid any
	if e.UserID != 0 {
		uid = e.UserID
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO audit_log (at, user_id, user_email, action, target, details, ip) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		now(), uid, e.UserEmail, e.Action, truncate(e.Target, 500), truncate(e.Details, 2000), e.IP)
	return err
}

// ListAudit returns audit records, newest first.
func (s *Store) ListAudit(ctx context.Context, p Page) ([]AuditEntry, int, error) {
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, at, COALESCE(user_id, 0), user_email, action, target, details, ip FROM audit_log ORDER BY id DESC LIMIT ? OFFSET ?`,
		p.limit(), p.Offset())
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var at int64
		if err := rows.Scan(&e.ID, &at, &e.UserID, &e.UserEmail, &e.Action, &e.Target, &e.Details, &e.IP); err != nil {
			return nil, 0, err
		}
		e.At = fromTS(at)
		out = append(out, e)
	}
	return out, total, rows.Err()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// cut on a rune boundary
	for n > 0 && n < len(s) && (s[n]&0xC0) == 0x80 {
		n--
	}
	return s[:n]
}
