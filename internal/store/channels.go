package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// Channel types.
const (
	ChannelSlack    = "slack"
	ChannelTeams    = "teams"
	ChannelTelegram = "telegram"
	ChannelWebhook  = "webhook"
)

// ValidChannelType reports whether t is a known channel type.
func ValidChannelType(t string) bool {
	return t == ChannelSlack || t == ChannelTeams || t == ChannelTelegram || t == ChannelWebhook
}

// LevelRank orders notification levels (info < warning < critical).
func LevelRank(level string) int {
	switch level {
	case LevelCritical:
		return 2
	case LevelWarning:
		return 1
	}
	return 0
}

// Channel is an outgoing notification destination. URL holds the webhook
// address, or the bot token for Telegram; it is a secret and never shown in
// full after it is saved.
type Channel struct {
	ID          int64
	Name        string
	Type        string
	URL         string
	Secret      string
	ChatID      string
	MinLevel    string
	Enabled     bool
	CreatedAt   time.Time
	LastSentAt  time.Time
	LastError   string
	LastErrorAt time.Time
}

// Accepts reports whether the channel forwards a notification of level.
func (c Channel) Accepts(level string) bool {
	return c.Enabled && LevelRank(level) >= LevelRank(c.MinLevel)
}

// Failing reports whether the last delivery attempt failed (a success
// clears the error).
func (c Channel) Failing() bool { return c.LastError != "" }

const channelCols = `id, name, type, url, secret, chat_id, min_level, enabled, created_at, last_sent_at, last_error, last_error_at`

func scanChannel(row interface{ Scan(...any) error }) (Channel, error) {
	var c Channel
	var enabled int
	var created, sent, errAt int64
	err := row.Scan(&c.ID, &c.Name, &c.Type, &c.URL, &c.Secret, &c.ChatID, &c.MinLevel, &enabled, &created, &sent, &c.LastError, &errAt)
	if errors.Is(err, sql.ErrNoRows) {
		return c, ErrNotFound
	}
	c.Enabled = enabled == 1
	c.CreatedAt, c.LastSentAt, c.LastErrorAt = fromTS(created), fromTS(sent), fromTS(errAt)
	return c, err
}

// ListChannels returns all channels ordered by name.
func (s *Store) ListChannels(ctx context.Context) ([]Channel, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+channelCols+` FROM notify_channels ORDER BY lower(name), name, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Channel
	for rows.Next() {
		c, err := scanChannel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ChannelByID returns one channel.
func (s *Store) ChannelByID(ctx context.Context, id int64) (Channel, error) {
	return scanChannel(s.db.QueryRowContext(ctx, `SELECT `+channelCols+` FROM notify_channels WHERE id = ?`, id))
}

// CreateChannel stores a channel.
func (s *Store) CreateChannel(ctx context.Context, c Channel) (int64, error) {
	return insertID(ctx, s.db, `INSERT INTO notify_channels (name, type, url, secret, chat_id, min_level, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		strings.TrimSpace(c.Name), c.Type, c.URL, c.Secret, c.ChatID, c.MinLevel, boolInt(c.Enabled), now())
}

// SetChannelEnabled switches a channel on or off.
func (s *Store) SetChannelEnabled(ctx context.Context, id int64, enabled bool) error {
	_, err := s.db.ExecContext(ctx, `UPDATE notify_channels SET enabled = ? WHERE id = ?`, boolInt(enabled), id)
	return err
}

// DeleteChannel removes a channel.
func (s *Store) DeleteChannel(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM notify_channels WHERE id = ?`, id)
	return err
}

// RecordChannelResult stores the outcome of a delivery (errMsg "" = success).
func (s *Store) RecordChannelResult(ctx context.Context, id int64, errMsg string) error {
	if errMsg == "" {
		_, err := s.db.ExecContext(ctx, `UPDATE notify_channels SET last_sent_at = ?, last_error = '', last_error_at = 0 WHERE id = ?`, now(), id)
		return err
	}
	_, err := s.db.ExecContext(ctx, `UPDATE notify_channels SET last_error = ?, last_error_at = ? WHERE id = ?`, truncate(errMsg, 500), now(), id)
	return err
}

// OnNotification registers a function called after every stored
// notification (for example to forward it to chat channels). It must not block.
func (s *Store) OnNotification(fn func(Notification)) { s.notifyHook.Store(&fn) }
