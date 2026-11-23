package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Channel types.
const (
	ChannelSlack      = "slack"
	ChannelTeams      = "teams"
	ChannelTelegram   = "telegram"
	ChannelWebhook    = "webhook"
	ChannelJira       = "jira"       // opens an issue per notification
	ChannelServiceNow = "servicenow" // opens an incident (or a record of another table)
	ChannelGLPI       = "glpi"       // opens a ticket
	ChannelZabbix     = "zabbix"     // sends a trapper item value (Zabbix sender protocol)
)

// ChannelTypes lists the channel types in form order.
var ChannelTypes = []string{ChannelSlack, ChannelTeams, ChannelTelegram, ChannelWebhook, ChannelJira, ChannelServiceNow, ChannelGLPI, ChannelZabbix}

// ValidChannelType reports whether t is a known channel type.
func ValidChannelType(t string) bool {
	for _, x := range ChannelTypes {
		if x == t {
			return true
		}
	}
	return false
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
	// Events limits the channel to these event ids (see notify.EventOf);
	// empty forwards every notification at or above MinLevel.
	Events []string
	// Config holds type-specific settings (Jira project, ServiceNow table,
	// GLPI app token, Zabbix host and item key).
	Config map[string]string
}

// Accepts reports whether the channel forwards a notification of level
// with event id event: chosen events decide on their own, without them the
// minimum level does.
func (c Channel) Accepts(level, event string) bool {
	if !c.Enabled {
		return false
	}
	if len(c.Events) > 0 {
		for _, e := range c.Events {
			if e == event {
				return true
			}
		}
		return false
	}
	return LevelRank(level) >= LevelRank(c.MinLevel)
}

// Failing reports whether the last delivery attempt failed (a success
// clears the error).
func (c Channel) Failing() bool { return c.LastError != "" }

const channelCols = `id, name, type, url, secret, chat_id, min_level, enabled, created_at, last_sent_at, last_error, last_error_at, events, config`

func scanChannel(row interface{ Scan(...any) error }) (Channel, error) {
	var c Channel
	var enabled int
	var created, sent, errAt int64
	var events, config string
	err := row.Scan(&c.ID, &c.Name, &c.Type, &c.URL, &c.Secret, &c.ChatID, &c.MinLevel, &enabled, &created, &sent, &c.LastError, &errAt, &events, &config)
	if errors.Is(err, sql.ErrNoRows) {
		return c, ErrNotFound
	}
	_ = json.Unmarshal([]byte(events), &c.Events)
	_ = json.Unmarshal([]byte(config), &c.Config)
	if c.Config == nil {
		c.Config = map[string]string{}
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
	events, _ := json.Marshal(nonNil(c.Events))
	config, _ := json.Marshal(c.Config)
	if c.Config == nil {
		config = []byte(`{}`)
	}
	return insertID(ctx, s.db, `INSERT INTO notify_channels (name, type, url, secret, chat_id, min_level, enabled, created_at, events, config) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		strings.TrimSpace(c.Name), c.Type, c.URL, c.Secret, c.ChatID, c.MinLevel, boolInt(c.Enabled), now(), string(events), string(config))
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

// SetChannelFilter stores a channel's minimum level and event filter.
func (s *Store) SetChannelFilter(ctx context.Context, id int64, minLevel string, events []string) error {
	b, _ := json.Marshal(nonNil(events))
	_, err := s.db.ExecContext(ctx, `UPDATE notify_channels SET min_level = ?, events = ? WHERE id = ?`, minLevel, string(b), id)
	return err
}

// Delivery is one attempt to forward a notification to a channel.
type Delivery struct {
	ID         int64
	ChannelID  int64
	Event      string
	Kind       string
	OK         bool
	Attempts   int
	Error      string
	DurationMS int64
	Payload    string // the notification as JSON
	CreatedAt  time.Time
}

// RecordDelivery stores a delivery (errors are already free of secrets).
func (s *Store) RecordDelivery(ctx context.Context, d Delivery) error {
	_, err := insertID(ctx, s.db, `INSERT INTO channel_deliveries (channel_id, event, kind, ok, attempts, error, duration_ms, payload, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.ChannelID, d.Event, d.Kind, boolInt(d.OK), d.Attempts, truncate(d.Error, 500), d.DurationMS, truncate(d.Payload, 64<<10), now())
	return err
}

// ListDeliveries returns a channel's deliveries, newest first.
func (s *Store) ListDeliveries(ctx context.Context, channelID int64, p Page) ([]Delivery, int, error) {
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM channel_deliveries WHERE channel_id = ?`, channelID).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, channel_id, event, kind, ok, attempts, error, duration_ms, payload, created_at FROM channel_deliveries
		WHERE channel_id = ? ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?`, channelID, p.limit(), p.Offset())
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Delivery
	for rows.Next() {
		var d Delivery
		var ok int
		var at int64
		if err := rows.Scan(&d.ID, &d.ChannelID, &d.Event, &d.Kind, &ok, &d.Attempts, &d.Error, &d.DurationMS, &d.Payload, &at); err != nil {
			return nil, 0, err
		}
		d.OK, d.CreatedAt = ok == 1, fromTS(at)
		out = append(out, d)
	}
	return out, total, rows.Err()
}

// DeliveryByID returns one delivery of a channel.
func (s *Store) DeliveryByID(ctx context.Context, channelID, id int64) (Delivery, error) {
	var d Delivery
	var ok int
	var at int64
	err := s.db.QueryRowContext(ctx, `SELECT id, channel_id, event, kind, ok, attempts, error, duration_ms, payload, created_at FROM channel_deliveries
		WHERE channel_id = ? AND id = ?`, channelID, id).Scan(&d.ID, &d.ChannelID, &d.Event, &d.Kind, &ok, &d.Attempts, &d.Error, &d.DurationMS, &d.Payload, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return d, ErrNotFound
	}
	d.OK, d.CreatedAt = ok == 1, fromTS(at)
	return d, err
}

// PruneDeliveries deletes delivery history older than d.
func (s *Store) PruneDeliveries(ctx context.Context, d time.Duration) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM channel_deliveries WHERE created_at < ?`, now()-int64(d.Seconds()))
	return err
}

// Emit forwards an event to the channels without storing it in the
// notification center (frequent events such as a job starting).
func (s *Store) Emit(level, kind string, params map[string]string, link string) {
	if fn := s.notifyHook.Load(); fn != nil {
		(*fn)(Notification{CreatedAt: fromTS(now()), Level: level, Kind: kind, Params: params, Link: link})
	}
}
