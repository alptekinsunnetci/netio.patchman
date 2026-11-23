package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"netio.patchman/internal/brand"
	"netio.patchman/internal/i18n"
	"netio.patchman/internal/settings"
	"netio.patchman/internal/store"
	"netio.patchman/internal/version"
	"netio.patchman/internal/vuln"
)

// Text renders a stored notification in l's language.
func Text(l i18n.Localizer, n store.Notification) string {
	args := make([]any, 0, len(n.Params)*2)
	for k, v := range n.Params {
		switch k {
		case "severity":
			v = l.T(vuln.Severity(v).LabelKey())
		case "job_type":
			v = l.T("job.type." + v)
		case "resource":
			v = l.T("health.resource." + v)
		case "target":
			// The file system of a disk limit, shown after the resource name.
			if v != "" {
				v = " (" + v + ")"
			}
		}
		args = append(args, k, v)
	}
	return l.T("notification."+n.Kind, args...)
}

// DefaultTelegramAPI is the Telegram Bot API base address.
const DefaultTelegramAPI = "https://api.telegram.org"

// Dispatcher forwards notifications to Slack, Microsoft Teams, Telegram and
// generic webhooks, and opens tickets in Jira, ServiceNow and GLPI or sends
// Zabbix trapper values. Notifications are queued and sent by Run; a failed
// delivery is retried three times and then recorded on the channel and in
// its delivery history (never as a new notification, so a broken channel
// cannot cause a loop).
type Dispatcher struct {
	st          *store.Store
	l           i18n.Localizer
	sys         *settings.Live
	logger      *slog.Logger
	client      *http.Client
	telegramAPI string
	retryDelays []time.Duration
	q           chan store.Notification
	// sending bounds concurrent deliveries; a channel waiting for a retry
	// does not hold up the others.
	sending chan struct{}
}

// DispatcherOptions configures a Dispatcher.
type DispatcherOptions struct {
	Store  *store.Store
	L      i18n.Localizer
	System *settings.Live // base URL for links
	Logger *slog.Logger
	// TelegramAPI replaces DefaultTelegramAPI (tests, API proxies).
	TelegramAPI string
	// RetryDelays between attempts; nil uses 5 s, 30 s and 2 min.
	RetryDelays []time.Duration
}

// NewDispatcher returns a Dispatcher; call Run to start delivery.
func NewDispatcher(o DispatcherOptions) *Dispatcher {
	d := &Dispatcher{st: o.Store, l: o.L, sys: o.System, logger: o.Logger, telegramAPI: o.TelegramAPI, retryDelays: o.RetryDelays,
		client: &http.Client{Timeout: 15 * time.Second}, q: make(chan store.Notification, 256), sending: make(chan struct{}, 8)}
	if d.telegramAPI == "" {
		d.telegramAPI = DefaultTelegramAPI
	}
	if d.retryDelays == nil {
		d.retryDelays = []time.Duration{5 * time.Second, 30 * time.Second, 2 * time.Minute}
	}
	return d
}

// Enqueue queues a notification without blocking; when the queue is full
// the notification is only kept in the notification center.
func (d *Dispatcher) Enqueue(n store.Notification) {
	select {
	case d.q <- n:
	default:
		d.logger.Warn(d.l.T("log.channel.queue_full"), slog.String("kind", n.Kind))
	}
}

// Run delivers queued notifications until ctx ends.
func (d *Dispatcher) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case n := <-d.q:
			d.deliver(ctx, n)
		}
	}
}

func (d *Dispatcher) deliver(ctx context.Context, n store.Notification) {
	chans, err := d.st.ListChannels(ctx)
	if err != nil {
		d.logger.Warn(d.l.T("log.channel.failed"), slog.String("error", err.Error()))
		return
	}
	for _, c := range chans {
		if !c.Accepts(n.Level, EventOf(n)) {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case d.sending <- struct{}{}:
		}
		go func() {
			defer func() { <-d.sending }()
			d.deliverTo(ctx, c, n)
		}()
	}
}

// deliverTo sends n to one channel with retries and records the outcome.
func (d *Dispatcher) deliverTo(ctx context.Context, c store.Channel, n store.Notification) {
	start := time.Now()
	var err error
	attempts := 0
	for attempt := 0; ; attempt++ {
		attempts++
		if err = d.Send(ctx, c, n); err == nil || attempt >= len(d.retryDelays) {
			break
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(d.retryDelays[attempt]):
		}
	}
	d.record(ctx, c, n, err, attempts, time.Since(start))
}

// record stores the outcome of a delivery on the channel and in its history.
func (d *Dispatcher) record(ctx context.Context, c store.Channel, n store.Notification, err error, attempts int, took time.Duration) {
	msg := ""
	if err != nil {
		msg = err.Error()
		d.logger.Warn(d.l.T("log.channel.failed"), slog.String("channel", c.Name), slog.String("type", c.Type), slog.String("error", msg))
	}
	_ = d.st.RecordChannelResult(ctx, c.ID, msg)
	payload, _ := json.Marshal(n)
	_ = d.st.RecordDelivery(ctx, store.Delivery{ChannelID: c.ID, Event: EventOf(n), Kind: n.Kind, OK: err == nil, Attempts: attempts,
		Error: msg, DurationMS: took.Milliseconds(), Payload: string(payload)})
}

// Resend delivers a recorded notification to a channel again, once.
func (d *Dispatcher) Resend(ctx context.Context, c store.Channel, payload string) error {
	var n store.Notification
	if err := json.Unmarshal([]byte(payload), &n); err != nil {
		return err
	}
	start := time.Now()
	err := d.Send(ctx, c, n)
	d.record(ctx, c, n, err, 1, time.Since(start))
	return err
}

// Message is the rendered notification sent to a channel.
type Message struct {
	Title string // "netio.patchman · Kritik"
	Text  string
	URL   string // absolute link into the dashboard ("" if none)
}

func (d *Dispatcher) render(n store.Notification) Message {
	m := Message{Title: brand.Name + " · " + d.l.T("level."+n.Level), Text: Text(d.l, n)}
	if n.Link != "" {
		m.URL = d.sys.Get().BaseURLString() + n.Link
	}
	return m
}

// Send delivers one notification to one channel synchronously (also used by
// the "send test message" button). Errors never contain the channel secret.
func (d *Dispatcher) Send(ctx context.Context, c store.Channel, n store.Notification) error {
	m := d.render(n)
	var body []byte
	target := c.URL
	headers := map[string]string{}
	switch c.Type {
	case store.ChannelSlack:
		text := "*" + slackEscape(m.Title) + "*\n" + slackEscape(m.Text)
		if m.URL != "" {
			text += "\n<" + m.URL + "|" + slackEscape(d.l.T("channel.open_link")) + ">"
		}
		body, _ = json.Marshal(map[string]any{"text": text})
	case store.ChannelTeams:
		card := map[string]any{
			"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4",
			"body": []any{
				map[string]any{"type": "TextBlock", "text": m.Title, "weight": "Bolder", "wrap": true},
				map[string]any{"type": "TextBlock", "text": m.Text, "wrap": true},
			},
		}
		if m.URL != "" {
			card["actions"] = []any{map[string]any{"type": "Action.OpenUrl", "title": d.l.T("channel.open_link"), "url": m.URL}}
		}
		body, _ = json.Marshal(map[string]any{"type": "message", "attachments": []any{
			map[string]any{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}}})
	case store.ChannelTelegram:
		text := m.Title + "\n" + m.Text
		if m.URL != "" {
			text += "\n" + m.URL
		}
		target = d.telegramAPI + "/bot" + c.URL + "/sendMessage"
		body, _ = json.Marshal(map[string]any{"chat_id": c.ChatID, "text": text, "disable_web_page_preview": true})
	case store.ChannelWebhook:
		body, _ = json.Marshal(map[string]any{
			"product": brand.Name, "version": version.Version, "event_id": n.ID, "event": EventOf(n), "kind": n.Kind, "level": n.Level,
			"title": m.Title, "text": m.Text, "link": n.Link, "url": m.URL, "params": n.Params,
			"created_at": n.CreatedAt.UTC().Format(time.RFC3339),
		})
		headers["X-Netio-Patchman-Event"] = n.Kind
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		headers["X-Netio-Patchman-Timestamp"] = ts
		if c.Secret != "" {
			// Body only (kept for existing receivers) and timestamp + "." + body,
			// which lets a receiver reject replays of old deliveries.
			mac := hmac.New(sha256.New, []byte(c.Secret))
			mac.Write(body)
			headers["X-Netio-Patchman-Signature"] = "sha256=" + hex.EncodeToString(mac.Sum(nil))
			mac = hmac.New(sha256.New, []byte(c.Secret))
			mac.Write([]byte(ts + "."))
			mac.Write(body)
			headers["X-Netio-Patchman-Signature-V2"] = "t=" + ts + ",sha256=" + hex.EncodeToString(mac.Sum(nil))
		}
	case store.ChannelJira, store.ChannelServiceNow, store.ChannelGLPI:
		return d.clean(c, d.ticket(ctx, c, n, m))
	case store.ChannelZabbix:
		return d.clean(c, d.zabbix(ctx, c, n, m))
	default:
		return fmt.Errorf("unknown channel type %q", c.Type)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return d.clean(c, err)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("User-Agent", brand.Name+"/"+version.Version)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return d.clean(c, err)
	}
	defer resp.Body.Close()
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return d.clean(c, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet))))
	}
	return nil
}

// clean removes the channel's secrets from an error message.
func (d *Dispatcher) clean(c store.Channel, err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	for _, secret := range []string{c.URL, c.Secret, c.Config["app_token"]} {
		if len(secret) >= 8 {
			msg = strings.ReplaceAll(msg, secret, "***")
		}
	}
	return fmt.Errorf("%s", msg)
}

// slackEscape escapes the characters Slack's mrkdwn treats as control text.
func slackEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

// TestNotification is the sample sent by the "send test message" button.
func TestNotification() store.Notification {
	return store.Notification{Level: store.LevelInfo, Kind: "channel_test", Params: map[string]string{}, Link: "/settings/channels"}
}
