package web_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"netio.patchman/internal/backup"
	"netio.patchman/internal/settings"
	"netio.patchman/internal/store"
)

// hooks records requests to fake Slack, Teams, webhook and Telegram endpoints.
type hooks struct {
	srv  *httptest.Server
	mu   sync.Mutex
	reqs []hookReq
	fail atomic500
}

type atomic500 struct {
	mu sync.Mutex
	on bool
}

type hookReq struct {
	Path   string
	Header http.Header
	Body   []byte
}

func newHooks(t *testing.T) *hooks {
	h := &hooks{}
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		h.mu.Lock()
		h.reqs = append(h.reqs, hookReq{Path: r.URL.Path, Header: r.Header.Clone(), Body: b})
		h.mu.Unlock()
		h.fail.mu.Lock()
		fail := h.fail.on
		h.fail.mu.Unlock()
		if fail {
			http.Error(w, "invalid_token", http.StatusForbidden)
			return
		}
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(h.srv.Close)
	return h
}

func (h *hooks) last(path string) (hookReq, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for i := len(h.reqs) - 1; i >= 0; i-- {
		if h.reqs[i].Path == path {
			return h.reqs[i], true
		}
	}
	return hookReq{}, false
}

func (h *hooks) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.reqs)
}

func setupAdmin(t *testing.T, e *env) *http.Client {
	t.Helper()
	pw := "çok-güçlü-parola-1"
	if status, _, _ := e.do(e.client, "POST", "/setup", url.Values{"name": {"Alptekin Sünnetci"}, "email": {"ayse@example.test"}, "password": {pw}, "password_confirm": {pw}}); status != http.StatusSeeOther {
		t.Fatalf("setup: %d", status)
	}
	return e.client
}

func TestNotificationChannels(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	admin := setupAdmin(t, e)
	token := e.csrf(admin)
	base := e.hooks.srv.URL

	// Validation.
	status, body, _ := e.do(admin, "POST", "/settings/channels", url.Values{"_csrf": {token}, "type": {"slack"}, "name": {"x"}, "min_level": {"info"}, "url": {"http://hooks.example.test/x"}})
	expect(t, "slack over http", status, 400, body, "https://")
	status, body, _ = e.do(admin, "POST", "/settings/channels", url.Values{"_csrf": {token}, "type": {"telegram"}, "name": {"x"}, "min_level": {"info"}, "bot_token": {"nope"}, "chat_id": {"abc"}})
	expect(t, "telegram invalid", status, 400, body, "Bot anahtarı geçersiz", "Sohbet kimliği")

	// One channel of each type. Slack and Teams need https in production; the
	// test servers are plain http, so they are stored directly.
	for _, c := range []store.Channel{
		{Name: "Slack", Type: store.ChannelSlack, URL: base + "/slack", MinLevel: store.LevelInfo, Enabled: true},
		{Name: "Teams", Type: store.ChannelTeams, URL: base + "/teams", MinLevel: store.LevelWarning, Enabled: true},
	} {
		if _, err := e.st.CreateChannel(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	tgToken := "123456789:AAEhBP0av28jmF6P8PA9kAsdfghjklqwe"
	for _, f := range []url.Values{
		{"type": {"telegram"}, "name": {"Telegram NOC"}, "min_level": {"critical"}, "bot_token": {tgToken}, "chat_id": {"-1001234567890"}},
		{"type": {"webhook"}, "name": {"SIEM"}, "min_level": {"info"}, "url": {base + "/hook"}, "secret": {"s3cret-key"}},
	} {
		f.Set("_csrf", token)
		if status, _, _ := e.do(admin, "POST", "/settings/channels", f); status != http.StatusSeeOther {
			t.Fatalf("create %s: %d", f.Get("type"), status)
		}
	}
	_, body, _ = e.do(admin, "GET", "/settings/channels", nil)
	expect(t, "channel list", 200, 200, body, "Slack", "Microsoft Teams", "Telegram sohbeti -1001234567890", "Webhook (JSON)")
	if strings.Contains(body, tgToken) || strings.Contains(body, "/slack") {
		t.Error("channel secret shown on the page")
	}

	// Test button sends synchronously.
	chans, _ := e.st.ListChannels(ctx)
	ids := map[string]int64{}
	for _, c := range chans {
		ids[c.Name] = c.ID
	}
	status, _, _ = e.do(admin, "POST", "/settings/channels/"+itoa(ids["SIEM"])+"/test", url.Values{"_csrf": {token}})
	if status != http.StatusSeeOther {
		t.Fatalf("test: %d", status)
	}
	req, ok := e.hooks.last("/hook")
	if !ok {
		t.Fatal("webhook not called")
	}
	mac := hmac.New(sha256.New, []byte("s3cret-key"))
	mac.Write(req.Body)
	if req.Header.Get("X-Netio-Patchman-Signature") != "sha256="+hex.EncodeToString(mac.Sum(nil)) {
		t.Error("webhook signature wrong")
	}
	var payload map[string]any
	_ = json.Unmarshal(req.Body, &payload)
	if payload["kind"] != "channel_test" || payload["product"] != "netio.patchman" || !strings.Contains(payload["text"].(string), "deneme mesajı") {
		t.Errorf("webhook payload: %s", req.Body)
	}

	// Stored notifications are forwarded by level.
	e.st.OnNotification(e.channels.Enqueue)
	go e.channels.Run(ctx)
	before := e.hooks.count()
	_ = e.st.AddNotification(ctx, store.LevelCritical, "agent_offline", map[string]string{"hostname": "db-01", "last_seen": "21.11.2026 10:00"}, "/servers/1")
	waitFor(t, func() bool { return e.hooks.count() >= before+4 })
	slack, _ := e.hooks.last("/slack")
	if !strings.Contains(string(slack.Body), "db-01 sunucusundaki ajana ulaşılamıyor") || !strings.Contains(string(slack.Body), "/servers/1|Panelde aç") {
		t.Errorf("slack payload: %s", slack.Body)
	}
	teams, _ := e.hooks.last("/teams")
	if !strings.Contains(string(teams.Body), "application/vnd.microsoft.card.adaptive") || !strings.Contains(string(teams.Body), "Action.OpenUrl") {
		t.Errorf("teams payload: %s", teams.Body)
	}
	tg, ok := e.hooks.last("/bot" + tgToken + "/sendMessage")
	if !ok || !strings.Contains(string(tg.Body), `"chat_id":"-1001234567890"`) {
		t.Errorf("telegram payload: %s", tg.Body)
	}
	// Info level goes to Slack and the webhook only (Teams: warning, Telegram: critical).
	before = e.hooks.count()
	_ = e.st.AddNotification(ctx, store.LevelInfo, "agent_online", map[string]string{"hostname": "db-01"}, "/servers/1")
	waitFor(t, func() bool { return e.hooks.count() >= before+2 })
	time.Sleep(100 * time.Millisecond)
	if n := e.hooks.count() - before; n != 2 {
		t.Errorf("info notification sent %d times, want 2", n)
	}

	// A failing channel records the error without the token.
	e.hooks.fail.mu.Lock()
	e.hooks.fail.on = true
	e.hooks.fail.mu.Unlock()
	status, body, hdr := e.do(admin, "POST", "/settings/channels/"+itoa(ids["Telegram NOC"])+"/test", url.Values{"_csrf": {token}})
	if status != http.StatusSeeOther {
		t.Fatalf("failing test: %d %s", status, hdr.Get("Location"))
	}
	c, _ := e.st.ChannelByID(ctx, ids["Telegram NOC"])
	if !c.Failing() || !strings.Contains(c.LastError, "HTTP 403") || strings.Contains(c.LastError, tgToken) {
		t.Errorf("failure record: %+v", c)
	}
	_, body, _ = e.do(admin, "GET", "/settings/channels", nil)
	expect(t, "failing shown", 200, 200, body, "HTTP 403")
	if strings.Contains(body, tgToken) {
		t.Error("token leaked on failure")
	}

	// Disable and delete.
	if status, _, _ = e.do(admin, "POST", "/settings/channels/"+itoa(ids["Slack"])+"/toggle", url.Values{"_csrf": {token}}); status != http.StatusSeeOther {
		t.Fatal("toggle")
	}
	if c, _ := e.st.ChannelByID(ctx, ids["Slack"]); c.Enabled {
		t.Error("channel still enabled")
	}
	if status, _, _ = e.do(admin, "POST", "/settings/channels/"+itoa(ids["Slack"])+"/delete", url.Values{"_csrf": {token}}); status != http.StatusSeeOther {
		t.Fatal("delete")
	}
	if _, err := e.st.ChannelByID(ctx, ids["Slack"]); err == nil {
		t.Error("channel not deleted")
	}
}

func itoa(id int64) string { return strconv.FormatInt(id, 10) }

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if ok() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("timed out waiting")
}

func TestBackups(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := setupAdmin(t, e)
	token := e.csrf(admin)

	_, body, _ := e.do(admin, "GET", "/settings", nil)
	expect(t, "settings backup section", 200, 200, body, "Otomatik yedekleme", `name="backup_time" value="02:30"`, "Henüz yedek alınmadı")

	status, _, hdr := e.do(admin, "POST", "/settings/backups/run", url.Values{"_csrf": {token}})
	if status != http.StatusSeeOther {
		t.Fatalf("run: %d %s", status, hdr.Get("Location"))
	}
	files, _ := e.backups.List()
	if len(files) != 1 {
		t.Fatalf("backups: %v", files)
	}
	_, body, _ = e.do(admin, "GET", "/settings", nil)
	expect(t, "backup listed", 200, 200, body, files[0].Name, "Son yedek:")

	// Download (admin only, audited) gives a working SQLite database.
	status, data, hdr := e.do(admin, "GET", "/settings/backups/"+files[0].Name, nil)
	if status != 200 || !strings.HasPrefix(data, "SQLite format 3") || !strings.Contains(hdr.Get("Content-Disposition"), files[0].Name) {
		t.Fatalf("download: %d %q", status, hdr.Get("Content-Disposition"))
	}
	p := filepath.Join(t.TempDir(), "copy.db")
	_ = os.WriteFile(p, []byte(data), 0o600)
	db, _ := sql.Open("sqlite", p)
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n); err != nil || n != 1 {
		t.Errorf("backup content: %d %v", n, err)
	}
	db.Close()
	if status, _, _ = e.do(admin, "GET", "/settings/backups/..%2Fsecret.db", nil); status != http.StatusNotFound {
		t.Errorf("traversal: %d", status)
	}
	viewer := newClient()
	e.do(admin, "POST", "/users", url.Values{"_csrf": {token}, "name": {"İzleyici"}, "email": {"v@example.test"}, "role": {"viewer"}, "password": {"izleyici-parola-1"}, "password_confirm": {"izleyici-parola-1"}})
	e.do(viewer, "POST", "/login", url.Values{"email": {"v@example.test"}, "password": {"izleyici-parola-1"}})
	if status, _, _ = e.do(viewer, "GET", "/settings/backups/"+files[0].Name, nil); status != http.StatusForbidden {
		t.Errorf("viewer download: %d", status)
	}

	// Settings: time and retention are saved; the daily tick prunes.
	status, _, _ = e.do(admin, "POST", "/settings", url.Values{"_csrf": {token}, "email_enabled": {"1"}, "email_min_severity": {"high"},
		"email_digest_threshold": {"5"}, "agent_offline_minutes": {"10"}, "agent_checkin_seconds": {"60"}, "agent_report_minutes": {"60"},
		"retention_days": {"90"}, "scan_enabled": {"1"}, "risk_max_days": {"365"}, "backup_enabled": {"1"}, "backup_time": {"04:15"}, "backup_keep": {"1"}})
	if status != http.StatusSeeOther {
		t.Fatalf("save: %d", status)
	}
	cfg, _ := settings.Load(ctx, e.st)
	if cfg.BackupMinute != 4*60+15 || cfg.BackupKeep != 1 || !cfg.BackupEnabled {
		t.Fatalf("backup settings: %+v", cfg)
	}
	// Due tomorrow at 04:15 (display zone): the tick takes one and keeps one.
	tomorrow := time.Now().Add(24 * time.Hour)
	loc, _ := time.LoadLocation("Europe/Istanbul")
	lt := tomorrow.In(loc)
	at := time.Date(lt.Year(), lt.Month(), lt.Day(), 4, 16, 0, 0, loc)
	time.Sleep(1100 * time.Millisecond) // distinct file name (seconds)
	e.backups.Tick(ctx, at)
	files, _ = e.backups.List()
	if len(files) != 1 {
		t.Errorf("after tick keep=1: %v", files)
	}

	// A failure is notified.
	bad := &backup.Runner{Store: e.st, Dir: filepath.Join(t.TempDir(), "file"), Zone: e.backups.Zone, L: e.backups.L, Logger: e.backups.Logger, OnFailure: e.backups.OnFailure}
	_ = os.WriteFile(bad.Dir, []byte("x"), 0o600) // a file, not a directory
	if _, err := bad.Run(ctx, 3); err == nil {
		t.Fatal("backup into a file path succeeded")
	}
	bad.OnFailure(ctx, os.ErrPermission)
	_, body, _ = e.do(admin, "GET", "/notifications", nil)
	expect(t, "backup failure notification", 200, 200, body, "Otomatik veritabanı yedeği alınamadı")
	_, body, _ = e.do(admin, "GET", "/settings", nil)
	expect(t, "failure shown", 200, 200, body, "Son yedekleme denemesi başarısız oldu")
}

func TestGermanAndRussianInterface(t *testing.T) {
	e := newEnv(t)
	admin := setupAdmin(t, e)
	_, body, _ := e.do(newClient(), "GET", "/login", nil)
	expect(t, "language links", 200, 200, body, ">Deutsch</a>", ">English</a>", ">Русский</a>", "<strong>Türkçe</strong>")
	for _, tc := range []struct{ locale, lang, login, dashboard string }{
		{"de-DE", `<html lang="de">`, "Am Dashboard anmelden", "Serverinventar"},
		{"ru-RU", `<html lang="ru">`, "Вход в панель управления", "Инвентарь серверов"},
	} {
		c := newClient()
		e.do(c, "GET", "/lang?to="+tc.locale+"&next=/login", nil)
		_, body, _ = e.do(c, "GET", "/login", nil)
		expect(t, tc.locale+" login", 200, 200, body, tc.lang, tc.login)
		status, _, _ := e.do(admin, "POST", "/profile/language", url.Values{"_csrf": {e.csrf(admin)}, "locale": {tc.locale}})
		if status != http.StatusSeeOther {
			t.Fatalf("%s profile: %d", tc.locale, status)
		}
		_, body, _ = e.do(admin, "GET", "/dashboard", nil)
		expect(t, tc.locale+" dashboard", 200, 200, body, tc.lang, tc.dashboard)
		_, body, _ = e.do(admin, "GET", "/agents", nil)
		if !strings.Contains(body, "--locale "+tc.locale) {
			t.Errorf("%s install command lacks --locale", tc.locale)
		}
		// Day-first dates and ';' CSV like Turkish.
		_, body, _ = e.do(admin, "GET", "/servers.csv", nil)
		if !strings.Contains(body, ";") {
			t.Errorf("%s CSV separator", tc.locale)
		}
	}
}

func TestEnglishInterface(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	c := newClient()

	// The setup page offers English; picking it sets the cookie and keeps ?next.
	_, body, _ := e.do(c, "GET", "/setup", nil)
	expect(t, "language links", 200, 200, body, `href="/lang?to=en-US&amp;next=%2fsetup"`, "English")
	status, _, hdr := e.do(c, "GET", "/lang?to=en-US&next=/setup", nil)
	if status != http.StatusFound || hdr.Get("Location") != "/setup" {
		t.Fatalf("lang switch: %d %s", status, hdr.Get("Location"))
	}
	_, body, _ = e.do(c, "GET", "/setup", nil)
	expect(t, "english setup", 200, 200, body, `<html lang="en">`, "Create the administrator account", "Türkçe")
	pw := "very-strong-password-1"
	if status, _, _ = e.do(c, "POST", "/setup", url.Values{"name": {"Jane Admin"}, "email": {"jane@example.test"}, "password": {pw}, "password_confirm": {pw}}); status != http.StatusSeeOther {
		t.Fatalf("setup: %d", status)
	}
	if u, _ := e.st.UserByEmail(ctx, "jane@example.test"); u.Locale != "en-US" {
		t.Errorf("setup language not saved: %q", u.Locale)
	}
	_, body, _ = e.do(c, "GET", "/dashboard", nil)
	expect(t, "english dashboard", 200, 200, body, "Dashboard · netio.patchman", "Server Inventory", "Compliance Report", "No servers registered yet")
	if strings.Contains(body, "Gösterge Paneli") {
		t.Error("Turkish text on the English dashboard")
	}
	_, body, _ = e.do(c, "GET", "/agents", nil)
	if !strings.Contains(body, "--locale en-US") {
		t.Error("English install command lacks --locale")
	}
	_, body, _ = e.do(c, "GET", "/settings/channels", nil)
	expect(t, "english channels", 200, 200, body, "Notification channels", "Add channel")

	// A new browser follows the saved preference after sign-in.
	c2 := newClient()
	_, body, _ = e.do(c2, "GET", "/login", nil)
	expect(t, "default login is Turkish", 200, 200, body, "Yönetim paneline giriş yapın")
	e.do(c2, "POST", "/login", url.Values{"email": {"jane@example.test"}, "password": {pw}})
	_, body, _ = e.do(c2, "GET", "/profile", nil)
	expect(t, "english after login", 200, 200, body, "My Profile", "Interface language")
	// Switching back on the profile page.
	status, _, _ = e.do(c2, "POST", "/profile/language", url.Values{"_csrf": {e.csrf(c2)}, "locale": {"tr-TR"}})
	if status != http.StatusSeeOther {
		t.Fatalf("profile language: %d", status)
	}
	_, body, _ = e.do(c2, "GET", "/profile", nil)
	expect(t, "turkish again", 200, 200, body, "Profilim", "Arayüz dili kaydedildi.")
	if u, _ := e.st.UserByEmail(ctx, "jane@example.test"); u.Locale != "tr-TR" {
		t.Errorf("preference: %q", u.Locale)
	}
	// Unknown languages and open redirects are ignored.
	status, _, hdr = e.do(c2, "GET", "/lang?to=xx-XX&next=//evil.example", nil)
	if status != http.StatusFound || hdr.Get("Location") != "/dashboard" {
		t.Errorf("bad lang switch: %s", hdr.Get("Location"))
	}
	// Dates follow the language.
	_, body, _ = e.do(c, "GET", "/users/1", nil)
	if !regexp.MustCompile(`\d{4}-\d{2}-\d{2} \d{2}:\d{2}`).MatchString(body) {
		t.Error("English date format missing")
	}
}
