package web_test

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	"netio.patchman/internal/notify/email"
	"netio.patchman/internal/settings"
	"netio.patchman/internal/store"
)

// fakeSMTP accepts one unauthenticated message per connection and records
// the envelope and data.
type fakeSMTP struct {
	ln   net.Listener
	mu   sync.Mutex
	from string
	to   []string
	data string
}

func newFakeSMTP(t *testing.T) *fakeSMTP {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSMTP{ln: ln}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeSMTP) port() int { return f.ln.Addr().(*net.TCPAddr).Port }

func (f *fakeSMTP) serve(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	say := func(s string) { _, _ = c.Write([]byte(s + "\r\n")) }
	say("220 fake ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			say("250 fake")
		case strings.HasPrefix(cmd, "MAIL FROM:"):
			f.mu.Lock()
			f.from = strings.Trim(strings.TrimSpace(line)[10:], "<>")
			f.mu.Unlock()
			say("250 ok")
		case strings.HasPrefix(cmd, "RCPT TO:"):
			f.mu.Lock()
			f.to = append(f.to, strings.Trim(strings.TrimSpace(line)[8:], "<>"))
			f.mu.Unlock()
			say("250 ok")
		case cmd == "DATA":
			say("354 go ahead")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			f.mu.Lock()
			f.data = b.String()
			f.mu.Unlock()
			say("250 queued")
		case cmd == "QUIT":
			say("221 bye")
			return
		default:
			say("250 ok")
		}
	}
}

// TestServerUpdateEmail: a new product version is emailed to administrators
// once, and the email can be switched off on the settings page.
func TestServerUpdateEmail(t *testing.T) {
	e := newEnv(t)
	admin := e.client
	if status, _, _ := e.do(admin, "POST", "/setup", url.Values{"name": {"Ayşe Yılmaz"}, "email": {"ayse@example.test"},
		"password": {"çok-güçlü-parola-1"}, "password_confirm": {"çok-güçlü-parola-1"}}); status != http.StatusSeeOther {
		t.Fatalf("setup: %d", status)
	}
	check := func() {
		token := e.csrf(admin)
		e.do(admin, "POST", "/settings/system/update-check", url.Values{"_csrf": {token}})
	}
	e.latest.Store("0.3.0\n")
	check()
	check()
	e.sender.mu.Lock()
	msgs := append([]email.Message(nil), e.sender.msgs...)
	e.sender.mu.Unlock()
	if len(msgs) != 1 {
		t.Fatalf("update emails = %d, want 1", len(msgs))
	}
	m := msgs[0]
	if m.Subject != "[BİLGİ] netio.patchman 0.3.0 sürümü yayımlandı" || m.To[0].Address != "ayse@example.test" {
		t.Errorf("email: %q to %v", m.Subject, m.To)
	}
	for _, want := range []string{"0.2.0", "docker compose up -d --build", "/releases/tag/v0.3.0", "/settings/system#updates"} {
		if !strings.Contains(m.Text, want) {
			t.Errorf("email text lacks %q:\n%s", want, m.Text)
		}
	}

	// Switched off: the next version only appears in the panel.
	token := e.csrf(admin)
	status, _, _ := e.do(admin, "POST", "/settings", url.Values{"_csrf": {token}, "email_enabled": {"1"}, "email_min_severity": {"high"},
		"email_digest_threshold": {"5"}, "agent_offline_minutes": {"10"}, "agent_checkin_seconds": {"60"}, "agent_report_minutes": {"60"},
		"retention_days": {"90"}, "scan_enabled": {"1"}})
	if status != http.StatusSeeOther {
		t.Fatalf("settings save: %d", status)
	}
	e.latest.Store("0.4.0\n")
	check()
	e.sender.mu.Lock()
	n := len(e.sender.msgs)
	e.sender.mu.Unlock()
	if n != 1 {
		t.Errorf("email sent while switched off (%d)", n)
	}
	if _, body, _ := e.do(admin, "GET", "/dashboard", nil); !strings.Contains(body, "netio.patchman 0.4.0 sürümü yayımlandı") {
		t.Error("panel notice missing for 0.4.0")
	}
}

func TestSystemConfiguration(t *testing.T) {
	e := newEnvWith(t, false)
	ctx := context.Background()
	admin := e.client
	status, _, _ := e.do(admin, "POST", "/setup", url.Values{"name": {"Ayşe Yılmaz"}, "email": {"ayse@example.test"},
		"password": {"çok-güçlü-parola-1"}, "password_confirm": {"çok-güçlü-parola-1"}})
	if status != http.StatusSeeOther {
		t.Fatalf("setup: %d", status)
	}

	status, body, _ := e.do(admin, "GET", "/settings/system", nil)
	expect(t, "system page", status, 200, body, "Sunucu yapılandırması · netio.patchman", "Sunucu adresi", e.srv.URL,
		"E-posta sunucusu (SMTP)", "E-posta gönderimi kapalı", "OSV API adresi", "Başlangıç yapılandırması", "PATCHMAN_DATABASE_URL")
	if strings.Contains(body, "Ortam değişkenlerine dön") {
		t.Error("reset offered before anything was saved")
	}
	status, body, _ = e.do(admin, "GET", "/settings", nil)
	expect(t, "settings links to system page", status, 200, body, `href="/settings/system"`)

	smtp := newFakeSMTP(t)
	form := func(token string, over map[string]string) url.Values {
		v := url.Values{"_csrf": {token}, "base_url": {e.srv.URL}, "timezone": {"Europe/Istanbul"}, "log_level": {"info"},
			"smtp_host": {"127.0.0.1"}, "smtp_port": {strconv.Itoa(smtp.port())}, "smtp_username": {""},
			"smtp_from_name": {"netio.patchman"}, "smtp_from_address": {"patchman@example.test"},
			"osv_url": {e.sys.Get().OSVURL}, "kev_enabled": {"1"}, "kev_url": {e.sys.Get().KEVSourceURL},
			"update_enabled": {"1"}, "update_url": {e.sys.Get().UpdateSourceURL}}
		for k, val := range over {
			v.Set(k, val)
		}
		return v
	}

	// Invalid input is rejected with Turkish messages and the input is kept.
	token := e.csrf(admin)
	status, body, _ = e.do(admin, "POST", "/settings/system", form(token, map[string]string{
		"base_url": "patchman.example.test", "timezone": "Mars/Olympus", "smtp_from_address": "", "smtp_from_name": "x\r\nBcc: y"}))
	expect(t, "invalid system config", status, 400, body,
		"Sunucu adresi için geçerli bir http:// veya https:// adresi girin.", "Geçersiz saat dilimi: Mars/Olympus",
		"SMTP sunucusu tanımlandığında gönderen adresi zorunludur.", "satır sonu veya kontrol karakteri", `value="patchman.example.test"`)
	if raw, _ := e.st.Settings(ctx); raw[settings.KeySMTPHost] != "" {
		t.Error("invalid form was saved")
	}

	// A valid save applies at once: SMTP, base URL, time zone.
	token = e.csrf(admin)
	status, _, hdr := e.do(admin, "POST", "/settings/system", form(token, map[string]string{
		"base_url": "https://patchman.example.test/", "timezone": "UTC", "log_level": "debug", "smtp_password": "çok-gizli-parola"}))
	if status != http.StatusSeeOther || hdr.Get("Location") != "/settings/system" {
		t.Fatalf("save: %d %s", status, hdr.Get("Location"))
	}
	sys := e.sys.Get()
	if sys.BaseURLString() != "https://patchman.example.test" || sys.Timezone != "UTC" || sys.LogLevelName() != "debug" ||
		!sys.SMTP.Enabled() || sys.SMTP.Password != "çok-gizli-parola" {
		t.Fatalf("not applied: %+v", sys)
	}
	status, body, _ = e.do(admin, "GET", "/settings/system", nil)
	expect(t, "after save", status, 200, body, "Yeni sunucu adresi", "Kayıtlı parolayı korumak için boş bırakın.", "Ortam değişkenlerine dön", `value="UTC"`)
	if strings.Contains(body, "çok-gizli-parola") || strings.Contains(body, "E-posta gönderimi kapalı") {
		t.Error("password echoed or email still reported off")
	}
	status, body, _ = e.do(admin, "GET", "/agents", nil)
	expect(t, "install command uses new base URL", status, 200, body, "curl -fsSL https://patchman.example.test/downloads/install-agent.sh")

	// The test email goes through the SMTP server configured in the panel.
	token = e.csrf(admin)
	status, _, hdr = e.do(admin, "POST", "/settings/test-email", url.Values{"_csrf": {token}, "to": {"ayse@example.test"}, "back": {"/settings/system"}})
	if status != http.StatusSeeOther || hdr.Get("Location") != "/settings/system" {
		t.Fatalf("test email: %d %s", status, hdr.Get("Location"))
	}
	smtp.mu.Lock()
	from, to, data := smtp.from, smtp.to, smtp.data
	smtp.mu.Unlock()
	if from != "patchman@example.test" || len(to) != 1 || to[0] != "ayse@example.test" || !strings.Contains(data, "https://patchman.example.test") {
		t.Errorf("smtp delivery: from=%q to=%v data has link=%v", from, to, strings.Contains(data, "https://patchman.example.test"))
	}

	// A blank password keeps the stored one; the clear box removes it.
	token = e.csrf(admin)
	e.do(admin, "POST", "/settings/system", form(token, map[string]string{"base_url": "https://patchman.example.test", "timezone": "UTC"}))
	if e.sys.Get().SMTP.Password != "çok-gizli-parola" {
		t.Error("blank password field cleared the stored password")
	}
	token = e.csrf(admin)
	e.do(admin, "POST", "/settings/system", form(token, map[string]string{"base_url": "https://patchman.example.test", "timezone": "UTC", "smtp_password_clear": "1"}))
	if e.sys.Get().SMTP.Password != "" {
		t.Error("password not cleared")
	}

	// Only key names are audited, never the password.
	rows, _, _ := e.st.ListAudit(ctx, store.Page{Number: 1, Size: 50})
	found := false
	for _, a := range rows {
		if strings.Contains(a.Details, "çok-gizli") {
			t.Errorf("audit leaks password: %q", a.Details)
		}
		found = found || (a.Action == "settings.system_update" && strings.Contains(a.Details, "smtp.password"))
	}
	if !found {
		t.Error("system update not audited")
	}

	// Plain-HTTP access on another address keeps working with an HTTPS base URL
	// (the session cookie is not marked Secure there).
	status, body, _ = e.do(admin, "GET", "/dashboard", nil)
	expect(t, "dashboard after https base url", status, 200, body, "Ayşe Yılmaz")

	// Disabling KEV and reverting to the environment values.
	token = e.csrf(admin)
	e.do(admin, "POST", "/settings/system", form(token, map[string]string{"base_url": "https://patchman.example.test", "kev_enabled": ""}))
	if e.sys.Get().KEVURL != "" {
		t.Error("kev still enabled")
	}
	token = e.csrf(admin)
	status, _, _ = e.do(admin, "POST", "/settings/system/reset", url.Values{"_csrf": {token}})
	if status != http.StatusSeeOther {
		t.Fatalf("reset: %d", status)
	}
	sys = e.sys.Get()
	if sys.BaseURLString() != e.srv.URL || sys.SMTP.Enabled() || sys.KEVURL == "" || sys.Timezone != "Europe/Istanbul" {
		t.Errorf("reset did not restore env values: %+v", sys)
	}

	// New-version check: up to date, then a newer VERSION is published.
	token = e.csrf(admin)
	status, _, hdr = e.do(admin, "POST", "/settings/system/update-check", url.Values{"_csrf": {token}})
	if status != http.StatusSeeOther || hdr.Get("Location") != "/settings/system#updates" {
		t.Fatalf("update check: %d %s", status, hdr.Get("Location"))
	}
	status, body, _ = e.do(admin, "GET", "/settings/system", nil)
	expect(t, "up to date", status, 200, body, "Güncel sürümü kullanıyorsunuz (0.2.0)", `id="updates"`)
	if strings.Contains(body, "Yeni sürüm:") {
		t.Error("update offered while up to date")
	}
	e.latest.Store("0.3.0\n")
	token = e.csrf(admin)
	e.do(admin, "POST", "/settings/system/update-check", url.Values{"_csrf": {token}})
	status, body, _ = e.do(admin, "GET", "/settings/system", nil)
	expect(t, "update available", status, 200, body, "Yeni sürüm mevcut: 0.3.0 (kurulu: 0.2.0)",
		"Yeni sürüm yayımlandı: 0.3.0", "docker compose up -d --build", "Yeni sürüm: 0.3.0")
	status, body, _ = e.do(admin, "GET", "/dashboard", nil)
	expect(t, "update banner", status, 200, body, "netio.patchman 0.3.0 sürümü yayımlandı (kurulu: 0.2.0).", `href="/settings/system#updates"`)
	status, body, _ = e.do(admin, "GET", "/notifications", nil)
	expect(t, "update notification", status, 200, body, "netio.patchman 0.3.0 sürümü yayımlandı. Kurulu sürüm: 0.2.0.")
	// Turning the check off hides the notice.
	token = e.csrf(admin)
	e.do(admin, "POST", "/settings/system", form(token, map[string]string{"base_url": "https://patchman.example.test", "update_enabled": ""}))
	if e.sys.Get().UpdateURL != "" {
		t.Error("update check still enabled")
	}
	status, body, _ = e.do(admin, "GET", "/dashboard", nil)
	if strings.Contains(body, "sürümü yayımlandı (kurulu") {
		t.Error("banner shown while the check is off")
	}
	token = e.csrf(admin)
	e.do(admin, "POST", "/settings/system/reset", url.Values{"_csrf": {token}})

	// Operators cannot open the page.
	token = e.csrf(admin)
	e.do(admin, "POST", "/users", url.Values{"_csrf": {token}, "name": {"Operatör"}, "email": {"op@example.test"}, "role": {"operator"},
		"password": {"operator-parola-1"}, "password_confirm": {"operator-parola-1"}})
	op := newClient()
	if status, _, _ = e.do(op, "POST", "/login", url.Values{"email": {"op@example.test"}, "password": {"operator-parola-1"}}); status != http.StatusSeeOther {
		t.Fatalf("operator login: %d", status)
	}
	if status, _, _ = e.do(op, "GET", "/settings/system", nil); status != http.StatusForbidden {
		t.Errorf("operator system page: %d", status)
	}
	ot := e.csrf(op)
	if status, _, _ = e.do(op, "POST", "/settings/system/reset", url.Values{"_csrf": {ot}}); status != http.StatusForbidden {
		t.Errorf("operator reset: %d", status)
	}
	if status, _, _ = e.do(op, "POST", "/settings/system/update-check", url.Values{"_csrf": {ot}}); status != http.StatusForbidden {
		t.Errorf("operator update check: %d", status)
	}
	// The new-version notice is for administrators only.
	if _, body, _ = e.do(op, "GET", "/dashboard", nil); strings.Contains(body, "sürümü yayımlandı (kurulu") {
		t.Error("operator sees the update banner")
	}
}
