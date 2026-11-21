package web_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/mail"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	agentdist "netio.patchman/deploy/agent"
	"netio.patchman/internal/agent"
	"netio.patchman/internal/api"
	"netio.patchman/internal/backup"
	"netio.patchman/internal/config"
	"netio.patchman/internal/i18n"
	"netio.patchman/internal/notify"
	"netio.patchman/internal/notify/email"
	"netio.patchman/internal/protocol"
	"netio.patchman/internal/release"
	"netio.patchman/internal/scanner"
	"netio.patchman/internal/settings"
	"netio.patchman/internal/store"
	"netio.patchman/internal/timeutil"
	"netio.patchman/internal/updatecheck"
	"netio.patchman/internal/web"
)

const fakeAgentBinary = "fake-agent-binary-9.9.9"

const cveDescription = "A crafted certificate can cause a heap overflow in the X.509 parser, leading to remote code execution."

// fakeOSV serves the subset of the OSV API used by the scanner.
func fakeOSV(t *testing.T) *httptest.Server {
	records := map[string]string{
		"DEBIAN-CVE-2026-0001": `{"id":"DEBIAN-CVE-2026-0001","modified":"2026-11-01T00:00:00Z","upstream":["CVE-2026-0001"],
			"details":"debian tracker text",
			"affected":[{"package":{"name":"openssl","ecosystem":"Debian:12"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.0.17-1~deb12u1"}]}]}]}`,
		"CVE-2026-0001": `{"id":"CVE-2026-0001","modified":"2026-11-01T00:00:00Z","published":"2026-10-30T10:00:00Z",
			"summary":"Heap overflow in X.509 parser","details":"` + cveDescription + `",
			"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
			"references":[{"type":"ADVISORY","url":"https://security-tracker.debian.org/tracker/CVE-2026-0001"}]}`,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Queries []struct {
				Package struct{ Name, Ecosystem string } `json:"package"`
				Version string                           `json:"version"`
			} `json:"queries"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		type vref struct {
			ID       string `json:"id"`
			Modified string `json:"modified"`
		}
		type result struct {
			Vulns []vref `json:"vulns,omitempty"`
		}
		out := struct {
			Results []result `json:"results"`
		}{}
		for _, q := range req.Queries {
			var res result
			if q.Package.Ecosystem == "Debian:12" && q.Package.Name == "openssl" && q.Version == "3.0.11-1~deb12u2" {
				res.Vulns = []vref{{"DEBIAN-CVE-2026-0001", "2026-11-01T00:00:00Z"}}
			}
			out.Results = append(out.Results, res)
		}
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("GET /v1/vulns/{id}", func(w http.ResponseWriter, r *http.Request) {
		rec, ok := records[r.PathValue("id")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, rec)
	})
	// Microsoft Security Update Guide: KB5044281 fixes CVE-2026-0002.
	mux.HandleFunc("GET /msrc/affectedProduct", func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Query().Get("$filter"), "'5044281'") {
			_, _ = io.WriteString(w, `{"value":[]}`)
			return
		}
		_, _ = io.WriteString(w, `{"value":[{"cveNumber":"CVE-2026-0002","severity":"Critical","baseScore":"9.8","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",`+
			`"kbArticles":[{"articleName":"5044281","supercedence":"5042881","fixedBuildNumber":"10.0.20348.2762"}]}]}`)
	})
	mux.HandleFunc("GET /msrc/vulnerability", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"value":[{"cveNumber":"CVE-2026-0002","cveTitle":"Windows TCP/IP Remote Code Execution Vulnerability","releaseDate":"2026-11-10T08:00:00-08:00"}]}`)
	})
	mux.HandleFunc("GET /kev.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"vulnerabilities":[{"cveID":"CVE-2026-0001","dateAdded":"2026-11-02","dueDate":"2026-11-23","knownRansomwareCampaignUse":"Unknown"}]}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

type captureSender struct {
	mu   sync.Mutex
	msgs []email.Message
}

func (c *captureSender) Send(m email.Message) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.msgs = append(c.msgs, m)
	return nil
}

type env struct {
	t        *testing.T
	srv      *httptest.Server
	st       *store.Store
	scan     *scanner.Scanner
	notifier *notify.Notifier
	sys      *settings.Live
	sender   *captureSender
	client   *http.Client
	updates  *updatecheck.Checker
	latest   atomic.Value // VERSION served by the fake repository
	backups  *backup.Runner
	channels *notify.Dispatcher
	telegram string // fake Telegram API base
	hooks    *hooks // records webhook and Telegram requests
}

func newEnv(t *testing.T) *env { return newEnvWith(t, true) }

// newEnvWith builds a test site; without capture, email goes through the
// SMTP settings of the server configuration.
func newEnvWith(t *testing.T, capture bool) *env {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir()+"/test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	l := i18n.MustLoad().Localizer(i18n.DefaultLocale)
	loc, _ := time.LoadLocation(timeutil.DefaultTimezone)
	f := timeutil.NewFormatter(loc, l)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	osv := fakeOSV(t)

	e := &env{t: t, st: st, sender: &captureSender{}}
	e.latest.Store("0.2.0\n")
	repo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, e.latest.Load().(string))
	}))
	t.Cleanup(repo.Close)
	renderer, err := email.NewRenderer(l, f, mail.Address{Name: "netio.patchman", Address: "patchman@example.test"})
	if err != nil {
		t.Fatal(err)
	}
	// The site URL is only known after the server starts; handlers read it lazily.
	base, _ := url.Parse("http://placeholder")
	e.sys, err = settings.NewLive(ctx, config.Config{
		BaseURL: base, TimezoneName: timeutil.DefaultTimezone, Timezone: loc, LogLevel: slog.LevelInfo,
		OSVURL: osv.URL, KEVURL: osv.URL + "/kev.json", MSRCURL: osv.URL + "/msrc", UpdateURL: repo.URL + "/VERSION",
		SMTP: config.SMTP{Port: 587, From: mail.Address{Name: "netio.patchman", Address: "patchman@example.test"}},
	}, st)
	if err != nil {
		t.Fatal(err)
	}
	e.sys.OnChange(func(_, cur settings.System) { f.Zone().Set(cur.Location) })
	var sender notify.Sender
	if capture {
		sender = e.sender
	}
	e.notifier = notify.New(notify.Options{Store: st, L: l, F: f, Logger: logger, System: e.sys, Renderer: renderer, Sender: sender})
	e.scan = scanner.New(scanner.Options{Store: st, OSV: scanner.NewOSVClient(osv.URL), System: e.sys, Logger: logger, L: l})

	// Agent distribution directory with a newer agent release.
	dist := t.TempDir()
	if err := os.WriteFile(dist+"/netio-patchman-agent-linux-amd64", []byte(fakeAgentBinary), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dist+"/netio-patchman-agent-windows-amd64.exe", []byte("MZ windows agent"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dist+"/version", []byte("9.9.9\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rel := release.Load(dist, "test")

	apiSrv := api.New(api.Options{Store: st, L: l, Logger: logger, Scanner: e.scan, Notifier: e.notifier, Assets: agentdist.Assets(), AgentDistDir: dist, Release: rel, System: e.sys})
	e.updates = updatecheck.New(ctx, updatecheck.Options{Current: "0.2.0", Store: st, System: e.sys, Logger: logger, L: l,
		OnNewVersion: func(ctx context.Context, s updatecheck.Status) {
			e.notifier.ServerUpdate(ctx, s.Current, s.Latest, s.ChangesURL())
		}})
	e.backups = &backup.Runner{Store: st, Dir: t.TempDir(), Zone: f.Zone(), L: l, Logger: logger, OnFailure: e.notifier.BackupFailed}
	e.hooks = newHooks(t)
	e.telegram = e.hooks.srv.URL
	e.channels = notify.NewDispatcher(notify.DispatcherOptions{Store: st, L: l, System: e.sys, Logger: logger, TelegramAPI: e.telegram, RetryDelays: []time.Duration{}})
	site, err := web.New(web.Options{Store: st, Localizer: l, Formatter: f, Logger: logger, Scanner: e.scan, Notifier: e.notifier, System: e.sys, API: apiSrv, Release: rel, Updates: e.updates,
		Bundle: i18n.MustLoad(), Backups: e.backups, Channels: e.channels})
	if err != nil {
		t.Fatal(err)
	}
	e.srv = httptest.NewServer(site.Handler())
	t.Cleanup(e.srv.Close)
	*base = *mustURL(e.srv.URL)
	e.client = newClient()
	return e
}

func mustURL(s string) *url.URL {
	u, _ := url.Parse(s)
	return u
}

func newClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (e *env) do(c *http.Client, method, path string, form url.Values) (int, string, http.Header) {
	e.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := c.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header
}

var csrfRE = regexp.MustCompile(`name="_csrf" value="([^"]+)"`)

func (e *env) csrf(c *http.Client) string {
	e.t.Helper()
	_, body, _ := e.do(c, "GET", "/profile", nil)
	m := csrfRE.FindStringSubmatch(body)
	if m == nil {
		e.t.Fatalf("no csrf token in page")
	}
	return m[1]
}

func expect(t *testing.T, what string, status, want int, body string, contains ...string) {
	t.Helper()
	if status != want {
		t.Errorf("%s: status %d, want %d", what, status, want)
	}
	for _, s := range contains {
		if !strings.Contains(body, s) {
			t.Errorf("%s: body missing %q", what, s)
		}
	}
}

func TestEndToEnd(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	admin := e.client

	// First run redirects to setup.
	status, _, hdr := e.do(admin, "GET", "/dashboard", nil)
	if status != http.StatusFound || hdr.Get("Location") != "/setup" {
		t.Fatalf("first run: %d %s", status, hdr.Get("Location"))
	}
	status, body, _ := e.do(admin, "GET", "/setup", nil)
	expect(t, "setup page", status, 200, body, `<html lang="tr">`, "İlk Kurulum · netio.patchman", "Yönetici hesabını oluşturun")
	status, body, _ = e.do(admin, "POST", "/setup", url.Values{"name": {"Ayşe Yılmaz"}, "email": {"ayse@example.test"}, "password": {"kısa"}, "password_confirm": {"kısa"}})
	expect(t, "weak password", status, 400, body, "Parola en az 10 karakter olmalıdır.")
	status, _, _ = e.do(admin, "POST", "/setup", url.Values{"name": {"Ayşe Yılmaz"}, "email": {"ayse@example.test"}, "password": {"çok-güçlü-parola-1"}, "password_confirm": {"çok-güçlü-parola-1"}})
	if status != http.StatusSeeOther {
		t.Fatalf("setup submit: %d", status)
	}
	status, body, _ = e.do(admin, "GET", "/dashboard", nil)
	expect(t, "empty dashboard", status, 200, body, "Gösterge Paneli · netio.patchman", "Henüz kayıtlı sunucu yok", "Ayşe Yılmaz")

	// Setup is closed once a user exists.
	status, _, hdr = e.do(newClient(), "GET", "/setup", nil)
	if status != http.StatusFound || hdr.Get("Location") != "/login" {
		t.Errorf("setup after first user: %d %s", status, hdr.Get("Location"))
	}

	// CSRF protection.
	status, body, _ = e.do(admin, "POST", "/agents/tokens", url.Values{"name": {"x"}})
	expect(t, "missing csrf", status, 403, body, "İstek doğrulanamadı")

	// Enrollment token, shown once.
	token := e.csrf(admin)
	status, body, _ = e.do(admin, "POST", "/agents/tokens", url.Values{"_csrf": {token}, "name": {"Üretim"}, "valid_days": {"7"}, "max_uses": {"0"}})
	expect(t, "token create", status, 200, body, "yalnızca şimdi gösterilir", "/downloads/install-agent.sh")
	m := regexp.MustCompile(`value="([^"]+)" readonly id="new-token"`).FindStringSubmatch(body)
	if m == nil {
		t.Fatal("token not shown")
	}
	enrollToken := html.UnescapeString(m[1])
	// Install command picker: Ubuntu defaults to sudo; RHEL-family runs as root
	// with curl; Debian and Alpine use wget.
	page := html.UnescapeString(body)
	base := e.srv.URL
	for _, want := range []string{
		">curl -fsSL " + base + "/downloads/install-agent.sh | sudo sh -s -- --server-url " + base + " --token " + enrollToken + "</textarea>",
		`value="rhel" data-root="curl -fsSL ` + base + "/downloads/install-agent.sh | sh -s -- --server-url " + base + " --token " + enrollToken + `"`,
		`value="debian" data-root="wget -qO- ` + base + "/downloads/install-agent.sh | sh -s --",
		`value="alpine" data-root="wget -qO- `,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("install command picker: missing %q", want)
		}
	}

	// Agent registration with a wrong and a valid token.
	client, err := agent.NewClient(agent.Config{ServerURL: mustURL(e.srv.URL)})
	if err != nil {
		t.Fatal(err)
	}
	info := protocol.HostInfo{Hostname: "web-01", MachineID: "abc123", OSID: "debian", OSVersionID: "12", OSVersion: "12 (bookworm)",
		OSName: "Debian GNU/Linux 12 (bookworm)", Kernel: "6.1.0-25-amd64", Arch: "amd64", PackageManager: "apt", AgentVersion: "test", RemoteUpdates: true,
		IPAddresses: []string{"10.0.0.11"}}
	if _, err := client.Register(ctx, "npe_wrong", info); err == nil || !strings.Contains(err.Error(), "Kayıt anahtarı geçersiz") {
		t.Errorf("invalid token accepted or error not Turkish: %v", err)
	}
	reg, err := client.Register(ctx, enrollToken, info)
	if err != nil {
		t.Fatal(err)
	}
	client.SetSecret(reg.AgentSecret)

	report := protocol.Report{Host: info, CollectedAt: timeutil.Now(),
		Packages: []protocol.Package{
			{Name: "libssl3", Version: "3.0.11-1~deb12u2", Arch: "amd64", SourceName: "openssl", SourceVersion: "3.0.11-1~deb12u2"},
			{Name: "openssl", Version: "3.0.11-1~deb12u2", Arch: "amd64", SourceName: "openssl", SourceVersion: "3.0.11-1~deb12u2"},
			{Name: "bash", Version: "5.2.15-2+b7", Arch: "amd64", SourceName: "bash", SourceVersion: "5.2.15-2"},
		},
		Updates: []protocol.Update{
			{Name: "libssl3", CurrentVersion: "3.0.11-1~deb12u2", AvailableVersion: "3.0.17-1~deb12u1", Repository: "Debian-Security:12/stable-security", Security: true},
			{Name: "openssl", CurrentVersion: "3.0.11-1~deb12u2", AvailableVersion: "3.0.17-1~deb12u1", Repository: "Debian-Security:12/stable-security", Security: true},
		},
		RebootRequired: true,
	}
	if err := client.Report(ctx, report); err != nil {
		t.Fatal(err)
	}

	// Scan, KEV and alerts.
	if err := e.scan.RefreshKEV(ctx); err != nil {
		t.Fatal(err)
	}
	if err := e.scan.ScanHost(ctx, reg.HostID); err != nil {
		t.Fatal(err)
	}
	e.notifier.ProcessAlerts(ctx)

	status, body, _ = e.do(admin, "GET", "/vulnerabilities", nil)
	expect(t, "vulnerabilities", status, 200, body, "CVE-2026-0001", "Heap overflow in X.509 parser", "Kritik", "KEV", "openssl")
	status, body, _ = e.do(admin, "GET", "/vulnerabilities/CVE-2026-0001", nil)
	expect(t, "vulnerability detail", status, 200, body,
		cveDescription, `lang="en"`, "Önem Derecesi", "CVSS Puanı", "9.8", "Etkilenen Sunucular", "Kurulu Sürüm", "Düzeltilmiş Sürüm",
		"3.0.17-1~deb12u1", "İlk Tespit Tarihi", "Son Kontrol Tarihi", "Güvenlik Önerisi", "İstismar Ediliyor mu?", "Çözüm Durumu",
		"openssl paketini 3.0.17-1~deb12u1 veya daha yeni bir sürüme güncelleyin.", "web-01")
	status, body, _ = e.do(admin, "GET", "/servers/1", nil)
	expect(t, "server detail", status, 200, body, "web-01", "Yeniden başlatma gerekli", "CVE-2026-0001")
	status, body, _ = e.do(admin, "GET", "/dashboard", nil)
	expect(t, "dashboard", status, 200, body, "Kritik Güvenlik Açığı", "web-01", "İstismar Edilen Açık")
	status, body, _ = e.do(admin, "GET", "/notifications", nil)
	expect(t, "notifications", status, 200, body, "CVE-2026-0001 (Kritik) güvenlik açığı 1 sunucuda tespit edildi", "web-01 sunucusu sisteme eklendi.")
	status, body, _ = e.do(admin, "GET", "/vulnerabilities.csv", nil)
	expect(t, "csv", status, 200, body, "\xEF\xBB\xBFCVE Numarası;", "CVE-2026-0001;Heap overflow in X.509 parser;Kritik;9.8;Evet;web-01;openssl")

	if len(e.sender.msgs) != 1 {
		t.Fatalf("expected 1 email, got %d", len(e.sender.msgs))
	}
	msg := e.sender.msgs[0]
	if msg.Subject != "[KRİTİK] CVE-2026-0001 - 1 sunucuda güvenlik açığı tespit edildi" {
		t.Errorf("email subject: %q", msg.Subject)
	}
	if !strings.Contains(msg.Text, cveDescription) || !strings.Contains(msg.Text, "web-01") || !strings.Contains(msg.Text, "İstismar Ediliyor mu?: Evet") {
		t.Errorf("email body:\n%s", msg.Text)
	}
	if msg.To[0].Address != "ayse@example.test" {
		t.Errorf("default recipients must be admins: %v", msg.To)
	}
	// Alerts are sent once.
	e.notifier.ProcessAlerts(ctx)
	if len(e.sender.msgs) != 1 {
		t.Errorf("duplicate alert email")
	}

	// Remediation queues a job for the binary packages built from the source package.
	token = e.csrf(admin)
	status, _, _ = e.do(admin, "POST", "/vulnerabilities/CVE-2026-0001/remediate", url.Values{"_csrf": {token}})
	if status != http.StatusSeeOther {
		t.Fatalf("remediate: %d", status)
	}
	resp, err := client.Checkin(ctx, info)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Jobs) != 1 || resp.Jobs[0].Type != protocol.JobUpgradePackages || strings.Join(resp.Jobs[0].Packages, ",") != "libssl3,openssl" {
		t.Fatalf("dispatched jobs: %+v", resp.Jobs)
	}
	jobID := resp.Jobs[0].ID
	if err := client.JobResult(ctx, jobID, protocol.JobResult{Succeeded: true, Output: "Setting up libssl3 (3.0.17-1~deb12u1) ...", StartedAt: timeutil.Now(), FinishedAt: timeutil.Now()}); err != nil {
		t.Fatal(err)
	}
	status, body, _ = e.do(admin, "GET", "/jobs/1", nil)
	expect(t, "job detail", status, 200, body, "Başarılı", "Setting up libssl3", "Seçili paket güncellemesi")

	// A job that left packages behind is partial; retrying queues only those.
	token = e.csrf(admin)
	if status, _, _ = e.do(admin, "POST", "/servers/1/jobs", url.Values{"_csrf": {token}, "type": {"upgrade_security"}}); status != http.StatusSeeOther {
		t.Fatalf("security job: %d", status)
	}
	resp, _ = client.Checkin(ctx, info)
	if len(resp.Jobs) != 1 {
		t.Fatalf("security job not dispatched: %+v", resp.Jobs)
	}
	partialID := strconv.FormatInt(resp.Jobs[0].ID, 10)
	_ = client.JobResult(ctx, resp.Jobs[0].ID, protocol.JobResult{Succeeded: true, Remaining: []string{"openssl"}, Output: "[netio.patchman] 2 paketten 1 tanesi güncellendi."})
	status, body, _ = e.do(admin, "GET", "/jobs/"+partialID, nil)
	expect(t, "partial job", status, 200, body, "Kısmen başarılı", "Güncellenemeyen paketler", "Kalanları yeniden dene")
	status, body, _ = e.do(admin, "GET", "/notifications", nil)
	expect(t, "partial notification", status, 200, body, "#"+partialID+" numaralı iş kısmen tamamlandı", "Kalanlar: openssl")
	token = e.csrf(admin)
	if status, _, _ = e.do(admin, "POST", "/jobs/"+partialID+"/retry", url.Values{"_csrf": {token}}); status != http.StatusSeeOther {
		t.Fatalf("retry: %d", status)
	}
	resp, _ = client.Checkin(ctx, info)
	if len(resp.Jobs) != 1 || resp.Jobs[0].Type != protocol.JobUpgradePackages || strings.Join(resp.Jobs[0].Packages, ",") != "openssl" {
		t.Fatalf("retry job: %+v", resp.Jobs)
	}
	_ = client.JobResult(ctx, resp.Jobs[0].ID, protocol.JobResult{Succeeded: true})

	// Services that need a restart are listed and can be restarted; a reboot can be queued once.
	report.RestartServices = []string{"cron.service", "nginx.service", "bad name"}
	if err := client.Report(ctx, report); err != nil {
		t.Fatal(err)
	}
	status, body, _ = e.do(admin, "GET", "/servers/1", nil)
	expect(t, "restart services", status, 200, body, "Yeniden başlatılması gereken servisler (2)", "nginx.service", "Seçili servisleri yeniden başlat")
	token = e.csrf(admin)
	e.do(admin, "POST", "/servers/1/jobs", url.Values{"_csrf": {token}, "type": {"restart_services"}, "packages": {"nginx.service"}})
	if status, _, _ = e.do(admin, "POST", "/servers/1/jobs", url.Values{"_csrf": {token}, "type": {"restart_services"}, "packages": {"--now"}}); status != http.StatusSeeOther {
		t.Fatalf("invalid service: %d", status)
	}
	e.do(admin, "POST", "/servers/1/jobs", url.Values{"_csrf": {token}, "type": {"reboot"}})
	_, body, _ = e.do(admin, "POST", "/servers/1/jobs", url.Values{"_csrf": {token}, "type": {"reboot"}})
	resp, _ = client.Checkin(ctx, info)
	if len(resp.Jobs) != 2 || resp.Jobs[0].Type != protocol.JobRestartServices || strings.Join(resp.Jobs[0].Packages, ",") != "nginx.service" || resp.Jobs[1].Type != protocol.JobReboot {
		t.Fatalf("restart/reboot jobs: %+v", resp.Jobs)
	}
	for _, j := range resp.Jobs {
		_ = client.JobResult(ctx, j.ID, protocol.JobResult{Succeeded: true})
	}
	report.RestartServices = nil
	if err := client.Report(ctx, report); err != nil {
		t.Fatal(err)
	}

	// Every page renders for an admin with real data.
	for path, want := range map[string]string{
		"/servers":                            "web-01",
		"/servers/1?tab=updates":              "Debian-Security:12/stable-security",
		"/servers/1?tab=packages":             "libssl3",
		"/servers/1?tab=jobs":                 "#1",
		"/servers/1?tab=info":                 "Sistem Bilgisi",
		"/servers.csv":                        "web-01;Debian GNU/Linux 12 (bookworm)",
		"/packages":                           "Tüm sunucularda güncelle",
		"/packages?security=1":                "libssl3",
		"/packages?tab=installed&q=ssl":       "3.0.11-1~deb12u2",
		"/packages/libssl3":                   "Güncelleme bekleyen sunucular",
		"/jobs":                               "Seçili paket güncellemesi",
		"/jobs?status=succeeded":              "Başarılı",
		"/agents":                             "Üretim",
		"/notifications?filter=unread":        "Okunmamış",
		"/users":                              "Ayşe Yılmaz",
		"/users/1":                            "Parolayı sıfırla",
		"/settings":                           "E-posta bildirimleri",
		"/profile":                            "Parolayı değiştir",
		"/vulnerabilities?severity=critical":  "CVE-2026-0001",
		"/vulnerabilities?kev=1&fix=1&q=x509": "Bu ölçütlere uyan",
	} {
		status, body, _ := e.do(admin, "GET", path, nil)
		expect(t, path, status, 200, body, want)
	}

	// After the upgrade the finding resolves automatically.
	report.Packages[0].Version, report.Packages[0].SourceVersion = "3.0.17-1~deb12u1", "3.0.17-1~deb12u1"
	report.Packages[1].Version, report.Packages[1].SourceVersion = "3.0.17-1~deb12u1", "3.0.17-1~deb12u1"
	report.Updates = nil
	if err := client.Report(ctx, report); err != nil {
		t.Fatal(err)
	}
	if err := e.scan.ScanHost(ctx, reg.HostID); err != nil {
		t.Fatal(err)
	}
	status, body, _ = e.do(admin, "GET", "/vulnerabilities", nil)
	expect(t, "resolved", status, 200, body, "Bu ölçütlere uyan güvenlik açığı bulunmuyor.")
	status, body, _ = e.do(admin, "GET", "/vulnerabilities/CVE-2026-0001?status=resolved", nil)
	expect(t, "resolved detail", status, 200, body, "Çözüldü")

	// Central updates on selected servers from the inventory list.
	token = e.csrf(admin)
	status, body, _ = e.do(admin, "GET", "/servers", nil)
	expect(t, "bulk bar", status, 200, body, `name="host_ids" value="1"`, "Seçili sunucularda:", "Eski sürüm")
	_, _, hdr = e.do(admin, "POST", "/servers/bulk-jobs", url.Values{"_csrf": {token}, "type": {"upgrade_security"}})
	if hdr.Get("Location") != "/servers" {
		t.Errorf("empty selection should return to list, got %q", hdr.Get("Location"))
	}
	status, _, hdr = e.do(admin, "POST", "/servers/bulk-jobs", url.Values{"_csrf": {token}, "type": {"upgrade_security"}, "host_ids": {"1", "999"}})
	if status != http.StatusSeeOther || hdr.Get("Location") != "/jobs" {
		t.Fatalf("bulk job: %d %s", status, hdr.Get("Location"))
	}
	resp, err = client.Checkin(ctx, info)
	if err != nil || len(resp.Jobs) != 1 || resp.Jobs[0].Type != protocol.JobUpgradeSecurity {
		t.Fatalf("bulk job not dispatched: %+v %v", resp.Jobs, err)
	}
	_ = client.JobResult(ctx, resp.Jobs[0].ID, protocol.JobResult{Succeeded: true})
	_, _, hdr = e.do(admin, "POST", "/packages/libssl3/upgrade", url.Values{"_csrf": {token}, "selection": {"1"}})
	if hdr.Get("Location") != "/packages/libssl3" {
		t.Errorf("package upgrade without selection: %q", hdr.Get("Location"))
	}

	// Automatic agent update: an outdated agent that accepts self-updates gets a job.
	info.SelfUpdate = true
	resp, err = client.Checkin(ctx, info)
	if err != nil || len(resp.Jobs) != 1 || resp.Jobs[0].Type != protocol.JobAgentUpdate {
		t.Fatalf("agent update not queued: %+v %v", resp.Jobs, err)
	}
	p := resp.Jobs[0].Params
	wantSum := sha256.Sum256([]byte(fakeAgentBinary))
	if p[protocol.ParamVersion] != "9.9.9" || p[protocol.ParamSHA256] != hex.EncodeToString(wantSum[:]) ||
		p[protocol.ParamPath] != "/downloads/agent/netio-patchman-agent-linux-amd64" {
		t.Errorf("agent update params: %v", p)
	}
	status, body, _ = e.do(newClient(), "GET", p[protocol.ParamPath], nil)
	if status != 200 || body != fakeAgentBinary {
		t.Errorf("agent download: %d %q", status, body)
	}
	// A failed update is not retried immediately.
	_ = client.JobResult(ctx, resp.Jobs[0].ID, protocol.JobResult{Succeeded: false, ExitCode: -1, Output: "[netio.patchman] SHA-256 eşleşmiyor"})
	if resp, _ = client.Checkin(ctx, info); len(resp.Jobs) != 0 {
		t.Errorf("failed agent update retried immediately: %+v", resp.Jobs)
	}
	status, body, _ = e.do(admin, "GET", "/agents", nil)
	expect(t, "agents page", status, 200, body, "Ajan güncellemeleri", "9.9.9", "Eski ajanları güncelle (1)")
	// Manual update for all outdated agents queues it again.
	status, _, hdr = e.do(admin, "POST", "/agents/update-all", url.Values{"_csrf": {e.csrf(admin)}})
	if status != http.StatusSeeOther {
		t.Fatalf("update-all: %d", status)
	}
	if resp, _ = client.Checkin(ctx, info); len(resp.Jobs) != 1 || resp.Jobs[0].Type != protocol.JobAgentUpdate {
		t.Errorf("manual agent update not dispatched: %+v", resp.Jobs)
	}
	_ = client.JobResult(ctx, resp.Jobs[0].ID, protocol.JobResult{Succeeded: true, Output: "ok"})
	// The restarted agent reports the new version: nothing more to do.
	info.AgentVersion = "9.9.9"
	if resp, _ = client.Checkin(ctx, info); len(resp.Jobs) != 0 {
		t.Errorf("current agent got jobs: %+v", resp.Jobs)
	}
	status, body, _ = e.do(admin, "GET", "/jobs?status=failed", nil)
	expect(t, "failed agent job", status, 200, body, "Ajan güncellemesi")

	// Scheduled updates (maintenance windows).
	report.Host = info
	report.Updates = []protocol.Update{{Name: "bash", CurrentVersion: "5.2.15-2+b7", AvailableVersion: "5.2.15-2+b8", Repository: "Debian-Security:12/stable-security", Security: true}}
	if err := client.Report(ctx, report); err != nil {
		t.Fatal(err)
	}
	status, body, _ = e.do(admin, "GET", "/schedules", nil)
	expect(t, "schedules empty", status, 200, body, "Zamanlanmış Güncellemeler", "Henüz zamanlanmış güncelleme yok", `href="/schedules/new"`)
	status, body, _ = e.do(admin, "GET", "/schedules/new", nil)
	expect(t, "schedule form", status, 200, body, "Pazartesi", `value="03:00"`, "Europe/Istanbul", `data-show-when="target=hosts"`)
	token = e.csrf(admin)
	status, body, _ = e.do(admin, "POST", "/schedules", url.Values{"_csrf": {token}, "name": {"Pazar gecesi"}, "job_type": {"upgrade_security"},
		"time": {"25:00"}, "window_minutes": {"120"}, "target": {"hosts"}, "enabled": {"1"}})
	expect(t, "schedule invalid", status, 400, body, "En az bir gün seçin.", "Başlangıç saatini SS:DD", "En az bir sunucu seçin.")
	status, _, hdr = e.do(admin, "POST", "/schedules", url.Values{"_csrf": {token}, "name": {"Pazar gecesi"}, "job_type": {"upgrade_security"},
		"days": {"0", "6"}, "time": {"03:00"}, "window_minutes": {"120"}, "target": {"hosts"}, "host_ids": {"1"}, "enabled": {"1"}})
	if status != http.StatusSeeOther || hdr.Get("Location") != "/schedules/1" {
		t.Fatalf("schedule create: %d %s", status, hdr.Get("Location"))
	}
	sc, err := e.st.ScheduleByID(ctx, 1)
	if err != nil || sc.Days != 0b1000001 || sc.Minute != 180 || len(sc.HostIDs) != 1 || sc.NextRunAt.IsZero() {
		t.Fatalf("stored schedule: %+v %v", sc, err)
	}
	if ist := sc.NextRunAt.In(time.FixedZone("TRT", 3*3600)); ist.Hour() != 3 || (ist.Weekday() != time.Sunday && ist.Weekday() != time.Saturday) {
		t.Errorf("next run %v is not Sat/Sun 03:00 Istanbul", ist)
	}
	status, body, _ = e.do(admin, "GET", "/schedules", nil)
	expect(t, "schedules list", status, 200, body, "Pazar gecesi", "Hafta sonu", "03:00", "1 seçili sunucu", "Güvenlik güncellemeleri")
	status, body, _ = e.do(admin, "GET", "/schedules/1", nil)
	expect(t, "schedule detail", status, 200, body, "Şu anda 1 sunucu kapsamda; 1 sunucuda", "Şimdi çalıştır", "Bu zamanlama henüz iş oluşturmadı.")
	status, _, _ = e.do(admin, "POST", "/schedules/1/run", url.Values{"_csrf": {token}})
	if status != http.StatusSeeOther {
		t.Fatalf("schedule run now: %d", status)
	}
	resp, err = client.Checkin(ctx, info)
	if err != nil || len(resp.Jobs) != 1 || resp.Jobs[0].Type != protocol.JobUpgradeSecurity {
		t.Fatalf("scheduled job not dispatched: %+v %v", resp.Jobs, err)
	}
	schedJob := resp.Jobs[0].ID
	_ = client.JobResult(ctx, schedJob, protocol.JobResult{Succeeded: true, Output: "ok"})
	status, body, _ = e.do(admin, "GET", "/jobs/"+strconv.FormatInt(schedJob, 10), nil)
	expect(t, "scheduled job", status, 200, body, "Zamanlama: Pazar gecesi", "Bakım Penceresi Sonu")
	status, body, _ = e.do(admin, "GET", "/notifications", nil)
	if strings.Contains(body, "#"+strconv.FormatInt(schedJob, 10)+" numaralı iş başarıyla") {
		t.Error("scheduled job success should not create a per-host notification")
	}
	status, body, _ = e.do(admin, "GET", "/servers/1?tab=info", nil)
	expect(t, "host schedules", status, 200, body, `href="/schedules/1"`, "Pazar gecesi")
	// Disable: no next run.
	status, _, _ = e.do(admin, "POST", "/schedules/1", url.Values{"_csrf": {token}, "name": {"Pazar gecesi"}, "job_type": {"upgrade_all"},
		"days": {"0"}, "time": {"04:30"}, "window_minutes": {"60"}, "target": {"os"}, "os_id": {"debian"}})
	if sc, _ = e.st.ScheduleByID(ctx, 1); status != http.StatusSeeOther || sc.Enabled || !sc.NextRunAt.IsZero() || sc.OSID != "debian" || len(sc.HostIDs) != 0 {
		t.Errorf("schedule update: %d %+v", status, sc)
	}
	// A second schedule is deleted again.
	e.do(admin, "POST", "/schedules", url.Values{"_csrf": {token}, "name": {"Silinecek"}, "job_type": {"upgrade_all"},
		"days": {"1"}, "time": {"22:00"}, "window_minutes": {"60"}, "target": {"all"}, "enabled": {"1"}})
	status, _, hdr = e.do(admin, "POST", "/schedules/2/delete", url.Values{"_csrf": {token}})
	if status != http.StatusSeeOther || hdr.Get("Location") != "/schedules" {
		t.Errorf("schedule delete: %d %s", status, hdr.Get("Location"))
	}
	if _, err := e.st.ScheduleByID(ctx, 2); err != store.ErrNotFound {
		t.Errorf("schedule not deleted: %v", err)
	}

	// Roles: a viewer can read but not start jobs or open admin pages.
	token = e.csrf(admin)
	status, _, _ = e.do(admin, "POST", "/users", url.Values{"_csrf": {token}, "name": {"İzleyici"}, "email": {"izleyici@example.test"}, "role": {"viewer"},
		"password": {"izleyici-parola-1"}, "password_confirm": {"izleyici-parola-1"}})
	if status != http.StatusSeeOther {
		t.Fatalf("create viewer: %d", status)
	}
	viewer := newClient()
	status, _, _ = e.do(viewer, "POST", "/login", url.Values{"email": {"izleyici@example.test"}, "password": {"yanlış-parola"}})
	if status != http.StatusUnauthorized {
		t.Errorf("wrong password: %d", status)
	}
	status, _, _ = e.do(viewer, "POST", "/login", url.Values{"email": {"IZLEYICI@example.test"}, "password": {"izleyici-parola-1"}})
	if status != http.StatusSeeOther {
		t.Fatalf("viewer login: %d", status)
	}
	status, body, _ = e.do(viewer, "GET", "/servers", nil)
	expect(t, "viewer servers", status, 200, body, "web-01")
	if strings.Contains(body, `href="/settings"`) {
		t.Error("viewer sees admin navigation")
	}
	vt := e.csrf(viewer)
	status, body, _ = e.do(viewer, "POST", "/servers/1/jobs", url.Values{"_csrf": {vt}, "type": {"upgrade_all"}})
	expect(t, "viewer job", status, 403, body, "Yetkiniz yok")
	status, _, _ = e.do(viewer, "GET", "/settings", nil)
	if status != http.StatusForbidden {
		t.Errorf("viewer settings: %d", status)
	}
	status, body, _ = e.do(viewer, "GET", "/schedules/1", nil)
	expect(t, "viewer schedule", status, 200, body, "yalnızca yöneticiler", "<fieldset class=\"fieldset\" disabled>")
	status, _, _ = e.do(viewer, "POST", "/schedules/1/run", url.Values{"_csrf": {vt}})
	if status != http.StatusForbidden {
		t.Errorf("viewer schedule run: %d", status)
	}

	// Last admin cannot be demoted.
	token = e.csrf(admin)
	_, _, hdr = e.do(admin, "POST", "/users/1", url.Values{"_csrf": {token}, "name": {"Ayşe Yılmaz"}, "role": {"viewer"}})
	if u, _ := e.st.UserByID(ctx, 1); u.Role != store.RoleAdmin {
		t.Error("last admin was demoted")
	}

	// Turkish error pages.
	status, body, _ = e.do(admin, "GET", "/olmayan-sayfa", nil)
	expect(t, "404", status, 404, body, "Sayfa bulunamadı")
	status, body, _ = e.do(admin, "PUT", "/dashboard", nil)
	expect(t, "405", status, 405, body, "İşlem desteklenmiyor")

	// Install assets and health.
	status, body, _ = e.do(newClient(), "GET", "/downloads/install-agent.sh", nil)
	expect(t, "install script", status, 200, body, "netio.patchman ajan kurulum betiği", "openrc")
	status, body, _ = e.do(newClient(), "GET", "/downloads/netio-patchman-agent.openrc", nil)
	expect(t, "openrc script", status, 200, body, "#!/sbin/openrc-run", "supervise-daemon")
	status, body, _ = e.do(newClient(), "GET", "/healthz", nil)
	expect(t, "healthz", status, 200, body, `"service":"netio.patchman"`)

	// Deleting the host revokes the agent.
	token = e.csrf(admin)
	e.do(admin, "POST", "/servers/1/delete", url.Values{"_csrf": {token}, "confirm": {"web-01"}})
	if _, err := client.Checkin(ctx, info); !agent.IsUnauthorized(err) {
		t.Errorf("deleted host still authenticated: %v", err)
	}

	// Audit trail.
	status, body, _ = e.do(admin, "GET", "/settings/audit", nil)
	expect(t, "audit", status, 200, body, "Kayıt anahtarı oluşturuldu", "Güncelleme işi başlatıldı", "Sunucu kaldırıldı", "Başarısız giriş denemesi",
		"Zamanlama oluşturuldu", "Zamanlama elle çalıştırıldı", "Zamanlama silindi")
}
