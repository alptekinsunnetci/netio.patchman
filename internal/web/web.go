// Package web serves the server-rendered Turkish dashboard.
//
// All visible text is resolved through the "t" template function; templates
// must not contain literal UI strings. Vulnerability data is rendered verbatim.
package web

import (
	"bytes"
	"context"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"netio.patchman/internal/api"
	"netio.patchman/internal/auth"
	"netio.patchman/internal/brand"
	"netio.patchman/internal/i18n"
	"netio.patchman/internal/notify"
	"netio.patchman/internal/release"
	"netio.patchman/internal/scanner"
	"netio.patchman/internal/schedule"
	"netio.patchman/internal/settings"
	"netio.patchman/internal/store"
	"netio.patchman/internal/timeutil"
	"netio.patchman/internal/updatecheck"
	"netio.patchman/internal/version"
	"netio.patchman/internal/vuln"
)

//go:embed templates static
var assets embed.FS

// Options configures the web server.
type Options struct {
	Store     *store.Store
	Localizer i18n.Localizer
	Formatter timeutil.Formatter
	Logger    *slog.Logger
	Scanner   *scanner.Scanner
	Notifier  *notify.Notifier
	// System is the runtime server configuration edited on /settings/system.
	System *settings.Live
	// API mounts the agent API on the same mux (optional).
	API *api.Server
	// Release is the agent version the server distributes.
	Release release.Release
	// Updates checks for new product versions (optional).
	Updates *updatecheck.Checker
}

// Server is the dashboard.
type Server struct {
	o       Options
	st      *store.Store
	l       i18n.Localizer
	f       timeutil.Formatter
	logger  *slog.Logger
	pages   map[string]*template.Template
	limiter *auth.Limiter
	// offlineSec caches the agent offline threshold (seconds).
	offlineSec atomic.Int64
}

type navItem struct {
	Key  string
	Href string
	Icon string
}

var navigation = []navItem{
	{"dashboard", "/dashboard", "dashboard"},
	{"servers", "/servers", "server"},
	{"vulnerabilities", "/vulnerabilities", "shield"},
	{"packages", "/packages", "package"},
	{"jobs", "/jobs", "jobs"},
	{"schedules", "/schedules", "calendar"},
	{"agents", "/agents", "agent"},
	{"notifications", "/notifications", "bell"},
	{"users", "/users", "users"},
	{"settings", "/settings", "settings"},
}

var pageNames = []string{
	"login", "setup", "error", "dashboard", "servers", "server", "vulnerabilities", "vulnerability",
	"packages", "package", "jobs", "job", "schedules", "schedule", "agents", "notifications", "users", "user", "profile", "settings", "audit", "system",
}

// New parses templates and returns a Server.
func New(o Options) (*Server, error) {
	s := &Server{o: o, st: o.Store, l: o.Localizer, f: o.Formatter, logger: o.Logger,
		pages: map[string]*template.Template{}, limiter: auth.NewLimiter(8, 15*time.Minute)}
	for _, page := range pageNames {
		t, err := template.New("").Funcs(s.funcs()).ParseFS(assets,
			"templates/base.html", "templates/shell.html", "templates/"+page+".html")
		if err != nil {
			return nil, fmt.Errorf("web: parse %s: %w", page, err)
		}
		s.pages[page] = t
	}
	s.reloadSettingsCache(context.Background())
	return s, nil
}

func (s *Server) sys() settings.System { return s.o.System.Get() }

func (s *Server) baseURL() string { return s.sys().BaseURLString() }

func (s *Server) clientIP(r *http.Request) string { return api.ClientIP(r, s.sys().TrustProxy) }

// secureCookie reports whether cookies set on r must carry the Secure flag:
// the request arrived over HTTPS, directly or through a trusted proxy, or it
// is addressed to the configured HTTPS base URL. Requests to another address
// over plain HTTP (e.g. http://localhost:8080 while the base URL is still
// being set up) keep working.
func (s *Server) secureCookie(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	sys := s.sys()
	if sys.TrustProxy && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		return true
	}
	return sys.BaseURL != nil && sys.BaseURL.Scheme == "https" && r.Host == sys.BaseURL.Host
}

func (s *Server) reloadSettingsCache(ctx context.Context) {
	cfg, _ := settings.Load(ctx, s.st)
	s.offlineSec.Store(int64(cfg.OfflineAfter().Seconds()))
}

func (s *Server) offlineAfter() time.Duration {
	return time.Duration(s.offlineSec.Load()) * time.Second
}

func (s *Server) funcs() template.FuncMap {
	l, f := s.l, s.f
	return template.FuncMap{
		"t":        l.T,
		"date":     f.Date,
		"datetime": f.DateTime,
		"long":     f.Long,
		"iso":      f.ISO,
		"ago":      s.ago,
		"uptime":   s.uptime,
		"sevLabel": func(sev vuln.Severity) string { return l.T(sev.LabelKey()) },
		"sevClass": func(sev vuln.Severity) string {
			switch sev {
			case vuln.SeverityCritical, vuln.SeverityHigh, vuln.SeverityMedium, vuln.SeverityLow:
				return string(sev)
			}
			return "unknown"
		},
		"statusLabel": func(st string) string { return l.T("status." + st) },
		"jobType":     func(t string) string { return l.T("job.type." + t) },
		"jobStatus":   func(st string) string { return l.T("job.status." + st) },
		"roleLabel":   func(r string) string { return l.T("role." + r) },
		"cvss": func(p *float64) string {
			if p == nil {
				return l.T("common.empty")
			}
			return strconv.FormatFloat(*p, 'f', 1, 64)
		},
		"join":      strings.Join,
		"list":      func(v ...string) []string { return v },
		"add":       func(a, b int) int { return a + b },
		"notifText": s.notificationText,
		"pct": func(part, total int) int {
			if total <= 0 {
				return 0
			}
			return int(math.Round(float64(part) * 100 / float64(total)))
		},
		"online": func(h store.Host) bool { return h.Online(s.offlineAfter()) },
		"agentOutdated": func(h store.Host) bool {
			return s.o.Release.Outdated(h.AgentVersion, h.Arch)
		},
		"agentRelease": func() string { return s.o.Release.Version },
		"param":        func(m map[string]string, k string) string { return m[k] },
		"scheduleDays": s.scheduleDays,
		"scheduleTarget": func(sc store.ScheduleRow) string {
			return s.scheduleTarget(sc.Target, sc.OSID, sc.HostCount)
		},
		"clock": schedule.Clock,
		"lower": l.Lower,
		"int64": func(i int64) string { return strconv.FormatInt(i, 10) },
		"truncate": func(s string, n int) string {
			r := []rune(s)
			if len(r) <= n {
				return s
			}
			return string(r[:n]) + "…"
		},
	}
}

func (s *Server) ago(t time.Time) string {
	if t.IsZero() {
		return s.l.T("time.never")
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return s.l.T("time.just_now")
	case d < time.Hour:
		return s.l.T("time.minutes_ago", "n", int(d.Minutes()))
	case d < 24*time.Hour:
		return s.l.T("time.hours_ago", "n", int(d.Hours()))
	default:
		return s.l.T("time.days_ago", "n", int(d.Hours()/24))
	}
}

func (s *Server) uptime(sec int64) string {
	if sec <= 0 {
		return s.l.T("common.empty")
	}
	d := time.Duration(sec) * time.Second
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	if days > 0 {
		return s.l.T("time.uptime_days", "d", days, "h", hours)
	}
	return s.l.T("time.uptime_hours", "h", hours, "m", int(d.Minutes())%60)
}

func (s *Server) notificationText(n store.Notification) string {
	args := make([]any, 0, len(n.Params)*2)
	for k, v := range n.Params {
		switch k {
		case "severity":
			v = s.l.T(vuln.Severity(v).LabelKey())
		case "job_type":
			v = s.l.T("job.type." + v)
		}
		args = append(args, k, v)
	}
	return s.l.T("notification."+n.Kind, args...)
}

// Handler returns the root handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(assets, "static")
	fileServer := http.StripPrefix("/static/", http.FileServerFS(static))
	mux.Handle("GET /static/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		fileServer.ServeHTTP(w, r)
	}))
	mux.HandleFunc("GET /healthz", s.health)
	if s.o.API != nil {
		s.o.API.Register(mux)
	}

	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.loginSubmit)
	mux.HandleFunc("POST /logout", s.logout)
	mux.HandleFunc("GET /setup", s.setupPage)
	mux.HandleFunc("POST /setup", s.setupSubmit)

	view, operate, admin := s.require(roleViewer), s.require(roleOperator), s.require(roleAdmin)

	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/dashboard", http.StatusFound) })
	mux.Handle("GET /dashboard", view(s.dashboard))

	mux.Handle("GET /servers", view(s.servers))
	mux.Handle("GET /servers.csv", view(s.serversCSV))
	mux.Handle("POST /servers/bulk-jobs", operate(s.serversBulkJob))
	mux.Handle("GET /servers/{id}", view(s.server))
	mux.Handle("POST /servers/{id}/jobs", operate(s.serverCreateJob))
	mux.Handle("POST /servers/{id}/rescan", operate(s.serverRescan))
	mux.Handle("POST /servers/{id}/notes", operate(s.serverNotes))
	mux.Handle("POST /servers/{id}/delete", admin(s.serverDelete))

	mux.Handle("GET /vulnerabilities", view(s.vulnerabilities))
	mux.Handle("GET /vulnerabilities.csv", view(s.vulnerabilitiesCSV))
	mux.Handle("GET /vulnerabilities/{id}", view(s.vulnerability))
	mux.Handle("POST /vulnerabilities/{id}/status", operate(s.vulnerabilityStatus))
	mux.Handle("POST /vulnerabilities/{id}/remediate", operate(s.vulnerabilityRemediate))

	mux.Handle("GET /packages", view(s.packages))
	mux.Handle("GET /packages/{name}", view(s.packageDetail))
	mux.Handle("POST /packages/{name}/upgrade", operate(s.packageUpgrade))
	mux.Handle("POST /packages/security-all", operate(s.packagesSecurityAll))

	mux.Handle("GET /jobs", view(s.jobs))
	mux.Handle("GET /jobs/{id}", view(s.job))
	mux.Handle("POST /jobs/{id}/cancel", operate(s.jobCancel))
	mux.Handle("POST /jobs/{id}/retry", operate(s.jobRetry))

	mux.Handle("GET /schedules", view(s.schedules))
	mux.Handle("GET /schedules/new", admin(s.scheduleNew))
	mux.Handle("POST /schedules", admin(s.scheduleCreate))
	mux.Handle("GET /schedules/{id}", view(s.scheduleDetail))
	mux.Handle("POST /schedules/{id}", admin(s.scheduleUpdate))
	mux.Handle("POST /schedules/{id}/delete", admin(s.scheduleDelete))
	mux.Handle("POST /schedules/{id}/run", admin(s.scheduleRunNow))

	mux.Handle("GET /agents", view(s.agents))
	mux.Handle("POST /agents/update-all", operate(s.agentsUpdateAll))
	mux.Handle("POST /agents/tokens", admin(s.tokenCreate))
	mux.Handle("POST /agents/tokens/{id}/revoke", admin(s.tokenRevoke))

	mux.Handle("GET /notifications", view(s.notifications))
	mux.Handle("POST /notifications/read", view(s.notificationsRead))

	mux.Handle("GET /users", admin(s.users))
	mux.Handle("POST /users", admin(s.userCreate))
	mux.Handle("GET /users/{id}", admin(s.user))
	mux.Handle("POST /users/{id}", admin(s.userUpdate))
	mux.Handle("POST /users/{id}/reset-password", admin(s.userResetPassword))
	mux.Handle("POST /users/{id}/delete", admin(s.userDelete))

	mux.Handle("GET /profile", view(s.profile))
	mux.Handle("POST /profile/password", view(s.profilePassword))

	mux.Handle("GET /settings", admin(s.settings))
	mux.Handle("POST /settings", admin(s.settingsSave))
	mux.Handle("POST /settings/test-email", admin(s.settingsTestEmail))
	mux.Handle("POST /settings/scan-now", admin(s.settingsScanNow))
	mux.Handle("GET /settings/audit", admin(s.auditLog))
	mux.Handle("GET /settings/system", admin(s.systemConfig))
	mux.Handle("POST /settings/system", admin(s.systemSave))
	mux.Handle("POST /settings/system/reset", admin(s.systemReset))
	mux.Handle("POST /settings/system/update-check", admin(s.updateCheck))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s.errorPage(w, r, http.StatusNotFound, "error.not_found")
	})
	return securityHeaders(s.methodGuard(mux))
}

// methodGuard renders a Turkish 405 page instead of the mux's plain text.
func (s *Server) methodGuard(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, pattern := mux.Handler(r)
		if pattern == "/" && r.Method != http.MethodGet && r.Method != http.MethodHead {
			// Only the catch-all matched: if the path exists for GET, this is a
			// 405 rather than a 404.
			probe := r.Clone(r.Context())
			probe.Method = http.MethodGet
			if _, p := mux.Handler(probe); p != "" && p != "/" {
				s.errorPage(w, r, http.StatusMethodNotAllowed, "error.method_not_allowed")
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "same-origin")
		}
		h.Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	status, code := "ok", http.StatusOK
	if err := s.st.DB().PingContext(r.Context()); err != nil {
		status, code = "degraded", http.StatusServiceUnavailable
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": status, "service": brand.Name, "version": version.Version,
		"time": timeutil.Now().Format(time.RFC3339),
	})
}

// ---------- rendering ----------

type flash struct {
	Kind string // success, error, info
	Text string
}

type pageData struct {
	Product string
	Version string
	Lang    string
	Title   string
	Active  string
	Nav     []navItem
	User    *store.User
	CSRF    string
	Flash   *flash
	Unread  int
	Error   string
	Data    any
	// Update is set for administrators when a newer product version exists.
	Update *updatecheck.Status
}

func (s *Server) page(r *http.Request, title, active string) pageData {
	d := pageData{Product: brand.Name, Version: version.Version, Lang: s.l.Lang(), Title: title, Active: active, Nav: navigation}
	if sess := sessionFrom(r); sess != nil {
		u := sess.user
		d.User, d.CSRF = &u, sess.csrf
		d.Unread, _ = s.st.UnreadNotifications(r.Context())
		if u.IsAdmin() && s.o.Updates != nil {
			if st := s.o.Updates.Status(); st.Enabled && st.Available() {
				d.Update = &st
			}
		}
	}
	return d
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, name string, d pageData) {
	if d.Flash == nil {
		d.Flash = s.takeFlash(w, r)
	}
	var buf bytes.Buffer
	if err := s.pages[name].ExecuteTemplate(&buf, "base", d); err != nil {
		s.logger.Error(s.l.T("log.http.render_failed"), slog.String("page", name), slog.Any("error", err))
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, s.l.T("error.internal.title"))
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

func (s *Server) errorPage(w http.ResponseWriter, r *http.Request, status int, key string) {
	d := s.page(r, s.l.T(key+".title"), "")
	d.Data = map[string]any{"Status": status, "Key": key}
	s.render(w, r, status, "error", d)
}

func (s *Server) serverError(w http.ResponseWriter, r *http.Request, err error) {
	s.logger.Error(s.l.T("log.http.request_failed"), slog.String("path", r.URL.Path), slog.String("error", err.Error()))
	s.errorPage(w, r, http.StatusInternalServerError, "error.internal")
}

const flashCookie = "np_flash"

func (s *Server) setFlash(w http.ResponseWriter, r *http.Request, kind, text string) {
	http.SetCookie(w, &http.Cookie{
		Name: flashCookie, Value: base64.RawURLEncoding.EncodeToString([]byte(kind + "\x00" + text)),
		Path: "/", HttpOnly: true, Secure: s.secureCookie(r), SameSite: http.SameSiteLaxMode, MaxAge: 60,
	})
}

func (s *Server) takeFlash(w http.ResponseWriter, r *http.Request) *flash {
	c, err := r.Cookie(flashCookie)
	if err != nil {
		return nil
	}
	http.SetCookie(w, &http.Cookie{Name: flashCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.secureCookie(r), SameSite: http.SameSiteLaxMode})
	b, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return nil
	}
	kind, text, ok := strings.Cut(string(b), "\x00")
	if !ok {
		return nil
	}
	return &flash{Kind: kind, Text: text}
}

// redirect sets a flash message and redirects with 303.
func (s *Server) redirect(w http.ResponseWriter, r *http.Request, to, kind, text string) {
	if text != "" {
		s.setFlash(w, r, kind, text)
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

func (s *Server) audit(r *http.Request, action, target, details string) {
	e := store.AuditEntry{Action: action, Target: target, Details: details, IP: s.clientIP(r)}
	if sess := sessionFrom(r); sess != nil {
		e.UserID, e.UserEmail = sess.user.ID, sess.user.Email
	}
	if err := s.st.Audit(r.Context(), e); err != nil {
		s.logger.Warn(s.l.T("log.audit.failed"), slog.String("error", err.Error()))
	}
}

// ---------- pagination ----------

const pageSize = 50

type pager struct {
	Page, Pages, Total, From, To int
	PrevURL, NextURL             string
}

func pageNumber(r *http.Request) int {
	n, err := strconv.Atoi(r.URL.Query().Get("page"))
	if err != nil || n < 1 {
		return 1
	}
	return n
}

func newPager(r *http.Request, page, total int) pager {
	p := pager{Page: page, Total: total, Pages: (total + pageSize - 1) / pageSize}
	if p.Pages == 0 {
		p.Pages = 1
	}
	if total > 0 {
		p.From = (page-1)*pageSize + 1
		p.To = min(page*pageSize, total)
	}
	link := func(n int) string {
		q := r.URL.Query()
		q.Set("page", strconv.Itoa(n))
		return r.URL.Path + "?" + q.Encode()
	}
	if page > 1 {
		p.PrevURL = link(page - 1)
	}
	if page < p.Pages {
		p.NextURL = link(page + 1)
	}
	return p
}

func pathID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id, err == nil && id > 0
}
