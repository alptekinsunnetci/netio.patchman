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
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"netio.patchman/internal/api"
	"netio.patchman/internal/auth"
	"netio.patchman/internal/backup"
	"netio.patchman/internal/brand"
	"netio.patchman/internal/eol"
	"netio.patchman/internal/i18n"
	"netio.patchman/internal/notify"
	"netio.patchman/internal/protocol"
	"netio.patchman/internal/release"
	"netio.patchman/internal/rollout"
	"netio.patchman/internal/scanner"
	"netio.patchman/internal/schedule"
	"netio.patchman/internal/score"
	"netio.patchman/internal/scoring"
	"netio.patchman/internal/selfupdate"
	"netio.patchman/internal/settings"
	"netio.patchman/internal/software"
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
	// Bundle offers every catalog as an interface language (optional; without
	// it the dashboard only uses Localizer).
	Bundle *i18n.Bundle
	// Backups takes and lists automatic database backups (optional).
	Backups *backup.Runner
	// Channels sends notifications to chat and webhook channels (optional).
	Channels *notify.Dispatcher
	// SelfUpdate talks to the optional updater container (optional).
	SelfUpdate *selfupdate.Manager
	// EOL supplies the support calendars (optional; nil uses the built-in snapshot).
	EOL *eol.Source
	// Scores recomputes security scores after a weight change (optional).
	Scores *scoring.Engine
	// Rollouts pauses, resumes and cancels rolling updates (optional; nil
	// uses one without notifications).
	Rollouts *rollout.Runner
	// ComplianceWait is how long a request waits for a compliance report
	// version before it is finished in the background (0: 20 s, <0: no wait).
	ComplianceWait time.Duration
}

// Server is the dashboard in one language. New returns the default-language
// Server; it keeps one Server per available locale (same store, shared state)
// and Handler serves each request in the language the user picked.
type Server struct {
	o      Options
	st     *store.Store
	l      i18n.Localizer
	f      timeutil.Formatter
	logger *slog.Logger
	pages  map[string]*template.Template
	*shared
}

// shared is the state common to every language variant.
type shared struct {
	limiter *auth.Limiter
	// offlineSec caches the agent offline threshold (seconds).
	offlineSec atomic.Int64
	// requireMFA caches the "two-factor sign-in required" setting.
	requireMFA atomic.Bool
	// mfa holds pending second-step sign-ins.
	mfa mfaChallenges
	// gen runs compliance report generations in the background.
	gen *genState
	// variants maps a locale to its Server; def is the server's default locale.
	variants map[string]*Server
	locales  []string
	def      string
}

func (s *Server) mfaRequired() bool { return s.requireMFA.Load() }

type navItem struct {
	Key   string
	Href  string
	Icon  string
	Group string // catalog key suffix of the section heading (nav.group.<Group>)
}

// navigation is the sidebar in sections; the template prints a section
// heading before the first visible item of each.
var navigation = []navItem{
	{"dashboard", "/dashboard", "dashboard", "overview"},
	{"notifications", "/notifications", "bell", "overview"},
	{"servers", "/servers", "server", "inventory"},
	{"groups", "/groups", "tag", "inventory"},
	{"software", "/software", "layers", "inventory"},
	{"packages", "/packages", "package", "inventory"},
	{"vulnerabilities", "/vulnerabilities", "shield", "security"},
	{"jobs", "/jobs", "jobs", "updates"},
	{"rollouts", "/rollouts", "rollout", "updates"},
	{"schedules", "/schedules", "calendar", "updates"},
	{"compliance", "/compliance", "audit", "compliance"},
	{"compliance_reports", "/compliance/reports", "report", "compliance"},
	{"compliance_evidence", "/compliance/evidence", "evidence", "compliance"},
	{"compliance_history", "/compliance/history", "history", "compliance"},
	{"compliance_policies", "/compliance/policies", "check", "compliance"},
	{"agents", "/agents", "agent", "admin"},
	{"users", "/users", "users", "admin"},
	{"settings", "/settings", "settings", "admin"},
}

var pageNames = []string{
	"login", "loginmfa", "setup", "error", "dashboard", "servers", "server", "vulnerabilities", "vulnerability",
	"packages", "package", "jobs", "job", "schedules", "schedule", "agents", "notifications", "users", "user", "profile", "settings", "system",
	"groups", "group", "channels", "software", "softwareitem", "hostscore", "scoresettings", "healthchecks", "rollouts", "rolloutnew", "rollout", "standards", "standard", "channel",
	"compliance", "compliancereports", "compliancereport", "complianceevidence", "complianceitem", "compliancehistory", "compliancepolicies",
}

// New parses templates and returns the Server for the default language
// (o.Localizer). With o.Bundle set, every other catalog gets its own variant.
func New(o Options) (*Server, error) {
	sh := &shared{limiter: auth.NewLimiter(8, 15*time.Minute), variants: map[string]*Server{}, def: o.Localizer.Locale(), gen: newGenState(o.ComplianceWait)}
	locales := []i18n.Localizer{o.Localizer}
	if o.Bundle != nil {
		for _, loc := range o.Bundle.Locales() {
			if loc != sh.def {
				locales = append(locales, o.Bundle.Localizer(loc))
			}
		}
	}
	var root *Server
	for i, l := range locales {
		f := o.Formatter
		if i > 0 {
			f = timeutil.NewZoneFormatter(o.Formatter.Zone(), l)
		}
		s := &Server{o: o, st: o.Store, l: l, f: f, logger: o.Logger, pages: map[string]*template.Template{}, shared: sh}
		for _, page := range pageNames {
			t, err := template.New("").Funcs(s.funcs()).ParseFS(assets,
				"templates/base.html", "templates/shell.html", "templates/"+page+".html")
			if err != nil {
				return nil, fmt.Errorf("web: parse %s (%s): %w", page, l.Locale(), err)
			}
			s.pages[page] = t
		}
		sh.variants[l.Locale()] = s
		sh.locales = append(sh.locales, l.Locale())
		if i == 0 {
			root = s
		}
	}
	root.reloadSettingsCache(context.Background())
	return root, nil
}

const langCookie = "np_lang"

// variant returns the Server for the request's language: the np_lang cookie
// if it names an available locale, otherwise the default.
func (s *Server) variant(r *http.Request) *Server {
	if c, err := r.Cookie(langCookie); err == nil {
		if v, ok := s.variants[c.Value]; ok {
			return v
		}
	}
	return s.variants[s.def]
}

func (s *Server) setLangCookie(w http.ResponseWriter, r *http.Request, locale string) {
	http.SetCookie(w, &http.Cookie{Name: langCookie, Value: locale, Path: "/", MaxAge: 365 * 24 * 3600,
		HttpOnly: true, Secure: s.secureCookie(r), SameSite: http.SameSiteLaxMode})
}

// langSwitch sets the interface language for this browser (GET /lang?to=en-US).
// Signed-in users keep their saved preference for new sessions on the profile page.
func (s *Server) langSwitch(w http.ResponseWriter, r *http.Request) {
	to := r.URL.Query().Get("to")
	if _, ok := s.variants[to]; ok {
		s.setLangCookie(w, r, to)
	}
	next := r.URL.Query().Get("next")
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\") {
		next = "/dashboard"
	}
	http.Redirect(w, r, next, http.StatusFound)
}

// languageOption is one entry of a language picker.
type languageOption struct {
	Locale, Name string
	Current      bool
}

// languages lists the available interface languages, each in its own language.
func (s *Server) languages() []languageOption {
	out := make([]languageOption, 0, len(s.locales))
	for _, loc := range s.locales {
		out = append(out, languageOption{Locale: loc, Name: s.variants[loc].l.T("language.name"), Current: loc == s.l.Locale()})
	}
	return out
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
	s.requireMFA.Store(cfg.AuthRequireMFA)
}

func (s *Server) offlineAfter() time.Duration {
	return time.Duration(s.offlineSec.Load()) * time.Second
}

func (s *Server) funcs() template.FuncMap {
	l, f := s.l, s.f
	return template.FuncMap{
		"t": l.T,
		// pathesc escapes a path segment (Windows program names have spaces, '#', '/').
		"pathesc":  url.PathEscape,
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
		"join": strings.Join,
		// epss formats an exploitation probability as a percentage.
		"epss": func(p *float64) string {
			if p == nil {
				return l.T("common.empty")
			}
			n := strconv.FormatFloat(*p*100, 'f', 1, 64)
			return l.T("format.percent", "n", strings.Replace(n, ".", l.T("number.decimal"), 1))
		},
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
		"usage":  usageBar,
		"sub64":  func(a, b int64) int64 { return a - b },
		"resval": func(key string, pct float64, limit int) resVal {
			u := usageBar(pct, limit)
			return resVal{Key: key, Used: u.Used, Level: u.Level, Known: pct >= 0}
		},
		"round": func(v float64) int { return int(math.Round(v)) },
		"dec": func(v float64) string {
			return strings.Replace(strconv.FormatFloat(v, 'f', 2, 64), ".", l.T("number.decimal"), 1)
		},
		"healthLabel": func(name, typ string, id int64) string {
			if id != 0 || !slices.Contains([]string{"disk", "memory", "cpu"}, typ) {
				return name
			}
			label := l.T("health.resource." + typ)
			if name != "" {
				label += " (" + name + ")"
			}
			return label
		},
		"agentOutdated": func(h store.Host) bool {
			return s.o.Release.Outdated(h.AgentVersion, h.OSID, h.Arch)
		},
		"agentRelease":  func() string { return s.o.Release.Version },
		"virt":          s.virtLabel,
		"size":          s.size,
		"channelTarget": s.channelTarget,
		"levelLabel":    func(level string) string { return l.T("level." + level) },
		"has":           func(m map[int64]bool, id int64) bool { return m[id] },
		"watching":      func(m map[string]bool, name string) bool { return m[name] },
		"scoreBand":     score.Band,
		"neg":           func(n int64) int64 { return -n },
		"revertible":    revertible,
		"previewLists": func(p *protocol.Preview) []previewList {
			return []previewList{{"upgrades", p.Upgrades}, {"installs", p.Installs}, {"removals", p.Removals}, {"downgrades", p.Downgrades}}
		},
		"eolDays": func(r eol.Release) int { return r.DaysLeft(timeutil.Now()) },
		"eolItem": func(m map[string]eol.Item, sw, cycle string) *eol.Item {
			if it, ok := m[sw+" "+cycle]; ok {
				return &it
			}
			return nil
		},
		"swName": func(id string) string {
			if d, ok := software.ByID(id); ok {
				return d.Name
			}
			return id
		},
		"swCatalogSize": func() int { return len(software.Catalog) },
		// versionName is a version with its release name: 1.0.5 “gökalp”.
		"versionName": func(v string) string {
			if c := version.Codename(v); c != "" {
				return l.T("version.with_codename", "version", v, "codename", c)
			}
			return v
		},
		// swRow passes a host software row to the "swrow" template.
		"swRow": func(r store.HostSoftwareRow, hostID int64, eol map[string]eol.Item) map[string]any {
			return map[string]any{"R": r, "HostID": hostID, "EOL": eol}
		},
		"swCategory": func(id string) string {
			if d, ok := software.ByID(id); ok {
				return d.Category
			}
			return ""
		},
		"star": func(d pageData, name string, on bool) starArgs {
			return starArgs{Name: name, On: on, CSRF: d.CSRF, Back: d.Path}
		},
		"riskTerm": func(days int) string {
			if days == 0 {
				return l.T("vuln.risk_days.none")
			}
			return l.T("vuln.risk_days.n", "n", days)
		},
		"param":        func(m map[string]string, k string) string { return m[k] },
		"scheduleDays": s.scheduleDays,
		"scheduleTarget": func(sc store.ScheduleRow) string {
			return s.scheduleTarget(sc.Target, sc.OSID, sc.HostCount, sc.GroupName)
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
		// Compliance & audit labels.
		"outcomeLabel": func(o string) string { return l.T("compliance.outcome." + o) },
		"outcomeClass": outcomeClass,
		"platform":     func(p string) string { return l.T("compliance.platform." + p) },
		"evidenceKind": func(k string) string { return l.T("compliance.kind." + k) },
		"reviewLabel":  func(st string) string { return l.T("compliance.review." + st) },
		// lastDay is the last moment before an exclusive period end.
		"lastDay": func(t time.Time) time.Time { return t.Add(-time.Second) },
		"shortHash": func(h string) string {
			if len(h) > 12 {
				return h[:12]
			}
			return h
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

func (s *Server) notificationText(n store.Notification) string { return notify.Text(s.l, n) }

// Handler returns the root handler: each request is served by the variant
// for its language.
func (s *Server) Handler() http.Handler {
	handlers := make(map[string]http.Handler, len(s.variants))
	for loc, v := range s.variants {
		handlers[loc] = v.mux()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlers[s.variant(r).l.Locale()].ServeHTTP(w, r)
	})
}

func (s *Server) mux() http.Handler {
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
	mux.HandleFunc("GET /lang", s.langSwitch)
	mux.HandleFunc("GET /login/mfa", s.loginMFAPage)
	mux.HandleFunc("POST /login/mfa", s.loginMFASubmit)
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
	mux.Handle("GET /servers/{id}/score", view(s.hostScore))
	mux.Handle("POST /servers/{id}/jobs", operate(s.serverCreateJob))
	mux.Handle("POST /servers/{id}/preview", operate(s.serverPreview))
	mux.Handle("POST /servers/{id}/rescan", operate(s.serverRescan))
	mux.Handle("POST /servers/{id}/notes", operate(s.serverNotes))
	mux.Handle("POST /servers/{id}/exclude", operate(s.serverExclude))
	mux.Handle("POST /servers/{id}/delete", admin(s.serverDelete))
	mux.Handle("POST /servers/{id}/groups", operate(s.serverGroups))
	mux.Handle("POST /servers/bulk-groups", operate(s.groupMembers))

	mux.Handle("GET /groups", view(s.groups))
	mux.Handle("POST /groups", admin(s.groupCreate))
	mux.Handle("GET /groups/{id}", view(s.group))
	mux.Handle("POST /groups/{id}", admin(s.groupUpdate))
	mux.Handle("POST /groups/{id}/delete", admin(s.groupDelete))

	// The compliance report moved into Compliance & audit.
	mux.Handle("GET /reports", view(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/compliance/reports", http.StatusMovedPermanently)
	}))
	mux.Handle("GET /compliance", view(s.complianceOverview))
	mux.Handle("GET /compliance/reports", view(s.complianceReports))
	mux.Handle("POST /compliance/reports", operate(s.complianceReportCreate))
	mux.Handle("GET /compliance/reports/{id}", view(s.complianceReport))
	mux.Handle("POST /compliance/reports/{id}/regenerate", operate(s.complianceRegenerate))
	mux.Handle("POST /compliance/reports/{id}/delete", admin(s.complianceDelete))
	mux.Handle("POST /compliance/reports/{id}/versions/{n}/review", admin(s.complianceReview))
	mux.Handle("POST /compliance/reports/{id}/versions/{n}/finalize", admin(s.complianceFinalize))
	mux.Handle("GET /compliance/reports/{id}/versions/{n}/export", view(s.complianceExport))
	mux.Handle("GET /compliance/evidence", view(s.complianceEvidence))
	mux.Handle("POST /compliance/evidence", operate(s.complianceEvidenceAdd))
	mux.Handle("GET /compliance/evidence/{id}", view(s.complianceEvidenceItem))
	mux.Handle("GET /compliance/history", view(s.complianceHistory))
	mux.Handle("GET /compliance/policies", view(s.compliancePolicies))
	mux.Handle("POST /compliance/policies", admin(s.compliancePoliciesSave))
	mux.Handle("POST /compliance/policies/controls", admin(s.complianceControlsSave))

	mux.Handle("GET /vulnerabilities", view(s.vulnerabilities))
	mux.Handle("GET /vulnerabilities.csv", view(s.vulnerabilitiesCSV))
	mux.Handle("GET /vulnerabilities/{id}", view(s.vulnerability))
	mux.Handle("POST /vulnerabilities/{id}/status", operate(s.vulnerabilityStatus))
	mux.Handle("POST /vulnerabilities/{id}/remediate", operate(s.vulnerabilityRemediate))

	mux.Handle("GET /packages", view(s.packages))
	mux.Handle("GET /packages/{name}", view(s.packageDetail))
	mux.Handle("POST /packages/{name}/upgrade", operate(s.packageUpgrade))
	mux.Handle("POST /packages/security-all", operate(s.packagesSecurityAll))
	mux.Handle("POST /watched", view(s.watchToggle))
	mux.Handle("GET /software", view(s.softwarePage))
	mux.Handle("GET /software/{id}", view(s.softwareDetail))

	mux.Handle("GET /jobs", view(s.jobs))
	mux.Handle("GET /jobs/{id}", view(s.job))
	mux.Handle("POST /jobs/{id}/cancel", operate(s.jobCancel))
	mux.Handle("POST /jobs/{id}/retry", operate(s.jobRetry))
	mux.Handle("POST /jobs/{id}/approve", operate(s.jobApprove))
	mux.Handle("POST /jobs/{id}/rollback-check", operate(s.jobRollbackCheck))
	mux.Handle("POST /jobs/{id}/rollback-apply", operate(s.jobRollbackApply))

	mux.Handle("GET /rollouts", view(s.rollouts))
	mux.Handle("GET /rollouts/new", operate(s.rolloutNew))
	mux.Handle("POST /rollouts", operate(s.rolloutCreate))
	mux.Handle("GET /rollouts/{id}", view(s.rolloutDetail))
	mux.Handle("POST /rollouts/{id}/{action}", operate(s.rolloutAction))
	mux.Handle("GET /standards", view(s.standards))
	mux.Handle("GET /standards/new", admin(s.standardNew))
	mux.Handle("POST /standards", admin(s.standardSave))
	mux.Handle("GET /standards/{id}", admin(s.standardEdit))
	mux.Handle("POST /standards/{id}", admin(s.standardSave))
	mux.Handle("POST /standards/{id}/delete", admin(s.standardDelete))
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
	mux.Handle("POST /profile/language", view(s.profileLanguage))
	mux.Handle("POST /profile/mfa/setup", view(s.profileMFASetup))
	mux.Handle("POST /profile/mfa/enable", view(s.profileMFAEnable))
	mux.Handle("POST /profile/mfa/disable", view(s.profileMFADisable))
	mux.Handle("POST /profile/mfa/recovery", view(s.profileMFARecovery))
	mux.Handle("POST /users/{id}/reset-mfa", admin(s.userResetMFA))

	mux.Handle("GET /settings", admin(s.settings))
	mux.Handle("POST /settings", admin(s.settingsSave))
	mux.Handle("POST /settings/test-email", admin(s.settingsTestEmail))
	mux.Handle("POST /settings/scan-now", admin(s.settingsScanNow))
	mux.Handle("GET /settings/audit", admin(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/compliance/history?tab=audit", http.StatusMovedPermanently)
	}))
	mux.Handle("GET /settings/system", admin(s.systemConfig))
	mux.Handle("POST /settings/system", admin(s.systemSave))
	mux.Handle("POST /settings/system/reset", admin(s.systemReset))
	mux.Handle("POST /settings/system/update-check", admin(s.updateCheck))
	mux.Handle("POST /settings/system/self-update", admin(s.selfUpdateStart))
	mux.Handle("GET /settings/system/self-update/status", admin(s.selfUpdateStatus))
	mux.Handle("POST /settings/backups/run", admin(s.backupRun))
	mux.Handle("GET /settings/backups/{name}", admin(s.backupDownload))
	mux.Handle("GET /settings/health", admin(s.healthChecks))
	mux.Handle("POST /settings/health", admin(s.healthCheckCreate))
	mux.Handle("GET /settings/health/{id}", admin(s.healthCheckEdit))
	mux.Handle("POST /settings/health/{id}", admin(s.healthCheckUpdate))
	mux.Handle("POST /settings/health/{id}/delete", admin(s.healthCheckDelete))
	mux.Handle("GET /settings/score", admin(s.scoreSettings))
	mux.Handle("POST /settings/score", admin(s.scoreSettingsSave))
	mux.Handle("GET /settings/channels", admin(s.channels))
	mux.Handle("POST /settings/channels", admin(s.channelCreate))
	mux.Handle("GET /settings/channels/{id}", admin(s.channelDetail))
	mux.Handle("POST /settings/channels/{id}/filter", admin(s.channelFilter))
	mux.Handle("POST /settings/channels/{id}/deliveries/{delivery}/resend", admin(s.channelResend))
	mux.Handle("POST /settings/channels/{id}/test", admin(s.channelTest))
	mux.Handle("POST /settings/channels/{id}/toggle", admin(s.channelToggle))
	mux.Handle("POST /settings/channels/{id}/delete", admin(s.channelDelete))

	mux.Handle("POST /profile/api-tokens", view(s.apiTokenCreate))
	mux.Handle("POST /profile/api-tokens/{id}/revoke", view(s.apiTokenRevoke))
	// REST API and Prometheus metrics (API key, no cookies).
	mux.Handle("GET /api/v1/hosts", s.apiAuth(false, s.apiHosts))
	mux.Handle("GET /api/v1/hosts/{id}", s.apiAuth(false, s.apiHost))
	mux.Handle("GET /api/v1/hosts/{id}/findings", s.apiAuth(false, s.apiHostFindings))
	mux.Handle("GET /api/v1/hosts/{id}/updates", s.apiAuth(false, s.apiHostUpdates))
	mux.Handle("GET /api/v1/hosts/{id}/software", s.apiAuth(false, s.apiHostSoftware))
	mux.Handle("GET /api/v1/software", s.apiAuth(false, s.apiSoftwareList))
	mux.Handle("GET /api/v1/eol", s.apiAuth(false, s.apiEOL))
	mux.Handle("GET /api/v1/hosts/{id}/score", s.apiAuth(false, s.apiHostScore))
	mux.Handle("GET /api/v1/drift", s.apiAuth(false, s.apiDrift))
	mux.Handle("GET /api/v1/hosts/{id}/health", s.apiAuth(false, s.apiHostHealth))
	mux.Handle("GET /api/v1/rollouts", s.apiAuth(false, s.apiRollouts))
	mux.Handle("GET /api/v1/compliance/reports", s.apiAuth(false, s.apiComplianceReports))
	mux.Handle("GET /api/v1/compliance/reports/{id}/versions/{n}", s.apiAuth(false, s.apiComplianceVersion))
	mux.Handle("GET /api/v1/compliance/evidence", s.apiAuth(false, s.apiComplianceEvidence))
	mux.Handle("POST /api/v1/hosts/{id}/jobs", s.apiAuth(true, s.apiCreateJob))
	mux.Handle("GET /api/v1/vulnerabilities", s.apiAuth(false, s.apiVulnerabilities))
	mux.Handle("GET /api/v1/vulnerabilities/{id}", s.apiAuth(false, s.apiVulnerability))
	mux.Handle("GET /api/v1/groups", s.apiAuth(false, s.apiGroups))
	mux.Handle("GET /api/v1/jobs", s.apiAuth(false, s.apiJobs))
	mux.Handle("GET /api/v1/jobs/{id}", s.apiAuth(false, s.apiJob))
	mux.Handle("GET /metrics", s.apiAuth(false, s.metrics))

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
	// Languages offers the interface languages (login and profile pages).
	Languages []languageOption
	// Path is the current request URI (for the language switch).
	Path string
}

func (s *Server) page(r *http.Request, title, active string) pageData {
	d := pageData{Product: brand.Name, Version: version.Version, Lang: s.l.Lang(), Title: title, Active: active, Nav: navigation,
		Languages: s.languages(), Path: r.URL.RequestURI()}
	if sess := sessionFrom(r); sess != nil {
		u := sess.user
		d.User, d.CSRF = &u, sess.csrf
		d.Unread, _ = s.st.UnreadNotifications(r.Context())
		if u.Limited() {
			// Group-limited users do not get the fleet-wide pages.
			d.Nav = nil
			for _, n := range navigation {
				if !fleetWidePath(n.Href) {
					d.Nav = append(d.Nav, n)
				}
			}
		}
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

// auditEntry builds the audit log entry of a request (user, IP, API key).
func (s *Server) auditEntry(r *http.Request, action, target, details string) store.AuditEntry {
	e := store.AuditEntry{Action: action, Target: target, Details: details, IP: s.clientIP(r)}
	if sess := sessionFrom(r); sess != nil {
		e.UserID, e.UserEmail = sess.user.ID, sess.user.Email
		if sess.apiToken != "" {
			e.Details = strings.TrimSpace(e.Details + " api_token=" + sess.apiToken)
		}
	}
	return e
}

func (s *Server) audit(r *http.Request, action, target, details string) {
	e := s.auditEntry(r, action, target, details)
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

// usage is a usage bar: used and free shares (data-grow) and the level
// against a warning limit (ok, warn within 10 points of it, bad at it).
type usage struct {
	Used, Free int
	Level      string
}

func usageBar(pct float64, limit int) usage {
	u := int(math.Round(min(max(pct, 0), 100)))
	level := "ok"
	switch {
	case limit > 0 && pct >= float64(limit):
		level = "bad"
	case limit > 0 && pct >= float64(limit-10):
		level = "warn"
	}
	return usage{Used: u, Free: 100 - u, Level: level}
}

// resVal is one compact resource value of the server list.
type resVal struct {
	Key, Level string
	Used       int
	Known      bool
}
