package web

import (
	"errors"
	"net/http"
	"net/mail"
	"strconv"
	"strings"
	"time"

	"netio.patchman/internal/auth"
	"netio.patchman/internal/notify"
	"netio.patchman/internal/release"
	"netio.patchman/internal/settings"
	"netio.patchman/internal/store"
	"netio.patchman/internal/timeutil"
	"netio.patchman/internal/vuln"
)

func parseEmail(s string) (string, error) {
	a, err := mail.ParseAddress(s)
	if err != nil {
		return "", err
	}
	return a.Address, nil
}

// ---------- agents & enrollment tokens ----------

type newToken struct {
	Name    string
	Token   string
	Command installPicker
}

// installTarget is one distribution family in the install command picker.
// The defaults follow a stock installation: Ubuntu and Fedora create a sudo
// user and lock root, while RHEL-family, Debian (with a root password), SUSE
// and Alpine are usually administered as root and may not have sudo at all.
// Minimal Debian and Alpine ship wget but not curl.
type installTarget struct {
	ID       string // i18n key suffix: agents.install.os.<ID>
	Wget     bool
	Sudo     bool // default privilege mode
	AsRoot   string
	WithSudo string
}

// Command is the command for the target's default privilege mode.
func (t installTarget) Command() string {
	if t.Sudo {
		return t.WithSudo
	}
	return t.AsRoot
}

// installPicker is the data for the "installcmd" template: one command per
// distribution and privilege mode. Without JS the first target is shown.
type installPicker struct {
	ID      string // element id prefix
	Targets []installTarget
}

// Default is the command shown before a distribution is picked.
func (p installPicker) Default() string { return p.Targets[0].Command() }

var installTargets = []installTarget{
	{ID: "ubuntu", Sudo: true},
	{ID: "debian", Wget: true},
	{ID: "rhel"},
	{ID: "fedora", Sudo: true},
	{ID: "suse"},
	{ID: "alpine", Wget: true},
}

func installCommands(base, token string, wget bool) (asRoot, withSudo string) {
	fetch := "curl -fsSL " + base + "/downloads/install-agent.sh"
	if wget {
		fetch = "wget -qO- " + base + "/downloads/install-agent.sh"
	}
	args := " -s -- --server-url " + base + " --token " + token
	return fetch + " | sh" + args, fetch + " | sudo sh" + args
}

func (s *Server) installCommand(id, token string) installPicker {
	base := s.baseURL()
	p := installPicker{ID: id}
	for _, t := range installTargets {
		t.AsRoot, t.WithSudo = installCommands(base, token, t.Wget)
		p.Targets = append(p.Targets, t)
	}
	return p
}

func (s *Server) agents(w http.ResponseWriter, r *http.Request) {
	s.renderAgents(w, r, nil, http.StatusOK)
}

func (s *Server) renderAgents(w http.ResponseWriter, r *http.Request, nt *newToken, status int) {
	ctx := r.Context()
	tokens, err := s.st.ListEnrollmentTokens(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	pg := pageNumber(r)
	hosts, total, err := s.st.ListHosts(ctx, store.HostFilter{OfflineAfter: s.offlineAfter(), Status: r.URL.Query().Get("status")}, store.Page{Number: pg, Size: pageSize})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	versions, _ := s.st.AgentVersions(ctx)
	cfg, _ := settings.Load(ctx, s.st)
	outdated := 0
	for _, v := range versions {
		if v[0] != s.o.Release.Version {
			n, _ := strconv.Atoi(v[1])
			outdated += n
		}
	}
	var archs []string
	for _, a := range release.SupportedArchs {
		if _, ok := s.o.Release.For(a); ok {
			archs = append(archs, a)
		}
	}
	d := s.page(r, s.l.T("nav.agents"), "agents")
	d.Data = map[string]any{
		"Tokens": tokens, "NewToken": nt, "Hosts": hosts, "Pager": newPager(r, pg, total), "Versions": versions,
		"Release": s.o.Release, "ReleaseArchs": strings.Join(archs, ", "), "AutoUpdate": cfg.AgentAutoUpdate, "Outdated": outdated,
		"BaseURL": s.baseURL(), "ExampleCommand": s.installCommand("example-command", s.l.T("agents.install.token_placeholder")),
		"Status": r.URL.Query().Get("status"),
	}
	s.render(w, r, status, "agents", d)
}

func (s *Server) tokenCreate(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PostFormValue("name"))
	if name == "" {
		s.redirect(w, r, "/agents", "error", s.l.T("validation.required", "field", s.l.T("agents.token.name")))
		return
	}
	days, _ := strconv.Atoi(r.PostFormValue("valid_days"))
	maxUses, _ := strconv.Atoi(r.PostFormValue("max_uses"))
	if days < 0 || days > 3650 || maxUses < 0 || maxUses > 100000 {
		s.redirect(w, r, "/agents", "error", s.l.T("agents.token.invalid_limits"))
		return
	}
	var expires time.Time
	if days > 0 {
		expires = timeutil.Now().Add(time.Duration(days) * 24 * time.Hour)
	}
	token := "npe_" + auth.RandomToken(24)
	prefix := token[:10]
	id, err := s.st.CreateEnrollmentToken(r.Context(), name, auth.HashToken(token), prefix, sessionFrom(r).user.ID, expires, maxUses)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "token.create", name, "token_id="+strconv.FormatInt(id, 10))
	// The token is shown exactly once; only its hash is stored.
	s.renderAgents(w, r, &newToken{Name: name, Token: token, Command: s.installCommand("new-command", token)}, http.StatusOK)
}

func (s *Server) tokenRevoke(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		s.errorPage(w, r, http.StatusNotFound, "error.not_found")
		return
	}
	if err := s.st.RevokeEnrollmentToken(r.Context(), id); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "token.revoke", strconv.FormatInt(id, 10), "")
	s.redirect(w, r, "/agents", "success", s.l.T("agents.token.revoked"))
}

// ---------- notifications ----------

func (s *Server) notifications(w http.ResponseWriter, r *http.Request) {
	unread := r.URL.Query().Get("filter") == "unread"
	pg := pageNumber(r)
	rows, total, err := s.st.ListNotifications(r.Context(), unread, store.Page{Number: pg, Size: pageSize})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d := s.page(r, s.l.T("nav.notifications"), "notifications")
	d.Data = map[string]any{"Rows": rows, "UnreadOnly": unread, "Pager": newPager(r, pg, total)}
	s.render(w, r, http.StatusOK, "notifications", d)
}

func (s *Server) notificationsRead(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PostFormValue("id"), 10, 64)
	if err := s.st.MarkNotificationsRead(r.Context(), id); err != nil {
		s.serverError(w, r, err)
		return
	}
	if link := r.PostFormValue("link"); id > 0 && strings.HasPrefix(link, "/") && !strings.HasPrefix(link, "//") {
		http.Redirect(w, r, link, http.StatusSeeOther)
		return
	}
	s.redirect(w, r, "/notifications", "success", s.l.T("notifications.marked_read"))
}

// ---------- users ----------

func (s *Server) users(w http.ResponseWriter, r *http.Request) {
	s.renderUsers(w, r, http.StatusOK, "", map[string]string{})
}

func (s *Server) renderUsers(w http.ResponseWriter, r *http.Request, status int, errMsg string, form map[string]string) {
	list, err := s.st.ListUsers(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d := s.page(r, s.l.T("nav.users"), "users")
	d.Error = errMsg
	d.Data = map[string]any{"Users": list, "Form": form, "Roles": []string{store.RoleAdmin, store.RoleOperator, store.RoleViewer}}
	s.render(w, r, status, "users", d)
}

func (s *Server) userCreate(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PostFormValue("name"))
	email := strings.TrimSpace(r.PostFormValue("email"))
	role := r.PostFormValue("role")
	pw, pw2 := r.PostFormValue("password"), r.PostFormValue("password_confirm")
	form := map[string]string{"name": name, "email": email, "role": role}
	if msg := s.validateUserInput(name, email, pw, pw2, true); msg != "" {
		s.renderUsers(w, r, http.StatusBadRequest, msg, form)
		return
	}
	if !store.ValidRole(role) {
		s.renderUsers(w, r, http.StatusBadRequest, s.l.T("user.error.invalid_role"), form)
		return
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	_, err = s.st.CreateUser(r.Context(), store.User{Email: email, Name: name, PasswordHash: hash, Role: role})
	if errors.Is(err, store.ErrDuplicate) {
		s.renderUsers(w, r, http.StatusConflict, s.l.T("user.error.duplicate_email"), form)
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "user.create", email, "role="+role)
	s.redirect(w, r, "/users", "success", s.l.T("user.created", "email", email))
}

func (s *Server) userOr404(w http.ResponseWriter, r *http.Request) (store.User, bool) {
	id, ok := pathID(r)
	if !ok {
		s.errorPage(w, r, http.StatusNotFound, "error.not_found")
		return store.User{}, false
	}
	u, err := s.st.UserByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, r, http.StatusNotFound, "error.not_found")
		return u, false
	}
	if err != nil {
		s.serverError(w, r, err)
		return u, false
	}
	return u, true
}

func (s *Server) user(w http.ResponseWriter, r *http.Request) {
	u, ok := s.userOr404(w, r)
	if !ok {
		return
	}
	d := s.page(r, u.Name, "users")
	d.Data = map[string]any{"U": u, "Roles": []string{store.RoleAdmin, store.RoleOperator, store.RoleViewer}}
	s.render(w, r, http.StatusOK, "user", d)
}

// wouldRemoveLastAdmin reports whether changing u leaves no active admin.
func (s *Server) wouldRemoveLastAdmin(r *http.Request, u store.User, newRole string, disabled bool) bool {
	if !u.IsAdmin() || u.Disabled || (newRole == store.RoleAdmin && !disabled) {
		return false
	}
	n, err := s.st.CountActiveAdmins(r.Context())
	return err != nil || n <= 1
}

func (s *Server) userUpdate(w http.ResponseWriter, r *http.Request) {
	u, ok := s.userOr404(w, r)
	if !ok {
		return
	}
	back := "/users/" + strconv.FormatInt(u.ID, 10)
	name := strings.TrimSpace(r.PostFormValue("name"))
	role := r.PostFormValue("role")
	disabled := r.PostFormValue("disabled") == "1"
	if name == "" {
		s.redirect(w, r, back, "error", s.l.T("validation.required", "field", s.l.T("user.field.name")))
		return
	}
	if !store.ValidRole(role) {
		s.redirect(w, r, back, "error", s.l.T("user.error.invalid_role"))
		return
	}
	if s.wouldRemoveLastAdmin(r, u, role, disabled) {
		s.redirect(w, r, back, "error", s.l.T("user.error.last_admin"))
		return
	}
	if err := s.st.UpdateUser(r.Context(), u.ID, name, role, disabled); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "user.update", u.Email, "role="+role+" disabled="+strconv.FormatBool(disabled))
	s.redirect(w, r, back, "success", s.l.T("common.saved"))
}

func (s *Server) userResetPassword(w http.ResponseWriter, r *http.Request) {
	u, ok := s.userOr404(w, r)
	if !ok {
		return
	}
	pw := auth.RandomPassword()
	hash, err := auth.HashPassword(pw)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if err := s.st.SetPassword(r.Context(), u.ID, hash, ""); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "user.password_reset", u.Email, "")
	d := s.page(r, u.Name, "users")
	d.Data = map[string]any{"U": u, "Roles": []string{store.RoleAdmin, store.RoleOperator, store.RoleViewer}, "NewPassword": pw}
	s.render(w, r, http.StatusOK, "user", d)
}

func (s *Server) userDelete(w http.ResponseWriter, r *http.Request) {
	u, ok := s.userOr404(w, r)
	if !ok {
		return
	}
	back := "/users/" + strconv.FormatInt(u.ID, 10)
	if u.ID == sessionFrom(r).user.ID {
		s.redirect(w, r, back, "error", s.l.T("user.error.delete_self"))
		return
	}
	if s.wouldRemoveLastAdmin(r, u, "", true) {
		s.redirect(w, r, back, "error", s.l.T("user.error.last_admin"))
		return
	}
	if err := s.st.DeleteUser(r.Context(), u.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "user.delete", u.Email, "")
	s.redirect(w, r, "/users", "success", s.l.T("user.deleted", "email", u.Email))
}

// ---------- settings ----------

func (s *Server) settings(w http.ResponseWriter, r *http.Request) {
	cfg, err := settings.Load(r.Context(), s.st)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	kevCount, _ := s.st.KEVCount(r.Context())
	d := s.page(r, s.l.T("nav.settings"), "settings")
	d.Data = map[string]any{
		"Cfg": cfg, "Recipients": strings.Join(cfg.EmailRecipients, "\n"), "EmailConfigured": s.o.Notifier.EmailConfigured(),
		"Scan": s.o.Scanner.Status(), "KEVCount": kevCount,
		"Severities": []vuln.Severity{vuln.SeverityCritical, vuln.SeverityHigh, vuln.SeverityMedium, vuln.SeverityLow},
	}
	s.render(w, r, http.StatusOK, "settings", d)
}

func (s *Server) settingsSave(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	b := func(k string) string { return strconv.FormatBool(r.PostFormValue(k) == "1") }
	intIn := func(k string, lo, hi int) (string, bool) {
		v, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue(k)))
		return strconv.Itoa(v), err == nil && v >= lo && v <= hi
	}
	kv := map[string]string{
		settings.KeyEmailEnabled:      b("email_enabled"),
		settings.KeyEmailKEVAlways:    b("email_kev_always"),
		settings.KeyEmailAgentOffline: b("email_agent_offline"),
		settings.KeyEmailJobFailed:    b("email_job_failed"),
		settings.KeyEmailServerUpdate: b("email_server_update"),
		settings.KeyScanEnabled:       b("scan_enabled"),
		settings.KeyAgentAutoUpdate:   b("agent_auto_update"),
	}
	var bad []string
	for _, f := range []struct {
		form, key, label string
		lo, hi           int
	}{
		{"email_digest_threshold", settings.KeyEmailDigestThreshold, "settings.email.digest_threshold", 1, 1000},
		{"agent_offline_minutes", settings.KeyAgentOfflineMinutes, "settings.agent.offline_minutes", 2, 10080},
		{"agent_checkin_seconds", settings.KeyAgentCheckinSeconds, "settings.agent.checkin_seconds", 15, 3600},
		{"agent_report_minutes", settings.KeyAgentReportMinutes, "settings.agent.report_minutes", 5, 1440},
		{"retention_days", settings.KeyRetentionDays, "settings.retention.days", 7, 3650},
	} {
		v, ok := intIn(f.form, f.lo, f.hi)
		if !ok {
			bad = append(bad, s.l.T("validation.range", "field", s.l.T(f.label), "min", f.lo, "max", f.hi))
			continue
		}
		kv[f.key] = v
	}
	sev := r.PostFormValue("email_min_severity")
	switch vuln.Severity(sev) {
	case vuln.SeverityCritical, vuln.SeverityHigh, vuln.SeverityMedium, vuln.SeverityLow:
		kv[settings.KeyEmailMinSeverity] = sev
	default:
		bad = append(bad, s.l.T("validation.required", "field", s.l.T("settings.email.min_severity")))
	}
	rawRecipients := r.PostFormValue("email_recipients")
	recipients := settings.ParseRecipients(rawRecipients)
	if strings.TrimSpace(rawRecipients) != "" && len(recipients) == 0 {
		bad = append(bad, s.l.T("validation.invalid_email"))
	}
	kv[settings.KeyEmailRecipients] = strings.Join(recipients, ",")
	if len(bad) > 0 {
		s.redirect(w, r, "/settings", "error", strings.Join(bad, " "))
		return
	}
	if err := s.st.SaveSettings(r.Context(), kv); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.reloadSettingsCache(r.Context())
	s.audit(r, "settings.update", "", "")
	s.redirect(w, r, "/settings", "success", s.l.T("common.saved"))
}

func (s *Server) settingsTestEmail(w http.ResponseWriter, r *http.Request) {
	back := "/settings"
	if r.PostFormValue("back") == "/settings/system" {
		back = "/settings/system"
	}
	to, err := parseEmail(strings.TrimSpace(r.PostFormValue("to")))
	if err != nil {
		s.redirect(w, r, back, "error", s.l.T("validation.invalid_email"))
		return
	}
	if err := s.o.Notifier.SendTest(r.Context(), to); err != nil {
		msg := err.Error()
		if errors.Is(err, notify.ErrEmailDisabled) {
			msg = s.l.T("settings.email.not_configured")
		}
		s.redirect(w, r, back, "error", s.l.T("settings.email.test_failed", "error", msg))
		return
	}
	s.audit(r, "settings.test_email", to, "")
	s.redirect(w, r, back, "success", s.l.T("settings.email.test_sent", "to", to))
}

func (s *Server) settingsScanNow(w http.ResponseWriter, r *http.Request) {
	if err := s.st.MarkAllForScan(r.Context()); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.o.Scanner.Trigger()
	s.audit(r, "scan.trigger", "", "")
	s.redirect(w, r, "/settings", "success", s.l.T("settings.scan.triggered"))
}

func (s *Server) auditLog(w http.ResponseWriter, r *http.Request) {
	pg := pageNumber(r)
	rows, total, err := s.st.ListAudit(r.Context(), store.Page{Number: pg, Size: pageSize})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d := s.page(r, s.l.T("audit.title"), "settings")
	d.Data = map[string]any{"Rows": rows, "Pager": newPager(r, pg, total)}
	s.render(w, r, http.StatusOK, "audit", d)
}
