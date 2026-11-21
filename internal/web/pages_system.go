package web

import (
	"context"
	"net/http"
	"net/mail"
	"slices"
	"strconv"
	"strings"
	"time"

	"netio.patchman/internal/settings"
)

// commonTimezones are offered as suggestions; any IANA zone name is accepted.
var commonTimezones = []string{
	"Europe/Istanbul", "UTC", "Europe/London", "Europe/Berlin", "Europe/Amsterdam", "Europe/Paris", "Europe/Moscow",
	"Europe/Kyiv", "Asia/Baku", "Asia/Dubai", "Asia/Tbilisi", "Asia/Almaty", "America/New_York", "America/Chicago",
	"America/Los_Angeles", "Asia/Tokyo", "Asia/Singapore", "Australia/Sydney",
}

// systemForm is the server configuration form. The SMTP password is never
// sent back to the browser.
type systemForm struct {
	BaseURL         string
	TrustProxy      bool
	Timezone        string
	LogLevel        string
	SMTPHost        string
	SMTPPort        string
	SMTPUsername    string
	SMTPFromName    string
	SMTPFromAddress string
	OSVURL          string
	KEVEnabled      bool
	KEVURL          string
	MSRCEnabled     bool
	MSRCURL         string
	EPSSEnabled     bool
	EPSSURL         string
	UpdateEnabled   bool
	UpdateURL       string
}

func systemFormFrom(sys settings.System) systemForm {
	return systemForm{
		BaseURL: sys.BaseURLString(), TrustProxy: sys.TrustProxy, Timezone: sys.Timezone, LogLevel: sys.LogLevelName(),
		SMTPHost: sys.SMTP.Host, SMTPPort: strconv.Itoa(sys.SMTP.Port), SMTPUsername: sys.SMTP.Username,
		SMTPFromName: sys.SMTP.From.Name, SMTPFromAddress: sys.SMTP.From.Address,
		OSVURL: sys.OSVURL, KEVEnabled: sys.KEVURL != "", KEVURL: sys.KEVSourceURL,
		MSRCEnabled: sys.MSRCURL != "", MSRCURL: sys.MSRCSourceURL,
		EPSSEnabled: sys.EPSSURL != "", EPSSURL: sys.EPSSSourceURL,
		UpdateEnabled: sys.UpdateURL != "", UpdateURL: sys.UpdateSourceURL,
	}
}

func (s *Server) systemConfig(w http.ResponseWriter, r *http.Request) {
	s.renderSystem(w, r, http.StatusOK, "", systemFormFrom(s.sys()))
}

func (s *Server) renderSystem(w http.ResponseWriter, r *http.Request, status int, errMsg string, form systemForm) {
	raw, err := s.st.Settings(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	stored := map[string]bool{}
	anyStored := false
	for _, k := range settings.SystemKeys {
		_, stored[k] = raw[k]
		anyStored = anyStored || stored[k]
	}
	sys := s.sys()
	env := s.o.System.Env()
	d := s.page(r, s.l.T("system.title"), "settings")
	d.Error = errMsg
	d.Data = map[string]any{
		"Form": form, "PasswordSet": sys.SMTP.Password != "", "EmailConfigured": s.o.Notifier.EmailConfigured(),
		"Stored": stored, "AnyStored": anyStored,
		"Timezones": commonTimezones, "LogLevels": settings.LogLevels,
		"Env": map[string]any{
			"HTTPAddr": env.HTTPAddr, "Database": env.DatabasePath(), "AgentDistDir": env.AgentDistDir,
			"TLS": env.TLSCertFile != "", "TLSCertFile": env.TLSCertFile, "LogFormat": env.LogFormat, "Locale": env.Locale,
		},
	}
	if s.o.Updates != nil {
		st := s.o.Updates.Status()
		d.Data.(map[string]any)["UpdateStatus"] = &st
	}
	s.render(w, r, status, "system", d)
}

// hasControl reports whether s contains CR, LF or other control characters
// (header injection in SMTP values).
func hasControl(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0
}

func (s *Server) systemSave(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	in := func(k string) string { return strings.TrimSpace(r.PostFormValue(k)) }
	f := systemForm{
		BaseURL: in("base_url"), TrustProxy: r.PostFormValue("trust_proxy") == "1", Timezone: in("timezone"), LogLevel: in("log_level"),
		SMTPHost: in("smtp_host"), SMTPPort: in("smtp_port"), SMTPUsername: in("smtp_username"),
		SMTPFromName: in("smtp_from_name"), SMTPFromAddress: in("smtp_from_address"),
		OSVURL: in("osv_url"), KEVEnabled: r.PostFormValue("kev_enabled") == "1", KEVURL: in("kev_url"),
		MSRCEnabled: r.PostFormValue("msrc_enabled") == "1", MSRCURL: in("msrc_url"),
		EPSSEnabled: r.PostFormValue("epss_enabled") == "1", EPSSURL: in("epss_url"),
		UpdateEnabled: r.PostFormValue("update_enabled") == "1", UpdateURL: in("update_url"),
	}
	password := r.PostFormValue("smtp_password") // not trimmed
	clearPassword := r.PostFormValue("smtp_password_clear") == "1"

	var bad []string
	field := func(key string) string { return s.l.T(key) }
	kv := map[string]string{}

	if u, err := settings.ParseBaseURL(f.BaseURL); err != nil {
		bad = append(bad, s.l.T("system.error.url", "field", field("system.base_url")))
	} else {
		kv[settings.KeyBaseURL] = u.String()
	}
	kv[settings.KeyTrustProxy] = strconv.FormatBool(f.TrustProxy)
	if _, err := settings.LoadTimezone(f.Timezone); err != nil {
		bad = append(bad, s.l.T("system.error.timezone", "value", f.Timezone))
	} else {
		kv[settings.KeyTimezone] = f.Timezone
	}
	if slices.Contains(settings.LogLevels, f.LogLevel) {
		kv[settings.KeyLogLevel] = f.LogLevel
	} else {
		bad = append(bad, s.l.T("validation.required", "field", field("system.log_level")))
	}

	if f.SMTPHost != "" && !settings.ValidSMTPHost(f.SMTPHost) {
		bad = append(bad, s.l.T("system.error.smtp_host"))
	}
	kv[settings.KeySMTPHost] = f.SMTPHost
	if p, err := strconv.Atoi(f.SMTPPort); err != nil || p < 1 || p > 65535 {
		bad = append(bad, s.l.T("validation.range", "field", field("system.smtp.port"), "min", 1, "max", 65535))
	} else {
		kv[settings.KeySMTPPort] = strconv.Itoa(p)
	}
	if hasControl(f.SMTPUsername) || hasControl(f.SMTPFromName) || hasControl(password) || len(f.SMTPFromName) > 100 {
		bad = append(bad, s.l.T("system.error.smtp_text"))
	}
	kv[settings.KeySMTPUsername] = f.SMTPUsername
	kv[settings.KeySMTPFromName] = f.SMTPFromName
	if f.SMTPFromAddress != "" {
		a, err := mail.ParseAddress(f.SMTPFromAddress)
		if err != nil {
			bad = append(bad, s.l.T("system.error.from_address"))
		} else {
			kv[settings.KeySMTPFromAddress] = a.Address
		}
	} else {
		if f.SMTPHost != "" {
			bad = append(bad, s.l.T("system.error.from_required"))
		}
		kv[settings.KeySMTPFromAddress] = ""
	}
	if clearPassword {
		kv[settings.KeySMTPPassword] = ""
	} else if password != "" {
		kv[settings.KeySMTPPassword] = password
	}

	if u, err := settings.ParseSourceURL(f.OSVURL); err != nil {
		bad = append(bad, s.l.T("system.error.url", "field", field("system.osv_url")))
	} else {
		kv[settings.KeyOSVURL] = u
	}
	kv[settings.KeyKEVEnabled] = strconv.FormatBool(f.KEVEnabled)
	if u, err := settings.ParseSourceURL(f.KEVURL); err != nil {
		if f.KEVEnabled || f.KEVURL != "" {
			bad = append(bad, s.l.T("system.error.url", "field", field("system.kev_url")))
		}
	} else {
		kv[settings.KeyKEVURL] = u
	}
	// Forms from before the MSRC fields keep the stored values.
	if _, ok := r.PostForm["msrc_url"]; ok {
		kv[settings.KeyMSRCEnabled] = strconv.FormatBool(f.MSRCEnabled)
		if u, err := settings.ParseSourceURL(f.MSRCURL); err != nil {
			if f.MSRCEnabled || f.MSRCURL != "" {
				bad = append(bad, s.l.T("system.error.url", "field", field("system.msrc_url")))
			}
		} else {
			kv[settings.KeyMSRCURL] = u
		}
	}
	if _, ok := r.PostForm["epss_url"]; ok {
		kv[settings.KeyEPSSEnabled] = strconv.FormatBool(f.EPSSEnabled)
		if u, err := settings.ParseSourceURL(f.EPSSURL); err != nil {
			if f.EPSSEnabled || f.EPSSURL != "" {
				bad = append(bad, s.l.T("system.error.url", "field", field("system.epss_url")))
			}
		} else {
			kv[settings.KeyEPSSURL] = u
		}
	}
	kv[settings.KeyUpdateEnabled] = strconv.FormatBool(f.UpdateEnabled)
	if u, err := settings.ParseSourceURL(f.UpdateURL); err != nil {
		if f.UpdateEnabled || f.UpdateURL != "" {
			bad = append(bad, s.l.T("system.error.url", "field", field("system.update.url")))
		}
	} else {
		kv[settings.KeyUpdateURL] = u
	}

	if len(bad) > 0 {
		s.renderSystem(w, r, http.StatusBadRequest, strings.Join(bad, " "), f)
		return
	}

	old, err := s.st.Settings(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	before := s.sys()
	var changed []string
	for _, k := range settings.SystemKeys {
		if v, ok := kv[k]; ok {
			if ov, had := old[k]; !had || ov != v {
				changed = append(changed, k)
			}
		}
	}
	if err := s.st.SaveSettings(r.Context(), kv); err != nil {
		s.serverError(w, r, err)
		return
	}
	if err := s.o.System.Reload(r.Context()); err != nil {
		s.serverError(w, r, err)
		return
	}
	// Only key names are audited; values (the SMTP password) are not.
	s.audit(r, "settings.system_update", "", "changed="+strings.Join(changed, ","))
	msg := s.l.T("common.saved")
	if before.BaseURLString() != s.sys().BaseURLString() {
		msg = s.l.T("system.saved_base_url")
	}
	s.redirect(w, r, "/settings/system", "success", msg)
}

func (s *Server) systemReset(w http.ResponseWriter, r *http.Request) {
	if err := s.st.DeleteSettings(r.Context(), settings.SystemKeys...); err != nil {
		s.serverError(w, r, err)
		return
	}
	if err := s.o.System.Reload(r.Context()); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "settings.system_reset", "", "")
	s.redirect(w, r, "/settings/system", "success", s.l.T("system.reset_done"))
}

// updateCheck runs the new-version check now.
func (s *Server) updateCheck(w http.ResponseWriter, r *http.Request) {
	const back = "/settings/system#updates"
	if s.o.Updates == nil || !s.o.Updates.Status().Enabled {
		s.redirect(w, r, back, "error", s.l.T("system.update.disabled"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	st := s.o.Updates.Check(ctx)
	switch {
	case st.Error != "":
		s.redirect(w, r, back, "error", s.l.T("system.update.checked_failed", "error", st.Error))
	case st.Available():
		s.redirect(w, r, back, "warning", s.l.T("system.update.checked_new", "latest", st.Latest, "current", st.Current))
	default:
		s.redirect(w, r, back, "success", s.l.T("system.update.checked_ok", "current", st.Current))
	}
}
