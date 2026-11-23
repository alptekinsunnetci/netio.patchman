package web

import (
	"errors"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"netio.patchman/internal/backup"
	"netio.patchman/internal/notify"
	"netio.patchman/internal/schedule"
	"netio.patchman/internal/settings"
	"netio.patchman/internal/store"
	"netio.patchman/internal/timeutil"
)

// ---------- backups ----------

// backupData is shown in the backup section of the settings page.
func (s *Server) backupData(cfg settings.Values) map[string]any {
	d := map[string]any{"Enabled": s.o.Backups != nil, "Clock": schedule.Clock(cfg.BackupMinute)}
	if s.o.Backups == nil {
		return d
	}
	files, err := s.o.Backups.List()
	if err != nil {
		d["ListError"] = err.Error()
	}
	d["Files"], d["Dir"] = files, s.o.Backups.Dir
	d["Failing"] = cfg.BackupLastError != ""
	return d
}

func (s *Server) backupRun(w http.ResponseWriter, r *http.Request) {
	if s.o.Backups == nil {
		s.errorPage(w, r, http.StatusNotFound, "error.not_found")
		return
	}
	cfg, _ := settings.Load(r.Context(), s.st)
	f, err := s.o.Backups.Run(r.Context(), cfg.BackupKeep)
	if err != nil {
		s.redirect(w, r, "/settings#backup", "error", s.l.T("backup.failed", "error", err.Error()))
		return
	}
	s.audit(r, "backup.run", f.Name, "bytes="+strconv.FormatInt(f.Size, 10))
	s.redirect(w, r, "/settings#backup", "success", s.l.T("backup.done", "file", f.Name, "size", s.size(f.Size)))
}

// backupDownload streams a backup file. Backups hold password hashes and the
// SMTP password, so only administrators reach this and every download is audited.
func (s *Server) backupDownload(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if s.o.Backups == nil || !backup.ValidName(name) {
		s.errorPage(w, r, http.StatusNotFound, "error.not_found")
		return
	}
	p, err := s.o.Backups.Path(name)
	if err != nil {
		s.errorPage(w, r, http.StatusNotFound, "error.not_found")
		return
	}
	f, err := os.Open(p)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "backup.download", name, "")
	w.Header().Set("Content-Type", "application/vnd.sqlite3")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	http.ServeContent(w, r, name, st.ModTime(), f)
}

// size formats a byte count ("12,4 MB" in Turkish, "12.4 MB" in English).
func (s *Server) size(n int64) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	v, i := float64(n), 0
	for v >= 1024 && i < len(units)-1 {
		v /= 1024
		i++
	}
	num := strconv.FormatFloat(v, 'f', 1, 64)
	if i == 0 {
		num = strconv.FormatInt(n, 10)
	}
	return strings.Replace(num, ".", s.l.T("number.decimal"), 1) + " " + units[i]
}

// ---------- notification channels ----------

var (
	telegramTokenRE = regexp.MustCompile(`^[0-9]{5,}:[A-Za-z0-9_-]{30,}$`)
	telegramChatRE  = regexp.MustCompile(`^(-?[0-9]{1,20}|@[A-Za-z][A-Za-z0-9_]{4,31})$`)
)

// channelTarget describes a channel without revealing its secret.
func (s *Server) channelTarget(c store.Channel) string {
	switch c.Type {
	case store.ChannelTelegram:
		return s.l.T("channel.telegram_target", "chat", c.ChatID)
	case store.ChannelZabbix:
		return c.URL + " · " + c.Config["host"]
	}
	if u, err := url.Parse(c.URL); err == nil && u.Host != "" {
		return u.Scheme + "://" + u.Host + "/…"
	}
	return "…"
}

func (s *Server) channels(w http.ResponseWriter, r *http.Request) {
	s.renderChannels(w, r, http.StatusOK, "", map[string]string{"type": store.ChannelSlack, "min_level": store.LevelWarning})
}

func (s *Server) renderChannels(w http.ResponseWriter, r *http.Request, status int, errMsg string, form map[string]string) {
	list, err := s.st.ListChannels(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d := s.page(r, s.l.T("channels.title"), "settings")
	d.Error = errMsg
	d.Data = map[string]any{"Channels": list, "Form": form, "Types": store.ChannelTypes, "Events": notify.Events,
		"Levels": []string{store.LevelInfo, store.LevelWarning, store.LevelCritical}, "Dispatcher": s.o.Channels != nil}
	s.render(w, r, status, "channels", d)
}

// parseChannel validates the form and returns Turkish messages.
func (s *Server) parseChannel(r *http.Request) (store.Channel, map[string]string, []string) {
	c := store.Channel{
		Name: strings.TrimSpace(r.PostFormValue("name")), Type: r.PostFormValue("type"), MinLevel: r.PostFormValue("min_level"), Enabled: true,
		ChatID: strings.TrimSpace(r.PostFormValue("chat_id")), Secret: r.PostFormValue("secret"),
	}
	form := map[string]string{"name": c.Name, "type": c.Type, "min_level": c.MinLevel, "chat_id": c.ChatID}
	var bad []string
	events, ok := s.channelEvents(r)
	if !ok {
		bad = append(bad, s.l.T("validation.invalid_choice"))
	}
	c.Events = events
	c.Config = map[string]string{}
	cfg := func(key string, max int, required bool) {
		v := strings.TrimSpace(r.PostFormValue(key))
		form[key] = v
		if (required && v == "") || len(v) > max || hasControl(v) {
			bad = append(bad, s.l.T("validation.required", "field", s.l.T("channel.field."+key)))
			return
		}
		if v != "" {
			c.Config[key] = v
		}
	}
	if c.Name == "" || utf8.RuneCountInString(c.Name) > 60 {
		bad = append(bad, s.l.T("channel.error.name"))
	}
	if store.LevelRank(c.MinLevel) == 0 && c.MinLevel != store.LevelInfo {
		bad = append(bad, s.l.T("validation.invalid_choice"))
	}
	switch c.Type {
	case store.ChannelTelegram:
		c.URL = strings.TrimSpace(r.PostFormValue("bot_token"))
		if !telegramTokenRE.MatchString(c.URL) {
			bad = append(bad, s.l.T("channel.error.telegram_token"))
		}
		if !telegramChatRE.MatchString(c.ChatID) {
			bad = append(bad, s.l.T("channel.error.telegram_chat"))
		}
		c.Secret = ""
	case store.ChannelSlack, store.ChannelTeams, store.ChannelWebhook:
		c.URL = strings.TrimSpace(r.PostFormValue("url"))
		u, err := url.Parse(c.URL)
		switch {
		case err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http"):
			bad = append(bad, s.l.T("channel.error.url"))
		case u.Scheme != "https" && c.Type != store.ChannelWebhook:
			bad = append(bad, s.l.T("channel.error.https"))
		}
		c.ChatID = ""
		if c.Type != store.ChannelWebhook {
			c.Secret = ""
		}
		if len(c.Secret) > 200 {
			bad = append(bad, s.l.T("channel.error.secret"))
		}
	case store.ChannelJira, store.ChannelServiceNow, store.ChannelGLPI:
		// Own field names: the webhook section with url/secret is in the same form.
		c.URL = strings.TrimSpace(r.PostFormValue("ticket_url"))
		c.Secret = r.PostFormValue("ticket_secret")
		if u, err := url.Parse(c.URL); err != nil || u.Host == "" || u.Scheme != "https" && u.Scheme != "http" {
			bad = append(bad, s.l.T("channel.error.url"))
		}
		c.ChatID = ""
		if c.Secret == "" || len(c.Secret) > 500 {
			bad = append(bad, s.l.T("channel.error.secret"))
		}
		switch c.Type {
		case store.ChannelJira:
			cfg("user", 200, true)
			cfg("project", 50, true)
			cfg("issue_type", 50, false)
		case store.ChannelServiceNow:
			cfg("user", 200, true)
			cfg("table", 80, false)
			if t := c.Config["table"]; t != "" && !tableNameRE.MatchString(t) {
				bad = append(bad, s.l.T("validation.invalid_choice"))
			}
		case store.ChannelGLPI:
			cfg("app_token", 200, false)
		}
	case store.ChannelZabbix:
		c.URL = strings.TrimSpace(r.PostFormValue("zabbix_server"))
		form["zabbix_server"] = c.URL
		if c.URL == "" || hasControl(c.URL) || strings.Contains(c.URL, "/") || len(c.URL) > 255 {
			bad = append(bad, s.l.T("channel.error.zabbix_server"))
		}
		c.ChatID, c.Secret = "", ""
		cfg("host", 128, true)
		cfg("key", 255, false)
	default:
		bad = append(bad, s.l.T("validation.invalid_choice"))
	}
	return c, form, bad
}

var tableNameRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,79}$`)

// channelEvents reads the event checkboxes; ok is false for unknown ids.
func (s *Server) channelEvents(r *http.Request) ([]string, bool) {
	var out []string
	for _, e := range r.PostForm["events"] {
		if !slices.Contains(notify.Events, e) {
			return nil, false
		}
		if !slices.Contains(out, e) {
			out = append(out, e)
		}
	}
	return out, true
}

// channelDetail shows a channel's filter and delivery history.
func (s *Server) channelDetail(w http.ResponseWriter, r *http.Request) {
	c, ok := s.channelOr404(w, r)
	if !ok {
		return
	}
	pg := pageNumber(r)
	list, total, err := s.st.ListDeliveries(r.Context(), c.ID, store.Page{Number: pg, Size: pageSize})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d := s.page(r, c.Name, "settings")
	d.Data = map[string]any{"C": c, "Deliveries": list, "Pager": newPager(r, pg, total), "Events": notify.Events,
		"Levels": []string{store.LevelInfo, store.LevelWarning, store.LevelCritical}, "Dispatcher": s.o.Channels != nil}
	s.render(w, r, http.StatusOK, "channel", d)
}

// channelFilter saves a channel's minimum level and events.
func (s *Server) channelFilter(w http.ResponseWriter, r *http.Request) {
	c, ok := s.channelOr404(w, r)
	if !ok {
		return
	}
	back := "/settings/channels/" + strconv.FormatInt(c.ID, 10)
	level := r.PostFormValue("min_level")
	events, valid := s.channelEvents(r)
	if !valid || (store.LevelRank(level) == 0 && level != store.LevelInfo) {
		s.redirect(w, r, back, "error", s.l.T("validation.invalid_choice"))
		return
	}
	if err := s.st.SetChannelFilter(r.Context(), c.ID, level, events); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "channel.update", c.Name, "min_level="+level+" events="+strings.Join(events, ","))
	s.redirect(w, r, back, "success", s.l.T("common.saved"))
}

// channelResend sends a recorded delivery again.
func (s *Server) channelResend(w http.ResponseWriter, r *http.Request) {
	c, ok := s.channelOr404(w, r)
	if !ok {
		return
	}
	back := "/settings/channels/" + strconv.FormatInt(c.ID, 10)
	did, err := strconv.ParseInt(r.PathValue("delivery"), 10, 64)
	if err != nil {
		s.errorPage(w, r, http.StatusNotFound, "error.not_found")
		return
	}
	dl, err := s.st.DeliveryByID(r.Context(), c.ID, did)
	if err != nil {
		s.errorPage(w, r, http.StatusNotFound, "error.not_found")
		return
	}
	if s.o.Channels == nil {
		s.redirect(w, r, back, "error", s.l.T("channel.unavailable"))
		return
	}
	err = s.o.Channels.Resend(r.Context(), c, dl.Payload)
	s.audit(r, "channel.test", c.Name, "resend="+strconv.FormatInt(did, 10)+" ok="+strconv.FormatBool(err == nil))
	if err != nil {
		s.redirect(w, r, back, "error", s.l.T("channel.test_failed", "name", c.Name, "error", err.Error()))
		return
	}
	s.redirect(w, r, back, "success", s.l.T("channel.resent"))
}

func (s *Server) channelCreate(w http.ResponseWriter, r *http.Request) {
	c, form, bad := s.parseChannel(r)
	if len(bad) > 0 {
		s.renderChannels(w, r, http.StatusBadRequest, strings.Join(bad, " "), form)
		return
	}
	id, err := s.st.CreateChannel(r.Context(), c)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "channel.create", c.Name, "channel_id="+strconv.FormatInt(id, 10)+" type="+c.Type+" min_level="+c.MinLevel)
	s.redirect(w, r, "/settings/channels", "success", s.l.T("channel.created", "name", c.Name))
}

func (s *Server) channelOr404(w http.ResponseWriter, r *http.Request) (store.Channel, bool) {
	id, ok := pathID(r)
	if !ok {
		s.errorPage(w, r, http.StatusNotFound, "error.not_found")
		return store.Channel{}, false
	}
	c, err := s.st.ChannelByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, r, http.StatusNotFound, "error.not_found")
		return c, false
	}
	if err != nil {
		s.serverError(w, r, err)
		return c, false
	}
	return c, true
}

func (s *Server) channelTest(w http.ResponseWriter, r *http.Request) {
	c, ok := s.channelOr404(w, r)
	if !ok {
		return
	}
	if s.o.Channels == nil {
		s.redirect(w, r, "/settings/channels", "error", s.l.T("channel.unavailable"))
		return
	}
	n := notify.TestNotification()
	n.CreatedAt = timeutil.Now()
	err := s.o.Channels.Send(r.Context(), c, n)
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	_ = s.st.RecordChannelResult(r.Context(), c.ID, msg)
	s.audit(r, "channel.test", c.Name, "ok="+strconv.FormatBool(err == nil))
	if err != nil {
		s.redirect(w, r, "/settings/channels", "error", s.l.T("channel.test_failed", "name", c.Name, "error", msg))
		return
	}
	s.redirect(w, r, "/settings/channels", "success", s.l.T("channel.test_sent", "name", c.Name))
}

func (s *Server) channelToggle(w http.ResponseWriter, r *http.Request) {
	c, ok := s.channelOr404(w, r)
	if !ok {
		return
	}
	if err := s.st.SetChannelEnabled(r.Context(), c.ID, !c.Enabled); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "channel.update", c.Name, "enabled="+strconv.FormatBool(!c.Enabled))
	s.redirect(w, r, "/settings/channels", "success", s.l.T("common.saved"))
}

func (s *Server) channelDelete(w http.ResponseWriter, r *http.Request) {
	c, ok := s.channelOr404(w, r)
	if !ok {
		return
	}
	if err := s.st.DeleteChannel(r.Context(), c.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "channel.delete", c.Name, "")
	s.redirect(w, r, "/settings/channels", "success", s.l.T("channel.deleted", "name", c.Name))
}
