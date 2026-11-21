package web

import (
	"errors"
	"net/http"
	"net/url"
	"os"
	"regexp"
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
	if c.Type == store.ChannelTelegram {
		return s.l.T("channel.telegram_target", "chat", c.ChatID)
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
	d.Data = map[string]any{"Channels": list, "Form": form, "Types": []string{store.ChannelSlack, store.ChannelTeams, store.ChannelTelegram, store.ChannelWebhook},
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
	default:
		bad = append(bad, s.l.T("validation.invalid_choice"))
	}
	return c, form, bad
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
