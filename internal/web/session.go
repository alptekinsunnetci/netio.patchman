package web

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"netio.patchman/internal/auth"
	"netio.patchman/internal/store"
	"netio.patchman/internal/timeutil"
)

const (
	sessionCookie = "np_session"
	sessionIdle   = 12 * time.Hour
)

type session struct {
	tokenHash string
	user      store.User
	csrf      string
}

type sessionKey struct{}

func sessionFrom(r *http.Request) *session {
	s, _ := r.Context().Value(sessionKey{}).(*session)
	return s
}

type role int

const (
	roleViewer role = iota
	roleOperator
	roleAdmin
)

func hasRole(u store.User, min role) bool {
	switch min {
	case roleAdmin:
		return u.IsAdmin()
	case roleOperator:
		return u.CanOperate()
	}
	return true
}

func (s *Server) loadSession(r *http.Request) (*session, error) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return nil, store.ErrNotFound
	}
	hash := auth.HashToken(c.Value)
	sess, user, err := s.st.SessionWithUser(r.Context(), hash)
	if err != nil {
		return nil, err
	}
	if time.Since(sess.LastSeenAt) > time.Minute {
		_ = s.st.TouchSession(r.Context(), hash, timeutil.Now().Add(sessionIdle))
	}
	return &session{tokenHash: hash, user: user, csrf: sess.CSRFToken}, nil
}

// require wraps a handler with authentication, role and CSRF checks.
func (s *Server) require(min role) func(http.HandlerFunc) http.Handler {
	return func(h http.HandlerFunc) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess, err := s.loadSession(r)
			if err != nil {
				if !errors.Is(err, store.ErrNotFound) {
					s.serverError(w, r, err)
					return
				}
				if n, _ := s.st.CountUsers(r.Context()); n == 0 {
					http.Redirect(w, r, "/setup", http.StatusFound)
					return
				}
				next := ""
				if r.Method == http.MethodGet {
					next = "?next=" + url.QueryEscape(r.URL.RequestURI())
				}
				http.Redirect(w, r, "/login"+next, http.StatusFound)
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), sessionKey{}, sess))
			if r.Method == http.MethodPost {
				if !s.sameOrigin(r) || subtle.ConstantTimeCompare([]byte(r.PostFormValue("_csrf")), []byte(sess.csrf)) != 1 {
					s.errorPage(w, r, http.StatusForbidden, "error.csrf")
					return
				}
			}
			if s.mfaRequired() && !sess.user.MFAEnabled() && !mfaAllowed(r.URL.Path) {
				s.redirect(w, r, "/profile#mfa", "error", s.l.T("mfa.required_notice"))
				return
			}
			if !hasRole(sess.user, min) {
				s.errorPage(w, r, http.StatusForbidden, "error.forbidden")
				return
			}
			h(w, r)
		})
	}
}

// sameOrigin rejects cross-site form posts when the browser sends Origin or Referer.
func (s *Server) sameOrigin(r *http.Request) bool {
	check := func(raw string) bool {
		u, err := url.Parse(raw)
		if err != nil {
			return false
		}
		if u.Host == r.Host {
			return true
		}
		base := s.sys().BaseURL
		return base != nil && u.Host == base.Host
	}
	if o := r.Header.Get("Origin"); o != "" && o != "null" {
		return check(o)
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		return check(ref)
	}
	return true
}

func (s *Server) startSession(w http.ResponseWriter, r *http.Request, u store.User) error {
	token := auth.RandomToken(32)
	err := s.st.CreateSession(r.Context(), store.Session{
		TokenHash: auth.HashToken(token), UserID: u.ID, CSRFToken: auth.RandomToken(24),
		ExpiresAt: timeutil.Now().Add(sessionIdle),
	}, s.clientIP(r), r.UserAgent())
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/", HttpOnly: true, Secure: s.secureCookie(r), SameSite: http.SameSiteLaxMode,
	})
	_ = s.st.TouchLogin(r.Context(), u.ID)
	return nil
}

func safeNext(next string) string {
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\") || strings.HasPrefix(next, "/login") {
		return "/dashboard"
	}
	return next
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if n, _ := s.st.CountUsers(r.Context()); n == 0 {
		http.Redirect(w, r, "/setup", http.StatusFound)
		return
	}
	if _, err := s.loadSession(r); err == nil {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}
	d := s.page(r, s.l.T("login.title"), "")
	d.Data = map[string]any{"Next": r.URL.Query().Get("next"), "Email": ""}
	s.render(w, r, http.StatusOK, "login", d)
}

func (s *Server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	email := strings.TrimSpace(r.PostFormValue("email"))
	password := r.PostFormValue("password")
	next := r.PostFormValue("next")
	fail := func(status int, key string) {
		d := s.page(r, s.l.T("login.title"), "")
		d.Error = s.l.T(key)
		d.Data = map[string]any{"Next": next, "Email": email}
		s.render(w, r, status, "login", d)
	}
	if !s.sameOrigin(r) {
		fail(http.StatusForbidden, "error.csrf.body")
		return
	}
	emailKey := "email:" + strings.ToLower(email)
	if s.limiter.Blocked("ip:"+ip) || s.limiter.Blocked(emailKey) {
		fail(http.StatusTooManyRequests, "login.rate_limited")
		return
	}
	u, err := s.st.UserByEmail(r.Context(), email)
	if err != nil {
		auth.VerifyDummy(password)
	}
	if err != nil || u.Disabled || !auth.VerifyPassword(u.PasswordHash, password) {
		s.limiter.Fail("ip:" + ip)
		s.limiter.Fail(emailKey)
		_ = s.st.Audit(r.Context(), store.AuditEntry{Action: "auth.login_failed", Target: email, IP: ip})
		fail(http.StatusUnauthorized, "login.invalid")
		return
	}
	s.limiter.Reset(emailKey)
	if u.MFAEnabled() {
		s.beginMFA(w, r, u, next)
		return
	}
	if err := s.startSession(w, r, u); err != nil {
		s.serverError(w, r, err)
		return
	}
	_ = s.st.Audit(r.Context(), store.AuditEntry{Action: "auth.login", UserID: u.ID, UserEmail: u.Email, IP: ip})
	http.Redirect(w, r, safeNext(next), http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if sess, err := s.loadSession(r); err == nil {
		if subtle.ConstantTimeCompare([]byte(r.PostFormValue("_csrf")), []byte(sess.csrf)) == 1 {
			_ = s.st.DeleteSession(r.Context(), sess.tokenHash)
			_ = s.st.Audit(r.Context(), store.AuditEntry{Action: "auth.logout", UserID: sess.user.ID, UserEmail: sess.user.Email, IP: s.clientIP(r)})
		}
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.secureCookie(r), SameSite: http.SameSiteLaxMode})
	s.redirect(w, r, "/login", "success", s.l.T("login.logged_out"))
}

func (s *Server) setupPage(w http.ResponseWriter, r *http.Request) {
	if n, _ := s.st.CountUsers(r.Context()); n > 0 {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	d := s.page(r, s.l.T("setup.title"), "")
	d.Data = map[string]any{"Name": "", "Email": ""}
	s.render(w, r, http.StatusOK, "setup", d)
}

func (s *Server) setupSubmit(w http.ResponseWriter, r *http.Request) {
	if n, _ := s.st.CountUsers(r.Context()); n > 0 {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	email := strings.TrimSpace(r.PostFormValue("email"))
	pw, pw2 := r.PostFormValue("password"), r.PostFormValue("password_confirm")
	fail := func(msg string) {
		d := s.page(r, s.l.T("setup.title"), "")
		d.Error = msg
		d.Data = map[string]any{"Name": name, "Email": email}
		s.render(w, r, http.StatusBadRequest, "setup", d)
	}
	if !s.sameOrigin(r) {
		fail(s.l.T("error.csrf.body"))
		return
	}
	if msg := s.validateUserInput(name, email, pw, pw2, true); msg != "" {
		fail(msg)
		return
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	id, err := s.st.CreateUser(r.Context(), store.User{Email: email, Name: name, PasswordHash: hash, Role: store.RoleAdmin})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	u, err := s.st.UserByID(r.Context(), id)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	_ = s.st.Audit(r.Context(), store.AuditEntry{Action: "setup.admin_created", UserID: u.ID, UserEmail: u.Email, IP: s.clientIP(r)})
	if err := s.startSession(w, r, u); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.redirect(w, r, "/agents", "success", s.l.T("setup.done"))
}

// validateUserInput returns a Turkish validation message or "".
func (s *Server) validateUserInput(name, email, pw, pw2 string, needPassword bool) string {
	if name == "" {
		return s.l.T("validation.required", "field", s.l.T("user.field.name"))
	}
	if a, err := parseEmail(email); err != nil || a != email {
		return s.l.T("validation.invalid_email")
	}
	if needPassword {
		if err := auth.CheckPasswordPolicy(pw); err != nil {
			return s.l.T("validation.password_length", "min", auth.MinPasswordLength)
		}
		if pw != pw2 {
			return s.l.T("validation.password_mismatch")
		}
	}
	return ""
}

func (s *Server) profile(w http.ResponseWriter, r *http.Request) {
	s.renderProfile(w, r, http.StatusOK, "", nil)
}

func (s *Server) profilePassword(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	cur, pw, pw2 := r.PostFormValue("current_password"), r.PostFormValue("password"), r.PostFormValue("password_confirm")
	fail := func(msg string) { s.renderProfile(w, r, http.StatusBadRequest, msg, nil) }
	if !auth.VerifyPassword(sess.user.PasswordHash, cur) {
		fail(s.l.T("profile.wrong_password"))
		return
	}
	if err := auth.CheckPasswordPolicy(pw); err != nil {
		fail(s.l.T("validation.password_length", "min", auth.MinPasswordLength))
		return
	}
	if pw != pw2 {
		fail(s.l.T("validation.password_mismatch"))
		return
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if err := s.st.SetPassword(r.Context(), sess.user.ID, hash, sess.tokenHash); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "user.password_changed", sess.user.Email, "")
	s.redirect(w, r, "/profile", "success", s.l.T("profile.password_changed"))
}
