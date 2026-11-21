package web

import (
	"html/template"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"netio.patchman/internal/auth"
	"netio.patchman/internal/brand"
	"netio.patchman/internal/store"
	"netio.patchman/internal/timeutil"
)

// Two-factor sign-in: after the password, users with an authenticator get a
// short-lived challenge (cookie np_mfa, in memory on the server) and enter a
// TOTP code or a single-use recovery code.

const (
	mfaCookie   = "np_mfa"
	mfaTTL      = 5 * time.Minute
	mfaAttempts = 5
)

type mfaChallenge struct {
	userID   int64
	next     string
	expires  time.Time
	attempts int
}

type mfaChallenges struct {
	mu sync.Mutex
	m  map[string]*mfaChallenge // by token hash
}

func (c *mfaChallenges) put(hash string, ch *mfaChallenge) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]*mfaChallenge{}
	}
	now := time.Now()
	for k, v := range c.m {
		if now.After(v.expires) {
			delete(c.m, k)
		}
	}
	c.m[hash] = ch
}

func (c *mfaChallenges) get(hash string) (mfaChallenge, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch, ok := c.m[hash]
	if !ok || time.Now().After(ch.expires) {
		delete(c.m, hash)
		return mfaChallenge{}, false
	}
	return *ch, true
}

// fail counts a wrong code and reports whether the challenge is still usable.
func (c *mfaChallenges) fail(hash string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch, ok := c.m[hash]
	if !ok {
		return false
	}
	ch.attempts++
	if ch.attempts >= mfaAttempts {
		delete(c.m, hash)
		return false
	}
	return true
}

func (c *mfaChallenges) drop(hash string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, hash)
}

// beginMFA starts the second step for a user whose password was verified.
func (s *Server) beginMFA(w http.ResponseWriter, r *http.Request, u store.User, next string) {
	token := auth.RandomToken(32)
	s.mfa.put(auth.HashToken(token), &mfaChallenge{userID: u.ID, next: next, expires: time.Now().Add(mfaTTL)})
	http.SetCookie(w, &http.Cookie{Name: mfaCookie, Value: token, Path: "/login", MaxAge: int(mfaTTL.Seconds()),
		HttpOnly: true, Secure: s.secureCookie(r), SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/login/mfa", http.StatusSeeOther)
}

func (s *Server) clearMFACookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: mfaCookie, Value: "", Path: "/login", MaxAge: -1, HttpOnly: true, Secure: s.secureCookie(r), SameSite: http.SameSiteStrictMode})
}

func (s *Server) mfaFromRequest(r *http.Request) (string, mfaChallenge, bool) {
	c, err := r.Cookie(mfaCookie)
	if err != nil || c.Value == "" {
		return "", mfaChallenge{}, false
	}
	hash := auth.HashToken(c.Value)
	ch, ok := s.mfa.get(hash)
	return hash, ch, ok
}

func (s *Server) loginMFAPage(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := s.mfaFromRequest(r); !ok {
		s.redirect(w, r, "/login", "error", s.l.T("mfa.login.expired"))
		return
	}
	s.render(w, r, http.StatusOK, "loginmfa", s.page(r, s.l.T("mfa.login.title"), ""))
}

var totpCodeRE = regexp.MustCompile(`^[0-9]{6}$`)

func (s *Server) loginMFASubmit(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	fail := func(status int, key string) {
		d := s.page(r, s.l.T("mfa.login.title"), "")
		d.Error = s.l.T(key)
		s.render(w, r, status, "loginmfa", d)
	}
	if !s.sameOrigin(r) {
		fail(http.StatusForbidden, "error.csrf.body")
		return
	}
	hash, ch, ok := s.mfaFromRequest(r)
	if !ok {
		s.clearMFACookie(w, r)
		s.redirect(w, r, "/login", "error", s.l.T("mfa.login.expired"))
		return
	}
	limitKey := "mfa:" + strconv.FormatInt(ch.userID, 10)
	if s.limiter.Blocked(limitKey) {
		fail(http.StatusTooManyRequests, "login.rate_limited")
		return
	}
	u, err := s.st.UserByID(r.Context(), ch.userID)
	if err != nil || u.Disabled || !u.MFAEnabled() {
		s.mfa.drop(hash)
		s.clearMFACookie(w, r)
		s.redirect(w, r, "/login", "error", s.l.T("login.invalid"))
		return
	}
	method, ok, err := s.checkSecondFactor(r, u, r.PostFormValue("code"))
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if !ok {
		s.limiter.Fail(limitKey)
		_ = s.st.Audit(r.Context(), store.AuditEntry{Action: "auth.mfa_failed", UserID: u.ID, UserEmail: u.Email, IP: ip})
		if !s.mfa.fail(hash) {
			s.clearMFACookie(w, r)
			s.redirect(w, r, "/login", "error", s.l.T("mfa.login.too_many"))
			return
		}
		fail(http.StatusUnauthorized, "mfa.login.invalid")
		return
	}
	s.mfa.drop(hash)
	s.clearMFACookie(w, r)
	s.limiter.Reset(limitKey)
	if err := s.startSession(w, r, u); err != nil {
		s.serverError(w, r, err)
		return
	}
	_ = s.st.Audit(r.Context(), store.AuditEntry{Action: "auth.login", UserID: u.ID, UserEmail: u.Email, Details: "mfa=" + method, IP: ip})
	if method == "recovery" {
		left, _ := s.st.RecoveryCodesLeft(r.Context(), u.ID)
		s.redirect(w, r, "/profile", "info", s.l.T("mfa.recovery_used", "count", left))
		return
	}
	http.Redirect(w, r, safeNext(ch.next), http.StatusSeeOther)
}

// checkSecondFactor accepts a current TOTP code (each step once) or an unused
// recovery code, and reports which one matched.
func (s *Server) checkSecondFactor(r *http.Request, u store.User, input string) (string, bool, error) {
	code := strings.ReplaceAll(strings.TrimSpace(input), " ", "")
	if totpCodeRE.MatchString(code) {
		step, ok := auth.VerifyTOTP(u.TOTPSecret, code, timeutil.Now())
		if !ok {
			return "totp", false, nil
		}
		fresh, err := s.st.UseTOTPStep(r.Context(), u.ID, step)
		return "totp", fresh, err
	}
	rc := auth.NormalizeRecoveryCode(code)
	if len(rc) != 14 {
		return "recovery", false, nil
	}
	used, err := s.st.UseRecoveryCode(r.Context(), u.ID, auth.HashToken(rc))
	return "recovery", used, err
}

// ---------- profile: set up, disable, new recovery codes ----------

type mfaSetup struct {
	Secret, Formatted string
	// URI is built from fixed parts and a base32 secret; html/template would
	// otherwise reject the otpauth: scheme.
	URI template.URL
}

func (s *Server) renderProfile(w http.ResponseWriter, r *http.Request, status int, errMsg string, extra map[string]any) {
	sess := sessionFrom(r)
	left, err := s.st.RecoveryCodesLeft(r.Context(), sess.user.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d := s.page(r, s.l.T("profile.title"), "profile")
	d.Error = errMsg
	tokens, err := s.st.ListAPITokens(r.Context(), sess.user.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	data := map[string]any{"RecoveryLeft": left, "MFARequired": s.mfaRequired(), "MissingMFA": s.mfaRequired() && !sess.user.MFAEnabled(),
		"APITokens": tokens, "BaseURL": s.baseURL()}
	for k, v := range extra {
		data[k] = v
	}
	d.Data = data
	s.render(w, r, status, "profile", d)
}

func (s *Server) newSetup(u store.User, secret string) mfaSetup {
	return mfaSetup{Secret: secret, Formatted: auth.FormatSecret(secret), URI: template.URL(auth.TOTPURI(brand.Name, u.Email, secret))} //nolint:gosec // see mfaSetup.URI
}

func (s *Server) profileMFASetup(w http.ResponseWriter, r *http.Request) {
	u := sessionFrom(r).user
	if u.MFAEnabled() {
		s.redirect(w, r, "/profile", "info", s.l.T("mfa.already_enabled"))
		return
	}
	s.renderProfile(w, r, http.StatusOK, "", map[string]any{"Setup": s.newSetup(u, auth.NewTOTPSecret())})
}

var secretRE = regexp.MustCompile(`^[A-Z2-7]{32}$`)

// newRecoveryCodes returns fresh codes and their hashes.
func newRecoveryCodes() ([]string, []string) {
	codes := auth.NewRecoveryCodes()
	hashes := make([]string, len(codes))
	for i, c := range codes {
		hashes[i] = auth.HashToken(c)
	}
	return codes, hashes
}

func (s *Server) profileMFAEnable(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	u := sess.user
	secret := r.PostFormValue("secret")
	if u.MFAEnabled() || !secretRE.MatchString(secret) {
		s.redirect(w, r, "/profile", "error", s.l.T("mfa.error.setup_again"))
		return
	}
	retry := func(key string) {
		s.renderProfile(w, r, http.StatusBadRequest, s.l.T(key), map[string]any{"Setup": s.newSetup(u, secret)})
	}
	if !auth.VerifyPassword(u.PasswordHash, r.PostFormValue("current_password")) {
		retry("profile.wrong_password")
		return
	}
	step, ok := auth.VerifyTOTP(secret, r.PostFormValue("code"), timeutil.Now())
	if !ok {
		retry("mfa.error.code")
		return
	}
	codes, hashes := newRecoveryCodes()
	if err := s.st.EnableTOTP(r.Context(), u.ID, secret, step, hashes, sess.tokenHash); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "user.mfa_enabled", u.Email, "")
	sess.user.TOTPSecret = secret
	s.renderProfile(w, r, http.StatusOK, "", map[string]any{"RecoveryCodes": codes, "Notice": s.l.T("mfa.enabled")})
}

// verifyProfileAction checks the current password and a second factor.
func (s *Server) verifyProfileAction(w http.ResponseWriter, r *http.Request) bool {
	u := sessionFrom(r).user
	if !u.MFAEnabled() {
		s.redirect(w, r, "/profile", "error", s.l.T("mfa.not_enabled"))
		return false
	}
	if !auth.VerifyPassword(u.PasswordHash, r.PostFormValue("current_password")) {
		s.renderProfile(w, r, http.StatusBadRequest, s.l.T("profile.wrong_password"), nil)
		return false
	}
	_, ok, err := s.checkSecondFactor(r, u, r.PostFormValue("code"))
	if err != nil {
		s.serverError(w, r, err)
		return false
	}
	if !ok {
		s.renderProfile(w, r, http.StatusBadRequest, s.l.T("mfa.error.code"), nil)
		return false
	}
	return true
}

func (s *Server) profileMFADisable(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	if s.mfaRequired() {
		s.redirect(w, r, "/profile", "error", s.l.T("mfa.error.required"))
		return
	}
	if !s.verifyProfileAction(w, r) {
		return
	}
	if err := s.st.DisableTOTP(r.Context(), sess.user.ID, sess.tokenHash); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "user.mfa_disabled", sess.user.Email, "")
	s.redirect(w, r, "/profile", "success", s.l.T("mfa.disabled"))
}

func (s *Server) profileMFARecovery(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	if !s.verifyProfileAction(w, r) {
		return
	}
	codes, hashes := newRecoveryCodes()
	if err := s.st.ReplaceRecoveryCodes(r.Context(), sess.user.ID, hashes); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "user.mfa_recovery_codes", sess.user.Email, "")
	s.renderProfile(w, r, http.StatusOK, "", map[string]any{"RecoveryCodes": codes, "Notice": s.l.T("mfa.recovery_regenerated")})
}

// userResetMFA lets an administrator remove a user's authenticator, for
// example after a lost phone. The user's sessions end.
func (s *Server) userResetMFA(w http.ResponseWriter, r *http.Request) {
	u, ok := s.userOr404(w, r)
	if !ok {
		return
	}
	back := "/users/" + strconv.FormatInt(u.ID, 10)
	if !u.MFAEnabled() {
		s.redirect(w, r, back, "info", s.l.T("mfa.not_enabled"))
		return
	}
	keep := ""
	if u.ID == sessionFrom(r).user.ID {
		keep = sessionFrom(r).tokenHash
	}
	if err := s.st.DisableTOTP(r.Context(), u.ID, keep); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "user.mfa_reset", u.Email, "")
	s.redirect(w, r, back, "success", s.l.T("mfa.reset_done", "email", u.Email))
}

// mfaAllowed lists the pages a user without a required authenticator may open.
func mfaAllowed(path string) bool {
	return path == "/profile" || strings.HasPrefix(path, "/profile/") || path == "/logout"
}
