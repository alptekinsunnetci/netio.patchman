// Package updatecheck tells administrators when a newer netio.patchman
// version is published.
//
// The server reads one small file at most every Interval: by default the
// VERSION file on the repository's main branch, which is exactly what
// "git pull && docker compose up -d --build" installs. A GitHub releases API
// response ({"tag_name": ...}) is accepted too, so the URL can point at
// /releases/latest or at an internal mirror. Nothing about the installation
// is sent except the User-Agent. The check is disabled in the server
// configuration (or with PATCHMAN_UPDATE_CHECK_URL=off) for air-gapped sites.
package updatecheck

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"netio.patchman/internal/brand"
	"netio.patchman/internal/i18n"
	"netio.patchman/internal/settings"
	"netio.patchman/internal/store"
	"netio.patchman/internal/timeutil"
)

const (
	// Interval is the time between two automatic checks.
	Interval = 12 * time.Hour
	// firstDelay lets the server finish starting before the first check.
	firstDelay = time.Minute
	maxBody    = 64 << 10

	// State is kept in the settings table under these keys. They are not
	// server configuration (settings.SystemKeys), so a reset keeps them.
	keyLatest    = "updates.state.latest"
	keyRelease   = "updates.state.release_url"
	keyCheckedAt = "updates.state.checked_at"
	keyError     = "updates.state.error"
	keyNotified  = "updates.state.notified"

	// NotificationKind is the notification stored for a new version.
	NotificationKind = "server_update"
)

// Status is the result of the last check.
type Status struct {
	Enabled    bool
	Current    string
	Latest     string
	ReleaseURL string // release page, when the source provides one
	CheckedAt  time.Time
	Error      string // last failure (localized); empty after a successful check
}

// Available reports whether Latest is newer than the running version.
func (s Status) Available() bool { return s.Latest != "" && Compare(s.Latest, s.Current) > 0 }

// ChangesURL links to the release notes or, for the VERSION file, the
// repository's commit history.
func (s Status) ChangesURL() string {
	if s.ReleaseURL != "" {
		return s.ReleaseURL
	}
	return brand.Repository + "/commits/main"
}

// Options configures a Checker.
type Options struct {
	Current string // running version
	Store   *store.Store
	System  *settings.Live
	Logger  *slog.Logger
	L       i18n.Localizer
	Client  *http.Client // optional
}

// Checker runs the new-version check.
type Checker struct {
	o   Options
	mu  sync.Mutex // one check at a time
	cur atomic.Pointer[Status]
}

// New returns a checker with the state saved by the last run.
func New(ctx context.Context, o Options) *Checker {
	if o.Client == nil {
		o.Client = &http.Client{Timeout: 20 * time.Second}
	}
	c := &Checker{o: o}
	st := Status{}
	if raw, err := o.Store.Settings(ctx); err == nil {
		st.Latest, st.ReleaseURL, st.Error = raw[keyLatest], raw[keyRelease], raw[keyError]
		if ts, err := strconv.ParseInt(raw[keyCheckedAt], 10, 64); err == nil && ts > 0 {
			st.CheckedAt = time.Unix(ts, 0).UTC()
		}
	}
	c.cur.Store(&st)
	return c
}

// Status returns the last known state.
func (c *Checker) Status() Status {
	st := *c.cur.Load()
	st.Current = c.o.Current
	st.Enabled = c.o.System.Get().UpdateURL != ""
	return st
}

// Check reads the latest version now. A failed check keeps the previously
// known latest version, so the notice does not disappear on a network error.
func (c *Checker) Check(ctx context.Context) Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	src := c.o.System.Get().UpdateURL
	if src == "" {
		return c.Status()
	}
	st := *c.cur.Load()
	latest, rel, err := c.fetch(ctx, src)
	st.CheckedAt = timeutil.Now()
	if err != nil {
		st.Error = err.Error()
		c.o.Logger.Warn(c.o.L.T("log.update.failed"), slog.String("url", src), slog.String("error", st.Error))
	} else {
		st.Latest, st.ReleaseURL, st.Error = latest, rel, ""
	}
	c.cur.Store(&st)
	_ = c.o.Store.SaveSettings(ctx, map[string]string{
		keyLatest: st.Latest, keyRelease: st.ReleaseURL, keyError: st.Error,
		keyCheckedAt: strconv.FormatInt(st.CheckedAt.Unix(), 10),
	})
	out := c.Status()
	if err == nil && out.Available() {
		c.notify(ctx, out)
	}
	return out
}

// notify stores one notification per new version.
func (c *Checker) notify(ctx context.Context, st Status) {
	raw, err := c.o.Store.Settings(ctx)
	if err != nil || raw[keyNotified] == st.Latest {
		return
	}
	c.o.Logger.Info(c.o.L.T("log.update.available"), slog.String("current", st.Current), slog.String("latest", st.Latest))
	if err := c.o.Store.AddNotification(ctx, store.LevelInfo, NotificationKind,
		map[string]string{"version": st.Latest, "current": st.Current}, "/settings/system#updates"); err != nil {
		return
	}
	_ = c.o.Store.SaveSettings(ctx, map[string]string{keyNotified: st.Latest})
}

// Run checks shortly after start and then every Interval. A check made less
// than Interval ago (before a restart) is not repeated early.
func (c *Checker) Run(ctx context.Context) {
	for {
		next := timeutil.Now().Add(firstDelay)
		if last := c.cur.Load().CheckedAt; !last.IsZero() && last.Add(Interval).After(next) {
			next = last.Add(Interval)
		}
		t := time.NewTimer(time.Until(next))
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		c.Check(ctx)
	}
}

type checkError struct{ msg string }

func (e checkError) Error() string { return e.msg }

func (c *Checker) fetch(ctx context.Context, src string) (version, releaseURL string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
	if err != nil {
		return "", "", checkError{c.o.L.T("update.error.request", "error", err.Error())}
	}
	req.Header.Set("User-Agent", brand.ServerUserAgent(c.o.Current))
	req.Header.Set("Accept", "application/vnd.github+json, text/plain;q=0.9, */*;q=0.1")
	resp, err := c.o.Client.Do(req)
	if err != nil {
		return "", "", checkError{c.o.L.T("update.error.request", "error", err.Error())}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", checkError{c.o.L.T("update.error.http", "status", resp.StatusCode)}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return "", "", checkError{c.o.L.T("update.error.request", "error", err.Error())}
	}
	version, releaseURL, ok := Parse(body)
	if !ok {
		return "", "", checkError{c.o.L.T("update.error.format")}
	}
	return version, releaseURL, nil
}

var versionRe = regexp.MustCompile(`^[0-9]+(\.[0-9]+){0,3}(-[0-9A-Za-z.-]+)?$`)

// Parse reads a version from a plain VERSION file or a GitHub release
// ({"tag_name": "v1.2.3", "html_url": ...}). A leading "v" is dropped.
func Parse(body []byte) (version, releaseURL string, ok bool) {
	body = bytes.TrimSpace(bytes.TrimPrefix(body, []byte("\xef\xbb\xbf")))
	if bytes.HasPrefix(body, []byte("{")) {
		var rel struct {
			TagName string `json:"tag_name"`
			HTMLURL string `json:"html_url"`
		}
		if json.Unmarshal(body, &rel) != nil {
			return "", "", false
		}
		version = rel.TagName
		if strings.HasPrefix(rel.HTMLURL, "https://") {
			releaseURL = rel.HTMLURL
		}
	} else {
		version, _, _ = strings.Cut(string(body), "\n")
	}
	version = strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(version), "v"), "V")
	if !versionRe.MatchString(version) {
		return "", "", false
	}
	return version, releaseURL, true
}

// Compare compares two versions numerically ("0.10.0" > "0.9.1"). A
// pre-release ("0.2.0-dev") sorts before its release ("0.2.0").
func Compare(a, b string) int {
	an, ap, _ := strings.Cut(strings.TrimPrefix(a, "v"), "-")
	bn, bp, _ := strings.Cut(strings.TrimPrefix(b, "v"), "-")
	as, bs := strings.Split(an, "."), strings.Split(bn, ".")
	for i := 0; i < max(len(as), len(bs)); i++ {
		x, y := 0, 0
		if i < len(as) {
			x, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			y, _ = strconv.Atoi(bs[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	switch {
	case ap == bp:
		return 0
	case ap == "":
		return 1
	case bp == "":
		return -1
	}
	return strings.Compare(ap, bp)
}
