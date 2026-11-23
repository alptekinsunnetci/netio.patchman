package settings

import (
	"context"
	"log/slog"
	"net/mail"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"netio.patchman/internal/brand"
	"netio.patchman/internal/config"
	"netio.patchman/internal/store"
)

// Server configuration keys, edited on the "Sunucu yapılandırması" page. A
// key that is present in the database overrides the PATCHMAN_* environment
// variable; environment values only serve as initial values.
const (
	KeyBaseURL         = "server.base_url"
	KeyTrustProxy      = "server.trust_proxy"
	KeyTimezone        = "server.timezone"
	KeyLogLevel        = "log.level"
	KeySMTPHost        = "smtp.host"
	KeySMTPPort        = "smtp.port"
	KeySMTPUsername    = "smtp.username"
	KeySMTPPassword    = "smtp.password"
	KeySMTPFromName    = "smtp.from_name"
	KeySMTPFromAddress = "smtp.from_address"
	KeyOSVURL          = "sources.osv_url"
	KeyKEVEnabled      = "sources.kev_enabled"
	KeyKEVURL          = "sources.kev_url"
	KeyMSRCEnabled     = "sources.msrc_enabled"
	KeyMSRCURL         = "sources.msrc_url"
	KeyEPSSEnabled     = "sources.epss_enabled"
	KeyEPSSURL         = "sources.epss_url"
	KeyEOLEnabled      = "sources.eol_enabled"
	KeyEOLURL          = "sources.eol_url"
	KeyUpdateEnabled   = "updates.check_enabled"
	KeyUpdateURL       = "updates.check_url"
)

// SystemKeys lists every server configuration key.
var SystemKeys = []string{
	KeyBaseURL, KeyTrustProxy, KeyTimezone, KeyLogLevel, KeySMTPHost, KeySMTPPort, KeySMTPUsername, KeySMTPPassword,
	KeySMTPFromName, KeySMTPFromAddress, KeyOSVURL, KeyKEVEnabled, KeyKEVURL, KeyMSRCEnabled, KeyMSRCURL, KeyEPSSEnabled, KeyEPSSURL,
	KeyEOLEnabled, KeyEOLURL, KeyUpdateEnabled, KeyUpdateURL,
}

// LogLevels are the selectable log levels.
var LogLevels = []string{"debug", "info", "warn", "error"}

// System is the effective server configuration.
type System struct {
	BaseURL    *url.URL
	TrustProxy bool
	Timezone   string
	Location   *time.Location
	LogLevel   slog.Level
	SMTP       config.SMTP
	OSVURL     string
	KEVURL     string // empty when the KEV feed is disabled
	// KEVSourceURL is the configured KEV address, kept while the feed is off.
	KEVSourceURL string
	// MSRCURL is the Microsoft Security Update Guide API, empty when disabled;
	// MSRCSourceURL is kept while it is off.
	MSRCURL       string
	MSRCSourceURL string
	// EPSSURL is the EPSS score file, empty when disabled; EPSSSourceURL is
	// kept while it is off.
	EPSSURL       string
	EPSSSourceURL string
	// EOLURL is the endoflife.date API, empty when only the built-in support
	// calendars are used; EOLSourceURL is kept while it is off.
	EOLURL       string
	EOLSourceURL string
	// UpdateURL is where the latest product version is read; empty when the
	// new-version check is disabled. UpdateSourceURL is kept while it is off.
	UpdateURL       string
	UpdateSourceURL string
}

// BaseURLString returns the base URL without a trailing slash.
func (s System) BaseURLString() string {
	if s.BaseURL == nil {
		return ""
	}
	return s.BaseURL.String()
}

// LogLevelName returns the lower-case level name used in the form.
func (s System) LogLevelName() string { return strings.ToLower(s.LogLevel.String()) }

// SystemFromEnv returns the configuration given by environment variables.
func SystemFromEnv(c config.Config) System {
	sys := System{
		BaseURL: c.BaseURL, TrustProxy: c.TrustProxy, Timezone: c.TimezoneName, Location: c.Timezone,
		LogLevel: c.LogLevel, SMTP: c.SMTP, OSVURL: c.OSVURL, KEVURL: c.KEVURL, KEVSourceURL: c.KEVURL,
		MSRCURL: c.MSRCURL, MSRCSourceURL: c.MSRCURL, EPSSURL: c.EPSSURL, EPSSSourceURL: c.EPSSURL, EOLURL: c.EOLURL, EOLSourceURL: c.EOLURL, UpdateURL: c.UpdateURL, UpdateSourceURL: c.UpdateURL,
	}
	if sys.KEVSourceURL == "" {
		sys.KEVSourceURL = config.DefaultKEVURL
	}
	if sys.MSRCSourceURL == "" {
		sys.MSRCSourceURL = config.DefaultMSRCURL
	}
	if sys.EPSSSourceURL == "" {
		sys.EPSSSourceURL = config.DefaultEPSSURL
	}
	if sys.EOLSourceURL == "" {
		sys.EOLSourceURL = config.DefaultEOLURL
	}
	if sys.UpdateSourceURL == "" {
		sys.UpdateSourceURL = config.DefaultUpdateURL
	}
	if sys.Location == nil {
		sys.Location = time.UTC
	}
	return sys
}

// SystemFrom applies stored values over the environment configuration.
// Invalid stored values are ignored.
func SystemFrom(raw map[string]string, c config.Config) System {
	sys := SystemFromEnv(c)
	if v, ok := raw[KeyBaseURL]; ok {
		if u, err := ParseBaseURL(v); err == nil {
			sys.BaseURL = u
		}
	}
	if v, ok := raw[KeyTrustProxy]; ok {
		if b, err := strconv.ParseBool(v); err == nil {
			sys.TrustProxy = b
		}
	}
	if v, ok := raw[KeyTimezone]; ok {
		if loc, err := LoadTimezone(v); err == nil {
			sys.Timezone, sys.Location = v, loc
		}
	}
	if v, ok := raw[KeyLogLevel]; ok {
		var lv slog.Level
		if err := lv.UnmarshalText([]byte(v)); err == nil {
			sys.LogLevel = lv
		}
	}
	if v, ok := raw[KeySMTPHost]; ok {
		sys.SMTP.Host = v
	}
	if v, ok := raw[KeySMTPPort]; ok {
		if p, err := strconv.Atoi(v); err == nil && p >= 1 && p <= 65535 {
			sys.SMTP.Port = p
		}
	}
	if v, ok := raw[KeySMTPUsername]; ok {
		sys.SMTP.Username = v
	}
	if v, ok := raw[KeySMTPPassword]; ok {
		sys.SMTP.Password = v
	}
	if v, ok := raw[KeySMTPFromName]; ok {
		if v == "" {
			v = brand.DefaultSenderName
		}
		sys.SMTP.From.Name = v
	}
	if v, ok := raw[KeySMTPFromAddress]; ok {
		if v == "" {
			sys.SMTP.From.Address = ""
		} else if a, err := mail.ParseAddress(v); err == nil {
			sys.SMTP.From.Address = a.Address
		}
	}
	if v, ok := raw[KeyOSVURL]; ok {
		if u, err := ParseSourceURL(v); err == nil {
			sys.OSVURL = u
		}
	}
	if v, ok := raw[KeyKEVURL]; ok {
		if u, err := ParseSourceURL(v); err == nil {
			sys.KEVSourceURL = u
			if sys.KEVURL != "" {
				sys.KEVURL = u
			}
		}
	}
	if v, ok := raw[KeyKEVEnabled]; ok {
		if b, err := strconv.ParseBool(v); err == nil {
			sys.KEVURL = ""
			if b {
				sys.KEVURL = sys.KEVSourceURL
			}
		}
	}
	if v, ok := raw[KeyMSRCURL]; ok {
		if u, err := ParseSourceURL(v); err == nil {
			u = strings.TrimRight(u, "/")
			sys.MSRCSourceURL = u
			if sys.MSRCURL != "" {
				sys.MSRCURL = u
			}
		}
	}
	if v, ok := raw[KeyMSRCEnabled]; ok {
		if b, err := strconv.ParseBool(v); err == nil {
			sys.MSRCURL = ""
			if b {
				sys.MSRCURL = sys.MSRCSourceURL
			}
		}
	}
	if v, ok := raw[KeyEPSSURL]; ok {
		if u, err := ParseSourceURL(v); err == nil {
			sys.EPSSSourceURL = u
			if sys.EPSSURL != "" {
				sys.EPSSURL = u
			}
		}
	}
	if v, ok := raw[KeyEPSSEnabled]; ok {
		if b, err := strconv.ParseBool(v); err == nil {
			sys.EPSSURL = ""
			if b {
				sys.EPSSURL = sys.EPSSSourceURL
			}
		}
	}
	if v, ok := raw[KeyEOLURL]; ok {
		if u, err := ParseSourceURL(v); err == nil {
			u = strings.TrimRight(u, "/")
			sys.EOLSourceURL = u
			if sys.EOLURL != "" {
				sys.EOLURL = u
			}
		}
	}
	if v, ok := raw[KeyEOLEnabled]; ok {
		if b, err := strconv.ParseBool(v); err == nil {
			sys.EOLURL = ""
			if b {
				sys.EOLURL = sys.EOLSourceURL
			}
		}
	}
	if v, ok := raw[KeyUpdateURL]; ok {
		if u, err := ParseSourceURL(v); err == nil {
			sys.UpdateSourceURL = u
			if sys.UpdateURL != "" {
				sys.UpdateURL = u
			}
		}
	}
	if v, ok := raw[KeyUpdateEnabled]; ok {
		if b, err := strconv.ParseBool(v); err == nil {
			sys.UpdateURL = ""
			if b {
				sys.UpdateURL = sys.UpdateSourceURL
			}
		}
	}
	return sys
}

// errInvalid marks a value that failed validation.
type errInvalid struct{}

func (errInvalid) Error() string { return "settings: invalid value" }

// ParseBaseURL validates the public address of the server.
func ParseBaseURL(s string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errInvalid{}
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return u, nil
}

// ParseSourceURL validates an external data source address.
func ParseSourceURL(s string) (string, error) {
	s = strings.TrimSpace(s)
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", errInvalid{}
	}
	return s, nil
}

// LoadTimezone loads an IANA zone name. "Local" is rejected because the
// container's local zone is not meaningful to users.
func LoadTimezone(name string) (*time.Location, error) {
	name = strings.TrimSpace(name)
	if name == "" || name == "Local" {
		return nil, errInvalid{}
	}
	return time.LoadLocation(name)
}

// ValidSMTPHost reports whether s looks like a host name or IP address.
func ValidSMTPHost(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, r := range s {
		if !(r == '.' || r == '-' || r == '_' || r == ':' || r == '[' || r == ']' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

// Live holds the effective server configuration and applies changes made on
// the configuration page without a restart. It is safe for concurrent use.
type Live struct {
	env config.Config
	st  *store.Store

	cur   atomic.Pointer[System]
	mu    sync.Mutex
	hooks []func(old, cur System)
}

// NewLive returns a Live holder for the environment configuration c and
// loads stored overrides from st (nil for tests).
func NewLive(ctx context.Context, c config.Config, st *store.Store) (*Live, error) {
	l := &Live{env: c, st: st}
	sys := SystemFromEnv(c)
	l.cur.Store(&sys)
	if st == nil {
		return l, nil
	}
	return l, l.Reload(ctx)
}

// StaticLive returns a holder with a fixed configuration (tests).
func StaticLive(sys System) *Live {
	if sys.Location == nil {
		sys.Location = time.UTC
	}
	l := &Live{}
	l.cur.Store(&sys)
	return l
}

// Get returns the current configuration.
func (l *Live) Get() System { return *l.cur.Load() }

// Env returns the configuration given by environment variables.
func (l *Live) Env() config.Config { return l.env }

// OnChange registers fn, called after every Reload with the previous and
// the new configuration.
func (l *Live) OnChange(fn func(old, cur System)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.hooks = append(l.hooks, fn)
}

// Reload reads the stored configuration and applies it.
func (l *Live) Reload(ctx context.Context) error {
	if l.st == nil {
		return nil
	}
	raw, err := l.st.Settings(ctx)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	old := l.Get()
	sys := SystemFrom(raw, l.env)
	l.cur.Store(&sys)
	for _, fn := range l.hooks {
		fn(old, sys)
	}
	return nil
}
