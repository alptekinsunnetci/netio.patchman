// Package config loads server configuration from PATCHMAN_* environment
// variables. Validation errors are returned in Turkish because they are read
// by the operator installing the product.
package config

import (
	"errors"
	"log/slog"
	"net/mail"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"netio.patchman/internal/brand"
	"netio.patchman/internal/i18n"
	"netio.patchman/internal/timeutil"
)

// Default URLs of external vulnerability data sources.
const (
	DefaultOSVURL = "https://api.osv.dev"
	DefaultKEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	// DefaultMSRCURL is the Microsoft Security Update Guide API (CVE details for Windows hosts).
	DefaultMSRCURL = "https://api.msrc.microsoft.com/sug/v2.0/en-US"
	// DefaultEPSSURL is the daily EPSS score file (FIRST.org model, CSV, gzip).
	DefaultEPSSURL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
	// DefaultUpdateURL is the VERSION file on the default branch: the version
	// an operator gets with "git pull" (see internal/updatecheck).
	DefaultUpdateURL = "https://raw.githubusercontent.com/" + brand.RepositoryPath + "/main/VERSION"
)

// Config is the server configuration.
type Config struct {
	HTTPAddr     string
	BaseURL      *url.URL
	Locale       string
	TimezoneName string
	Timezone     *time.Location
	LogLevel     slog.Level
	LogFormat    string
	SMTP         SMTP

	DataDir      string
	BackupDir    string // automatic backups (default <DataDir>/backups)
	AgentDistDir string
	TLSCertFile  string
	TLSKeyFile   string
	TrustProxy   bool
	OSVURL       string
	KEVURL       string // empty disables the KEV feed
	MSRCURL      string // empty disables MSRC lookups
	EPSSURL      string // empty disables EPSS scores
	UpdateURL    string // empty disables the new-version check
}

// DatabasePath is the SQLite database file.
func (c Config) DatabasePath() string { return filepath.Join(c.DataDir, "netio-patchman.db") }

// SecureCookies reports whether cookies must carry the Secure flag.
func (c Config) SecureCookies() bool { return c.BaseURL != nil && c.BaseURL.Scheme == "https" }

// SMTP holds outbound email settings.
type SMTP struct {
	Host     string
	Port     int
	Username string
	Password string
	// From is the sender. Name defaults to "netio.patchman"; the address has
	// no default and must be configured by the operator.
	From mail.Address
}

// Enabled reports whether email notifications can be sent.
func (s SMTP) Enabled() bool { return s.Host != "" && s.From.Address != "" }

// Load reads configuration using getenv (normally os.Getenv).
func Load(b *i18n.Bundle, getenv func(string) string) (Config, error) {
	l := b.Localizer(i18n.DefaultLocale)
	env := func(key, def string) string {
		if v := strings.TrimSpace(getenv(brand.EnvPrefix + key)); v != "" {
			return v
		}
		return def
	}

	var errs []error
	fail := func(key string, args ...any) { errs = append(errs, errors.New(l.T(key, args...))) }

	cfg := Config{
		HTTPAddr:     env("HTTP_ADDR", ":8080"),
		Locale:       env("LOCALE", i18n.DefaultLocale),
		TimezoneName: env("TIMEZONE", timeutil.DefaultTimezone),
		LogFormat:    env("LOG_FORMAT", "json"),
	}

	if !b.Supports(cfg.Locale) {
		fail("config.error.unknown_locale", "value", cfg.Locale, "available", strings.Join(b.Locales(), ", "))
	}

	loc, err := time.LoadLocation(cfg.TimezoneName)
	if err != nil {
		fail("config.error.invalid_timezone", "value", cfg.TimezoneName)
	}
	cfg.Timezone = loc

	rawBase := env("BASE_URL", "http://localhost:8080")
	base, err := url.Parse(rawBase)
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" {
		fail("config.error.invalid_base_url", "value", rawBase)
	} else {
		base.Path = strings.TrimRight(base.Path, "/")
		cfg.BaseURL = base
	}

	rawLevel := env("LOG_LEVEL", "info")
	if err := cfg.LogLevel.UnmarshalText([]byte(rawLevel)); err != nil {
		fail("config.error.invalid_log_level", "value", rawLevel)
	}
	if cfg.LogFormat != "json" && cfg.LogFormat != "text" {
		fail("config.error.invalid_log_format", "value", cfg.LogFormat)
	}

	cfg.SMTP = SMTP{
		Host:     env("SMTP_HOST", ""),
		Username: env("SMTP_USERNAME", ""),
		Password: getenv(brand.EnvPrefix + "SMTP_PASSWORD"), // not trimmed
		From:     mail.Address{Name: env("SMTP_FROM_NAME", brand.DefaultSenderName)},
	}
	rawPort := env("SMTP_PORT", "587")
	port, err := strconv.Atoi(rawPort)
	if err != nil || port < 1 || port > 65535 {
		fail("config.error.invalid_smtp_port", "value", rawPort)
	}
	cfg.SMTP.Port = port

	if rawFrom := env("SMTP_FROM_ADDRESS", ""); rawFrom != "" {
		addr, err := mail.ParseAddress(rawFrom)
		if err != nil {
			fail("config.error.invalid_from_address", "value", rawFrom)
		} else {
			cfg.SMTP.From.Address = addr.Address
		}
	} else if cfg.SMTP.Host != "" {
		fail("config.error.from_address_required")
	}

	cfg.DataDir = env("DATA_DIR", "/var/lib/netio-patchman")
	cfg.BackupDir = env("BACKUP_DIR", filepath.Join(cfg.DataDir, "backups"))
	cfg.AgentDistDir = env("AGENT_DIST_DIR", "/usr/share/netio-patchman/agent")
	cfg.TLSCertFile = env("TLS_CERT_FILE", "")
	cfg.TLSKeyFile = env("TLS_KEY_FILE", "")
	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		fail("config.error.tls_pair")
	}
	rawProxy := env("TRUST_PROXY", "false")
	tp, err := strconv.ParseBool(rawProxy)
	if err != nil {
		fail("config.error.invalid_bool", "name", "PATCHMAN_TRUST_PROXY", "value", rawProxy)
	}
	cfg.TrustProxy = tp
	cfg.OSVURL = strings.TrimRight(env("OSV_URL", DefaultOSVURL), "/")
	if u, err := url.Parse(cfg.OSVURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		fail("config.error.invalid_url", "name", "PATCHMAN_OSV_URL", "value", cfg.OSVURL)
	}
	cfg.KEVURL = env("KEV_URL", DefaultKEVURL)
	if strings.EqualFold(cfg.KEVURL, "off") {
		cfg.KEVURL = ""
	} else if u, err := url.Parse(cfg.KEVURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		fail("config.error.invalid_url", "name", "PATCHMAN_KEV_URL", "value", cfg.KEVURL)
	}
	cfg.MSRCURL = strings.TrimRight(env("MSRC_URL", DefaultMSRCURL), "/")
	if strings.EqualFold(cfg.MSRCURL, "off") {
		cfg.MSRCURL = ""
	} else if u, err := url.Parse(cfg.MSRCURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		fail("config.error.invalid_url", "name", "PATCHMAN_MSRC_URL", "value", cfg.MSRCURL)
	}
	cfg.EPSSURL = env("EPSS_URL", DefaultEPSSURL)
	if strings.EqualFold(cfg.EPSSURL, "off") {
		cfg.EPSSURL = ""
	} else if u, err := url.Parse(cfg.EPSSURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		fail("config.error.invalid_url", "name", "PATCHMAN_EPSS_URL", "value", cfg.EPSSURL)
	}
	cfg.UpdateURL = env("UPDATE_CHECK_URL", DefaultUpdateURL)
	if strings.EqualFold(cfg.UpdateURL, "off") {
		cfg.UpdateURL = ""
	} else if u, err := url.Parse(cfg.UpdateURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		fail("config.error.invalid_url", "name", "PATCHMAN_UPDATE_CHECK_URL", "value", cfg.UpdateURL)
	}

	return cfg, errors.Join(errs...)
}
