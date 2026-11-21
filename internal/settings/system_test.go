package settings

import (
	"log/slog"
	"net/mail"
	"net/url"
	"testing"
	"time"

	"netio.patchman/internal/config"
)

func envConfig() config.Config {
	base, _ := url.Parse("http://localhost:8080")
	loc, _ := time.LoadLocation("Europe/Istanbul")
	return config.Config{
		BaseURL: base, TimezoneName: "Europe/Istanbul", Timezone: loc, LogLevel: slog.LevelInfo,
		SMTP: config.SMTP{Host: "mail.example.test", Port: 587, Password: "env-secret",
			From: mail.Address{Name: "netio.patchman", Address: "patchman@example.test"}},
		OSVURL: config.DefaultOSVURL, KEVURL: config.DefaultKEVURL,
	}
}

func TestSystemFromEnvOnly(t *testing.T) {
	sys := SystemFrom(map[string]string{}, envConfig())
	if sys.BaseURLString() != "http://localhost:8080" || sys.Timezone != "Europe/Istanbul" || !sys.SMTP.Enabled() ||
		sys.SMTP.Password != "env-secret" || sys.KEVURL != config.DefaultKEVURL || sys.LogLevelName() != "info" {
		t.Fatalf("env values not used: %+v", sys)
	}
}

func TestSystemFromStoredOverrides(t *testing.T) {
	sys := SystemFrom(map[string]string{
		KeyBaseURL: "https://patchman.example.test", KeyTrustProxy: "true", KeyTimezone: "UTC", KeyLogLevel: "debug",
		KeySMTPHost: "", KeySMTPFromName: "", KeyOSVURL: "https://osv-mirror.example.test",
		KeyKEVEnabled: "false", KeyKEVURL: "https://kev.example.test/kev.json",
	}, envConfig())
	if sys.BaseURLString() != "https://patchman.example.test" || !sys.TrustProxy || sys.Location != time.UTC || sys.LogLevel != slog.LevelDebug {
		t.Errorf("server overrides: %+v", sys)
	}
	// A stored empty host overrides the environment and disables email.
	if sys.SMTP.Enabled() || sys.SMTP.Password != "env-secret" || sys.SMTP.From.Name != "netio.patchman" {
		t.Errorf("smtp: %+v", sys.SMTP)
	}
	if sys.OSVURL != "https://osv-mirror.example.test" || sys.KEVURL != "" || sys.KEVSourceURL != "https://kev.example.test/kev.json" {
		t.Errorf("sources: osv=%q kev=%q src=%q", sys.OSVURL, sys.KEVURL, sys.KEVSourceURL)
	}

	on := SystemFrom(map[string]string{KeyKEVEnabled: "true", KeyKEVURL: "https://kev.example.test/kev.json"}, envConfig())
	if on.KEVURL != "https://kev.example.test/kev.json" {
		t.Errorf("kev enabled: %q", on.KEVURL)
	}

	// MSRC: the environment default (none set here) and stored overrides.
	if def := SystemFrom(nil, envConfig()); def.MSRCURL != "" || def.MSRCSourceURL != config.DefaultMSRCURL {
		t.Errorf("msrc default: %q %q", def.MSRCURL, def.MSRCSourceURL)
	}
	c := envConfig()
	c.MSRCURL = config.DefaultMSRCURL
	off := SystemFrom(map[string]string{KeyMSRCEnabled: "false", KeyMSRCURL: "https://msrc.example.test/sug/"}, c)
	if off.MSRCURL != "" || off.MSRCSourceURL != "https://msrc.example.test/sug" {
		t.Errorf("msrc off: %q %q", off.MSRCURL, off.MSRCSourceURL)
	}
	if on := SystemFrom(map[string]string{KeyMSRCURL: "https://msrc.example.test/sug"}, c); on.MSRCURL != "https://msrc.example.test/sug" {
		t.Errorf("msrc on: %q", on.MSRCURL)
	}
}

func TestSystemFromIgnoresInvalidStoredValues(t *testing.T) {
	sys := SystemFrom(map[string]string{
		KeyBaseURL: "ftp://x", KeyTimezone: "Mars/Olympus", KeyLogLevel: "loud", KeySMTPPort: "70000",
		KeySMTPFromAddress: "not-an-address", KeyOSVURL: "nope",
	}, envConfig())
	if sys.BaseURLString() != "http://localhost:8080" || sys.Timezone != "Europe/Istanbul" || sys.LogLevelName() != "info" ||
		sys.SMTP.Port != 587 || sys.SMTP.From.Address != "patchman@example.test" || sys.OSVURL != config.DefaultOSVURL {
		t.Errorf("invalid values must fall back: %+v", sys)
	}
}

func TestParseHelpers(t *testing.T) {
	if u, err := ParseBaseURL(" https://patchman.example.test/ "); err != nil || u.String() != "https://patchman.example.test" {
		t.Errorf("base url: %v %v", u, err)
	}
	for _, bad := range []string{"", "patchman.example.test", "https://user:pw@x.test", "https://x.test/?a=1", "javascript:alert(1)"} {
		if _, err := ParseBaseURL(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := LoadTimezone("Local"); err == nil {
		t.Error("Local accepted")
	}
	if !ValidSMTPHost("smtp.example.test") || !ValidSMTPHost("10.0.0.5") || ValidSMTPHost("a b") || ValidSMTPHost("x\r\nRCPT") {
		t.Error("smtp host validation")
	}
}
