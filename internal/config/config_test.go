package config

import (
	"strings"
	"testing"

	"netio.patchman/internal/i18n"
)

func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestDefaults(t *testing.T) {
	cfg, err := Load(i18n.MustLoad(), envMap(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Locale != "tr-TR" || cfg.TimezoneName != "Europe/Istanbul" || cfg.Timezone == nil {
		t.Errorf("unexpected locale/timezone defaults: %+v", cfg)
	}
	if cfg.SMTP.From.Name != "netio.patchman" || cfg.SMTP.From.Address != "" {
		t.Errorf("sender name must default to netio.patchman with no address, got %+v", cfg.SMTP.From)
	}
	if cfg.SMTP.Enabled() {
		t.Error("email must be disabled without configuration")
	}
}

func TestErrorsAreTurkish(t *testing.T) {
	_, err := Load(i18n.MustLoad(), envMap(map[string]string{
		"PATCHMAN_TIMEZONE":  "Mars/Olympus",
		"PATCHMAN_SMTP_HOST": "smtp.example.test",
		"PATCHMAN_SMTP_PORT": "99999",
	}))
	if err == nil {
		t.Fatal("expected error")
	}
	for _, want := range []string{"Geçersiz saat dilimi: Mars/Olympus", "Geçersiz SMTP portu: 99999", "gönderen e-posta adresi"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error missing %q:\n%s", want, err)
		}
	}
}

func TestSenderConfigurable(t *testing.T) {
	cfg, err := Load(i18n.MustLoad(), envMap(map[string]string{
		"PATCHMAN_SMTP_HOST":         "smtp.example.test",
		"PATCHMAN_SMTP_FROM_ADDRESS": "patchman@example.test",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.SMTP.From.String(); got != `"netio.patchman" <patchman@example.test>` {
		t.Errorf("From = %s", got)
	}
}
