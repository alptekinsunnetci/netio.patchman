package config

import (
	"net/url"
	"os"
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

func TestDatabaseURL(t *testing.T) {
	b := i18n.MustLoad()
	cfg, err := Load(b, envMap(map[string]string{"PATCHMAN_DATA_DIR": "/data"}))
	if err != nil || cfg.Postgres() || cfg.Database() != cfg.DatabasePath() {
		t.Fatalf("default must be SQLite: %+v %v", cfg, err)
	}
	cfg, _ = Load(b, envMap(map[string]string{"PATCHMAN_DATABASE_URL": "sqlite"}))
	if cfg.Postgres() {
		t.Error("sqlite value must select SQLite")
	}

	pw := t.TempDir() + "/password"
	if err := os.WriteFile(pw, []byte("s3cr:et/\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err = Load(b, envMap(map[string]string{
		"PATCHMAN_DATABASE_URL":           "postgres://patchman@postgres:5432/patchman?sslmode=disable",
		"PATCHMAN_DATABASE_PASSWORD_FILE": pw,
	}))
	if err != nil || !cfg.Postgres() {
		t.Fatalf("%+v %v", cfg, err)
	}
	u, _ := url.Parse(cfg.Database())
	if p, _ := u.User.Password(); p != "s3cr:et/" || u.User.Username() != "patchman" {
		t.Errorf("password not taken from the file: %q", cfg.Database())
	}
	if d := cfg.DatabaseDisplay(); strings.Contains(d, "s3cr") || d != "postgres://patchman@postgres:5432/patchman?sslmode=disable" {
		t.Errorf("display: %q", d)
	}

	_, err = Load(b, envMap(map[string]string{"PATCHMAN_DATABASE_URL": "mysql://root:geheim@db/x"}))
	if err == nil || !strings.Contains(err.Error(), "PATCHMAN_DATABASE_URL") || strings.Contains(err.Error(), "geheim") {
		t.Errorf("invalid URL error: %v", err)
	}
	_, err = Load(b, envMap(map[string]string{"PATCHMAN_DATABASE_URL": "postgres://u@db/x", "PATCHMAN_DATABASE_PASSWORD_FILE": pw + ".missing"}))
	if err == nil || !strings.Contains(err.Error(), "PATCHMAN_DATABASE_PASSWORD_FILE") {
		t.Errorf("missing password file: %v", err)
	}
	// A password in the URL wins; the file is then not needed.
	cfg, err = Load(b, envMap(map[string]string{"PATCHMAN_DATABASE_URL": "postgres://u:pw@db/x", "PATCHMAN_DATABASE_PASSWORD_FILE": pw + ".missing"}))
	if err != nil || cfg.Database() != "postgres://u:pw@db/x" {
		t.Errorf("URL password: %q %v", cfg.Database(), err)
	}
}
