package i18n

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestDefaultCatalogLoads(t *testing.T) {
	b, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !b.Supports(DefaultLocale) {
		t.Fatalf("default locale %s missing", DefaultLocale)
	}
	for _, k := range b.Keys(DefaultLocale) {
		if strings.TrimSpace(b.catalogs[DefaultLocale][k]) == "" {
			t.Errorf("empty message for key %q", k)
		}
	}
}

// TestCatalogsMatch requires every catalog to have exactly the default
// catalog's keys, with the same {placeholders} in each message.
func TestCatalogsMatch(t *testing.T) {
	b := MustLoad()
	ph := regexp.MustCompile(`\{[a-z_]+\}`)
	set := func(s string) string {
		m := ph.FindAllString(s, -1)
		sort.Strings(m)
		return strings.Join(slices.Compact(m), ",")
	}
	def := b.catalogs[DefaultLocale]
	if len(b.Locales()) < 2 {
		t.Fatal("only one catalog")
	}
	for _, loc := range b.Locales() {
		if loc == DefaultLocale {
			continue
		}
		cat := b.catalogs[loc]
		for k, v := range def {
			other, ok := cat[k]
			if !ok {
				t.Errorf("%s: missing key %q", loc, k)
				continue
			}
			if set(v) != set(other) {
				t.Errorf("%s: %q placeholders %s, want %s", loc, k, set(other), set(v))
			}
		}
		for k := range cat {
			if _, ok := def[k]; !ok {
				t.Errorf("%s: extra key %q", loc, k)
			}
		}
	}
}

func TestTInterpolationAndFallback(t *testing.T) {
	l := MustLoad().Localizer("xx-XX") // unknown locale falls back to tr-TR
	if l.Locale() != DefaultLocale {
		t.Fatalf("locale = %s, want %s", l.Locale(), DefaultLocale)
	}
	got := l.T("validation.required", "field", "E-posta")
	if got != "E-posta alanı zorunludur." {
		t.Errorf("got %q", got)
	}
	if got := l.T("no.such.key"); got != "no.such.key" {
		t.Errorf("missing key should return key, got %q", got)
	}
}

func TestTurkishUpperCase(t *testing.T) {
	l := MustLoad().Localizer(DefaultLocale)
	cases := map[string]string{"Kritik": "KRİTİK", "Yüksek": "YÜKSEK", "Düşük": "DÜŞÜK", "Bilinmiyor": "BİLİNMİYOR"}
	for in, want := range cases {
		if got := l.Upper(in); got != want {
			t.Errorf("Upper(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestReferencedKeysExist scans Go sources and templates for literal catalog
// keys and fails if any is missing from the default catalog.
func TestReferencedKeysExist(t *testing.T) {
	b := MustLoad()
	have := map[string]bool{}
	for _, k := range b.Keys(DefaultLocale) {
		have[k] = true
	}
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`\.T\("([a-z0-9_.]*[a-z0-9_])"\s*[,)]`), // skips dynamic keys like "nav."+key
		regexp.MustCompile(`\{\{-?\s*t "([a-z0-9_.]+)"`),
		regexp.MustCompile(`\(t "([a-z0-9_.]+)"`),
		regexp.MustCompile(`fail\("([a-z0-9_.]+)"`),
		regexp.MustCompile(`errorPage\([^)]*"(error\.[a-z0-9_.]+)"\)`),
	}
	root := filepath.Join("..", "..")
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "node_modules") {
			return filepath.SkipDir
		}
		ext := filepath.Ext(path)
		if d.IsDir() || (ext != ".go" && ext != ".html" && ext != ".txt") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, re := range patterns {
			for _, m := range re.FindAllStringSubmatch(string(src), -1) {
				key := m[1]
				if strings.HasPrefix(key, "error.") && !strings.Contains(key, ".title") && !strings.Contains(key, ".body") && key != "error.back_to_dashboard" {
					// errorPage(key) uses key+".title" and key+".body"
					for _, suffix := range []string{".title", ".body"} {
						if !have[key+suffix] {
							t.Errorf("%s: missing catalog key %q", path, key+suffix)
						}
					}
					continue
				}
				if !have[key] {
					t.Errorf("%s: missing catalog key %q", path, key)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Keys built at runtime from identifiers.
	families := map[string][]string{
		"severity.":   {"critical", "high", "medium", "low", "none", "unknown"},
		"status.":     {"open", "in_progress", "resolved", "accepted_risk", "false_positive"},
		"job.type.":   {"refresh", "upgrade_security", "upgrade_all", "upgrade_packages", "agent_update", "restart_services", "reboot"},
		"job.status.": {"queued", "dispatched", "succeeded", "partial", "failed", "timed_out", "cancelled", "expired"},
		"role.":       {"admin", "operator", "viewer"},
		"level.":      {"critical", "warning", "info"},
		"nav.":        {"dashboard", "servers", "groups", "vulnerabilities", "packages", "reports", "jobs", "schedules", "agents", "notifications", "users", "settings"},
		"notification.": {"vuln_detected", "vulns_detected", "agent_offline", "agent_online", "agent_enrolled", "agent_reenrolled", "job_succeeded", "job_failed", "job_partial", "scan_failed", "email_failed",
			"schedule_ran", "schedule_expired", "schedule_missed", "server_update", "risk_expired", "backup_failed", "channel_test"},
		"channel.type.": {"slack", "teams", "telegram", "webhook"},
		"channel.help.": {"slack", "teams", "webhook", "secret", "telegram"},
		"host.virt.": {"unknown", "none", "vmware", "microsoft", "kvm", "qemu", "oracle", "xen", "amazon", "google", "parallels", "bochs", "vm-other",
			"docker", "podman", "lxc", "lxc-libvirt", "openvz", "systemd-nspawn", "wsl"},
		"trend.metric.": {"critical_high", "kev", "open_findings", "security_updates"},
		"api.error.":    {"bad_request", "unauthorized", "invalid_token", "rate_limited", "too_large", "job_not_found", "not_found", "internal"},
		"audit.action.": {"auth.login", "auth.login_failed", "auth.logout", "setup.admin_created", "user.create", "user.update", "user.delete",
			"user.password_changed", "user.password_reset", "agent.enroll", "token.create", "token.revoke", "job.create", "job.cancel",
			"host.rescan", "host.notes", "host.delete", "finding.status", "settings.update", "settings.test_email", "scan.trigger",
			"settings.system_update", "settings.system_reset", "schedule.create", "schedule.update", "schedule.delete", "schedule.run", "schedule.run_now",
			"group.create", "group.update", "group.delete", "group.add_hosts", "group.remove_hosts", "host.groups", "user.mfa_enabled", "user.mfa_disabled",
			"user.mfa_recovery_codes", "user.mfa_reset", "auth.mfa_failed", "finding.risk_expired",
			"backup.run", "backup.download", "channel.create", "channel.update", "channel.delete", "channel.test", "user.language"},
		"schedule.target.":   {"all", "os", "group", "hosts"},
		"system.log_level.":  {"debug", "info", "warn", "error"},
		"weekday.":           {"0", "1", "2", "3", "4", "5", "6"},
		"agents.install.os.": {"ubuntu", "debian", "rhel", "fedora", "suse", "alpine"},
		"weekday.short.":     {"0", "1", "2", "3", "4", "5", "6"},
	}
	for prefix, ids := range families {
		for _, id := range ids {
			if !have[prefix+id] {
				t.Errorf("missing catalog key %q", prefix+id)
			}
		}
	}
	for m := 1; m <= 12; m++ {
		if !have["month."+strconv.Itoa(m)] {
			t.Errorf("missing month %d", m)
		}
	}
}

// TestCatalogsHaveNoDuplicateKeys catches a key written twice (json.Unmarshal
// silently keeps the last value).
func TestCatalogsHaveNoDuplicateKeys(t *testing.T) {
	files, err := filepath.Glob("locales/*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("no catalogs: %v", err)
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		dec := json.NewDecoder(strings.NewReader(string(data)))
		if _, err := dec.Token(); err != nil { // {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		for dec.More() {
			tok, err := dec.Token()
			if err != nil {
				t.Fatalf("%s: %v", f, err)
			}
			key := tok.(string)
			if seen[key] {
				t.Errorf("%s: duplicate key %q", f, key)
			}
			seen[key] = true
			var v json.RawMessage
			if err := dec.Decode(&v); err != nil {
				t.Fatalf("%s: %v", f, err)
			}
		}
	}
}
