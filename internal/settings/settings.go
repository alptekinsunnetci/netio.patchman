// Package settings provides typed access to runtime settings stored in the
// database and edited on the "Sistem Ayarları" page.
package settings

import (
	"context"
	"net/mail"
	"strconv"
	"strings"
	"time"

	"netio.patchman/internal/store"
	"netio.patchman/internal/vuln"
)

// Keys.
const (
	KeyEmailEnabled         = "email.enabled"
	KeyEmailMinSeverity     = "email.min_severity"
	KeyEmailRecipients      = "email.recipients"
	KeyEmailKEVAlways       = "email.kev_always"
	KeyEmailDigestThreshold = "email.digest_threshold"
	KeyEmailAgentOffline    = "email.agent_offline"
	KeyEmailJobFailed       = "email.job_failed"
	KeyEmailServerUpdate    = "email.server_update"
	KeyAgentOfflineMinutes  = "agent.offline_minutes"
	KeyAgentCheckinSeconds  = "agent.checkin_seconds"
	KeyAgentReportMinutes   = "agent.report_minutes"
	KeyAgentAutoUpdate      = "agent.auto_update"
	KeyScanEnabled          = "scan.enabled"
	KeyRetentionDays        = "retention.days"
	KeyScannerLastDaily     = "scanner.last_daily"
	KeyKEVUpdatedAt         = "kev.updated_at"
	KeyAuthRequireMFA       = "auth.require_mfa"
	KeyRiskMaxDays          = "risk.max_days"
	KeyBackupEnabled        = "backup.enabled"
	KeyBackupMinute         = "backup.minute"
	KeyBackupKeep           = "backup.keep"
	KeyBackupLastAt         = "backup.last_at"
	KeyBackupLastError      = "backup.last_error"
	KeyBackupLastErrorAt    = "backup.last_error_at"
)

// Values is a typed snapshot of all settings.
type Values struct {
	EmailEnabled         bool
	EmailMinSeverity     vuln.Severity
	EmailRecipients      []string
	EmailKEVAlways       bool
	EmailDigestThreshold int
	EmailAgentOffline    bool
	EmailJobFailed       bool
	EmailServerUpdate    bool // a new netio.patchman version was published
	AgentOfflineMinutes  int
	AgentCheckinSeconds  int
	AgentReportMinutes   int
	AgentAutoUpdate      bool
	ScanEnabled          bool
	RetentionDays        int
	ScannerLastDaily     time.Time
	KEVUpdatedAt         time.Time
	// AuthRequireMFA sends users without an authenticator to set one up.
	AuthRequireMFA bool
	// RiskMaxDays caps how long a risk can be accepted (0 = no limit).
	RiskMaxDays int
	// Automatic database backups: daily at BackupMinute (minutes after
	// midnight, display zone), keeping the newest BackupKeep files.
	BackupEnabled     bool
	BackupMinute      int
	BackupKeep        int
	BackupLastAt      time.Time
	BackupLastError   string
	BackupLastErrorAt time.Time
}

// OfflineAfter is the duration after which an agent counts as offline.
func (v Values) OfflineAfter() time.Duration {
	return time.Duration(v.AgentOfflineMinutes) * time.Minute
}

// Retention is how long resolved findings, finished jobs and notifications are kept.
func (v Values) Retention() time.Duration { return time.Duration(v.RetentionDays) * 24 * time.Hour }

// Defaults returns the built-in defaults.
func Defaults() Values {
	return Values{
		EmailEnabled:         true,
		EmailMinSeverity:     vuln.SeverityHigh,
		EmailKEVAlways:       true,
		EmailDigestThreshold: 5,
		EmailAgentOffline:    false,
		EmailJobFailed:       true,
		EmailServerUpdate:    true,
		AgentOfflineMinutes:  10,
		AgentCheckinSeconds:  60,
		AgentReportMinutes:   60,
		AgentAutoUpdate:      true,
		ScanEnabled:          true,
		RetentionDays:        90,
		RiskMaxDays:          365,
		BackupEnabled:        true,
		BackupMinute:         2*60 + 30,
		BackupKeep:           7,
	}
}

// Load reads settings, applying defaults for missing or invalid values.
func Load(ctx context.Context, st *store.Store) (Values, error) {
	raw, err := st.Settings(ctx)
	if err != nil {
		return Defaults(), err
	}
	return FromMap(raw), nil
}

// FromMap converts raw key/value pairs.
func FromMap(raw map[string]string) Values {
	v := Defaults()
	b := func(key string, dst *bool) {
		if s, ok := raw[key]; ok {
			if p, err := strconv.ParseBool(s); err == nil {
				*dst = p
			}
		}
	}
	i := func(key string, dst *int, lo, hi int) {
		if s, ok := raw[key]; ok {
			if p, err := strconv.Atoi(s); err == nil && p >= lo && p <= hi {
				*dst = p
			}
		}
	}
	t := func(key string, dst *time.Time) {
		if s, ok := raw[key]; ok {
			if p, err := strconv.ParseInt(s, 10, 64); err == nil && p > 0 {
				*dst = time.Unix(p, 0).UTC()
			}
		}
	}
	b(KeyEmailEnabled, &v.EmailEnabled)
	b(KeyEmailKEVAlways, &v.EmailKEVAlways)
	b(KeyEmailAgentOffline, &v.EmailAgentOffline)
	b(KeyEmailJobFailed, &v.EmailJobFailed)
	b(KeyEmailServerUpdate, &v.EmailServerUpdate)
	b(KeyScanEnabled, &v.ScanEnabled)
	b(KeyAgentAutoUpdate, &v.AgentAutoUpdate)
	b(KeyAuthRequireMFA, &v.AuthRequireMFA)
	i(KeyRiskMaxDays, &v.RiskMaxDays, 0, 3650)
	b(KeyBackupEnabled, &v.BackupEnabled)
	i(KeyBackupMinute, &v.BackupMinute, 0, 24*60-1)
	i(KeyBackupKeep, &v.BackupKeep, 1, 365)
	t(KeyBackupLastAt, &v.BackupLastAt)
	t(KeyBackupLastErrorAt, &v.BackupLastErrorAt)
	v.BackupLastError = raw[KeyBackupLastError]
	i(KeyEmailDigestThreshold, &v.EmailDigestThreshold, 1, 1000)
	i(KeyAgentOfflineMinutes, &v.AgentOfflineMinutes, 2, 10080)
	i(KeyAgentCheckinSeconds, &v.AgentCheckinSeconds, 15, 3600)
	i(KeyAgentReportMinutes, &v.AgentReportMinutes, 5, 1440)
	i(KeyRetentionDays, &v.RetentionDays, 7, 3650)
	t(KeyScannerLastDaily, &v.ScannerLastDaily)
	t(KeyKEVUpdatedAt, &v.KEVUpdatedAt)
	if s, ok := raw[KeyEmailMinSeverity]; ok {
		switch sev := vuln.Severity(s); sev {
		case vuln.SeverityCritical, vuln.SeverityHigh, vuln.SeverityMedium, vuln.SeverityLow:
			v.EmailMinSeverity = sev
		}
	}
	v.EmailRecipients = ParseRecipients(raw[KeyEmailRecipients])
	return v
}

// ParseRecipients splits a comma/newline separated list and keeps valid addresses.
func ParseRecipients(s string) []string {
	var out []string
	seen := map[string]bool{}
	for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' || r == '\n' || r == '\r' || r == ' ' }) {
		a, err := mail.ParseAddress(strings.TrimSpace(part))
		if err != nil {
			continue
		}
		key := strings.ToLower(a.Address)
		if !seen[key] {
			seen[key] = true
			out = append(out, a.Address)
		}
	}
	return out
}

// Stamp stores a timestamp setting.
func Stamp(ctx context.Context, st *store.Store, key string, t time.Time) error {
	return st.SaveSettings(ctx, map[string]string{key: strconv.FormatInt(t.UTC().Unix(), 10)})
}
