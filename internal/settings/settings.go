// Package settings provides typed access to runtime settings stored in the
// database and edited on the "Sistem Ayarları" page.
package settings

import (
	"context"
	"net/mail"
	"strconv"
	"strings"
	"time"

	"netio.patchman/internal/protocol"
	"netio.patchman/internal/score"
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
	KeyUpdateExclude        = "updates.exclude"
	KeySLACriticalDays      = "sla.critical_days"
	KeySLAHighDays          = "sla.high_days"
	KeySLAMediumDays        = "sla.medium_days"
	KeySLALowDays           = "sla.low_days"
	KeyEmailSLAOverdue      = "email.sla_overdue"
	KeyEPSSUpdatedAt        = "epss.updated_at"
	KeySoftwareNotify       = "software.notify_changes"
	KeyEOLWarnDays          = "eol.warn_days"
	KeyEOLNotify            = "eol.notify"
	KeyEOLUpdatedAt         = "eol.updated_at"
	KeyScoreAlertBelow      = "score.alert_below"
	KeyHealthPolicy         = "health.policy"
	KeyHealthDelay          = "health.delay_seconds"
	KeyRequirePreview       = "updates.require_preview"
)

// ScoreWeight is one adjustable weight of the security score.
type ScoreWeight struct {
	Key   string // settings key and form field (dots replaced)
	Label string // catalog key
	Max   float64
	Field func(*score.Weights) *float64
}

// ScoreWeights lists the adjustable weights in form order.
var ScoreWeights = []ScoreWeight{
	{"score.critical", "score.weight.critical", 100, func(w *score.Weights) *float64 { return &w.Critical }},
	{"score.high", "score.weight.high", 100, func(w *score.Weights) *float64 { return &w.High }},
	{"score.medium", "score.weight.medium", 100, func(w *score.Weights) *float64 { return &w.Medium }},
	{"score.low", "score.weight.low", 100, func(w *score.Weights) *float64 { return &w.Low }},
	{"score.unknown", "score.weight.unknown", 100, func(w *score.Weights) *float64 { return &w.Unknown }},
	{"score.kev", "score.weight.kev", 100, func(w *score.Weights) *float64 { return &w.KEV }},
	{"score.epss", "score.weight.epss", 100, func(w *score.Weights) *float64 { return &w.EPSS }},
	{"score.overdue", "score.weight.overdue", 100, func(w *score.Weights) *float64 { return &w.Overdue }},
	{"score.vuln_cap", "score.weight.vuln_cap", 100, func(w *score.Weights) *float64 { return &w.VulnCap }},
	{"score.os_eol", "score.weight.os_eol", 100, func(w *score.Weights) *float64 { return &w.OSEOL }},
	{"score.os_soon", "score.weight.os_soon", 100, func(w *score.Weights) *float64 { return &w.OSSoon }},
	{"score.software_eol", "score.weight.software_eol", 100, func(w *score.Weights) *float64 { return &w.SoftwareEOL }},
	{"score.software_eol_cap", "score.weight.software_eol_cap", 100, func(w *score.Weights) *float64 { return &w.SoftwareEOLCap }},
	{"score.security_update", "score.weight.security_update", 100, func(w *score.Weights) *float64 { return &w.SecurityUpdate }},
	{"score.security_update_cap", "score.weight.security_update_cap", 100, func(w *score.Weights) *float64 { return &w.SecurityUpdateCap }},
}

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
	// UpdateExclude are package name patterns no job updates on any host.
	UpdateExclude []string
	// SLA: days to remediate a finding by severity, counted from detection
	// (0 = no target for that severity).
	SLACriticalDays, SLAHighDays, SLAMediumDays, SLALowDays int
	EmailSLAOverdue                                         bool
	EPSSUpdatedAt                                           time.Time
	// SoftwareNotify adds a notification when software is installed, removed
	// or changes version on a host.
	SoftwareNotify bool
	// EOLWarnDays is how long before the end of support a release counts as
	// ending soon; EOLNotify sends a notification once per release.
	EOLWarnDays  int
	EOLNotify    bool
	EOLUpdatedAt time.Time
	// ScoreWeights are the security score weights; ScoreAlertBelow notifies
	// when a host's score drops under it (0 = off).
	ScoreWeights    score.Weights
	ScoreAlertBelow int
	// HealthContinue runs an update even when a health check fails before
	// it (default: the update is skipped); HealthDelay is the wait between
	// the update and the checks after it.
	HealthContinue bool
	HealthDelay    int
	// RequirePreview: an update started on a server page first runs a dry
	// run; the update starts only after the plan is approved.
	RequirePreview bool
}

// EOLWarn is the end-of-support warning period.
func (v Values) EOLWarn() time.Duration { return time.Duration(v.EOLWarnDays) * 24 * time.Hour }

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
		SLACriticalDays:      15,
		SLAHighDays:          30,
		SLAMediumDays:        90,
		SLALowDays:           180,
		EmailSLAOverdue:      true,
		SoftwareNotify:       true,
		EOLWarnDays:          90,
		EOLNotify:            true,
		ScoreWeights:         score.DefaultWeights(),
		HealthDelay:          15,
		RequirePreview:       true,
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
	v.UpdateExclude, _ = protocol.ParseExcludePatterns(raw[KeyUpdateExclude])
	i(KeySLACriticalDays, &v.SLACriticalDays, 0, 3650)
	i(KeySLAHighDays, &v.SLAHighDays, 0, 3650)
	i(KeySLAMediumDays, &v.SLAMediumDays, 0, 3650)
	i(KeySLALowDays, &v.SLALowDays, 0, 3650)
	b(KeyEmailSLAOverdue, &v.EmailSLAOverdue)
	t(KeyEPSSUpdatedAt, &v.EPSSUpdatedAt)
	b(KeySoftwareNotify, &v.SoftwareNotify)
	i(KeyEOLWarnDays, &v.EOLWarnDays, 0, 730)
	b(KeyEOLNotify, &v.EOLNotify)
	t(KeyEOLUpdatedAt, &v.EOLUpdatedAt)
	for _, sw := range ScoreWeights {
		if s, ok := raw[sw.Key]; ok {
			if p, err := strconv.ParseFloat(s, 64); err == nil && p >= 0 && p <= sw.Max {
				*sw.Field(&v.ScoreWeights) = p
			}
		}
	}
	i(KeyScoreAlertBelow, &v.ScoreAlertBelow, 0, 100)
	v.HealthContinue = raw[KeyHealthPolicy] == "continue"
	i(KeyHealthDelay, &v.HealthDelay, 0, 600)
	b(KeyRequirePreview, &v.RequirePreview)
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

// SLADays returns the remediation target in days for a severity (0 = none).
func (v Values) SLADays(sev vuln.Severity) int {
	switch sev {
	case vuln.SeverityCritical:
		return v.SLACriticalDays
	case vuln.SeverityHigh:
		return v.SLAHighDays
	case vuln.SeverityMedium:
		return v.SLAMediumDays
	case vuln.SeverityLow:
		return v.SLALowDays
	}
	return 0
}

// SLA returns the targets for the store's due date queries.
func (v Values) SLA() store.SLA {
	return store.SLA{Critical: v.SLACriticalDays, High: v.SLAHighDays, Medium: v.SLAMediumDays, Low: v.SLALowDays}
}
