// Package vuln defines the vulnerability domain model.
//
// LANGUAGE POLICY: every field documented as "verbatim" holds data exactly as
// published by its source (NVD, OSV, distribution security trackers, vendor
// advisories). These values are never translated, never machine-translated,
// never rewritten and never re-cased. Only the labels around them are
// localized, through the i18n catalog.
package vuln

import (
	"math"
	"time"
)

// Severity is the normalized severity level. The value is a stable English
// identifier; its Turkish label comes from the catalog key LabelKey().
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityNone     Severity = "none"
	SeverityUnknown  Severity = "unknown"
)

// LabelKey returns the i18n catalog key for the severity label.
func (s Severity) LabelKey() string {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityNone:
		return "severity." + string(s)
	default:
		return "severity.unknown"
	}
}

// Rank orders severities for sorting; higher is more severe.
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityNone:
		return 1
	default:
		return 0
	}
}

// SeverityFromCVSS maps a CVSS v3.x / v4.0 base score to a severity using the
// FIRST qualitative rating scale.
func SeverityFromCVSS(score float64) Severity {
	switch {
	case math.IsNaN(score) || score < 0 || score > 10:
		return SeverityUnknown
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score > 0:
		return SeverityLow
	default:
		return SeverityNone
	}
}

// ResolutionStatus is the remediation state of a finding.
type ResolutionStatus string

const (
	StatusOpen          ResolutionStatus = "open"
	StatusInProgress    ResolutionStatus = "in_progress"
	StatusResolved      ResolutionStatus = "resolved"
	StatusAcceptedRisk  ResolutionStatus = "accepted_risk"
	StatusFalsePositive ResolutionStatus = "false_positive"
)

// LabelKey returns the i18n catalog key for the status label.
func (s ResolutionStatus) LabelKey() string { return "status." + string(s) }

// Vulnerability is a published vulnerability record.
type Vulnerability struct {
	// CVEID is the identifier, e.g. "CVE-2026-12345". Verbatim.
	CVEID string `json:"cve_id"`
	// Aliases are other identifiers (GHSA, DSA, USN, RHSA...). Verbatim.
	Aliases []string `json:"aliases,omitempty"`
	// Title is the official title. Verbatim.
	Title string `json:"title"`
	// Description is the official description. Verbatim, never translated.
	Description string `json:"description"`
	// DescriptionLang is the BCP 47 language of Description, normally "en".
	// Used for the HTML lang attribute so the text is rendered and read
	// correctly inside a Turkish page.
	DescriptionLang string `json:"description_lang"`
	// CVSSScore is the base score, nil if not yet scored. Verbatim.
	CVSSScore *float64 `json:"cvss_score,omitempty"`
	// CVSSVector is the vector string, e.g. "CVSS:3.1/AV:N/...". Verbatim.
	CVSSVector string `json:"cvss_vector,omitempty"`
	// CVSSVersion is "3.1", "4.0", ... Verbatim.
	CVSSVersion string `json:"cvss_version,omitempty"`
	// Severity is the normalized severity.
	Severity Severity `json:"severity"`
	// KnownExploited is true when listed in an exploitation catalog such as CISA KEV.
	KnownExploited bool `json:"known_exploited"`
	// KEVDateAdded and KEVDueDate are verbatim CISA KEV dates (YYYY-MM-DD).
	KEVDateAdded string `json:"kev_date_added,omitempty"`
	KEVDueDate   string `json:"kev_due_date,omitempty"`
	// Source names the feed the record came from, e.g. "nvd", "osv". Verbatim.
	Source string `json:"source"`
	// Advisories are vendor advisories referencing this vulnerability.
	Advisories []Advisory `json:"advisories,omitempty"`
	// References are reference URLs. Verbatim.
	References []string `json:"references,omitempty"`
	// PublishedAt and ModifiedAt are UTC.
	PublishedAt time.Time `json:"published_at"`
	ModifiedAt  time.Time `json:"modified_at"`
}

// DescriptionLanguage returns DescriptionLang, defaulting to "en".
func (v Vulnerability) DescriptionLanguage() string {
	if v.DescriptionLang == "" {
		return "en"
	}
	return v.DescriptionLang
}

// Advisory is a vendor security advisory. All fields are verbatim.
type Advisory struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	URL   string `json:"url"`
}

// Finding is one vulnerability affecting one package on one server.
type Finding struct {
	CVEID    string `json:"cve_id"`
	ServerID string `json:"server_id"`
	// PackageName, InstalledVersion and FixedVersion are verbatim package
	// manager values.
	PackageName      string           `json:"package_name"`
	InstalledVersion string           `json:"installed_version"`
	FixedVersion     string           `json:"fixed_version,omitempty"`
	Status           ResolutionStatus `json:"status"`
	// FirstDetectedAt and LastCheckedAt are UTC.
	FirstDetectedAt time.Time `json:"first_detected_at"`
	LastCheckedAt   time.Time `json:"last_checked_at"`
}
