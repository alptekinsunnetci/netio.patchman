package compliance

import "time"

// Schema is the identifier of the report model (the JSON export).
const Schema = "netio.patchman/compliance-report/v1"

// EngineVersion changes when the evaluation rules change, so a version
// records the rules it was assessed with.
const EngineVersion = "1"

// Automated outcomes of checks and controls. They describe the evidence,
// never conformity with a standard.
const (
	OutcomeSufficient     = "evidence_sufficient" // the evidence supports the control
	OutcomePartial        = "partial"             // evidence exists but shows gaps
	OutcomeDeviation      = "deviation"           // the evidence shows a deviation
	OutcomeMissing        = "evidence_missing"    // no evidence for the period
	OutcomeManualRequired = "manual_required"     // only manual evidence can support it
	OutcomeManualEvidence = "manual_evidence"     // manual evidence is attached, needs review
	OutcomeNotApplicable  = "not_applicable"
)

// Outcomes lists the outcomes in display order.
var Outcomes = []string{OutcomeDeviation, OutcomeMissing, OutcomePartial, OutcomeManualRequired, OutcomeManualEvidence,
	OutcomeSufficient, OutcomeNotApplicable}

// severity ranks outcomes of primary checks (higher is worse).
func severity(o string) int {
	switch o {
	case OutcomeDeviation:
		return 4
	case OutcomeMissing:
		return 3
	case OutcomePartial:
		return 2
	case OutcomeSufficient:
		return 1
	}
	return 0
}

// Text is a catalog key with parameters, rendered in the reader's language.
type Text struct {
	Key    string            `json:"key"`
	Params map[string]string `json:"params,omitempty"`
}

// Metric is a measured value of a check.
type Metric struct {
	Key   string  `json:"key"` // catalog key suffix: compliance.metric.<key>
	Value float64 `json:"value"`
	Unit  string  `json:"unit"` // count, percent, days
}

// Units.
const (
	UnitCount   = "count"
	UnitPercent = "percent"
	UnitDays    = "days"
)

// Report is the stored content of a report version.
type Report struct {
	Schema          string              `json:"schema"`
	Engine          string              `json:"engine"`
	Product         string              `json:"product"`
	ProductVersion  string              `json:"product_version"`
	ReportID        int64               `json:"report_id"`
	Title           string              `json:"title"`
	Note            string              `json:"note,omitempty"`
	GeneratedAt     time.Time           `json:"generated_at"`
	GeneratedBy     string              `json:"generated_by"`
	PeriodFrom      time.Time           `json:"period_from"`
	PeriodTo        time.Time           `json:"period_to"` // exclusive
	Scope           Scope               `json:"scope"`
	Profiles        []ProfileRef        `json:"profiles"`
	CollectionStart time.Time           `json:"collection_start"`
	Summary         Summary             `json:"summary"`
	Inventory       []Asset             `json:"inventory"`
	Updates         []PlatformRow       `json:"updates"`
	Vulnerabilities VulnSection         `json:"vulnerabilities"`
	Patch           PatchSection        `json:"patch"`
	SLA             SLASection          `json:"sla"`
	EOL             []EOLRow            `json:"eol"`
	Changes         ChangeSection       `json:"changes"`
	Audit           AuditSection        `json:"audit"`
	Checks          []CheckResult       `json:"checks"`
	Controls        []ProfileAssessment `json:"controls"`
	Evidence        EvidenceIndex       `json:"evidence"`
	Gaps            []GapRow            `json:"gaps"`
}

// Scope is the hosts a report covers.
type Scope struct {
	GroupID   int64    `json:"group_id,omitempty"`
	GroupName string   `json:"group_name,omitempty"`
	Platforms []string `json:"platforms,omitempty"`
}

// ProfileRef names a profile version.
type ProfileRef struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

// Key is "id@version".
func (p ProfileRef) Key() string { return p.ID + "@" + p.Version }

// Summary is the executive summary.
type Summary struct {
	Hosts      int              `json:"hosts"`
	ByPlatform map[string]int   `json:"by_platform"`
	Profiles   []ProfileSummary `json:"profiles"`
	Warnings   []Text           `json:"warnings,omitempty"`
	Highlights []Text           `json:"highlights,omitempty"`
}

// ProfileSummary counts a profile's controls by outcome.
type ProfileSummary struct {
	Profile  string         `json:"profile"`
	Controls int            `json:"controls"`
	Outcomes map[string]int `json:"outcomes"`
}

// Asset is a host of the inventory (its last state in the period).
type Asset struct {
	HostID       int64     `json:"host_id"`
	Hostname     string    `json:"hostname"`
	Platform     string    `json:"platform"`
	OSName       string    `json:"os_name"`
	OSVersion    string    `json:"os_version"`
	AgentVersion string    `json:"agent_version"`
	LastSeen     time.Time `json:"last_seen"`
	Groups       []string  `json:"groups,omitempty"`
	OSSupport    string    `json:"os_support,omitempty"`
}

// PlatformRow is the update state of one platform at the end of the period.
type PlatformRow struct {
	Platform            string `json:"platform"`
	Hosts               int    `json:"hosts"`
	HostsWithSecurity   int    `json:"hosts_with_security_updates"`
	SecurityUpdates     int    `json:"security_updates"`
	Updates             int    `json:"updates"`
	RebootPending       int    `json:"reboot_pending"`
	UpdateJobsSucceeded int    `json:"update_jobs_succeeded"`
	UpdateJobsFailed    int    `json:"update_jobs_failed"`
}

// SeverityCounts are open findings (distinct CVEs per host) by severity.
type SeverityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	KEV      int `json:"kev"`
}

// VulnSection is the vulnerability management section.
type VulnSection struct {
	OpenAtStart SeverityCounts `json:"open_at_start"`
	OpenAtEnd   SeverityCounts `json:"open_at_end"`
	Resolved    int            `json:"resolved"`
	MeanFixDays float64        `json:"mean_fix_days"`
	KEVResolved int            `json:"kev_resolved"`
	KEVOverdue  int            `json:"kev_overdue"`
	KEVOpen     []KEVRow       `json:"kev_open,omitempty"`
}

// KEVRow is an actively exploited CVE still open at generation time.
type KEVRow struct {
	CVE     string `json:"cve"`
	Title   string `json:"title,omitempty"`
	DueDate string `json:"due_date,omitempty"`
	Hosts   int    `json:"hosts"`
}

// PatchSection is the patch compliance section.
type PatchSection struct {
	Jobs       int `json:"jobs"`
	Succeeded  int `json:"succeeded"`
	Partial    int `json:"partial"`
	Failed     int `json:"failed"`
	NotRun     int `json:"not_run"`
	Packages   int `json:"packages"`
	HostsClean int `json:"hosts_without_security_updates"`
	Hosts      int `json:"hosts"`
}

// SLASection is the security update SLA section.
type SLASection struct {
	Enabled     bool           `json:"enabled"`
	Days        map[string]int `json:"days"`
	Resolved    int            `json:"resolved"`
	WithinSLA   int            `json:"within_sla"`
	Late        int            `json:"late"`
	OpenOverdue int            `json:"open_overdue"`
}

// EOLRow is a host whose operating system is out of or near the end of support.
type EOLRow struct {
	Hostname string `json:"hostname"`
	Platform string `json:"platform"`
	OSName   string `json:"os_name"`
	Status   string `json:"status"`
}

// ChangeSection is the change management section.
type ChangeSection struct {
	Total          int            `json:"total"`
	ByType         map[string]int `json:"by_type"`
	ByStatus       map[string]int `json:"by_status"`
	ByOrigin       map[string]int `json:"by_origin"`
	Approvals      int            `json:"approvals"`
	RequirePreview bool           `json:"require_preview"`
}

// AuditSection summarizes the audit log of the period.
type AuditSection struct {
	Events      int            `json:"events"`
	ByAction    map[string]int `json:"by_action"`
	ChainOK     bool           `json:"chain_ok"`
	ChainItems  int            `json:"chain_items"`
	ChainBroken int64          `json:"chain_broken_id,omitempty"`
	ChainReason string         `json:"chain_reason,omitempty"`
}

// CheckResult is the outcome of one shared check (for some platforms).
type CheckResult struct {
	Key       string   `json:"key"` // check id with platforms
	Check     string   `json:"check"`
	Platforms []string `json:"platforms,omitempty"`
	Outcome   string   `json:"outcome"`
	Metrics   []Metric `json:"metrics,omitempty"`
	Gaps      []Text   `json:"gaps,omitempty"`
	Evidence  int      `json:"evidence"`

	ids []int64
}

// ProfileAssessment holds a profile's control assessments.
type ProfileAssessment struct {
	Profile  string              `json:"profile"`
	Version  string              `json:"version"`
	Controls []ControlAssessment `json:"controls"`
}

// ControlAssessment is the automated assessment of one control.
type ControlAssessment struct {
	ID            string         `json:"id"`
	Outcome       string         `json:"outcome"`
	Applicable    bool           `json:"applicable"`
	Justification string         `json:"justification,omitempty"`
	Checks        []ControlCheck `json:"checks,omitempty"`
	Manual        string         `json:"manual,omitempty"`
	ManualItems   int            `json:"manual_items,omitempty"`
	Evidence      int            `json:"evidence"`
}

// ControlCheck is a check's part in a control.
type ControlCheck struct {
	Key       string `json:"key"`
	Check     string `json:"check"`
	Relevance string `json:"relevance"`
	Outcome   string `json:"outcome"`
}

// EvidenceIndex lists evidence the version used (the newest when there
// are many; the full list is in the repository and the exports).
type EvidenceIndex struct {
	Total int           `json:"total"`
	Shown int           `json:"shown"`
	Items []EvidenceRef `json:"items"`
}

// EvidenceRef is one item of the index.
type EvidenceRef struct {
	ID         int64     `json:"id"`
	Kind       string    `json:"kind"`
	OccurredAt time.Time `json:"occurred_at"`
	Hostname   string    `json:"hostname,omitempty"`
	Subject    string    `json:"subject,omitempty"`
	Outcome    string    `json:"outcome,omitempty"`
	SHA256     string    `json:"sha256"`
	Controls   []string  `json:"controls"`
}

// GapRow is a control whose evidence is missing or shows gaps, with what to do.
type GapRow struct {
	Profile         string `json:"profile"`
	Control         string `json:"control"`
	Outcome         string `json:"outcome"`
	Gaps            []Text `json:"gaps,omitempty"`
	Recommendations []Text `json:"recommendations,omitempty"`
}
