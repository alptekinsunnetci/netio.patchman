// Package protocol defines the JSON messages exchanged between
// netio-patchman-agent and the server under /api/v1/agent/.
//
// Flow:
//  1. POST /api/v1/agent/register  (enrollment token) -> agent ID + secret
//  2. POST /api/v1/agent/checkin   (every CheckinInterval) -> pending jobs
//  3. POST /api/v1/agent/report    (inventory, gzip allowed)
//  4. POST /api/v1/agent/jobs/{id}/result
//
// Steps 2-4 authenticate with "Authorization: Bearer <secret>".
package protocol

import (
	"regexp"
	"time"
)

// Paths.
const (
	PathRegister  = "/api/v1/agent/register"
	PathCheckin   = "/api/v1/agent/checkin"
	PathReport    = "/api/v1/agent/report"
	PathJobResult = "/api/v1/agent/jobs/{id}/result"
)

// Package managers.
const (
	PMApt    = "apt"
	PMDnf    = "dnf"
	PMYum    = "yum"
	PMZypper = "zypper"
	PMApk    = "apk"
)

// HostInfo identifies a host. Values are verbatim from the operating system.
type HostInfo struct {
	Hostname       string   `json:"hostname"`
	FQDN           string   `json:"fqdn,omitempty"`
	MachineID      string   `json:"machine_id,omitempty"`
	OSID           string   `json:"os_id"`         // /etc/os-release ID
	OSIDLike       string   `json:"os_id_like"`    // ID_LIKE
	OSVersionID    string   `json:"os_version_id"` // VERSION_ID
	OSVersion      string   `json:"os_version"`    // VERSION
	OSName         string   `json:"os_name"`       // PRETTY_NAME
	Kernel         string   `json:"kernel"`
	Arch           string   `json:"arch"`
	IPAddresses    []string `json:"ip_addresses,omitempty"`
	PackageManager string   `json:"package_manager"`
	AgentVersion   string   `json:"agent_version"`
	RemoteUpdates  bool     `json:"remote_updates"`
	SelfUpdate     bool     `json:"self_update"`
	UptimeSeconds  int64    `json:"uptime_seconds"`
}

// RegisterRequest enrolls a new agent.
type RegisterRequest struct {
	EnrollmentToken string   `json:"enrollment_token"`
	Host            HostInfo `json:"host"`
}

// RegisterResponse carries the agent's long-lived credentials.
type RegisterResponse struct {
	HostID      int64  `json:"host_id"`
	AgentSecret string `json:"agent_secret"`
}

// CheckinRequest is the periodic heartbeat.
type CheckinRequest struct {
	Host HostInfo `json:"host"`
}

// CheckinResponse tells the agent what to do next.
type CheckinResponse struct {
	Jobs                   []Job `json:"jobs,omitempty"`
	ReportRequested        bool  `json:"report_requested"`
	CheckinIntervalSeconds int   `json:"checkin_interval_seconds"`
	ReportIntervalSeconds  int   `json:"report_interval_seconds"`
}

// Package is an installed package. SourceName/SourceVersion are the source
// package (deb, apk origin, rpm SRPM name) used for vulnerability matching.
type Package struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	Arch          string `json:"arch,omitempty"`
	SourceName    string `json:"source_name,omitempty"`
	SourceVersion string `json:"source_version,omitempty"`
}

// Update is an available package update.
type Update struct {
	Name             string `json:"name"`
	CurrentVersion   string `json:"current_version,omitempty"`
	AvailableVersion string `json:"available_version"`
	Repository       string `json:"repository,omitempty"`
	Security         bool   `json:"security"`
}

// Report is the full inventory.
type Report struct {
	Host           HostInfo  `json:"host"`
	Packages       []Package `json:"packages"`
	Updates        []Update  `json:"updates"`
	RebootRequired bool      `json:"reboot_required"`
	// RestartServices are services still running old code (deleted libraries
	// or binaries) after an update; restarting them activates the update.
	RestartServices []string  `json:"restart_services,omitempty"`
	CollectedAt     time.Time `json:"collected_at"`
	Errors          []string  `json:"errors,omitempty"`
}

// Job types.
const (
	JobRefresh         = "refresh"          // collect and send a report now
	JobUpgradeSecurity = "upgrade_security" // install security updates
	JobUpgradeAll      = "upgrade_all"      // install all updates
	JobUpgradePackages = "upgrade_packages" // upgrade the listed packages
	JobAgentUpdate     = "agent_update"     // replace the agent binary and restart
	JobRestartServices = "restart_services" // restart services that still run old code
	JobReboot          = "reboot"           // reboot the host one minute after the result is sent
)

// ValidJobType reports whether t is a known job type.
func ValidJobType(t string) bool {
	switch t {
	case JobRefresh, JobUpgradeSecurity, JobUpgradeAll, JobUpgradePackages, JobAgentUpdate, JobRestartServices, JobReboot:
		return true
	}
	return false
}

// Agent update job parameters.
const (
	ParamVersion = "version" // target agent version
	ParamSHA256  = "sha256"  // hex SHA-256 of the binary
	ParamPath    = "path"    // download path on the server, under AgentDownloadPrefix
)

// AgentDownloadPrefix is where the server serves agent binaries.
const AgentDownloadPrefix = "/downloads/agent/"

// AgentBinaryName returns the download name for a Linux architecture.
func AgentBinaryName(arch string) string { return "netio-patchman-agent-linux-" + arch }

// Job is work dispatched to an agent.
type Job struct {
	ID       int64             `json:"id"`
	Type     string            `json:"type"`
	Packages []string          `json:"packages,omitempty"`
	Params   map[string]string `json:"params,omitempty"`
}

var versionRE = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+~_-]{0,63}$`)

// ValidVersion validates an agent version string.
func ValidVersion(v string) bool { return versionRE.MatchString(v) }

// Job statuses.
const (
	JobQueued     = "queued"
	JobDispatched = "dispatched"
	JobSucceeded  = "succeeded"
	JobPartial    = "partial" // finished, but some targeted packages or services were left
	JobFailed     = "failed"
	JobCancelled  = "cancelled"
)

// JobResult is sent by the agent when a job finishes.
type JobResult struct {
	Succeeded bool   `json:"succeeded"`
	ExitCode  int    `json:"exit_code"`
	Output    string `json:"output"`
	// Remaining lists the packages (or services) the job targeted that are
	// still pending after it ran. With Succeeded the job is partial.
	Remaining  []string  `json:"remaining,omitempty"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
}

// ErrorResponse is returned with non-2xx statuses. Message is Turkish.
type ErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// MaxOutputBytes caps job output sent to the server.
const MaxOutputBytes = 256 << 10

var packageNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_:~@-]{0,199}$`)

// ValidPackageName rejects names that could be read as command options or
// contain shell metacharacters. Both sides check it.
func ValidPackageName(name string) bool { return packageNameRE.MatchString(name) }

var serviceNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9@._:\-]{0,199}$`)

// ValidServiceName accepts systemd unit names (sshd.service, getty@tty1.service)
// and OpenRC service names. Both sides check it.
func ValidServiceName(name string) bool { return serviceNameRE.MatchString(name) }
