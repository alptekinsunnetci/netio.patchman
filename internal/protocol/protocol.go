// Package protocol defines the JSON messages exchanged between
// netio-patchman-agent and the server under /api/v1/agent/.
//
// Flow:
//  1. POST /api/v1/agent/register  (enrollment token) -> agent ID + secret
//  2. POST /api/v1/agent/checkin   (every CheckinInterval) -> pending jobs
//  3. POST /api/v1/agent/report    (inventory, gzip allowed)
//  4. POST /api/v1/agent/jobs/{id}/result
//  5. POST /api/v1/agent/health    (monitoring results, CapHealthMonitor)
//
// Steps 2-4 authenticate with "Authorization: Bearer <secret>".
package protocol

import (
	"path"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Paths.
const (
	PathRegister  = "/api/v1/agent/register"
	PathCheckin   = "/api/v1/agent/checkin"
	PathReport    = "/api/v1/agent/report"
	PathJobResult = "/api/v1/agent/jobs/{id}/result"
	PathHealth    = "/api/v1/agent/health"
)

// Package managers.
const (
	PMApt    = "apt"
	PMDnf    = "dnf"
	PMYum    = "yum"
	PMZypper = "zypper"
	PMApk    = "apk"
	// PMWindowsUpdate is the Windows Update Agent (Windows hosts).
	PMWindowsUpdate = "windows-update"
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
	// Virtualization is the platform: systemd-detect-virt ids such as
	// "vmware", "kvm", "microsoft", "docker", or "none" for physical machines.
	// Empty when unknown (agents before 0.3.0).
	Virtualization string `json:"virtualization,omitempty"`
	// Upstream is the release a derivative distribution is built on, from
	// os-release UBUNTU_CODENAME or DEBIAN_CODENAME: "ubuntu:jammy", "debian:bookworm".
	// Empty for Ubuntu and Debian themselves.
	Upstream string `json:"upstream,omitempty"`
	// Capabilities lists the optional features the agent implements (Cap*
	// constants). The server only sends jobs and parameters an agent
	// declared; agents before 1.0.0 send none.
	Capabilities []string `json:"capabilities,omitempty"`
}

// Agent capabilities. A new feature that needs agent support adds a
// constant here; old agents never see the jobs or parameters behind it.
const (
	// CapServices: Report.Services lists the host's services.
	CapServices = "services"
	// CapHealth: health_check jobs and the health parameter of package jobs.
	CapHealth = "health"
	// CapPreview: preview (dry-run) jobs.
	CapPreview = "preview"
	// CapRollback: rollback jobs and JobResult.Changes on package jobs.
	CapRollback = "rollback"
	// CapHealthMonitor: the agent runs CheckinResponse.Health on its interval
	// and posts a HealthStatus with its resource usage.
	CapHealthMonitor = "health_monitor"
)

// Supports reports whether the agent declared capability c.
func (h HostInfo) Supports(c string) bool {
	for _, x := range h.Capabilities {
		if x == c {
			return true
		}
	}
	return false
}

var capabilityRE = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

// CleanCapabilities keeps valid, distinct capability names (at most 32).
func CleanCapabilities(caps []string) []string {
	out := []string{}
	for _, c := range caps {
		if len(out) < 32 && capabilityRE.MatchString(c) && !containsString(out, c) {
			out = append(out, c)
		}
	}
	return out
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

var virtRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// CleanVirtualization returns v if it is a valid platform id, otherwise "".
func CleanVirtualization(v string) string {
	if virtRE.MatchString(v) {
		return v
	}
	return ""
}

var upstreamRE = regexp.MustCompile(`^(ubuntu|debian):[a-z]{3,20}$`)

// CleanUpstream returns v if it is a valid upstream release, otherwise "".
func CleanUpstream(v string) string {
	if upstreamRE.MatchString(v) {
		return v
	}
	return ""
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
	// Health is the monitoring schedule (CapHealthMonitor agents only).
	Health *HealthSchedule `json:"health,omitempty"`
}

// HealthSchedule asks the agent to run Checks every IntervalSeconds and to
// post a HealthStatus (with resource usage even without checks).
type HealthSchedule struct {
	IntervalSeconds int           `json:"interval_seconds"`
	Checks          []HealthCheck `json:"checks,omitempty"`
}

// HealthStatus is one monitoring run of an agent.
type HealthStatus struct {
	CheckedAt time.Time      `json:"checked_at"`
	Results   []HealthResult `json:"results,omitempty"`
	Resources *Resources     `json:"resources,omitempty"`
}

// Resources is a snapshot of the host's resource usage. Sizes are bytes;
// Load is the 1, 5 and 15 minute load average (none on Windows).
type Resources struct {
	CPUs int `json:"cpus"`
	// CPUPercent is the average CPU use since the previous round (nil when
	// unknown, from agents before 1.0.2).
	CPUPercent      *float64    `json:"cpu_percent,omitempty"`
	Load            []float64   `json:"load,omitempty"`
	MemoryTotal     int64       `json:"memory_total"`
	MemoryAvailable int64       `json:"memory_available"`
	SwapTotal       int64       `json:"swap_total"`
	SwapFree        int64       `json:"swap_free"`
	Disks           []DiskUsage `json:"disks,omitempty"`
}

// DiskUsage is one file system. Used and Available as df counts them
// (Available excludes blocks reserved for root).
type DiskUsage struct {
	Path      string `json:"path"`
	Total     int64  `json:"total"`
	Used      int64  `json:"used"`
	Available int64  `json:"available"`
}

// Percent is the use as df shows it: used over used plus available.
func (d DiskUsage) Percent() float64 {
	if d.Used+d.Available <= 0 {
		return 0
	}
	return float64(d.Used) / float64(d.Used+d.Available) * 100
}

// MemoryPercent is the memory in use (total minus available); -1 unknown.
func (r Resources) MemoryPercent() float64 {
	if r.MemoryTotal <= 0 {
		return -1
	}
	return float64(r.MemoryTotal-r.MemoryAvailable) / float64(r.MemoryTotal) * 100
}

// SwapPercent is the swap in use; -1 without swap.
func (r Resources) SwapPercent() float64 {
	if r.SwapTotal <= 0 {
		return -1
	}
	return float64(r.SwapTotal-r.SwapFree) / float64(r.SwapTotal) * 100
}

// CPU is the CPU use in percent; -1 unknown.
func (r Resources) CPU() float64 {
	if r.CPUPercent == nil {
		return -1
	}
	return *r.CPUPercent
}

// CPUOrLoad is the CPU use, or the load per core from agents that do not
// report it; -1 unknown.
func (r Resources) CPUOrLoad() float64 {
	if v := r.CPU(); v >= 0 {
		return v
	}
	return r.LoadPercent()
}

// DiskMax is the use of the fullest file system; -1 without file systems.
func (r Resources) DiskMax() float64 {
	m := -1.0
	for _, d := range r.Disks {
		if d.Total > 0 {
			m = max(m, d.Percent())
		}
	}
	return m
}

// LoadPercent is the 1-minute load average per CPU core; -1 unknown.
func (r Resources) LoadPercent() float64 {
	if len(r.Load) == 0 || r.CPUs <= 0 {
		return -1
	}
	return r.Load[0] / float64(r.CPUs) * 100
}

// MaxDisks bounds the file systems of one snapshot.
const MaxDisks = 30

// Clean bounds a received snapshot: no negative sizes, at most MaxDisks
// file systems with printable paths.
func (r *Resources) Clean() {
	clamp := func(v *int64) {
		if *v < 0 {
			*v = 0
		}
	}
	for _, v := range []*int64{&r.MemoryTotal, &r.MemoryAvailable, &r.SwapTotal, &r.SwapFree} {
		clamp(v)
	}
	r.MemoryAvailable, r.SwapFree = min(r.MemoryAvailable, r.MemoryTotal), min(r.SwapFree, r.SwapTotal)
	if r.CPUs < 0 || r.CPUs > 100000 {
		r.CPUs = 0
	}
	if r.CPUPercent != nil && (*r.CPUPercent < 0 || *r.CPUPercent > 100) {
		r.CPUPercent = nil
	}
	if len(r.Load) > 3 {
		r.Load = r.Load[:3]
	}
	for i, l := range r.Load {
		if l < 0 || l > 1e6 {
			r.Load[i] = 0
		}
	}
	var disks []DiskUsage
	for _, d := range r.Disks {
		if len(disks) >= MaxDisks || d.Path == "" || len(d.Path) > 200 || !utf8.ValidString(d.Path) || strings.IndexFunc(d.Path, unicode.IsControl) >= 0 {
			continue
		}
		clamp(&d.Total)
		clamp(&d.Used)
		clamp(&d.Available)
		disks = append(disks, d)
	}
	r.Disks = disks
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
	// Windows Update only: the update title and Microsoft severity
	// (Critical, Important, Moderate, Low) verbatim, and the CVEs it fixes.
	Title    string   `json:"title,omitempty"`
	Severity string   `json:"severity,omitempty"`
	CVEs     []string `json:"cves,omitempty"`
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
	// KernelPatch is the live kernel patching service, nil when none.
	KernelPatch *KernelPatch `json:"kernel_patch,omitempty"`
	// Services are the host's services (CapServices); nil when the agent
	// does not report them or the service manager could not be read.
	Services []Service `json:"services,omitempty"`
	// Products are software installs the agent found outside the package
	// manager (hosting panels, IIS, SQL Server on Windows). Older agents
	// send none.
	Products []Product `json:"products,omitempty"`
}

// Product is a probed software install: a catalog id (software.Probed)
// and its version as the product reports it.
type Product struct {
	Software string `json:"software"`
	Version  string `json:"version"`
}

var productVersionRE = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+~_-]{0,63}$`)

// CleanProducts drops invalid entries and duplicates (at most 50 kept).
func CleanProducts(in []Product, known func(string) bool) []Product {
	var out []Product
	seen := map[Product]bool{}
	for _, p := range in {
		if !known(p.Software) || !productVersionRE.MatchString(p.Version) || seen[p] || len(out) >= 50 {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// Service states.
const (
	ServiceRunning = "running"
	ServiceStopped = "stopped"
	ServiceFailed  = "failed"
)

// Service is a system service (systemd unit without ".service", OpenRC
// service or Windows service name).
type Service struct {
	Name    string `json:"name"`
	State   string `json:"state"`
	Enabled bool   `json:"enabled"`
}

// MaxServices bounds the services of one report.
const MaxServices = 2000

// Live kernel patching services.
const (
	KernelCare = "kernelcare" // TuxCare KernelCare: kcarectl --uname is the effective kernel
	Livepatch  = "livepatch"  // Canonical Livepatch: a list of patched CVEs
)

// KernelPatch describes live patches applied to the running kernel.
type KernelPatch struct {
	Provider string `json:"provider"`
	// EffectiveKernel is the kernel release the patched kernel corresponds to
	// (KernelCare), in uname -r form.
	EffectiveKernel string `json:"effective_kernel,omitempty"`
	// CVEs are fixed in the running kernel by live patches (Livepatch).
	CVEs []string `json:"cves,omitempty"`
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
	case JobRefresh, JobUpgradeSecurity, JobUpgradeAll, JobUpgradePackages, JobAgentUpdate, JobRestartServices, JobReboot, JobHealthCheck, JobPreview, JobRollback:
		return true
	}
	return false
}

// Agent update job parameters.
const (
	// ParamExclude is set on package jobs: comma separated name patterns the
	// job must not update (see Excluded).
	ParamExclude = "exclude"
	ParamVersion = "version" // target agent version
	ParamSHA256  = "sha256"  // hex SHA-256 of the binary
	ParamPath    = "path"    // download path on the server, under AgentDownloadPrefix
)

// AgentDownloadPrefix is where the server serves agent binaries.
const AgentDownloadPrefix = "/downloads/agent/"

// OSWindows is HostInfo.OSID of Windows hosts (Linux hosts report the
// os-release ID). Windows hosts use the PMWindowsUpdate package manager.
const OSWindows = "windows"

// AgentPlatforms are the GOOS/GOARCH pairs the server builds agents for.
var AgentPlatforms = [][2]string{{"linux", "amd64"}, {"linux", "arm64"}, {"windows", "amd64"}}

// AgentOS returns the agent's GOOS for a host's OS ID.
func AgentOS(osID string) string {
	if osID == OSWindows {
		return "windows"
	}
	return "linux"
}

// AgentBinaryName returns the download name of an agent binary, e.g.
// netio-patchman-agent-linux-amd64 or netio-patchman-agent-windows-amd64.exe.
func AgentBinaryName(goos, arch string) string {
	name := "netio-patchman-agent-" + goos + "-" + arch
	if goos == "windows" {
		name += ".exe"
	}
	return name
}

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
	// Health is the outcome of the health checks (CapHealth), nil without.
	Health *HealthReport `json:"health,omitempty"`
	// Preview is the plan of a preview job (CapPreview).
	Preview *Preview `json:"preview,omitempty"`
	// Changes are the package versions a package or rollback job changed
	// (CapRollback): From before, To after; empty From = new, empty To = removed.
	Changes []PackageChange `json:"changes,omitempty"`
	// Rollback is the per-package outcome of a rollback job.
	Rollback []RollbackItem `json:"rollback,omitempty"`
}

// ---------- health checks (CapHealth) ----------

// Health check types.
const (
	HealthResources = "resources" // CPU load, memory and disk usage against limits
	HealthService   = "service"   // a service must be running
	HealthHTTP      = "http"      // an HTTP(S) URL must answer as expected
	HealthTCP       = "tcp"       // a TCP port must accept connections
	// HealthCommand runs an executable the host's administrator placed in
	// the agent's health.d directory; the server only names it.
	HealthCommand = "command"
)

// Job type and parameters of health checks.
const (
	JobHealthCheck = "health_check" // run the checks now (no update)
	// ParamHealth carries the checks (JSON array of HealthCheck) on
	// health_check jobs and on package jobs, which run them before and after.
	ParamHealth = "health"
	// ParamHealthPolicy: "abort" (default) skips the update when a check
	// fails before it; "continue" runs it anyway.
	ParamHealthPolicy = "health_policy"
	// ParamHealthDelay is the wait in seconds between the update and the
	// checks after it (services restart), default 15.
	ParamHealthDelay = "health_delay"
)

// HealthCheck is one check to run on the host.
type HealthCheck struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
	// Target: service name, URL, host:port or command name.
	Target string `json:"target,omitempty"`
	// HTTP: expected status (0 = any 2xx/3xx), required body text, and
	// whether certificate errors are accepted.
	Expect   int    `json:"expect,omitempty"`
	Contains string `json:"contains,omitempty"`
	Insecure bool   `json:"insecure,omitempty"`
	// Resources: highest allowed usage in percent (0 = not checked); CPU is
	// the 1-minute load average per CPU core.
	CPU    int      `json:"cpu,omitempty"`
	Memory int      `json:"memory,omitempty"`
	Disk   int      `json:"disk,omitempty"`
	Paths  []string `json:"paths,omitempty"` // file systems for Disk, default "/"
	// TimeoutSeconds bounds the check (default 10, at most 120).
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`
}

// HealthResult is the outcome of one check. Value and Message are verbatim
// measurements and program output; the agent's own text is localized.
type HealthResult struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	OK         bool   `json:"ok"`
	Value      string `json:"value,omitempty"`
	Message    string `json:"message,omitempty"`
	DurationMS int64  `json:"duration_ms"`
}

// HealthReport holds the checks of a job: before and after an update, or
// Checks for a health_check job. Aborted: a check failed before the update
// and the update was not run.
type HealthReport struct {
	Before  []HealthResult `json:"before,omitempty"`
	After   []HealthResult `json:"after,omitempty"`
	Checks  []HealthResult `json:"checks,omitempty"`
	Aborted bool           `json:"aborted,omitempty"`
}

// MaxHealthChecks bounds the checks of one job.
const MaxHealthChecks = 50

var commandNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

// ValidCommandName accepts health.d command names (no path separators).
func ValidCommandName(name string) bool {
	return commandNameRE.MatchString(name) && !strings.Contains(name, "..")
}

// ---------- update preview (CapPreview) ----------

// JobPreview simulates a package job without changing the host: the
// package manager's own dry run. ParamPreviewType names the job type to
// simulate (upgrade_all, upgrade_security, upgrade_packages); Packages holds
// the packages for upgrade_packages.
const (
	JobPreview       = "preview"
	ParamPreviewType = "preview_type"
)

// PackageChange is one package in a plan: From is empty for a new package,
// To is empty for a removal. Versions are verbatim.
type PackageChange struct {
	Name string `json:"name"`
	Arch string `json:"arch,omitempty"`
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

// Preview is the package manager's plan for a job.
type Preview struct {
	PackageManager string          `json:"package_manager"`
	Upgrades       []PackageChange `json:"upgrades,omitempty"`
	Installs       []PackageChange `json:"installs,omitempty"` // new packages (dependencies)
	Removals       []PackageChange `json:"removals,omitempty"`
	Downgrades     []PackageChange `json:"downgrades,omitempty"`
	// Kernel: a kernel package changes; Reboot: a kernel, C library, init
	// system or microcode package changes, so a reboot will be needed.
	Kernel bool `json:"kernel"`
	Reboot bool `json:"reboot"`
	// DownloadBytes and DiskBytes (change in used space, negative when space
	// is freed) are -1 when the package manager does not report them;
	// FreeBytes is the free space of the file system the packages go to.
	DownloadBytes int64 `json:"download_bytes"`
	DiskBytes     int64 `json:"disk_bytes"`
	FreeBytes     int64 `json:"free_bytes"`
	// Conflicts are the package manager's error lines (dependency problems,
	// conflicts); a plan with conflicts cannot be applied as is.
	Conflicts []string `json:"conflicts,omitempty"`
	// Plan is the package manager's output, verbatim and shortened.
	Plan string `json:"plan,omitempty"`
}

// MaxPreviewPackages bounds each list of a preview.
const MaxPreviewPackages = 5000

// ---------- rollback (CapRollback) ----------

// JobRollback returns packages to earlier versions. ParamRollbackTargets
// holds the targets (JSON array of PackageChange: Name, Arch, To = version
// to return to); ParamRollbackMode is "check" (availability and the package
// manager's simulation, nothing changes) or "apply".
const (
	JobRollback          = "rollback"
	ParamRollbackTargets = "targets"
	ParamRollbackMode    = "mode"
	RollbackCheck        = "check"
	RollbackApply        = "apply"
)

// Rollback item statuses.
const (
	RollbackAvailable   = "available"   // the version can be installed
	RollbackUnavailable = "unavailable" // no repository or cache offers the version
	RollbackCurrent     = "current"     // already installed: nothing to do
	RollbackDone        = "done"        // installed and verified
	RollbackFailed      = "failed"      // not installed after the run
)

// RollbackItem is the outcome for one target package.
type RollbackItem struct {
	Name    string `json:"name"`
	Arch    string `json:"arch,omitempty"`
	From    string `json:"from,omitempty"` // installed version before the job
	To      string `json:"to"`             // target version
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

// MaxRollbackTargets bounds a rollback job.
const MaxRollbackTargets = 200

var pkgVersionRE = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+~:_^-]{0,127}$`)

// ValidPackageVersion accepts distribution package versions ("1:3.0.7-27.el9",
// "1.22.1-9+deb12u2", "1.2.3-r0"). Both sides check it.
func ValidPackageVersion(v string) bool { return pkgVersionRE.MatchString(v) }

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

var excludeRE = regexp.MustCompile(`^[A-Za-z0-9.+_:~@*?\[\]-]{1,100}$`)

// MaxExcludePatterns bounds an exclusion list.
const MaxExcludePatterns = 200

// ParseExcludePatterns splits a comma, space or newline separated list of
// package name patterns ("kernel*", "mysql-server", "KB5034439"). Shell-style
// wildcards: * ? [..]. Invalid entries are returned separately.
func ParseExcludePatterns(s string) (patterns, invalid []string) {
	seen := map[string]bool{}
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\r' || r == '\t' }) {
		if _, err := path.Match(f, ""); err != nil || !excludeRE.MatchString(f) {
			invalid = append(invalid, f)
			continue
		}
		if !seen[strings.ToLower(f)] && len(patterns) < MaxExcludePatterns {
			seen[strings.ToLower(f)] = true
			patterns = append(patterns, f)
		}
	}
	return patterns, invalid
}

// Excluded reports whether name matches one of the patterns (case-insensitive).
func Excluded(patterns []string, name string) bool {
	n := strings.ToLower(name)
	for _, p := range patterns {
		if ok, _ := path.Match(strings.ToLower(p), n); ok {
			return true
		}
	}
	return false
}

// DiffPackages returns the packages whose version changed, appeared (From
// empty) or disappeared (To empty) between two inventories.
func DiffPackages(before, after []Package) []PackageChange {
	key := func(p Package) string { return p.Name + "\x00" + p.Arch }
	old := make(map[string]Package, len(before))
	for _, p := range before {
		old[key(p)] = p
	}
	var out []PackageChange
	seen := map[string]bool{}
	for _, p := range after {
		k := key(p)
		seen[k] = true
		if o, ok := old[k]; !ok {
			out = append(out, PackageChange{Name: p.Name, Arch: p.Arch, To: p.Version})
		} else if o.Version != p.Version {
			out = append(out, PackageChange{Name: p.Name, Arch: p.Arch, From: o.Version, To: p.Version})
		}
	}
	for _, p := range before {
		if !seen[key(p)] {
			out = append(out, PackageChange{Name: p.Name, Arch: p.Arch, From: p.Version})
		}
	}
	if len(out) > MaxPreviewPackages {
		out = out[:MaxPreviewPackages]
	}
	return out
}
