package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"netio.patchman/internal/auth"
	"netio.patchman/internal/eol"
	"netio.patchman/internal/protocol"
	"netio.patchman/internal/settings"
	"netio.patchman/internal/software"
	"netio.patchman/internal/store"
	"netio.patchman/internal/timeutil"
	"netio.patchman/internal/version"
	"netio.patchman/internal/vuln"
)

// REST API (/api/v1/...) and Prometheus metrics (/metrics) for scripts,
// Ansible and dashboards. Requests authenticate with an API key created on
// the profile page ("Authorization: Bearer npat_…"); a key acts as its user,
// with the same role and group limit. Cookies are not accepted here, so the
// API needs no CSRF protection. Field names are English and stable; values
// such as CVE titles are verbatim.

const apiTokenPrefix = "npat_"

type apiKey struct{}

// apiAuth wraps an API handler. write requires a key that is not read-only
// and an operator (or administrator) user.
func (s *Server) apiAuth(write bool, h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := s.clientIP(r)
		if s.limiter.Blocked("api:" + ip) {
			s.apiError(w, http.StatusTooManyRequests, "rate_limited")
			return
		}
		raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		raw = strings.TrimSpace(raw)
		if !ok || !strings.HasPrefix(raw, apiTokenPrefix) {
			s.apiError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		tok, user, err := s.st.APITokenUser(r.Context(), auth.HashToken(raw))
		if errors.Is(err, store.ErrNotFound) {
			s.limiter.Fail("api:" + ip)
			s.apiError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if err != nil {
			s.apiError(w, http.StatusInternalServerError, "internal")
			return
		}
		if write && (tok.ReadOnly || !user.CanOperate()) {
			s.apiError(w, http.StatusForbidden, "forbidden")
			return
		}
		// The key acts like a session of its user: audit entries, created
		// jobs and the group limit work as in the dashboard.
		ctx := context.WithValue(r.Context(), sessionKey{}, &session{user: user, apiToken: tok.Name})
		ctx = context.WithValue(ctx, apiKey{}, tok)
		if ids, ok := user.Scope(); ok {
			ctx = store.WithScope(ctx, ids)
		}
		w.Header().Set("Cache-Control", "no-store")
		h(w, r.WithContext(ctx))
	})
}

func (s *Server) apiJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func (s *Server) apiError(w http.ResponseWriter, status int, code string) {
	s.apiJSON(w, status, protocol.ErrorResponse{Code: code, Message: s.l.T("api.error." + code)})
}

// ---------- JSON views ----------

type apiHost struct {
	ID              int64          `json:"id"`
	Hostname        string         `json:"hostname"`
	FQDN            string         `json:"fqdn,omitempty"`
	OSID            string         `json:"os_id"`
	OSName          string         `json:"os_name"`
	OSVersion       string         `json:"os_version,omitempty"`
	Kernel          string         `json:"kernel"`
	Arch            string         `json:"arch"`
	IPAddresses     []string       `json:"ip_addresses"`
	PackageManager  string         `json:"package_manager"`
	Platform        string         `json:"platform,omitempty"`
	AgentVersion    string         `json:"agent_version"`
	Online          bool           `json:"online"`
	LastSeenAt      *time.Time     `json:"last_seen_at"`
	LastScanAt      *time.Time     `json:"last_scan_at"`
	RemoteUpdates   bool           `json:"remote_updates"`
	RebootRequired  bool           `json:"reboot_required"`
	KernelPatch     string         `json:"kernel_patch,omitempty"`
	Groups          []string       `json:"groups"`
	Packages        int            `json:"packages"`
	Updates         int            `json:"updates"`
	SecurityUpdates int            `json:"security_updates"`
	Vulnerabilities map[string]int `json:"vulnerabilities"`
	// SecurityScore is 0-100, null before the first computation.
	SecurityScore *int     `json:"security_score"`
	Capabilities  []string `json:"capabilities"`
}

func tsPtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

func (s *Server) apiHostView(h store.Host) apiHost {
	groups := []string{}
	for _, g := range h.Groups {
		groups = append(groups, g.Name)
	}
	var sc *int
	if h.SecurityScore >= 0 {
		v := h.SecurityScore
		sc = &v
	}
	return apiHost{
		SecurityScore: sc, Capabilities: append([]string{}, h.Capabilities...),
		ID: h.ID, Hostname: h.Hostname, FQDN: h.FQDN, OSID: h.OSID, OSName: h.OSName, OSVersion: h.OSVersion, Kernel: h.Kernel,
		Arch: h.Arch, IPAddresses: append([]string{}, h.IPAddresses...), PackageManager: h.PackageManager, Platform: h.Virtualization,
		AgentVersion: h.AgentVersion, Online: h.Online(s.offlineAfter()), LastSeenAt: tsPtr(h.LastSeenAt), LastScanAt: tsPtr(h.LastScanAt),
		RemoteUpdates: h.RemoteUpdates, RebootRequired: h.RebootRequired, KernelPatch: h.KernelPatch, Groups: groups,
		Packages: h.PackageCount, Updates: h.UpdateCount, SecurityUpdates: h.SecurityUpdateCount,
		Vulnerabilities: map[string]int{"critical": h.Vulns.Critical, "high": h.Vulns.High, "medium": h.Vulns.Medium, "low": h.Vulns.Low, "other": h.Vulns.Other},
	}
}

type apiFinding struct {
	ID               int64      `json:"id"`
	HostID           int64      `json:"host_id"`
	Hostname         string     `json:"hostname"`
	CVE              string     `json:"cve"`
	Title            string     `json:"title"`
	Severity         string     `json:"severity"`
	CVSS             *float64   `json:"cvss"`
	EPSS             *float64   `json:"epss"`
	KnownExploited   bool       `json:"known_exploited"`
	Package          string     `json:"package"`
	InstalledVersion string     `json:"installed_version"`
	FixedVersion     string     `json:"fixed_version"`
	Status           string     `json:"status"`
	FirstDetectedAt  time.Time  `json:"first_detected_at"`
	DueAt            *time.Time `json:"due_at"`
	Overdue          bool       `json:"overdue"`
}

func apiFindingView(f store.FindingRow) apiFinding {
	return apiFinding{ID: f.ID, HostID: f.HostID, Hostname: f.Hostname, CVE: f.CVEID, Title: f.Title, Severity: string(f.Severity),
		CVSS: f.CVSSScore, EPSS: f.EPSS, KnownExploited: f.KnownExploited, Package: f.PackageName, InstalledVersion: f.InstalledVersion,
		FixedVersion: f.FixedVersion, Status: f.Status, FirstDetectedAt: f.FirstDetectedAt.UTC(), DueAt: tsPtr(f.DueAt), Overdue: f.Overdue()}
}

type apiJob struct {
	ID         int64             `json:"id"`
	HostID     int64             `json:"host_id"`
	Hostname   string            `json:"hostname"`
	Type       string            `json:"type"`
	Packages   []string          `json:"packages"`
	Status     string            `json:"status"`
	CreatedBy  string            `json:"created_by,omitempty"`
	Schedule   string            `json:"schedule,omitempty"`
	CreatedAt  time.Time         `json:"created_at"`
	FinishedAt *time.Time        `json:"finished_at"`
	ExitCode   int               `json:"exit_code"`
	Remaining  []string          `json:"remaining"`
	Params     map[string]string `json:"params,omitempty"`
	Output     string            `json:"output,omitempty"`
}

func apiJobView(j store.Job) apiJob {
	return apiJob{ID: j.ID, HostID: j.HostID, Hostname: j.Hostname, Type: j.Type, Packages: append([]string{}, j.Packages...), Status: j.Status,
		CreatedBy: j.CreatedBy, Schedule: j.ScheduleName, CreatedAt: j.CreatedAt.UTC(), FinishedAt: tsPtr(j.FinishedAt), ExitCode: j.ExitCode,
		Remaining: append([]string{}, j.Remaining...), Output: j.Output}
}

type apiPage struct {
	Page  int `json:"page"`
	Size  int `json:"page_size"`
	Total int `json:"total"`
}

func apiPageOf(r *http.Request, total int) apiPage {
	return apiPage{Page: pageNumber(r), Size: pageSize, Total: total}
}

// ---------- handlers ----------

func (s *Server) apiHosts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	gid, _ := strconv.ParseInt(q.Get("group"), 10, 64)
	f := store.HostFilter{Search: q.Get("q"), Status: q.Get("status"), OSID: q.Get("os"), GroupID: gid, Platform: q.Get("platform"), OfflineAfter: s.offlineAfter()}
	hosts, total, err := s.st.ListHosts(r.Context(), f, store.Page{Number: pageNumber(r), Size: pageSize})
	if err != nil {
		s.apiError(w, http.StatusInternalServerError, "internal")
		return
	}
	out := make([]apiHost, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, s.apiHostView(h))
	}
	s.apiJSON(w, http.StatusOK, map[string]any{"hosts": out, "pagination": apiPageOf(r, total)})
}

func (s *Server) apiHostOr404(w http.ResponseWriter, r *http.Request) (store.Host, bool) {
	id, ok := pathID(r)
	if !ok {
		s.apiError(w, http.StatusNotFound, "not_found")
		return store.Host{}, false
	}
	h, err := s.st.HostByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		s.apiError(w, http.StatusNotFound, "not_found")
		return h, false
	}
	if err != nil {
		s.apiError(w, http.StatusInternalServerError, "internal")
		return h, false
	}
	return h, true
}

func (s *Server) apiHost(w http.ResponseWriter, r *http.Request) {
	if h, ok := s.apiHostOr404(w, r); ok {
		s.apiJSON(w, http.StatusOK, s.apiHostView(h))
	}
}

func (s *Server) apiHostFindings(w http.ResponseWriter, r *http.Request) {
	h, ok := s.apiHostOr404(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	f := store.FindingFilter{HostID: h.ID, Status: q.Get("status"), Severity: q.Get("severity"), KEVOnly: q.Get("kev") == "1",
		SLA: s.sla(r.Context()), OverdueOnly: q.Get("overdue") == "1"}
	rows, total, err := s.st.ListFindings(r.Context(), f, store.Page{Number: pageNumber(r), Size: pageSize})
	if err != nil {
		s.apiError(w, http.StatusInternalServerError, "internal")
		return
	}
	out := make([]apiFinding, 0, len(rows))
	for _, f := range rows {
		out = append(out, apiFindingView(f))
	}
	s.apiJSON(w, http.StatusOK, map[string]any{"findings": out, "pagination": apiPageOf(r, total)})
}

func (s *Server) apiHostUpdates(w http.ResponseWriter, r *http.Request) {
	h, ok := s.apiHostOr404(w, r)
	if !ok {
		return
	}
	ups, err := s.st.HostUpdates(r.Context(), h.ID)
	if err != nil {
		s.apiError(w, http.StatusInternalServerError, "internal")
		return
	}
	patterns := s.effectiveExcludes(r.Context(), h.ID)
	type update struct {
		protocol.Update
		Excluded bool `json:"excluded"`
	}
	out := make([]update, 0, len(ups))
	for _, u := range ups {
		out = append(out, update{Update: u, Excluded: protocol.Excluded(patterns, u.Name)})
	}
	s.apiJSON(w, http.StatusOK, map[string]any{"updates": out, "exclude": patterns})
}

// apiSoftwareItem is a product release on a host in the REST API.
type apiSoftwareItem struct {
	Software       string `json:"software"`
	Name           string `json:"name"`
	Cycle          string `json:"cycle"`
	Version        string `json:"version"`
	Package        string `json:"package"`
	PackageVersion string `json:"package_version"`
	// Running: true, false, or null when unknown.
	Running        *bool  `json:"running"`
	Service        string `json:"service,omitempty"`
	HostID         int64  `json:"host_id"`
	Hostname       string `json:"hostname"`
	OpenCVEs       int    `json:"open_cves"`
	Severity       string `json:"severity,omitempty"`
	KnownExploited bool   `json:"known_exploited"`
}

func apiSoftware(rows []store.HostSoftwareRow) []apiSoftwareItem {
	out := make([]apiSoftwareItem, 0, len(rows))
	for _, r := range rows {
		it := apiSoftwareItem{Software: r.Software, Cycle: r.Cycle, Version: r.Version, Package: r.Package, PackageVersion: r.PackageVersion,
			Service: r.Service, HostID: r.HostID, Hostname: r.Hostname, OpenCVEs: r.CVECount, KnownExploited: r.KnownExploited}
		if d, ok := software.ByID(r.Software); ok {
			it.Name = d.Name
		}
		if r.Running >= 0 {
			b := r.Running == 1
			it.Running = &b
		}
		if r.CVECount > 0 {
			it.Severity = string(r.Severity)
		}
		out = append(out, it)
	}
	return out
}

func (s *Server) apiHostSoftware(w http.ResponseWriter, r *http.Request) {
	h, ok := s.apiHostOr404(w, r)
	if !ok {
		return
	}
	rows, err := s.st.HostSoftware(r.Context(), h.ID)
	if err != nil {
		s.apiError(w, http.StatusInternalServerError, "internal")
		return
	}
	svcs, known, err := s.st.HostServices(r.Context(), h.ID)
	if err != nil {
		s.apiError(w, http.StatusInternalServerError, "internal")
		return
	}
	if !known {
		svcs = nil
	}
	s.apiJSON(w, http.StatusOK, map[string]any{"software": apiSoftware(rows), "services_known": known, "services": svcs})
}

// apiSoftwareList lists product releases across the visible fleet;
// ?software=nginx and ?cycle=1.24 narrow it.
func (s *Server) apiSoftwareList(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("software")
	var rows []store.HostSoftwareRow
	if id != "" {
		if _, ok := software.ByID(id); !ok {
			s.apiError(w, http.StatusBadRequest, "bad_request")
			return
		}
		var err error
		if rows, err = s.st.SoftwareHosts(r.Context(), id, r.URL.Query().Get("cycle")); err != nil {
			s.apiError(w, http.StatusInternalServerError, "internal")
			return
		}
	} else {
		for _, d := range software.Catalog {
			more, err := s.st.SoftwareHosts(r.Context(), d.ID, "")
			if err != nil {
				s.apiError(w, http.StatusInternalServerError, "internal")
				return
			}
			rows = append(rows, more...)
		}
	}
	s.apiJSON(w, http.StatusOK, map[string]any{"software": apiSoftware(rows)})
}

func (s *Server) apiVulnerabilities(w http.ResponseWriter, r *http.Request) {
	f := s.vulnFilter(r)
	rows, total, err := s.st.ListVulnSummaries(r.Context(), f, store.Page{Number: pageNumber(r), Size: pageSize})
	if err != nil {
		s.apiError(w, http.StatusInternalServerError, "internal")
		return
	}
	type item struct {
		CVE             string     `json:"cve"`
		Title           string     `json:"title"`
		Severity        string     `json:"severity"`
		CVSS            *float64   `json:"cvss"`
		EPSS            *float64   `json:"epss"`
		KnownExploited  bool       `json:"known_exploited"`
		Hosts           int        `json:"hosts"`
		Packages        []string   `json:"packages"`
		FixAvailable    bool       `json:"fix_available"`
		FirstDetectedAt time.Time  `json:"first_detected_at"`
		DueAt           *time.Time `json:"due_at"`
		Overdue         bool       `json:"overdue"`
	}
	out := make([]item, 0, len(rows))
	for _, v := range rows {
		out = append(out, item{CVE: v.CVEID, Title: v.Title, Severity: string(v.Severity), CVSS: v.CVSSScore, EPSS: v.EPSS, KnownExploited: v.KnownExploited,
			Hosts: v.HostCount, Packages: append([]string{}, v.Packages...), FixAvailable: v.FixAvailable, FirstDetectedAt: v.FirstDetectedAt.UTC(),
			DueAt: tsPtr(v.DueAt), Overdue: v.Overdue()})
	}
	s.apiJSON(w, http.StatusOK, map[string]any{"vulnerabilities": out, "pagination": apiPageOf(r, total)})
}

func (s *Server) apiVulnerability(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	v, err := s.st.Vulnerability(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		s.apiError(w, http.StatusNotFound, "not_found")
		return
	}
	if err != nil {
		s.apiError(w, http.StatusInternalServerError, "internal")
		return
	}
	rows, total, err := s.st.ListFindings(r.Context(), store.FindingFilter{CVEID: id, Status: r.URL.Query().Get("status"), SLA: s.sla(r.Context())},
		store.Page{Number: pageNumber(r), Size: pageSize})
	if err != nil {
		s.apiError(w, http.StatusInternalServerError, "internal")
		return
	}
	// A CVE that affects none of the caller's hosts is not disclosed to a
	// group-limited key.
	if total == 0 && r.URL.Query().Get("status") == "" {
		if _, limited := store.ScopeFrom(r.Context()); limited {
			s.apiError(w, http.StatusNotFound, "not_found")
			return
		}
	}
	findings := make([]apiFinding, 0, len(rows))
	for _, f := range rows {
		findings = append(findings, apiFindingView(f))
	}
	s.apiJSON(w, http.StatusOK, map[string]any{"vulnerability": v.Vulnerability, "findings": findings, "pagination": apiPageOf(r, total)})
}

func (s *Server) apiGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := s.st.ListGroups(r.Context())
	if err != nil {
		s.apiError(w, http.StatusInternalServerError, "internal")
		return
	}
	type item struct {
		ID          int64  `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Hosts       int    `json:"hosts"`
	}
	out := make([]item, 0, len(groups))
	for _, g := range groups {
		out = append(out, item{ID: g.ID, Name: g.Name, Description: g.Description, Hosts: g.HostCount})
	}
	s.apiJSON(w, http.StatusOK, map[string]any{"groups": out})
}

func (s *Server) apiJobs(w http.ResponseWriter, r *http.Request) {
	hostID, _ := strconv.ParseInt(r.URL.Query().Get("host"), 10, 64)
	jobs, total, err := s.st.ListJobs(r.Context(), store.JobFilter{HostID: hostID, Status: r.URL.Query().Get("status")}, store.Page{Number: pageNumber(r), Size: pageSize})
	if err != nil {
		s.apiError(w, http.StatusInternalServerError, "internal")
		return
	}
	out := make([]apiJob, 0, len(jobs))
	for _, j := range jobs {
		out = append(out, apiJobView(j))
	}
	s.apiJSON(w, http.StatusOK, map[string]any{"jobs": out, "pagination": apiPageOf(r, total)})
}

func (s *Server) apiJob(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		s.apiError(w, http.StatusNotFound, "not_found")
		return
	}
	j, err := s.st.JobByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		s.apiError(w, http.StatusNotFound, "not_found")
		return
	}
	if err != nil {
		s.apiError(w, http.StatusInternalServerError, "internal")
		return
	}
	s.apiJSON(w, http.StatusOK, apiJobView(j))
}

// apiCreateJob queues a job: {"type": "upgrade_security"} or
// {"type": "upgrade_packages", "packages": ["openssl"]}.
func (s *Server) apiCreateJob(w http.ResponseWriter, r *http.Request) {
	h, ok := s.apiHostOr404(w, r)
	if !ok {
		return
	}
	var req struct {
		Type     string   `json:"type"`
		Packages []string `json:"packages"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		s.apiError(w, http.StatusBadRequest, "bad_request")
		return
	}
	if !slices.Contains([]string{protocol.JobRefresh, protocol.JobUpgradeSecurity, protocol.JobUpgradeAll, protocol.JobUpgradePackages,
		protocol.JobRestartServices, protocol.JobReboot, protocol.JobAgentUpdate, protocol.JobHealthCheck}, req.Type) {
		s.apiError(w, http.StatusBadRequest, "bad_request")
		return
	}
	id, msg := s.queueJob(r, h, req.Type, req.Packages)
	if msg != "" {
		s.apiJSON(w, http.StatusConflict, protocol.ErrorResponse{Code: "job_rejected", Message: msg})
		return
	}
	j, err := s.st.JobByID(r.Context(), id)
	if err != nil {
		s.apiError(w, http.StatusInternalServerError, "internal")
		return
	}
	s.apiJSON(w, http.StatusCreated, apiJobView(j))
}

// ---------- Prometheus ----------

// metrics serves the fleet state in the Prometheus text format. Per-host
// series carry the hostname label; with hundreds of hosts this stays small.
func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	stats, err := s.st.FleetStats(ctx, s.offlineAfter())
	if err != nil {
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	sev, kev, _ := s.st.FleetSeverityCounts(ctx)
	overdue, _, _ := s.st.OverdueCounts(ctx, s.sla(ctx))
	day := timeutil.Now()
	jobs, _ := s.st.JobCounts(ctx, day.Add(-24*time.Hour), day.Add(time.Minute), 0)

	var b strings.Builder
	gauge := func(name, help string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n", name, help, name)
	}
	val := func(name, labels string, v any) {
		if labels != "" {
			labels = "{" + labels + "}"
		}
		fmt.Fprintf(&b, "%s%s %v\n", name, labels, v)
	}
	gauge("netio_patchman_info", "Server version.")
	val("netio_patchman_info", `version="`+promLabel(version.Version)+`"`, 1)
	gauge("netio_patchman_hosts", "Managed hosts by agent state.")
	val("netio_patchman_hosts", `state="online"`, stats.Online)
	val("netio_patchman_hosts", `state="offline"`, stats.Offline)
	val("netio_patchman_hosts", `state="never_seen"`, stats.NeverSeen)
	gauge("netio_patchman_hosts_reboot_required", "Hosts waiting for a reboot.")
	val("netio_patchman_hosts_reboot_required", "", stats.RebootRequired)
	gauge("netio_patchman_vulnerabilities", "Distinct CVEs with active findings by severity.")
	for _, p := range []struct {
		sev vuln.Severity
		n   int
	}{{vuln.SeverityCritical, sev.Critical}, {vuln.SeverityHigh, sev.High}, {vuln.SeverityMedium, sev.Medium}, {vuln.SeverityLow, sev.Low}, {"other", sev.Other}} {
		val("netio_patchman_vulnerabilities", `severity="`+string(p.sev)+`"`, p.n)
	}
	gauge("netio_patchman_vulnerabilities_known_exploited", "Distinct CVEs in CISA KEV with active findings.")
	val("netio_patchman_vulnerabilities_known_exploited", "", kev)
	gauge("netio_patchman_findings_overdue", "Active findings past their remediation deadline (SLA).")
	val("netio_patchman_findings_overdue", "", overdue)
	gauge("netio_patchman_updates_pending", "Pending updates on all hosts.")
	val("netio_patchman_updates_pending", `kind="all"`, stats.PendingUpdates)
	val("netio_patchman_updates_pending", `kind="security"`, stats.SecurityUpdates)
	gauge("netio_patchman_jobs_last_24h", "Jobs created in the last 24 hours by status.")
	for _, st := range []string{protocol.JobQueued, protocol.JobDispatched, protocol.JobSucceeded, protocol.JobPartial, protocol.JobFailed, "timed_out", protocol.JobCancelled, "expired"} {
		val("netio_patchman_jobs_last_24h", `status="`+st+`"`, jobs[st])
	}
	if st := s.o.Scanner.Status(); !st.LastRunAt.IsZero() {
		gauge("netio_patchman_scan_last_run_timestamp_seconds", "Time of the last vulnerability scan.")
		val("netio_patchman_scan_last_run_timestamp_seconds", "", st.LastRunAt.Unix())
	}
	if fs, err := s.st.FleetScore(ctx); err == nil && fs.Hosts > 0 {
		gauge("netio_patchman_security_score", "Security score of the fleet (0-100, higher is better).")
		val("netio_patchman_security_score", `stat="avg"`, fs.Avg)
		val("netio_patchman_security_score", `stat="min"`, fs.Min)
	}
	if items, err := s.assessEOL(ctx, 0); err == nil {
		sum := eol.Summarize(items)
		gauge("netio_patchman_eol", "Operating systems (hosts) and software installations past or near end of life.")
		val("netio_patchman_eol", `kind="os",status="eol"`, sum.OSEOL)
		val("netio_patchman_eol", `kind="os",status="soon"`, sum.OSSoon)
		val("netio_patchman_eol", `kind="software",status="eol"`, sum.SoftwareEOL)
		val("netio_patchman_eol", `kind="software",status="soon"`, sum.SoftwareSoon)
		val("netio_patchman_eol", `kind="software",status="eol_distro_maintained"`, sum.SoftwareEOLDistro)
	}
	if _, total, err := s.st.ListDrift(ctx, store.DriftFilter{}, store.Page{Number: 1, Size: 1}); err == nil {
		gauge("netio_patchman_drift_deviations", "Open deviations from server standards.")
		val("netio_patchman_drift_deviations", "", total)
	}
	if _, limited := store.ScopeFrom(ctx); !limited {
		if counts, err := s.st.RolloutStatusCounts(ctx); err == nil {
			gauge("netio_patchman_rollouts", "Rolling updates by status.")
			for _, st := range []string{store.RolloutRunning, store.RolloutPaused, store.RolloutFailed} {
				val("netio_patchman_rollouts", `status="`+st+`"`, counts[st])
			}
		}
		if chans, err := s.st.ListChannels(ctx); err == nil {
			gauge("netio_patchman_channel_failing", "1 if the last delivery to a notification channel failed.")
			for _, c := range chans {
				if c.Enabled {
					val("netio_patchman_channel_failing", `channel="`+promLabel(c.Name)+`",type="`+c.Type+`"`, boolNum(c.Failing()))
				}
			}
		}
	}

	// Per-host series.
	type hostSeries struct {
		h      store.Host
		online bool
	}
	var hosts []hostSeries
	for pg := 1; ; pg++ {
		list, _, err := s.st.ListHosts(ctx, store.HostFilter{OfflineAfter: s.offlineAfter()}, store.Page{Number: pg, Size: 500})
		if err != nil {
			break
		}
		for _, h := range list {
			hosts = append(hosts, hostSeries{h, h.Online(s.offlineAfter())})
		}
		if len(list) < 500 {
			break
		}
	}
	gauge("netio_patchman_host_up", "1 if the host's agent checked in recently.")
	for _, h := range hosts {
		val("netio_patchman_host_up", hostLabels(h.h), boolNum(h.online))
	}
	gauge("netio_patchman_host_vulnerabilities", "Distinct CVEs with active findings on a host by severity.")
	for _, h := range hosts {
		v := h.h.Vulns
		for _, p := range []struct {
			sev string
			n   int
		}{{"critical", v.Critical}, {"high", v.High}, {"medium", v.Medium}, {"low", v.Low}, {"other", v.Other}} {
			val("netio_patchman_host_vulnerabilities", hostLabels(h.h)+`,severity="`+p.sev+`"`, p.n)
		}
	}
	gauge("netio_patchman_host_updates_pending", "Pending updates on a host.")
	for _, h := range hosts {
		val("netio_patchman_host_updates_pending", hostLabels(h.h)+`,kind="all"`, h.h.UpdateCount)
		val("netio_patchman_host_updates_pending", hostLabels(h.h)+`,kind="security"`, h.h.SecurityUpdateCount)
	}
	gauge("netio_patchman_host_reboot_required", "1 if the host waits for a reboot.")
	for _, h := range hosts {
		val("netio_patchman_host_reboot_required", hostLabels(h.h), boolNum(h.h.RebootRequired))
	}
	if failing, err := s.st.FailingHealth(ctx); err == nil {
		gauge("netio_patchman_host_health_failing", "Failing monitored health checks and built-in limits on a host.")
		for _, h := range hosts {
			val("netio_patchman_host_health_failing", hostLabels(h.h), failing[h.h.ID])
		}
	}
	// Resource usage from monitoring rounds; stale snapshots (an agent that
	// stopped reporting) are left out.
	cfg, _ := settings.Load(ctx, s.st)
	fresh := max(3*time.Duration(cfg.HealthMonitor)*time.Minute, 15*time.Minute)
	if res, err := s.st.FleetResources(ctx, timeutil.Now().Add(-fresh)); err == nil && len(res) > 0 {
		gauge("netio_patchman_host_memory_used_percent", "Memory in use on a host (total minus available).")
		for _, h := range hosts {
			if r, ok := res[h.h.ID]; ok && r.MemoryPercent() >= 0 {
				val("netio_patchman_host_memory_used_percent", hostLabels(h.h), promFloat(r.MemoryPercent()))
			}
		}
		gauge("netio_patchman_host_load_per_cpu_percent", "1-minute load average per CPU core (Linux).")
		for _, h := range hosts {
			if r, ok := res[h.h.ID]; ok && r.LoadPercent() >= 0 {
				val("netio_patchman_host_load_per_cpu_percent", hostLabels(h.h), promFloat(r.LoadPercent()))
			}
		}
		gauge("netio_patchman_host_disk_used_percent", "File system use on a host (as df shows it).")
		for _, h := range hosts {
			for _, d := range res[h.h.ID].Disks {
				val("netio_patchman_host_disk_used_percent", hostLabels(h.h)+`,path="`+promLabel(d.Path)+`"`, promFloat(d.Percent()))
			}
		}
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write([]byte(b.String()))
}

func promFloat(v float64) string { return strconv.FormatFloat(v, 'f', 1, 64) }

func hostLabels(h store.Host) string {
	return `host="` + promLabel(h.Hostname) + `",os="` + promLabel(h.OSID) + `"`
}

func boolNum(b bool) int {
	if b {
		return 1
	}
	return 0
}

// promLabel escapes a label value (backslash, quote, newline).
func promLabel(v string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(v)
}

// ---------- key management (profile page) ----------

func (s *Server) apiTokenCreate(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	name := strings.TrimSpace(r.PostFormValue("name"))
	if name == "" || len([]rune(name)) > 100 {
		s.renderProfile(w, r, http.StatusBadRequest, s.l.T("validation.required", "field", s.l.T("apitoken.field.name")), nil)
		return
	}
	days, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue("valid_days")))
	if err != nil || days < 0 || days > 3650 {
		s.renderProfile(w, r, http.StatusBadRequest, s.l.T("validation.range", "field", s.l.T("apitoken.field.valid_days"), "min", 0, "max", 3650), nil)
		return
	}
	var expires time.Time
	if days > 0 {
		expires = timeutil.Now().AddDate(0, 0, days)
	}
	// Viewers only get read-only keys.
	readOnly := r.PostFormValue("write") != "1" || !sess.user.CanOperate()
	token := apiTokenPrefix + auth.RandomToken(32)
	_, err = s.st.CreateAPIToken(r.Context(), sess.user.ID, name, auth.HashToken(token), token[:12], readOnly, expires)
	if errors.Is(err, store.ErrLimit) {
		s.renderProfile(w, r, http.StatusBadRequest, s.l.T("apitoken.error.limit", "max", store.MaxAPITokensPerUser), nil)
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "apitoken.create", name, "read_only="+strconv.FormatBool(readOnly))
	s.renderProfile(w, r, http.StatusOK, "", map[string]any{"NewAPIToken": token})
}

func (s *Server) apiTokenRevoke(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	id, ok := pathID(r)
	if !ok {
		s.errorPage(w, r, http.StatusNotFound, "error.not_found")
		return
	}
	t, err := s.st.RevokeAPIToken(r.Context(), id, sess.user.ID)
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, r, http.StatusNotFound, "error.not_found")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "apitoken.revoke", t.Name, "")
	s.redirect(w, r, "/profile#api", "success", s.l.T("apitoken.revoked", "name", t.Name))
}
