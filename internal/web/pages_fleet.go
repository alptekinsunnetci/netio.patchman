package web

import (
	"context"
	"encoding/csv"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"netio.patchman/internal/eol"
	"netio.patchman/internal/protocol"
	"netio.patchman/internal/scanner"
	"netio.patchman/internal/settings"
	"netio.patchman/internal/store"
	"netio.patchman/internal/timeutil"
	"netio.patchman/internal/vuln"
)

// ---------- dashboard ----------

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	stats, err := s.st.FleetStats(ctx, s.offlineAfter())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	sev, kev, err := s.st.FleetSeverityCounts(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	topVulns, _, _ := s.st.ListVulnSummaries(ctx, store.VulnFilter{}, store.Page{Number: 1, Size: 8})
	topHosts, _ := s.st.TopVulnerableHosts(ctx, 8)
	jobs, _, _ := s.st.ListJobs(ctx, store.JobFilter{}, store.Page{Number: 1, Size: 6})
	sla := s.sla(ctx)
	overdue, overdueCVEs, _ := s.st.OverdueCounts(ctx, sla)
	to := calendarDay(timeutil.Now())
	from := to.AddDate(0, 0, -29)
	// Trends are fleet-wide; group-limited users do not see them.
	var snaps []store.Snapshot
	if !s.limited(r) {
		snaps, err = s.st.Snapshots(ctx, from, to)
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	watched, err := s.st.WatchedSummary(ctx, sessionFrom(r).user.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	eolItems, err := s.assessEOL(ctx, 0)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	fleetScore, err := s.st.FleetScore(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d := s.page(r, s.l.T("dashboard.title"), "dashboard")
	d.Data = map[string]any{
		"Stats": stats, "Sev": sev, "KEV": kev, "TopVulns": topVulns, "TopHosts": topHosts, "Jobs": jobs, "Watched": watched, "EOL": eol.Summarize(eolItems), "FleetScore": fleetScore,
		"SLAEnabled": sla.Enabled(), "Overdue": overdue, "OverdueCVEs": overdueCVEs,
		"Scan": s.o.Scanner.Status(), "Trend": s.buildTrends(snaps, from, to),
	}
	s.render(w, r, http.StatusOK, "dashboard", d)
}

// ---------- servers ----------

func (s *Server) hostFilter(r *http.Request) store.HostFilter {
	q := r.URL.Query()
	group, _ := strconv.ParseInt(q.Get("group"), 10, 64)
	platform := q.Get("platform")
	if platform != "virtual" && platform != "physical" && platform != "unknown" {
		platform = protocol.CleanVirtualization(platform)
	}
	below, _ := strconv.Atoi(q.Get("score_below"))
	sort := q.Get("sort")
	if sort != "score" {
		sort = ""
	}
	return store.HostFilter{Search: q.Get("q"), Status: q.Get("status"), OSID: q.Get("os"), GroupID: max(group, 0), Platform: platform, OfflineAfter: s.offlineAfter(),
		ScoreBelow: min(max(below, 0), 100), Sort: sort}
}

// virtLabel names a platform id in Turkish; unknown ids are shown verbatim.
func (s *Server) virtLabel(id string) string {
	switch id {
	case "":
		return s.l.T("host.virt.unknown")
	case "none", "vmware", "microsoft", "kvm", "qemu", "oracle", "xen", "amazon", "google", "parallels", "bochs", "vm-other",
		"docker", "podman", "lxc", "lxc-libvirt", "openvz", "systemd-nspawn", "wsl":
		return s.l.T("host.virt." + id)
	}
	return id
}

func (s *Server) servers(w http.ResponseWriter, r *http.Request) {
	f := s.hostFilter(r)
	pg := pageNumber(r)
	hosts, total, err := s.st.ListHosts(r.Context(), f, store.Page{Number: pg, Size: pageSize})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	osOpts, _ := s.st.OSOptions(r.Context())
	groups, _ := s.st.ListGroups(r.Context())
	platforms, _ := s.st.PlatformOptions(r.Context())
	d := s.page(r, s.l.T("nav.servers"), "servers")
	d.Data = map[string]any{"Hosts": hosts, "Filter": f, "OSOptions": osOpts, "Groups": groups, "Platforms": platforms,
		"Pager": newPager(r, pg, total), "Query": r.URL.RawQuery}
	s.render(w, r, http.StatusOK, "servers", d)
}

func (s *Server) server(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		s.errorPage(w, r, http.StatusNotFound, "error.not_found")
		return
	}
	ctx := r.Context()
	h, err := s.st.HostByID(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, r, http.StatusNotFound, "error.not_found")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	tab := r.URL.Query().Get("tab")
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	userID := sessionFrom(r).user.ID
	watchedCount, _ := s.st.CountHostWatched(ctx, userID, id)
	data := map[string]any{"Host": h, "Tab": tab, "Online": h.Online(s.offlineAfter()), "Q": q, "WatchedCount": watchedCount,
		"OSEOL":         osEOL(s.hostEOL(ctx, h, nil)),
		"ScanSupported": scanner.TargetFor(h.HostInfo()).Supported()}
	pg := pageNumber(r)
	switch tab {
	case "updates":
		ups, err := s.st.HostUpdates(ctx, id)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		data["UpdateTotal"] = len(ups)
		if q != "" {
			ups = filterUpdates(ups, q)
		}
		data["Updates"] = ups
		patterns := s.effectiveExcludes(ctx, id)
		excluded := map[string]bool{}
		for _, u := range ups {
			excluded[u.Name] = protocol.Excluded(patterns, u.Name)
		}
		data["ExcludePatterns"], data["Excluded"] = patterns, excluded
	case "packages":
		pkgs, total, err := s.st.SearchHostPackages(ctx, id, q, store.Page{Number: pg, Size: pageSize})
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		data["Packages"], data["Pager"], data["Watched"] = pkgs, newPager(r, pg, total), s.watchedSet(ctx, r)
	case "watched":
		rows, missing, err := s.st.HostWatched(ctx, userID, id)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		data["WatchedRows"], data["WatchedMissing"] = rows, missing
	case "health":
		latest, err := s.st.LatestHostHealth(ctx, id)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		hist, total, err := s.st.HostHealth(ctx, id, store.Page{Number: pg, Size: pageSize})
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		checks, err := s.st.ChecksForHost(ctx, id, false)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		data["HealthLatest"], data["HealthHistory"], data["Pager"], data["HealthChecks"] = latest, hist, newPager(r, pg, total), checks
	case "software":
		sw, err := s.st.HostSoftware(ctx, id)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		svcs, known, err := s.st.HostServices(ctx, id)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		if r.URL.Query().Get("services") != "all" {
			// Running and failed services by default; stopped ones on request.
			var shown []protocol.Service
			for _, sv := range svcs {
				if sv.State != protocol.ServiceStopped {
					shown = append(shown, sv)
				}
			}
			data["ServicesHidden"] = len(svcs) - len(shown)
			svcs = shown
		}
		events, _, err := s.st.ListSoftwareEvents(ctx, store.SoftwareEventFilter{HostID: id}, store.Page{Number: 1, Size: 10})
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		data["Software"], data["Services"], data["ServicesKnown"], data["SoftwareEvents"] = sw, svcs, known, events
		data["SoftwareEOL"] = softwareEOL(s.hostEOL(ctx, h, sw))
		driftRows, _, err := s.st.ListDrift(ctx, store.DriftFilter{HostID: id}, store.Page{Number: 1, Size: 200})
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		data["Drift"] = driftRows
		data["AllServices"] = r.URL.Query().Get("services") == "all"
	case "jobs":
		jobs, total, err := s.st.ListJobs(ctx, store.JobFilter{HostID: id}, store.Page{Number: pg, Size: pageSize})
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		data["Jobs"], data["Pager"] = jobs, newPager(r, pg, total)
	case "info":
		scheds, err := s.st.SchedulesForHost(ctx, h)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		groups, err := s.st.ListGroups(ctx)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		member := map[int64]bool{}
		for _, g := range h.Groups {
			member[g.ID] = true
		}
		data["Schedules"], data["AllGroups"], data["Member"] = scheds, groups, member
	default:
		data["Tab"] = "vulns"
		status := r.URL.Query().Get("status")
		overdue := r.URL.Query().Get("overdue") == "1"
		rows, total, err := s.st.ListFindings(ctx, store.FindingFilter{HostID: id, Status: status, Search: q, SLA: s.sla(ctx), OverdueOnly: overdue}, store.Page{Number: pg, Size: pageSize})
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		data["Findings"], data["Pager"], data["Status"], data["Overdue"] = rows, newPager(r, pg, total), status, overdue
	}
	d := s.page(r, h.Hostname, "servers")
	d.Data = data
	s.render(w, r, http.StatusOK, "server", d)
}

func (s *Server) hostOr404(w http.ResponseWriter, r *http.Request) (store.Host, bool) {
	id, ok := pathID(r)
	if !ok {
		s.errorPage(w, r, http.StatusNotFound, "error.not_found")
		return store.Host{}, false
	}
	h, err := s.st.HostByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, r, http.StatusNotFound, "error.not_found")
		return h, false
	}
	if err != nil {
		s.serverError(w, r, err)
		return h, false
	}
	return h, true
}

// queueJob validates and queues a job; it returns a Turkish error message.
func (s *Server) queueJob(r *http.Request, h store.Host, typ string, pkgs []string) (int64, string) {
	if !protocol.ValidJobType(typ) {
		return 0, s.l.T("job.error.invalid_type")
	}
	var params map[string]string
	switch typ {
	case protocol.JobAgentUpdate:
		if !h.SelfUpdate {
			return 0, s.l.T("job.error.self_update_disabled", "hostname", h.Hostname)
		}
		if h.AgentVersion == s.o.Release.Version {
			return 0, s.l.T("job.error.agent_current", "hostname", h.Hostname)
		}
		p, ok := s.o.Release.JobParams(h.OSID, h.Arch)
		if !ok {
			return 0, s.l.T("job.error.no_agent_binary", "arch", h.Arch)
		}
		if active, _ := s.st.HasActiveJob(r.Context(), h.ID, typ); active {
			return 0, s.l.T("job.error.already_queued", "hostname", h.Hostname)
		}
		params, pkgs = p, nil
	case protocol.JobRefresh:
		pkgs = nil
	case protocol.JobHealthCheck:
		// Read-only: allowed with remote updates off, needs agent support.
		if !h.Supports(protocol.CapHealth) {
			return 0, s.l.T("job.error.agent_capability", "hostname", h.Hostname)
		}
		checks, err := s.st.ChecksForHost(r.Context(), h.ID, false)
		if err != nil {
			return 0, s.l.T("error.internal.body")
		}
		if len(checks) == 0 {
			return 0, s.l.T("job.error.no_health_checks", "hostname", h.Hostname)
		}
		if active, _ := s.st.HasActiveJob(r.Context(), h.ID, typ); active {
			return 0, s.l.T("job.error.already_queued", "hostname", h.Hostname)
		}
		pkgs = nil
	default:
		if !h.RemoteUpdates {
			return 0, s.l.T("job.error.remote_disabled", "hostname", h.Hostname)
		}
		switch typ {
		case protocol.JobUpgradePackages:
			if len(pkgs) == 0 {
				return 0, s.l.T("job.error.no_packages")
			}
			for _, p := range pkgs {
				if !protocol.ValidPackageName(p) {
					return 0, s.l.T("job.error.invalid_package", "package", p)
				}
			}
		case protocol.JobRestartServices:
			// The services travel in the packages field.
			if len(pkgs) == 0 {
				return 0, s.l.T("job.error.no_services")
			}
			for _, p := range pkgs {
				if !protocol.ValidServiceName(p) {
					return 0, s.l.T("job.error.invalid_service", "service", p)
				}
			}
		case protocol.JobReboot:
			if active, _ := s.st.HasActiveJob(r.Context(), h.ID, typ); active {
				return 0, s.l.T("job.error.reboot_queued", "hostname", h.Hostname)
			}
			pkgs = nil
		default:
			pkgs = nil
		}
	}
	sess := sessionFrom(r)
	id, err := s.st.CreateJob(r.Context(), h.ID, typ, pkgs, params, sess.user.ID)
	if err != nil {
		return 0, s.l.T("error.internal.body")
	}
	details := "job_id=" + strconv.FormatInt(id, 10) + " type=" + typ
	if len(pkgs) > 0 {
		details += " packages=" + strings.Join(pkgs, ",")
	}
	if v := params[protocol.ParamVersion]; v != "" {
		details += " version=" + v
	}
	s.audit(r, "job.create", h.Hostname, details)
	return id, ""
}

// formIDs parses repeated numeric form values (e.g. host_ids).
func formIDs(r *http.Request, key string) []int64 {
	_ = r.ParseForm()
	var out []int64
	seen := map[int64]bool{}
	for _, v := range r.PostForm[key] {
		id, err := strconv.ParseInt(v, 10, 64)
		if err == nil && id > 0 && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// queueOnHosts queues the same job on several hosts and reports a summary.
// Hosts where the job cannot run (e.g. remote updates disabled) are skipped.
func (s *Server) queueOnHosts(r *http.Request, ids []int64, typ string, pkgsFor func(store.Host) []string) (queued int, skipped []string) {
	for _, id := range ids {
		h, err := s.st.HostByID(r.Context(), id)
		if err != nil {
			continue
		}
		var pkgs []string
		if pkgsFor != nil {
			pkgs = pkgsFor(h)
		}
		if _, msg := s.queueJob(r, h, typ, pkgs); msg != "" {
			skipped = append(skipped, h.Hostname)
			continue
		}
		queued++
	}
	return
}

func (s *Server) bulkResult(w http.ResponseWriter, r *http.Request, back string, queued int, skipped []string) {
	if queued == 0 {
		s.redirect(w, r, back, "error", s.l.T("jobs.none_queued"))
		return
	}
	msg := s.l.T("jobs.queued_bulk", "count", queued, "skipped", len(skipped))
	if len(skipped) > 0 {
		names := skipped
		if len(names) > 10 {
			names = append(names[:10:10], "…")
		}
		msg += " " + s.l.T("jobs.skipped_hosts", "hosts", strings.Join(names, ", "))
	}
	s.redirect(w, r, back, "success", msg)
}

// serversBulkJob queues a job on the servers selected in the inventory list.
func (s *Server) serversBulkJob(w http.ResponseWriter, r *http.Request) {
	ids := formIDs(r, "host_ids")
	typ := r.PostFormValue("type")
	back := "/servers"
	if q := r.PostFormValue("back_query"); q != "" {
		back += "?" + q
	}
	if len(ids) == 0 {
		s.redirect(w, r, back, "error", s.l.T("servers.bulk.none_selected"))
		return
	}
	switch typ {
	case protocol.JobRefresh, protocol.JobUpgradeSecurity, protocol.JobUpgradeAll, protocol.JobAgentUpdate:
	default:
		s.redirect(w, r, back, "error", s.l.T("job.error.invalid_type"))
		return
	}
	queued, skipped := s.queueOnHosts(r, ids, typ, nil)
	s.bulkResult(w, r, "/jobs", queued, skipped)
}

// agentsUpdateAll queues an agent update on every outdated agent.
func (s *Server) agentsUpdateAll(w http.ResponseWriter, r *http.Request) {
	var ids []int64
	for pg := 1; ; pg++ {
		hosts, _, err := s.st.ListHosts(r.Context(), store.HostFilter{OfflineAfter: s.offlineAfter()}, store.Page{Number: pg, Size: 500})
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		for _, h := range hosts {
			if h.SelfUpdate && s.o.Release.Outdated(h.AgentVersion, h.OSID, h.Arch) {
				ids = append(ids, h.ID)
			}
		}
		if len(hosts) < 500 {
			break
		}
	}
	if len(ids) == 0 {
		s.redirect(w, r, "/agents", "info", s.l.T("agents.update.none_outdated"))
		return
	}
	queued, skipped := s.queueOnHosts(r, ids, protocol.JobAgentUpdate, nil)
	s.bulkResult(w, r, "/agents", queued, skipped)
}

func (s *Server) serverCreateJob(w http.ResponseWriter, r *http.Request) {
	h, ok := s.hostOr404(w, r)
	if !ok {
		return
	}
	_ = r.ParseForm()
	back := "/servers/" + strconv.FormatInt(h.ID, 10)
	if t := r.PostFormValue("back_tab"); t != "" {
		back += "?tab=" + t
	}
	typ := r.PostFormValue("type")
	// With previews required, an update started here first shows its plan;
	// the update runs after the plan is approved on the job page.
	if cfg, _ := settings.Load(r.Context(), s.st); cfg.RequirePreview && isPackageJobType(typ) && h.Supports(protocol.CapPreview) && h.RemoteUpdates {
		id, msg := s.queuePreview(r, h, typ, r.PostForm["packages"])
		if msg != "" {
			s.redirect(w, r, back, "error", msg)
			return
		}
		s.redirect(w, r, "/jobs/"+strconv.FormatInt(id, 10), "success", s.l.T("preview.queued_required"))
		return
	}
	id, msg := s.queueJob(r, h, typ, r.PostForm["packages"])
	if msg != "" {
		s.redirect(w, r, back, "error", msg)
		return
	}
	s.redirect(w, r, "/jobs/"+strconv.FormatInt(id, 10), "success", s.l.T("job.queued"))
}

func (s *Server) serverRescan(w http.ResponseWriter, r *http.Request) {
	h, ok := s.hostOr404(w, r)
	if !ok {
		return
	}
	if err := s.st.MarkForScan(r.Context(), h.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.o.Scanner.Trigger()
	s.audit(r, "host.rescan", h.Hostname, "")
	s.redirect(w, r, "/servers/"+strconv.FormatInt(h.ID, 10), "success", s.l.T("server.rescan_queued"))
}

func (s *Server) serverNotes(w http.ResponseWriter, r *http.Request) {
	h, ok := s.hostOr404(w, r)
	if !ok {
		return
	}
	if err := s.st.SetHostNotes(r.Context(), h.ID, strings.TrimSpace(r.PostFormValue("notes"))); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "host.notes", h.Hostname, "")
	s.redirect(w, r, "/servers/"+strconv.FormatInt(h.ID, 10)+"?tab=info", "success", s.l.T("common.saved"))
}

func (s *Server) serverDelete(w http.ResponseWriter, r *http.Request) {
	h, ok := s.hostOr404(w, r)
	if !ok {
		return
	}
	if r.PostFormValue("confirm") != h.Hostname {
		s.redirect(w, r, "/servers/"+strconv.FormatInt(h.ID, 10)+"?tab=info", "error", s.l.T("server.delete_confirm_mismatch"))
		return
	}
	if err := s.st.DeleteHost(r.Context(), h.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "host.delete", h.Hostname, "host_id="+strconv.FormatInt(h.ID, 10))
	s.redirect(w, r, "/servers", "success", s.l.T("server.deleted", "hostname", h.Hostname))
}

// ---------- vulnerabilities ----------

func (s *Server) vulnFilter(r *http.Request) store.VulnFilter {
	q := r.URL.Query()
	f := store.VulnFilter{Search: q.Get("q"), Severity: q.Get("severity"), Status: q.Get("status"),
		KEVOnly: q.Get("kev") == "1", FixOnly: q.Get("fix") == "1", SLA: s.sla(r.Context()), OverdueOnly: q.Get("overdue") == "1"}
	if q.Get("sort") == "epss" {
		f.Sort = "epss"
	}
	return f
}

// sla returns the remediation targets from the settings.
func (s *Server) sla(ctx context.Context) store.SLA {
	cfg, _ := settings.Load(ctx, s.st)
	return cfg.SLA()
}

func (s *Server) vulnerabilities(w http.ResponseWriter, r *http.Request) {
	f := s.vulnFilter(r)
	pg := pageNumber(r)
	rows, total, err := s.st.ListVulnSummaries(r.Context(), f, store.Page{Number: pg, Size: pageSize})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	sev, kev, _ := s.st.FleetSeverityCounts(r.Context())
	d := s.page(r, s.l.T("nav.vulnerabilities"), "vulnerabilities")
	d.Data = map[string]any{"Rows": rows, "Filter": f, "Pager": newPager(r, pg, total), "Sev": sev, "KEV": kev, "Query": r.URL.RawQuery}
	s.render(w, r, http.StatusOK, "vulnerabilities", d)
}

func (s *Server) vulnerability(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx := r.Context()
	v, err := s.st.Vulnerability(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, r, http.StatusNotFound, "error.not_found")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	status := r.URL.Query().Get("status")
	pg := pageNumber(r)
	rows, total, err := s.st.ListFindings(ctx, store.FindingFilter{CVEID: id, Status: status, SLA: s.sla(ctx)}, store.Page{Number: pg, Size: pageSize})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	// Remediation guidance from distinct (package, fixed version) pairs.
	type fix struct{ Package, Version string }
	seen := map[fix]bool{}
	var fixes []fix
	noFix := false
	for _, f := range rows {
		if f.FixedVersion == "" {
			noFix = true
			continue
		}
		k := fix{f.PackageName, f.FixedVersion}
		if !seen[k] {
			seen[k] = true
			fixes = append(fixes, k)
		}
	}
	sort.Slice(fixes, func(i, j int) bool { return fixes[i].Package+fixes[i].Version < fixes[j].Package+fixes[j].Version })
	var remediation []string
	for _, f := range fixes {
		switch {
		case scanner.KBNumber(f.Package) != "" && f.Version != f.Package:
			// Windows: the KB and the OS build that contains the fix.
			remediation = append(remediation, s.l.T("remediation.windows_update", "package", f.Package, "version", f.Version))
		case scanner.KBNumber(f.Package) != "":
			remediation = append(remediation, s.l.T("remediation.windows_update_kb", "package", f.Package))
		default:
			remediation = append(remediation, s.l.T("remediation.update", "package", f.Package, "version", f.Version))
		}
	}
	if noFix || len(fixes) == 0 {
		remediation = append(remediation, s.l.T("remediation.no_fix"))
	}
	d := s.page(r, v.CVEID, "vulnerabilities")
	d.Data = map[string]any{"V": v, "Findings": rows, "Pager": newPager(r, pg, total), "Status": status,
		"Remediation": remediation, "HasFix": len(fixes) > 0, "Statuses": manualStatuses, "RiskOptions": s.riskOptions(r)}
	s.render(w, r, http.StatusOK, "vulnerability", d)
}

var manualStatuses = []string{store.StatusOpen, store.StatusInProgress, store.StatusAcceptedRisk, store.StatusFalsePositive}

func (s *Server) vulnerabilityStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	status := r.PostFormValue("status")
	note := strings.TrimSpace(r.PostFormValue("note"))
	back := "/vulnerabilities/" + id
	if !store.ValidManualStatus(status) {
		s.redirect(w, r, back, "error", s.l.T("vuln.error.invalid_status"))
		return
	}
	if (status == store.StatusAcceptedRisk || status == store.StatusFalsePositive) && note == "" {
		s.redirect(w, r, back, "error", s.l.T("vuln.error.note_required"))
		return
	}
	var expires time.Time
	if status == store.StatusAcceptedRisk {
		days, msg := s.riskDays(r)
		if msg != "" {
			s.redirect(w, r, back, "error", msg)
			return
		}
		if days > 0 {
			// The risk reopens at the end of that day in the display time zone.
			y, m, dd := timeutil.Now().In(s.f.Location()).AddDate(0, 0, days).Date()
			expires = time.Date(y, m, dd, 23, 59, 59, 0, s.f.Location())
		}
	}
	n, err := s.st.SetCVEStatus(r.Context(), id, status, note, sessionFrom(r).user.ID, expires)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	details := "status=" + status + " count=" + strconv.FormatInt(n, 10) + " note=" + note
	if !expires.IsZero() {
		details += " expires=" + expires.UTC().Format(time.RFC3339)
	}
	s.audit(r, "finding.status", id, details)
	msg := s.l.T("vuln.status_updated", "count", n, "status", s.l.T("status."+status))
	if !expires.IsZero() {
		msg += " " + s.l.T("vuln.risk_expires", "date", s.f.Date(expires))
	}
	s.redirect(w, r, back, "success", msg)
}

// riskDayOptions are the terms offered for accepting a risk (0 = no expiry).
var riskDayOptions = []int{30, 90, 180, 365, 0}

// riskOptions returns the terms allowed by the maximum term setting.
func (s *Server) riskOptions(r *http.Request) []int {
	cfg, _ := settings.Load(r.Context(), s.st)
	var out []int
	for _, d := range riskDayOptions {
		if cfg.RiskMaxDays == 0 || (d > 0 && d < cfg.RiskMaxDays) {
			out = append(out, d)
		}
	}
	if cfg.RiskMaxDays > 0 {
		out = append(out, cfg.RiskMaxDays) // the longest allowed term itself
	}
	return out
}

// riskDays reads the accepted-risk term and checks it against the setting.
func (s *Server) riskDays(r *http.Request) (int, string) {
	days, err := strconv.Atoi(r.PostFormValue("risk_days"))
	for _, d := range s.riskOptions(r) {
		if err == nil && d == days {
			return days, ""
		}
	}
	cfg, _ := settings.Load(r.Context(), s.st)
	return 0, s.l.T("vuln.error.risk_days", "max", cfg.RiskMaxDays)
}

// vulnerabilityRemediate queues package upgrades on hosts affected by a CVE.
func (s *Server) vulnerabilityRemediate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx := r.Context()
	rows, _, err := s.st.ListFindings(ctx, store.FindingFilter{CVEID: id}, store.Page{Number: 1, Size: 500})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	byHost := map[int64]map[string]bool{}
	for _, f := range rows {
		if f.FixedVersion == "" {
			continue
		}
		names, err := s.st.UpgradablePackagesFor(ctx, f.HostID, f.PackageName)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		for _, n := range names {
			if byHost[f.HostID] == nil {
				byHost[f.HostID] = map[string]bool{}
			}
			byHost[f.HostID][n] = true
		}
	}
	queued, skipped := s.queueForHosts(r, byHost)
	back := "/vulnerabilities/" + id
	if queued == 0 {
		s.redirect(w, r, back, "error", s.l.T("vuln.remediate_none"))
		return
	}
	s.redirect(w, r, back, "success", s.l.T("jobs.queued_bulk", "count", queued, "skipped", skipped))
}

func (s *Server) queueForHosts(r *http.Request, byHost map[int64]map[string]bool) (queued, skipped int) {
	for hostID, set := range byHost {
		h, err := s.st.HostByID(r.Context(), hostID)
		if err != nil {
			skipped++
			continue
		}
		pkgs := make([]string, 0, len(set))
		for n := range set {
			pkgs = append(pkgs, n)
		}
		sort.Strings(pkgs)
		if _, msg := s.queueJob(r, h, protocol.JobUpgradePackages, pkgs); msg != "" {
			skipped++
			continue
		}
		queued++
	}
	return
}

// ---------- packages ----------

func (s *Server) packages(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	tab := q.Get("tab")
	pg := pageNumber(r)
	data := map[string]any{"Tab": tab, "Q": q.Get("q"), "Security": q.Get("security") == "1", "Watched": s.watchedSet(r.Context(), r)}
	if tab == "installed" {
		rows, total, err := s.st.SearchInstalled(r.Context(), q.Get("q"), store.Page{Number: pg, Size: pageSize})
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		data["Installed"], data["Pager"] = rows, newPager(r, pg, total)
	} else {
		data["Tab"] = "updates"
		rows, total, err := s.st.ListFleetUpdates(r.Context(), q.Get("q"), q.Get("security") == "1", store.Page{Number: pg, Size: pageSize})
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		stats, _ := s.st.FleetStats(r.Context(), s.offlineAfter())
		data["Updates"], data["Pager"], data["Stats"] = rows, newPager(r, pg, total), stats
	}
	d := s.page(r, s.l.T("nav.packages"), "packages")
	d.Data = data
	s.render(w, r, http.StatusOK, "packages", d)
}

func (s *Server) packageDetail(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !validPackageView(name) {
		s.errorPage(w, r, http.StatusNotFound, "error.not_found")
		return
	}
	withUpdate, err := s.st.HostsWithUpdate(r.Context(), name)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	installed, err := s.st.HostsWithPackage(r.Context(), name)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d := s.page(r, name, "packages")
	d.Data = map[string]any{"Name": name, "WithUpdate": withUpdate, "Installed": installed, "Watching": s.watchedSet(r.Context(), r)[name]}
	s.render(w, r, http.StatusOK, "package", d)
}

func (s *Server) packageUpgrade(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	back := "/packages/" + url.PathEscape(name)
	if !protocol.ValidPackageName(name) {
		s.redirect(w, r, "/packages", "error", s.l.T("job.error.invalid_package", "package", name))
		return
	}
	hosts, err := s.st.HostsWithUpdate(r.Context(), name)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	// Optional selection; without it the package is upgraded on every host
	// that has the update pending.
	selected := map[int64]bool{}
	for _, id := range formIDs(r, "host_ids") {
		selected[id] = true
	}
	if r.PostFormValue("selection") == "1" && len(selected) == 0 {
		s.redirect(w, r, back, "error", s.l.T("servers.bulk.none_selected"))
		return
	}
	byHost := map[int64]map[string]bool{}
	for _, h := range hosts {
		if len(selected) == 0 || selected[h.ID] {
			byHost[h.ID] = map[string]bool{name: true}
		}
	}
	queued, skipped := s.queueForHosts(r, byHost)
	if queued == 0 {
		s.redirect(w, r, back, "error", s.l.T("jobs.none_queued"))
		return
	}
	s.redirect(w, r, back, "success", s.l.T("jobs.queued_bulk", "count", queued, "skipped", skipped))
}

func (s *Server) packagesSecurityAll(w http.ResponseWriter, r *http.Request) {
	hosts, err := s.st.HostsWithSecurityUpdates(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	queued, skipped := 0, 0
	for _, ref := range hosts {
		h, err := s.st.HostByID(r.Context(), ref.ID)
		if err != nil {
			skipped++
			continue
		}
		if _, msg := s.queueJob(r, h, protocol.JobUpgradeSecurity, nil); msg != "" {
			skipped++
			continue
		}
		queued++
	}
	if queued == 0 {
		s.redirect(w, r, "/packages", "error", s.l.T("jobs.none_queued"))
		return
	}
	s.redirect(w, r, "/jobs", "success", s.l.T("jobs.queued_bulk", "count", queued, "skipped", skipped))
}

// ---------- jobs ----------

func (s *Server) jobs(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	pg := pageNumber(r)
	jobs, total, err := s.st.ListJobs(r.Context(), store.JobFilter{Status: status}, store.Page{Number: pg, Size: pageSize})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d := s.page(r, s.l.T("nav.jobs"), "jobs")
	d.Data = map[string]any{"Jobs": jobs, "Status": status, "Pager": newPager(r, pg, total),
		"Statuses": []string{protocol.JobQueued, protocol.JobDispatched, protocol.JobSucceeded, protocol.JobPartial, protocol.JobFailed, store.JobTimedOut, store.JobExpired, protocol.JobCancelled}}
	s.render(w, r, http.StatusOK, "jobs", d)
}

func (s *Server) job(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		s.errorPage(w, r, http.StatusNotFound, "error.not_found")
		return
	}
	j, err := s.st.JobByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, r, http.StatusNotFound, "error.not_found")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d := s.page(r, s.l.T("job.title", "id", j.ID), "jobs")
	_, _, canRetry := retryJob(j)
	outcome, failedChecks := j.Data.HealthOutcome()
	d.Data = map[string]any{"Job": j, "CanRetry": canRetry, "HealthRows": healthRows(j.Data.Health), "HealthOutcome": outcome, "HealthFailed": failedChecks}
	if j.Type == protocol.JobPreview {
		if h, err := s.st.HostByID(r.Context(), j.HostID); err == nil {
			ok, why := s.approvable(j, h)
			d.Data.(map[string]any)["CanApprove"], d.Data.(map[string]any)["ApproveBlocked"] = ok, why
			d.Data.(map[string]any)["PreviewStale"] = !j.FinishedAt.IsZero() && time.Since(j.FinishedAt) > previewStale
		}
	}
	if pid := j.Params[ParamPreviewJob]; pid != "" {
		d.Data.(map[string]any)["PreviewJob"] = pid
	}
	if changes, source := s.jobChanges(r.Context(), j); len(changes) > 0 {
		dm := d.Data.(map[string]any)
		dm["Changes"], dm["ChangesSource"] = changes, source
		if h, err := s.st.HostByID(r.Context(), j.HostID); err == nil {
			dm["RollbackBlocked"] = s.rollbackBlocked(h)
		}
	}
	if j.Type == protocol.JobRollback {
		dm := d.Data.(map[string]any)
		dm["RollbackOf"], dm["RollbackCheck"] = j.Params[store.ParamRollbackOf], j.Params[store.ParamRollbackCheck]
		if j.Params[protocol.ParamRollbackMode] == protocol.RollbackCheck {
			applied, _ := s.st.JobFromParam(r.Context(), store.ParamRollbackCheck, strconv.FormatInt(j.ID, 10))
			dm["RollbackApplied"] = applied
			if h, err := s.st.HostByID(r.Context(), j.HostID); err == nil {
				dm["RollbackBlocked"] = s.rollbackBlocked(h)
			}
		}
	}
	s.render(w, r, http.StatusOK, "job", d)
}

func (s *Server) jobCancel(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		s.errorPage(w, r, http.StatusNotFound, "error.not_found")
		return
	}
	back := "/jobs/" + strconv.FormatInt(id, 10)
	cancelled, err := s.st.CancelJob(r.Context(), id)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if !cancelled {
		s.redirect(w, r, back, "error", s.l.T("job.cancel_too_late"))
		return
	}
	s.audit(r, "job.cancel", strconv.FormatInt(id, 10), "")
	s.redirect(w, r, back, "success", s.l.T("job.cancelled"))
}

// retryJob returns the job type and targets for retrying a finished job: the
// packages (or services) it left behind, otherwise the same job again.
func retryJob(j store.Job) (typ string, pkgs []string, ok bool) {
	if j.Active() || j.Status == protocol.JobSucceeded || j.Type == protocol.JobAgentUpdate || j.Type == protocol.JobRefresh {
		return "", nil, false
	}
	if len(j.Remaining) > 0 {
		switch j.Type {
		case protocol.JobUpgradeAll, protocol.JobUpgradeSecurity, protocol.JobUpgradePackages:
			return protocol.JobUpgradePackages, j.Remaining, true
		case protocol.JobRestartServices:
			return protocol.JobRestartServices, j.Remaining, true
		}
	}
	return j.Type, j.Packages, true
}

func (s *Server) jobRetry(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		s.errorPage(w, r, http.StatusNotFound, "error.not_found")
		return
	}
	back := "/jobs/" + strconv.FormatInt(id, 10)
	j, err := s.st.JobByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, r, http.StatusNotFound, "error.not_found")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	typ, pkgs, ok := retryJob(j)
	if !ok {
		s.redirect(w, r, back, "error", s.l.T("job.retry_not_possible"))
		return
	}
	h, err := s.st.HostByID(r.Context(), j.HostID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	newID, msg := s.queueJob(r, h, typ, pkgs)
	if msg != "" {
		s.redirect(w, r, back, "error", msg)
		return
	}
	s.redirect(w, r, "/jobs/"+strconv.FormatInt(newID, 10), "success", s.l.T("job.retried", "id", j.ID))
}

// ---------- CSV exports ----------

// csvWriter writes UTF-8 with BOM and the locale's separator (';' for
// Turkish Excel, ',' for English). Cells that a spreadsheet would
// evaluate as formulas are prefixed with an apostrophe.
func (s *Server) csvWriter(w http.ResponseWriter, filename string) *safeCSV {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	_, _ = w.Write([]byte("\xEF\xBB\xBF"))
	cw := csv.NewWriter(w)
	cw.Comma = ';'
	if sep := []rune(s.l.T("csv.separator")); len(sep) == 1 {
		cw.Comma = sep[0] // Turkish Excel expects ';', English ','
	}
	return &safeCSV{cw}
}

type safeCSV struct{ *csv.Writer }

func (c *safeCSV) Write(rec []string) error {
	for i, v := range rec {
		if v != "" && strings.ContainsRune("=+@\t\r", rune(v[0])) {
			rec[i] = "'" + v
		}
	}
	return c.Writer.Write(rec)
}

func (s *Server) serversCSV(w http.ResponseWriter, r *http.Request) {
	cw := s.csvWriter(w, s.l.T("csv.file.servers"))
	l := s.l
	_ = cw.Write([]string{l.T("host.field.hostname"), l.T("host.field.os"), l.T("host.field.ip"), l.T("host.field.status"),
		l.T("host.field.last_seen"), l.T("severity.critical"), l.T("severity.high"), l.T("severity.medium"), l.T("severity.low"),
		l.T("host.field.security_updates"), l.T("host.field.updates"), l.T("host.field.reboot_required"), l.T("host.field.agent_version"),
		l.T("host.field.platform"), l.T("host.field.groups")})
	f := s.hostFilter(r)
	for pg := 1; ; pg++ {
		hosts, _, err := s.st.ListHosts(r.Context(), f, store.Page{Number: pg, Size: 500})
		if err != nil || len(hosts) == 0 {
			break
		}
		for _, h := range hosts {
			status := l.T("host.status.offline")
			if h.Online(s.offlineAfter()) {
				status = l.T("host.status.online")
			}
			reboot := l.T("common.no")
			if h.RebootRequired {
				reboot = l.T("common.yes")
			}
			_ = cw.Write([]string{h.Hostname, h.OSName, strings.Join(h.IPAddresses, " "), status, s.f.DateTime(h.LastSeenAt),
				strconv.Itoa(h.Vulns.Critical), strconv.Itoa(h.Vulns.High), strconv.Itoa(h.Vulns.Medium), strconv.Itoa(h.Vulns.Low),
				strconv.Itoa(h.SecurityUpdateCount), strconv.Itoa(h.UpdateCount), reboot, h.AgentVersion, s.virtLabel(h.Virtualization), groupNames(h.Groups)})
		}
		if len(hosts) < 500 {
			break
		}
	}
	cw.Flush()
}

func groupNames(gs []store.GroupRef) string {
	names := make([]string, len(gs))
	for i, g := range gs {
		names[i] = g.Name
	}
	return strings.Join(names, ", ")
}

func (s *Server) vulnerabilitiesCSV(w http.ResponseWriter, r *http.Request) {
	cw := s.csvWriter(w, s.l.T("csv.file.vulnerabilities"))
	l := s.l
	_ = cw.Write([]string{l.T("vuln.field.cve_id"), l.T("vuln.field.title"), l.T("vuln.field.severity"), l.T("vuln.field.cvss_score"),
		l.T("vuln.field.known_exploited"), l.T("host.field.hostname"), l.T("vuln.field.affected_package"), l.T("vuln.field.installed_version"),
		l.T("vuln.field.fixed_version"), l.T("vuln.field.status"), l.T("vuln.field.first_detected"), l.T("vuln.field.last_checked"),
		l.T("vuln.field.epss"), l.T("vuln.field.due")})
	vf := s.vulnFilter(r)
	ff := store.FindingFilter{Severity: vf.Severity, Search: vf.Search, KEVOnly: vf.KEVOnly, Status: vf.Status, SLA: vf.SLA, OverdueOnly: vf.OverdueOnly}
	for pg := 1; ; pg++ {
		rows, _, err := s.st.ListFindings(r.Context(), ff, store.Page{Number: pg, Size: 500})
		if err != nil || len(rows) == 0 {
			break
		}
		for _, f := range rows {
			score := ""
			if f.CVSSScore != nil {
				score = strconv.FormatFloat(*f.CVSSScore, 'f', 1, 64)
			}
			kev := l.T("common.no")
			if f.KnownExploited {
				kev = l.T("common.yes")
			}
			epss, due := "", ""
			if f.EPSS != nil {
				epss = strconv.FormatFloat(*f.EPSS, 'f', 5, 64)
			}
			if !f.DueAt.IsZero() {
				due = s.f.Date(f.DueAt)
			}
			_ = cw.Write([]string{f.CVEID, f.Title, l.T(vuln.Severity(f.Severity).LabelKey()), score, kev, f.Hostname, f.PackageName,
				f.InstalledVersion, f.FixedVersion, l.T("status." + f.Status), s.f.DateTime(f.FirstDetectedAt), s.f.DateTime(f.LastCheckedAt), epss, due})
		}
		if len(rows) < 500 {
			break
		}
	}
	cw.Flush()
}

// validPackageView accepts package names for viewing: besides package
// manager names, Windows program names ("7-Zip 26.01 (x64)"). Jobs still
// require protocol.ValidPackageName.
// filterUpdates keeps the updates whose name, title (Windows) or CVE list
// contains q, ignoring case.
func filterUpdates(ups []protocol.Update, q string) []protocol.Update {
	q = strings.ToLower(q)
	var out []protocol.Update
	for _, u := range ups {
		if strings.Contains(strings.ToLower(u.Name), q) || strings.Contains(strings.ToLower(u.Title), q) ||
			strings.Contains(strings.ToLower(strings.Join(u.CVEs, " ")), q) {
			out = append(out, u)
		}
	}
	return out
}

func validPackageView(name string) bool {
	if name == "" || len(name) > 200 || !utf8.ValidString(name) {
		return false
	}
	return !strings.ContainsFunc(name, unicode.IsControl)
}

// effectiveExcludes returns the package patterns no job updates on a host:
// the fleet-wide list, the host's own and its groups'.
func (s *Server) effectiveExcludes(ctx context.Context, hostID int64) []string {
	cfg, _ := settings.Load(ctx, s.st)
	raw, _ := s.st.HostExcludes(ctx, hostID)
	list, _ := protocol.ParseExcludePatterns(strings.Join(cfg.UpdateExclude, ",") + "," + raw)
	return list
}

func (s *Server) serverExclude(w http.ResponseWriter, r *http.Request) {
	h, ok := s.hostOr404(w, r)
	if !ok {
		return
	}
	back := "/servers/" + strconv.FormatInt(h.ID, 10) + "?tab=info"
	patterns, invalid := protocol.ParseExcludePatterns(r.PostFormValue("exclude"))
	if len(invalid) > 0 {
		s.redirect(w, r, back, "error", s.l.T("exclude.error.invalid", "patterns", strings.Join(invalid, ", ")))
		return
	}
	if err := s.st.SetHostExclude(r.Context(), h.ID, patterns); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "host.exclude", h.Hostname, strings.Join(patterns, ", "))
	s.redirect(w, r, back, "success", s.l.T("common.saved"))
}
