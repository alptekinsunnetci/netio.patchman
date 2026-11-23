// Package notify creates in-app notifications and sends Turkish emails for
// new vulnerabilities, offline agents and failed update jobs.
package notify

import (
	"context"
	"errors"
	"log/slog"
	"net/mail"
	"strconv"
	"strings"
	"sync"

	"netio.patchman/internal/drift"
	"netio.patchman/internal/eol"
	"netio.patchman/internal/i18n"
	"netio.patchman/internal/notify/email"
	"netio.patchman/internal/protocol"
	"netio.patchman/internal/selfupdate"
	"netio.patchman/internal/settings"
	"netio.patchman/internal/software"
	"netio.patchman/internal/store"
	"netio.patchman/internal/timeutil"
	"netio.patchman/internal/vuln"
)

// Sender delivers email messages.
type Sender interface {
	Send(email.Message) error
}

// Notifier dispatches notifications.
type Notifier struct {
	st       *store.Store
	l        i18n.Localizer
	f        timeutil.Formatter
	logger   *slog.Logger
	sys      *settings.Live
	renderer *email.Renderer
	sender   Sender // fixed sender (tests); nil means SMTP from sys

	mu sync.Mutex // serializes alert processing
}

// Options configures a Notifier.
type Options struct {
	Store  *store.Store
	L      i18n.Localizer
	F      timeutil.Formatter
	Logger *slog.Logger
	// System supplies the base URL for links and the SMTP settings; both
	// can change at runtime.
	System   *settings.Live
	Renderer *email.Renderer
	// Sender replaces SMTP delivery (tests).
	Sender Sender
}

// New returns a Notifier.
func New(o Options) *Notifier {
	return &Notifier{st: o.Store, l: o.L, f: o.F, logger: o.Logger, sys: o.System, renderer: o.Renderer, sender: o.Sender}
}

// mailer returns the sender for the current configuration, or nil when
// email cannot be sent.
func (n *Notifier) mailer() (Sender, mail.Address) {
	smtp := n.sys.Get().SMTP
	if n.sender != nil {
		return n.sender, smtp.From
	}
	if !smtp.Enabled() {
		return nil, smtp.From
	}
	return email.SMTPSender{Host: smtp.Host, Port: smtp.Port, Username: smtp.Username, Password: smtp.Password}, smtp.From
}

func (n *Notifier) baseURL() string { return n.sys.Get().BaseURLString() }

// EmailConfigured reports whether SMTP is configured.
func (n *Notifier) EmailConfigured() bool {
	s, _ := n.mailer()
	return s != nil
}

// ErrEmailDisabled is returned when no email can be sent.
var ErrEmailDisabled = errors.New("notify: email not configured")

func (n *Notifier) recipients(ctx context.Context, cfg settings.Values) []mail.Address {
	list := cfg.EmailRecipients
	if len(list) == 0 {
		list, _ = n.st.ActiveAdminEmails(ctx)
	}
	out := make([]mail.Address, 0, len(list))
	for _, a := range list {
		out = append(out, mail.Address{Address: a})
	}
	return out
}

func (n *Notifier) emailEnabled(cfg settings.Values) bool {
	return n.EmailConfigured() && cfg.EmailEnabled
}

func (n *Notifier) send(ctx context.Context, m email.Message) {
	sender, from := n.mailer()
	if sender == nil {
		return
	}
	if from.Address != "" {
		m.From = from
	}
	if err := sender.Send(m); err != nil {
		n.logger.Error(n.l.T("log.email.failed"), slog.String("subject", m.Subject), slog.String("error", err.Error()))
		_ = n.st.AddNotification(ctx, store.LevelWarning, "email_failed", map[string]string{"error": err.Error()}, "/settings")
		return
	}
	n.logger.Info(n.l.T("log.email.sent"), slog.String("subject", m.Subject), slog.Int("recipients", len(m.To)))
}

func levelFor(sev vuln.Severity, kev bool) string {
	if sev == vuln.SeverityCritical || kev {
		return store.LevelCritical
	}
	if sev == vuln.SeverityHigh {
		return store.LevelWarning
	}
	return store.LevelInfo
}

// ProcessAlerts notifies about findings that have not been notified yet.
// CVEs at or above the configured severity (or listed in CISA KEV) produce
// one notification/email each, or a single digest above the threshold.
func (n *Notifier) ProcessAlerts(ctx context.Context) {
	n.mu.Lock()
	defer n.mu.Unlock()
	cfg, err := settings.Load(ctx, n.st)
	if err != nil {
		n.logger.Error(n.l.T("log.notify.failed"), slog.String("error", err.Error()))
		return
	}
	pending, err := n.st.PendingAlerts(ctx)
	if err != nil || len(pending) == 0 {
		return
	}
	var qualifying []store.PendingAlert
	all := make([]string, 0, len(pending))
	for _, a := range pending {
		all = append(all, a.CVEID)
		if a.Severity.Rank() >= cfg.EmailMinSeverity.Rank() || (a.KEV && cfg.EmailKEVAlways) {
			qualifying = append(qualifying, a)
		}
	}
	if len(qualifying) > 0 {
		to := n.recipients(ctx, cfg)
		sendMail := n.emailEnabled(cfg) && len(to) > 0
		if len(qualifying) <= cfg.EmailDigestThreshold {
			for _, a := range qualifying {
				d, err := n.st.AlertDetailsFor(ctx, a.CVEID)
				if err != nil || len(d.Hostnames) == 0 {
					continue
				}
				kevFlag := "0"
				if a.KEV {
					kevFlag = "1"
				}
				_ = n.st.AddNotification(ctx, levelFor(a.Severity, a.KEV), "vuln_detected", map[string]string{
					"cve": a.CVEID, "severity": string(a.Severity), "count": strconv.Itoa(len(d.Hostnames)), "package": d.PackageName, "kev": kevFlag,
				}, "/vulnerabilities/"+a.CVEID)
				if !sendMail {
					continue
				}
				v, err := n.st.Vulnerability(ctx, a.CVEID)
				if err != nil {
					v.Vulnerability = vuln.Vulnerability{CVEID: a.CVEID, Severity: a.Severity}
				}
				m, err := n.renderer.VulnerabilityAlert(email.VulnerabilityAlert{
					Vulnerability: v.Vulnerability, PackageName: d.PackageName, InstalledVersion: d.InstalledVersion,
					FixedVersion: d.FixedVersion, Servers: d.Hostnames, FirstDetectedAt: d.FirstDetectedAt,
					DashboardURL: n.baseURL() + "/vulnerabilities/" + a.CVEID,
				}, to)
				if err == nil {
					n.send(ctx, m)
				}
			}
		} else {
			top := vuln.SeverityUnknown
			kev, kevCount := false, 0
			for _, a := range qualifying {
				if a.Severity.Rank() > top.Rank() {
					top = a.Severity
				}
				if a.KEV {
					kev = true
					kevCount++
				}
			}
			_ = n.st.AddNotification(ctx, levelFor(top, kev), "vulns_detected", map[string]string{
				"count": strconv.Itoa(len(qualifying)), "severity": string(top), "kev": strconv.Itoa(kevCount),
			}, "/vulnerabilities")
			if sendMail {
				items := make([]email.DigestItem, 0, len(qualifying))
				for _, a := range qualifying {
					d, err := n.st.AlertDetailsFor(ctx, a.CVEID)
					if err != nil || len(d.Hostnames) == 0 {
						continue
					}
					it := email.DigestItem{CVEID: a.CVEID, Severity: a.Severity, KnownExploited: a.KEV, PackageName: d.PackageName,
						HostCount: len(d.Hostnames), URL: n.baseURL() + "/vulnerabilities/" + a.CVEID}
					if v, err := n.st.Vulnerability(ctx, a.CVEID); err == nil {
						it.Title, it.CVSS = v.Title, v.CVSSScore
					}
					items = append(items, it)
				}
				if len(items) > 0 {
					if m, err := n.renderer.Digest(items, n.baseURL()+"/vulnerabilities", to); err == nil {
						n.send(ctx, m)
					}
				}
			}
		}
	}
	if err := n.st.MarkNotified(ctx, all); err != nil {
		n.logger.Error(n.l.T("log.notify.failed"), slog.String("error", err.Error()))
	}
}

// CheckOffline notifies about agents that stopped checking in.
func (n *Notifier) CheckOffline(ctx context.Context) {
	cfg, err := settings.Load(ctx, n.st)
	if err != nil {
		return
	}
	hosts, err := n.st.HostsGoneOffline(ctx, cfg.OfflineAfter())
	if err != nil {
		n.logger.Error(n.l.T("log.notify.failed"), slog.String("error", err.Error()))
		return
	}
	for _, h := range hosts {
		link := "/servers/" + strconv.FormatInt(h.ID, 10)
		_ = n.st.AddNotification(ctx, store.LevelWarning, "agent_offline", map[string]string{
			"hostname": h.Hostname, "last_seen": n.f.DateTime(h.LastSeenAt),
		}, link)
		if n.emailEnabled(cfg) && cfg.EmailAgentOffline {
			to := n.recipients(ctx, cfg)
			if len(to) == 0 {
				continue
			}
			m, err := n.renderer.Notice(email.Notice{
				Subject: n.l.T("email.offline.subject", "hostname", h.Hostname),
				Heading: n.l.T("email.offline.heading"),
				Body:    n.l.T("email.offline.body", "hostname", h.Hostname),
				Rows: []email.NoticeRow{
					{Label: n.l.T("host.field.hostname"), Value: h.Hostname, Mono: true},
					{Label: n.l.T("host.field.last_seen"), Value: n.f.Long(h.LastSeenAt)},
					{Label: n.l.T("host.field.os"), Value: h.OSName},
				},
				LinkURL: n.baseURL() + link, LinkText: n.l.T("email.vuln.dashboard_link"),
			}, to)
			if err == nil {
				n.send(ctx, m)
			}
		}
	}
}

// AgentOnline records that an offline agent is back.
func (n *Notifier) AgentOnline(ctx context.Context, hostID int64, hostname string) {
	_ = n.st.AddNotification(ctx, store.LevelInfo, "agent_online", map[string]string{"hostname": hostname}, "/servers/"+strconv.FormatInt(hostID, 10))
}

// AgentEnrolled records a new or re-enrolled agent.
func (n *Notifier) AgentEnrolled(ctx context.Context, hostID int64, hostname string, reenrolled bool) {
	kind := "agent_enrolled"
	if reenrolled {
		kind = "agent_reenrolled"
	}
	_ = n.st.AddNotification(ctx, store.LevelInfo, kind, map[string]string{"hostname": hostname}, "/servers/"+strconv.FormatInt(hostID, 10))
}

// JobFinished records the outcome of an update job.
func (n *Notifier) JobFinished(ctx context.Context, j store.Job) {
	link := "/jobs/" + strconv.FormatInt(j.ID, 10)
	params := map[string]string{"hostname": j.Hostname, "job_type": j.Type, "id": strconv.FormatInt(j.ID, 10)}
	if j.Status == protocol.JobSucceeded {
		switch {
		case j.Type == protocol.JobRollback && j.Params[protocol.ParamRollbackMode] == protocol.RollbackApply:
			_ = n.st.AddNotification(ctx, store.LevelInfo, "rollback_done", params, link)
		case j.Type == protocol.JobPreview || j.Type == protocol.JobHealthCheck || j.Type == protocol.JobRollback:
			// Read-only runs: the result is on the job page.
		case j.Type != "agent_update" && j.ScheduleID == 0:
			// Fleet-wide automatic agent updates and scheduled runs would flood
			// the notification center; only their failures are reported (a
			// schedule run adds one summary notification).
			_ = n.st.AddNotification(ctx, store.LevelInfo, "job_succeeded", params, link)
		}
		return
	}
	// "partial": the job ran but some packages or services were left.
	kind := "job_failed"
	if j.Status == protocol.JobPartial {
		kind = "job_partial"
		params["remaining"] = strings.Join(j.Remaining, ", ")
	}
	_ = n.st.AddNotification(ctx, store.LevelWarning, kind, params, link)
	cfg, err := settings.Load(ctx, n.st)
	if err != nil || !n.emailEnabled(cfg) || !cfg.EmailJobFailed {
		return
	}
	to := n.recipients(ctx, cfg)
	if len(to) == 0 {
		return
	}
	rows := []email.NoticeRow{
		{Label: n.l.T("host.field.hostname"), Value: j.Hostname, Mono: true},
		{Label: n.l.T("job.field.type"), Value: n.l.T("job.type." + j.Type)},
		{Label: n.l.T("job.field.status"), Value: n.l.T("job.status." + j.Status)},
		{Label: n.l.T("job.field.exit_code"), Value: strconv.Itoa(j.ExitCode), Mono: true},
		{Label: n.l.T("job.field.finished_at"), Value: n.f.Long(j.FinishedAt)},
	}
	if len(j.Remaining) > 0 {
		rows = append(rows, email.NoticeRow{Label: n.l.T("job.field.remaining"), Value: strings.Join(j.Remaining, ", "), Mono: true})
	}
	output := j.Output
	if len(output) > 8000 {
		output = "…" + output[len(output)-8000:]
	}
	m, err := n.renderer.Notice(email.Notice{
		Subject: n.l.T("email."+kind+".subject", "hostname", j.Hostname),
		Heading: n.l.T("email." + kind + ".heading"),
		Body:    n.l.T("email."+kind+".body", "hostname", j.Hostname, "job_type", n.l.T("job.type."+j.Type)),
		Rows:    rows,
		Output:  output,
		LinkURL: n.baseURL() + link, LinkText: n.l.T("email.vuln.dashboard_link"),
	}, to)
	if err == nil {
		n.send(ctx, m)
	}
}

// ServerUpdate emails administrators that a newer netio.patchman version was
// published. The in-app notification is stored by internal/updatecheck; this
// is called once per new version.
func (n *Notifier) ServerUpdate(ctx context.Context, current, latest, changesURL string) {
	cfg, err := settings.Load(ctx, n.st)
	if err != nil || !n.emailEnabled(cfg) || !cfg.EmailServerUpdate {
		return
	}
	to := n.recipients(ctx, cfg)
	if len(to) == 0 {
		return
	}
	m, err := n.renderer.Notice(email.Notice{
		Subject: n.l.T("email.server_update.subject", "latest", latest),
		Heading: n.l.T("email.server_update.heading"),
		Body:    n.l.T("email.server_update.body", "latest", latest, "current", current),
		Rows: []email.NoticeRow{
			{Label: n.l.T("system.update.current"), Value: current, Mono: true},
			{Label: n.l.T("system.update.latest"), Value: latest, Mono: true},
			{Label: n.l.T("email.server_update.changes"), Value: changesURL, Mono: true},
		},
		Output:  "git pull\ndocker compose up -d --build",
		LinkURL: n.baseURL() + "/settings/system#updates", LinkText: n.l.T("email.server_update.link"),
	}, to)
	if err == nil {
		n.send(ctx, m)
	}
}

// RisksExpired records accepted risks that reopened because their term ended
// (one notification per CVE) and emails a summary when alerts are enabled.
func (n *Notifier) RisksExpired(ctx context.Context, risks []store.ExpiredRisk) {
	if len(risks) == 0 {
		return
	}
	byCVE := map[string][]string{}
	var order []string
	for _, r := range risks {
		if _, ok := byCVE[r.CVEID]; !ok {
			order = append(order, r.CVEID)
		}
		byCVE[r.CVEID] = append(byCVE[r.CVEID], r.Hostname)
	}
	for _, c := range order {
		_ = n.st.AddNotification(ctx, store.LevelWarning, "risk_expired", map[string]string{
			"cve": c, "count": strconv.Itoa(len(byCVE[c])), "hosts": strings.Join(byCVE[c], ", "),
		}, "/vulnerabilities/"+c)
	}
	cfg, err := settings.Load(ctx, n.st)
	if err != nil || !n.emailEnabled(cfg) {
		return
	}
	to := n.recipients(ctx, cfg)
	if len(to) == 0 {
		return
	}
	rows := make([]email.NoticeRow, 0, len(order))
	for _, c := range order {
		rows = append(rows, email.NoticeRow{Label: c, Value: strings.Join(byCVE[c], ", "), Mono: true})
	}
	m, err := n.renderer.Notice(email.Notice{
		Subject: n.l.T("email.risk_expired.subject", "count", len(order)),
		Heading: n.l.T("email.risk_expired.heading"),
		Body:    n.l.T("email.risk_expired.body", "count", len(order)),
		Rows:    rows,
		LinkURL: n.baseURL() + "/vulnerabilities", LinkText: n.l.T("email.vuln.dashboard_link"),
	}, to)
	if err == nil {
		n.send(ctx, m)
	}
}

// SLAOverdue reports findings that passed their remediation deadline since the
// last check: one summary notification and, when enabled, one email.
func (n *Notifier) SLAOverdue(ctx context.Context) {
	cfg, err := settings.Load(ctx, n.st)
	if err != nil {
		return
	}
	hosts, err := n.st.ClaimOverdue(ctx, cfg.SLA())
	if err != nil || len(hosts) == 0 {
		return
	}
	total := 0
	for _, h := range hosts {
		total += h.Count
	}
	_ = n.st.AddNotification(ctx, store.LevelWarning, "sla_overdue", map[string]string{
		"count": strconv.Itoa(total), "hosts": strconv.Itoa(len(hosts)),
	}, "/vulnerabilities?overdue=1")
	if !cfg.EmailSLAOverdue || !n.emailEnabled(cfg) {
		return
	}
	to := n.recipients(ctx, cfg)
	if len(to) == 0 {
		return
	}
	rows := make([]email.NoticeRow, 0, len(hosts))
	for i, h := range hosts {
		if i == 50 {
			break
		}
		rows = append(rows, email.NoticeRow{Label: h.Hostname, Value: n.l.T("email.sla_overdue.row", "count", h.Count)})
	}
	m, err := n.renderer.Notice(email.Notice{
		Subject: n.l.T("email.sla_overdue.subject", "count", total),
		Heading: n.l.T("email.sla_overdue.heading"),
		Body:    n.l.T("email.sla_overdue.body", "count", total, "hosts", len(hosts)),
		Rows:    rows,
		LinkURL: n.baseURL() + "/vulnerabilities?overdue=1", LinkText: n.l.T("email.vuln.dashboard_link"),
	}, to)
	if err == nil {
		n.send(ctx, m)
	}
}

// SelfUpdateFinished records the end of an update started from the panel
// (one notification per update, matched by its finish time).
func (n *Notifier) SelfUpdateFinished(ctx context.Context, su *selfupdate.Manager) {
	if su == nil {
		return
	}
	st, ok := su.Status()
	if !ok || st.Running() || st.FinishedAt.IsZero() {
		return
	}
	raw, err := n.st.Settings(ctx)
	if err != nil {
		return
	}
	stamp := strconv.FormatInt(st.FinishedAt.Unix(), 10)
	if raw[keySelfUpdateNotified] == stamp {
		return
	}
	if err := n.st.SaveSettings(ctx, map[string]string{keySelfUpdateNotified: stamp}); err != nil {
		return
	}
	if st.State == selfupdate.StateSucceeded {
		_ = n.st.AddNotification(ctx, store.LevelInfo, "self_update_succeeded", map[string]string{"from": st.From, "to": st.To}, "/settings/system#self-update")
		return
	}
	_ = n.st.AddNotification(ctx, store.LevelCritical, "self_update_failed", map[string]string{"step": st.Step}, "/settings/system#self-update")
}

// keySelfUpdateNotified stores the finish time of the last reported update.
const keySelfUpdateNotified = "selfupdate.notified_at"

// BackupFailed records a failed database backup and emails the recipients
// when email notifications are on.
func (n *Notifier) BackupFailed(ctx context.Context, err error) {
	_ = n.st.AddNotification(ctx, store.LevelCritical, "backup_failed", map[string]string{"error": err.Error()}, "/settings#backup")
	cfg, lerr := settings.Load(ctx, n.st)
	if lerr != nil || !n.emailEnabled(cfg) {
		return
	}
	to := n.recipients(ctx, cfg)
	if len(to) == 0 {
		return
	}
	m, merr := n.renderer.Notice(email.Notice{
		Subject: n.l.T("email.backup_failed.subject"),
		Heading: n.l.T("email.backup_failed.heading"),
		Body:    n.l.T("email.backup_failed.body"),
		Rows:    []email.NoticeRow{{Label: n.l.T("backup.error"), Value: err.Error(), Mono: true}},
		LinkURL: n.baseURL() + "/settings#backup", LinkText: n.l.T("email.vuln.dashboard_link"),
	}, to)
	if merr == nil {
		n.send(ctx, m)
	}
}

// SendTest sends a test email to the given address synchronously.
func (n *Notifier) SendTest(ctx context.Context, to string) error {
	sender, from := n.mailer()
	if sender == nil {
		return ErrEmailDisabled
	}
	m, err := n.renderer.Notice(email.Notice{
		Subject: n.l.T("email.test.subject"),
		Heading: n.l.T("email.test.heading"),
		Body:    n.l.T("email.test.body"),
		Rows:    []email.NoticeRow{{Label: n.l.T("email.test.sent_at"), Value: n.f.Long(timeutil.Now())}},
		LinkURL: n.baseURL(), LinkText: n.l.T("email.vuln.dashboard_link"),
	}, []mail.Address{{Address: to}})
	if err != nil {
		return err
	}
	if from.Address != "" {
		m.From = from
	}
	return sender.Send(m)
}

// SoftwareChanged records software installed, removed or changed on a host
// (one notification per report). Product names are verbatim.
func (n *Notifier) SoftwareChanged(ctx context.Context, hostID int64, hostname string, events []store.SoftwareEvent) {
	cfg, err := settings.Load(ctx, n.st)
	if err != nil || !cfg.SoftwareNotify || len(events) == 0 {
		return
	}
	var added, removed, changed []string
	for _, e := range events {
		name := e.Software
		if d, ok := software.ByID(e.Software); ok {
			name = d.Name
		}
		if e.Cycle != "" {
			name += " " + e.Cycle
		}
		switch e.Event {
		case store.SoftwareInstalled:
			added = append(added, name)
		case store.SoftwareRemoved:
			removed = append(removed, name)
		default:
			changed = append(changed, name+" ("+e.OldVersion+" → "+e.NewVersion+")")
		}
	}
	list := func(s []string) string {
		if len(s) == 0 {
			return "-"
		}
		return strings.Join(s, ", ")
	}
	_ = n.st.AddNotification(ctx, store.LevelInfo, "software_changed", map[string]string{
		"hostname": hostname, "added": list(added), "removed": list(removed), "changed": list(changed),
	}, "/servers/"+strconv.FormatInt(hostID, 10)+"?tab=software")
}

// EOLCheck notifies once per release whose end of support was reached or
// is near (see eol.Notices). Disabled notifications leave the releases
// unmarked, so enabling them later still reports them.
func (n *Notifier) EOLCheck(ctx context.Context, d eol.Data) {
	cfg, err := settings.Load(ctx, n.st)
	if err != nil || !cfg.EOLNotify {
		return
	}
	notices, err := eol.Notices(ctx, n.st, d, timeutil.Now(), cfg.EOLWarn())
	if err != nil {
		n.logger.Error(n.l.T("log.notify.failed"), slog.String("error", err.Error()))
	}
	for _, x := range notices {
		kind, level := "eol_approaching", store.LevelWarning
		if x.Kind == eol.StatusEOL {
			kind = "eol_reached"
			if x.Group.Kind == eol.KindOS {
				level = store.LevelCritical
			}
		}
		date := "-"
		if !x.Release.EOL.IsZero() {
			date = n.f.Date(x.Release.EOL)
		}
		_ = n.st.AddNotification(ctx, level, kind, map[string]string{
			"product": x.Name + " " + x.Cycle, "date": date, "hosts": strconv.Itoa(len(x.Hosts)),
		}, "/software?tab=eol")
	}
}

// ScoreBelow notifies about hosts whose security score dropped below the
// configured threshold (once until the score recovers).
func (n *Notifier) ScoreBelow(ctx context.Context, hosts []store.HostRef, threshold int) {
	for _, h := range hosts {
		_ = n.st.AddNotification(ctx, store.LevelWarning, "score_below", map[string]string{
			"hostname": h.Hostname, "score": h.Version, "threshold": strconv.Itoa(threshold),
		}, "/servers/"+strconv.FormatInt(h.ID, 10)+"/score")
	}
}

// HealthResult notifies when a job's health checks failed: regressed after
// an update, failed before it (the update was skipped) or in a manual run.
func (n *Notifier) HealthResult(ctx context.Context, j store.Job) {
	outcome, checks := j.Data.HealthOutcome()
	kind, level := "", store.LevelWarning
	switch outcome {
	case store.HealthRegressed:
		kind, level = "health_regressed", store.LevelCritical
	case store.HealthAborted:
		kind = "health_aborted"
	case store.HealthFailed:
		kind = "health_failed"
	default:
		return
	}
	_ = n.st.AddNotification(ctx, level, kind, map[string]string{
		"hostname": j.Hostname, "id": strconv.FormatInt(j.ID, 10), "checks": strings.Join(checks, ", "), "job_type": j.Type,
	}, "/jobs/"+strconv.FormatInt(j.ID, 10))
}

// HealthMonitor notifies monitored checks that started failing or
// recovered: health_down/health_up for defined checks, resource_high/
// resource_ok for the built-in disk, memory and CPU limits.
func (n *Notifier) HealthMonitor(ctx context.Context, hostID int64, hostname string, changes []store.HealthChange, limits map[string]int) {
	link := "/servers/" + strconv.FormatInt(hostID, 10) + "?tab=health"
	for _, c := range changes {
		level, params := store.LevelInfo, map[string]string{"hostname": hostname, "value": c.Value}
		var kind string
		switch {
		case c.Builtin() && c.Down:
			kind, level = "resource_high", store.LevelWarning
			params["resource"], params["target"], params["limit"] = c.Type, c.Target(), strconv.Itoa(limits[c.Type])
		case c.Builtin():
			kind = "resource_ok"
			params["resource"], params["target"] = c.Type, c.Target()
		case c.Down:
			kind, level = "health_down", store.LevelWarning
			params["check"], params["detail"] = c.Name, c.Message
			if c.Message == "" {
				params["detail"] = c.Value
			}
		default:
			kind = "health_up"
			params["check"] = c.Name
		}
		if c.Type != "disk" {
			params["target"] = ""
		}
		_ = n.st.AddNotification(ctx, level, kind, params, link)
	}
}

// RolloutEvent records that a rolling update paused, stopped or completed.
func (n *Notifier) RolloutEvent(ctx context.Context, kind, level string, r store.Rollout) {
	reason := ""
	if r.Reason != "" {
		reason = n.l.T("rollout.reason." + r.Reason)
	}
	_ = n.st.AddNotification(ctx, level, kind, map[string]string{
		"name": r.Name, "reason": reason,
		"done": strconv.Itoa(r.Counts.Done()), "failed": strconv.Itoa(r.Counts.Failed), "total": strconv.Itoa(r.Counts.Total),
	}, "/rollouts/"+strconv.FormatInt(r.ID, 10))
}

// DriftDetected notifies about hosts that deviate from their standards in
// new ways (one notification per host).
func (n *Notifier) DriftDetected(ctx context.Context, hosts []drift.HostDrift) {
	for _, h := range hosts {
		_ = n.st.AddNotification(ctx, store.LevelWarning, "drift_detected", map[string]string{
			"hostname": h.Hostname, "count": strconv.Itoa(h.Count), "standards": strings.Join(h.Standards, ", "),
		}, "/servers/"+strconv.FormatInt(h.HostID, 10)+"?tab=software")
	}
}
