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

	"netio.patchman/internal/i18n"
	"netio.patchman/internal/notify/email"
	"netio.patchman/internal/protocol"
	"netio.patchman/internal/settings"
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
				_ = n.st.AddNotification(ctx, levelFor(a.Severity, a.KEV), "vuln_detected", map[string]string{
					"cve": a.CVEID, "severity": string(a.Severity), "count": strconv.Itoa(len(d.Hostnames)), "package": d.PackageName,
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
			kev := false
			for _, a := range qualifying {
				if a.Severity.Rank() > top.Rank() {
					top = a.Severity
				}
				kev = kev || a.KEV
			}
			_ = n.st.AddNotification(ctx, levelFor(top, kev), "vulns_detected", map[string]string{
				"count": strconv.Itoa(len(qualifying)), "severity": string(top),
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
		// Fleet-wide automatic agent updates and scheduled runs would flood
		// the notification center; only their failures are reported (a
		// schedule run adds one summary notification).
		if j.Type != "agent_update" && j.ScheduleID == 0 {
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
