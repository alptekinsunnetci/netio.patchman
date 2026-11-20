// Package email renders and sends Turkish notification emails.
//
// All labels and sentences come from the i18n catalog. Vulnerability data
// (CVE ID, official description, CVSS, package names, versions) is inserted
// verbatim and never translated.
package email

import (
	"bytes"
	"crypto/tls"
	"embed"
	"fmt"
	htmltemplate "html/template"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	texttemplate "text/template"
	"time"

	"netio.patchman/internal/brand"
	"netio.patchman/internal/i18n"
	"netio.patchman/internal/timeutil"
	"netio.patchman/internal/version"
	"netio.patchman/internal/vuln"
)

//go:embed templates/*
var templateFS embed.FS

// VulnerabilityAlert is the input for a vulnerability notification.
type VulnerabilityAlert struct {
	Vulnerability    vuln.Vulnerability
	PackageName      string
	InstalledVersion string
	FixedVersion     string
	Servers          []string // hostnames
	FirstDetectedAt  time.Time
	DashboardURL     string
}

// Message is a rendered email.
type Message struct {
	From    mail.Address
	To      []mail.Address
	Subject string
	Text    string
	HTML    string
	Date    time.Time
}

// Renderer renders notification emails for one locale.
type Renderer struct {
	l    i18n.Localizer
	f    timeutil.Formatter
	from mail.Address
	html *htmltemplate.Template
	text *texttemplate.Template
}

// NewRenderer parses the embedded templates.
func NewRenderer(l i18n.Localizer, f timeutil.Formatter, from mail.Address) (*Renderer, error) {
	funcs := map[string]any{"t": l.T, "sevColor": severityColor}
	h, err := htmltemplate.New("").Funcs(funcs).ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("email: parse html templates: %w", err)
	}
	t, err := texttemplate.New("").Funcs(funcs).ParseFS(templateFS, "templates/*.txt")
	if err != nil {
		return nil, fmt.Errorf("email: parse text templates: %w", err)
	}
	return &Renderer{l: l, f: f, from: from, html: h, text: t}, nil
}

// severityColor returns the badge color used in HTML emails.
func severityColor(s string) string {
	switch vuln.Severity(s) {
	case vuln.SeverityCritical:
		return "#b42318"
	case vuln.SeverityHigh:
		return "#c4320a"
	case vuln.SeverityMedium:
		return "#a15c07"
	case vuln.SeverityLow:
		return "#175cd3"
	default:
		return "#475467"
	}
}

type alertView struct {
	Product         string
	Lang            string
	Alert           VulnerabilityAlert
	V               vuln.Vulnerability
	SeverityLabel   string
	Severity        string
	CVSS            string
	FixedVersion    string
	FirstDetected   string
	Remediation     string
	ServerCount     int
	DescriptionLang string
}

// VulnerabilityAlert renders a vulnerability notification.
func (r *Renderer) VulnerabilityAlert(a VulnerabilityAlert, to []mail.Address) (Message, error) {
	v := a.Vulnerability
	sevLabel := r.l.T(v.Severity.LabelKey())

	view := alertView{
		Product:         brand.Name,
		Lang:            r.l.Lang(),
		Alert:           a,
		V:               v,
		SeverityLabel:   sevLabel,
		Severity:        string(v.Severity),
		CVSS:            r.l.T("common.empty"),
		FixedVersion:    a.FixedVersion,
		FirstDetected:   r.f.Long(a.FirstDetectedAt),
		ServerCount:     len(a.Servers),
		DescriptionLang: v.DescriptionLanguage(),
	}
	if v.CVSSScore != nil {
		// CVSS metrics are shown unchanged, with a dot decimal separator.
		view.CVSS = strconv.FormatFloat(*v.CVSSScore, 'f', 1, 64)
	}
	if a.FixedVersion != "" {
		view.Remediation = r.l.T("remediation.update", "package", a.PackageName, "version", a.FixedVersion)
	} else {
		view.FixedVersion = r.l.T("vuln.fix_not_available")
		view.Remediation = r.l.T("remediation.no_fix")
	}

	var htmlBuf, textBuf bytes.Buffer
	if err := r.html.ExecuteTemplate(&htmlBuf, "vulnerability_alert.html", view); err != nil {
		return Message{}, fmt.Errorf("email: render html: %w", err)
	}
	if err := r.text.ExecuteTemplate(&textBuf, "vulnerability_alert.txt", view); err != nil {
		return Message{}, fmt.Errorf("email: render text: %w", err)
	}

	return Message{
		From: r.from,
		To:   to,
		Subject: r.l.T("email.vuln.subject",
			"severity", r.l.Upper(sevLabel),
			"cve", v.CVEID,
			"count", len(a.Servers),
		),
		Text: textBuf.String(),
		HTML: htmlBuf.String(),
		Date: timeutil.Now(),
	}, nil
}

// DigestItem is one CVE line in a digest email. Values are verbatim.
type DigestItem struct {
	CVEID          string
	Title          string
	Severity       vuln.Severity
	CVSS           *float64
	KnownExploited bool
	PackageName    string
	HostCount      int
	URL            string
}

type digestRow struct {
	DigestItem
	SeverityLabel string
	CVSSText      string
}

// Digest renders one email that lists many new vulnerabilities, used when a
// scan finds more CVEs than the per-CVE email threshold.
func (r *Renderer) Digest(items []DigestItem, dashboardURL string, to []mail.Address) (Message, error) {
	top := vuln.SeverityUnknown
	rows := make([]digestRow, len(items))
	for i, it := range items {
		if it.Severity.Rank() > top.Rank() {
			top = it.Severity
		}
		rows[i] = digestRow{DigestItem: it, SeverityLabel: r.l.T(it.Severity.LabelKey()), CVSSText: r.l.T("common.empty")}
		if it.CVSS != nil {
			rows[i].CVSSText = strconv.FormatFloat(*it.CVSS, 'f', 1, 64)
		}
	}
	view := map[string]any{
		"Product": brand.Name, "Lang": r.l.Lang(), "Rows": rows, "Count": len(items), "DashboardURL": dashboardURL,
	}
	var htmlBuf, textBuf bytes.Buffer
	if err := r.html.ExecuteTemplate(&htmlBuf, "digest.html", view); err != nil {
		return Message{}, fmt.Errorf("email: render html: %w", err)
	}
	if err := r.text.ExecuteTemplate(&textBuf, "digest.txt", view); err != nil {
		return Message{}, fmt.Errorf("email: render text: %w", err)
	}
	return Message{
		From: r.from, To: to,
		Subject: r.l.T("email.digest.subject", "severity", r.l.Upper(r.l.T(top.LabelKey())), "count", len(items)),
		Text:    textBuf.String(), HTML: htmlBuf.String(), Date: timeutil.Now(),
	}, nil
}

// NoticeRow is a label/value pair in a notice email.
type NoticeRow struct {
	Label string
	Value string
	Mono  bool
}

// Notice is a short informational email (test mail, agent offline, job failed).
type Notice struct {
	Subject  string
	Heading  string
	Body     string
	Rows     []NoticeRow
	Output   string // optional preformatted block (job output), verbatim
	LinkURL  string
	LinkText string
}

// Notice renders a notice email. All strings must already be localized.
func (r *Renderer) Notice(n Notice, to []mail.Address) (Message, error) {
	view := map[string]any{"Product": brand.Name, "Lang": r.l.Lang(), "N": n}
	var htmlBuf, textBuf bytes.Buffer
	if err := r.html.ExecuteTemplate(&htmlBuf, "notice.html", view); err != nil {
		return Message{}, fmt.Errorf("email: render html: %w", err)
	}
	if err := r.text.ExecuteTemplate(&textBuf, "notice.txt", view); err != nil {
		return Message{}, fmt.Errorf("email: render text: %w", err)
	}
	return Message{From: r.from, To: to, Subject: n.Subject, Text: textBuf.String(), HTML: htmlBuf.String(), Date: timeutil.Now()}, nil
}

// Bytes encodes the message as a UTF-8 multipart/alternative RFC 5322 message.
func (m Message) Bytes() ([]byte, error) {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for _, part := range []struct{ ctype, content string }{
		{"text/plain; charset=UTF-8", m.Text},
		{"text/html; charset=UTF-8", m.HTML},
	} {
		w, err := mw.CreatePart(textproto.MIMEHeader{
			"Content-Type":              {part.ctype},
			"Content-Transfer-Encoding": {"quoted-printable"},
		})
		if err != nil {
			return nil, err
		}
		qp := quotedprintable.NewWriter(w)
		if _, err := qp.Write([]byte(part.content)); err != nil {
			return nil, err
		}
		if err := qp.Close(); err != nil {
			return nil, err
		}
	}
	if err := mw.Close(); err != nil {
		return nil, err
	}

	to := make([]string, len(m.To))
	for i, a := range m.To {
		to[i] = a.String()
	}

	var out bytes.Buffer
	header := func(k, v string) { fmt.Fprintf(&out, "%s: %s\r\n", k, v) }
	header("From", m.From.String())
	header("To", strings.Join(to, ", "))
	header("Subject", mime.BEncoding.Encode("UTF-8", m.Subject))
	header("Date", m.Date.Format(time.RFC1123Z))
	header("MIME-Version", "1.0")
	header("Content-Type", `multipart/alternative; boundary="`+mw.Boundary()+`"`)
	header("X-Mailer", brand.Name+"/"+version.Version)
	out.WriteString("\r\n")
	out.Write(body.Bytes())
	return out.Bytes(), nil
}

// SMTPSender sends messages through an SMTP server. net/smtp upgrades the
// connection with STARTTLS when the server offers it.
type SMTPSender struct {
	Host     string
	Port     int
	Username string
	Password string
}

// Send delivers m. Port 465 uses implicit TLS; other ports upgrade with
// STARTTLS when offered. Credentials are only sent over TLS (net/smtp
// PlainAuth refuses plaintext except to localhost).
func (s SMTPSender) Send(m Message) error {
	raw, err := m.Bytes()
	if err != nil {
		return err
	}
	addr := net.JoinHostPort(s.Host, strconv.Itoa(s.Port))
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	tlsConf := &tls.Config{ServerName: s.Host, MinVersion: tls.VersionTLS12}
	var conn net.Conn
	if s.Port == 465 {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsConf)
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Now().Add(2 * time.Minute))
	c, err := smtp.NewClient(conn, s.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if s.Port != 465 {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(tlsConf); err != nil {
				return err
			}
		}
	}
	if s.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", s.Username, s.Password, s.Host)); err != nil {
			return err
		}
	}
	if err := c.Mail(m.From.Address); err != nil {
		return err
	}
	for _, a := range m.To {
		if err := c.Rcpt(a.Address); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(raw); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}
