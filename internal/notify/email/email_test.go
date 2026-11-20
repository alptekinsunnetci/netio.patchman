package email

import (
	"bytes"
	"html"
	"io"
	"mime"
	"net/mail"
	"strings"
	"testing"
	"time"

	"netio.patchman/internal/i18n"
	"netio.patchman/internal/timeutil"
	"netio.patchman/internal/vuln"
)

const sourceDescription = "Remote code execution vulnerability in the affected package's \"parser\" component."

func newTestRenderer(t *testing.T) *Renderer {
	t.Helper()
	l := i18n.MustLoad().Localizer(i18n.DefaultLocale)
	loc, _ := time.LoadLocation(timeutil.DefaultTimezone)
	r, err := NewRenderer(l, timeutil.NewFormatter(loc, l), mail.Address{Name: "netio.patchman", Address: "patchman@example.test"})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func testAlert(n int) VulnerabilityAlert {
	score := 9.8
	servers := make([]string, n)
	for i := range servers {
		servers[i] = "web-" + string(rune('a'+i)) + ".example.test"
	}
	return VulnerabilityAlert{
		Vulnerability: vuln.Vulnerability{
			CVEID:       "CVE-2026-0001",
			Title:       "Example parser RCE",
			Description: sourceDescription,
			CVSSScore:   &score,
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			Severity:    vuln.SeverityCritical,
		},
		PackageName:      "libexample",
		InstalledVersion: "1.2.3-1ubuntu0.1",
		FixedVersion:     "1.2.3-1ubuntu0.2",
		Servers:          servers,
		FirstDetectedAt:  time.Date(2026, 11, 19, 6, 5, 0, 0, time.UTC),
		DashboardURL:     "https://patchman.example.test/vulnerabilities/CVE-2026-0001",
	}
}

func TestSubjectIsTurkish(t *testing.T) {
	m, err := newTestRenderer(t).VulnerabilityAlert(testAlert(12), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := "[KRİTİK] CVE-2026-0001 - 12 sunucuda güvenlik açığı tespit edildi"
	if m.Subject != want {
		t.Errorf("subject = %q\nwant     %q", m.Subject, want)
	}
}

func TestBodyKeepsSourceDataVerbatim(t *testing.T) {
	m, err := newTestRenderer(t).VulnerabilityAlert(testAlert(2), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{sourceDescription, "CVE-2026-0001", "9.8", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "libexample", "1.2.3-1ubuntu0.2"} {
		if !strings.Contains(m.Text, s) {
			t.Errorf("text body missing verbatim %q", s)
		}
	}
	if !strings.Contains(html.UnescapeString(m.HTML), sourceDescription) {
		t.Error("html body missing verbatim description")
	}
	if !strings.Contains(m.HTML, `lang="en"`) {
		t.Error("source description must carry lang=\"en\"")
	}
	for _, label := range []string{"CVSS Puanı", "Önem Derecesi", "Etkilenen Paket", "Kurulu Sürüm", "Düzeltilmiş Sürüm", "Etkilenen Sunucular", "İlk Tespit Tarihi", "Çözüm Önerisi", "19 Kasım 2026 09:05"} {
		if !strings.Contains(m.Text, label) {
			t.Errorf("text body missing %q", label)
		}
	}
	if strings.Contains(m.HTML, "ZgotmplZ") {
		t.Error("html template rejected a value (ZgotmplZ)")
	}
}

func TestNoFixedVersion(t *testing.T) {
	a := testAlert(1)
	a.FixedVersion = ""
	m, err := newTestRenderer(t).VulnerabilityAlert(a, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(m.Text, "Henüz yayımlanmadı") || !strings.Contains(m.Text, "Henüz düzeltilmiş sürüm yayımlanmadı") {
		t.Errorf("missing no-fix guidance:\n%s", m.Text)
	}
}

func TestMessageBytesRoundTrip(t *testing.T) {
	m, err := newTestRenderer(t).VulnerabilityAlert(testAlert(3), []mail.Address{{Name: "Güvenlik Ekibi", Address: "sec@example.test"}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := m.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	subject, err := new(mime.WordDecoder).DecodeHeader(parsed.Header.Get("Subject"))
	if err != nil {
		t.Fatal(err)
	}
	if subject != m.Subject {
		t.Errorf("decoded subject = %q, want %q", subject, m.Subject)
	}
	from, err := parsed.Header.AddressList("From")
	if err != nil || from[0].Name != "netio.patchman" {
		t.Errorf("from = %v, %v", from, err)
	}
	to, err := parsed.Header.AddressList("To")
	if err != nil || to[0].Name != "Güvenlik Ekibi" {
		t.Errorf("to = %v, %v", to, err)
	}
	body, _ := io.ReadAll(parsed.Body)
	if !bytes.Contains(body, []byte("text/plain; charset=UTF-8")) {
		t.Error("missing text part")
	}
}
