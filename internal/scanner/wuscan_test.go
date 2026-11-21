package scanner

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"netio.patchman/internal/i18n"
	"netio.patchman/internal/protocol"
	"netio.patchman/internal/store"
	"netio.patchman/internal/vuln"
)

type msrcRow struct {
	CVE, Severity, Score, Vector, KB, Supersedes, Build string
}

// fakeMSRC serves /affectedProduct and /vulnerability like the Security
// Update Guide, with the KB rows split over two pages.
func fakeMSRC(t *testing.T, rows []msrcRow, titles map[string]string, requests *atomic.Int32) *httptest.Server {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		filter := r.URL.Query().Get("$filter")
		var value []map[string]any
		switch r.URL.Path {
		case "/affectedProduct":
			kb := strings.TrimSuffix(strings.TrimPrefix(filter, "kbArticles/any(kb:kb/articleName eq '"), "')")
			var match []msrcRow
			for _, row := range rows {
				if row.KB == kb {
					match = append(match, row)
				}
			}
			page := r.URL.Query().Get("page")
			if len(match) > 1 && page == "" {
				match = match[:1]
			} else if len(match) > 1 {
				match = match[1:]
			}
			for _, row := range match {
				value = append(value, map[string]any{"cveNumber": row.CVE, "severity": row.Severity, "baseScore": row.Score, "vectorString": row.Vector,
					"kbArticles": []map[string]any{{"articleName": row.KB, "supercedence": row.Supersedes, "fixedBuildNumber": row.Build}}})
			}
			doc := map[string]any{"value": value}
			if page == "" && len(rows) > 0 && countKB(rows, kb) > 1 {
				doc["@odata.nextLink"] = srv.URL + r.URL.Path + "?" + r.URL.RawQuery + "&page=2"
			}
			_ = json.NewEncoder(w).Encode(doc)
			return
		case "/vulnerability":
			for _, part := range strings.Split(filter, " or ") {
				id := strings.TrimSuffix(strings.TrimPrefix(part, "cveNumber eq '"), "'")
				if title, ok := titles[id]; ok {
					value = append(value, map[string]any{"cveNumber": id, "cveTitle": title, "releaseDate": "2024-10-08T07:00:00-07:00"})
				}
			}
		default:
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"value": value})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func countKB(rows []msrcRow, kb string) int {
	n := 0
	for _, r := range rows {
		if r.KB == kb {
			n++
		}
	}
	return n
}

func TestScanWindows(t *testing.T) {
	ctx := context.Background()
	const vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C"
	rows := []msrcRow{
		{"CVE-2024-0001", "Critical", "9.8", vec, "5044281", "5042881", "10.0.20348.2762"},
		{"CVE-2024-0002", "Important", "", "", "5044281", "5042881", "10.0.20348.2762"},
		{"CVE-2024-0001", "Important", "8.1", vec, "5044281", "", "10.0.20348.2762"}, // another product row
		{"CVE-2024-0003", "Important", "7.8", "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "5042881", "5041160", "10.0.20348.2700"},
		{"CVE-2024-0004", "Important", "7.0", "", "5041160", "", "10.0.20348.2655"},
		{"CVE-2024-0005", "Important", "7.0", "", "5040000", "", "10.0.17763.9999"}, // another OS: not comparable
	}
	var requests atomic.Int32
	srv := fakeMSRC(t, rows, map[string]string{"CVE-2024-0001": "Windows TCP/IP Remote Code Execution Vulnerability"}, &requests)

	st, err := store.Open(ctx, t.TempDir()+"/t.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	sc := New(Options{Store: st, OSV: NewOSVClient("http://127.0.0.1:1"), MSRCURL: srv.URL,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), L: i18n.MustLoad().Localizer(i18n.DefaultLocale)})

	info := protocol.HostInfo{Hostname: "ws2022", MachineID: "ws2022", OSID: protocol.OSWindows, OSVersionID: "10.0.20348", Kernel: "10.0.20348.2700"}
	if _, err := st.CreateEnrollmentToken(ctx, "t", "tok", "p", 0, time.Time{}, 0); err != nil {
		t.Fatal(err)
	}
	id, _, err := st.RegisterHost(ctx, "tok", info, "", "secret")
	if err != nil {
		t.Fatal(err)
	}
	report := func(build string) {
		info.Kernel = build
		rep := protocol.Report{Host: info, Updates: []protocol.Update{
			{Name: "KB5044281", AvailableVersion: "2024-10-08", Security: true, Title: "2024-10 Cumulative Update (KB5044281)"},
			// Windows Update reported CVEs itself; the guide has no rows for it.
			{Name: "KB5999999", AvailableVersion: "2024-10-08", Security: true, Severity: "Moderate", CVEs: []string{"CVE-2024-0009", "not-a-cve"}},
			{Name: "KB890830", AvailableVersion: "2024-10-08"},
		}}
		if err := st.SaveReport(ctx, id, rep, "Windows"); err != nil {
			t.Fatal(err)
		}
		if err := sc.ScanHost(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	findings := func() map[string]store.FindingRow {
		list, _, err := st.ListFindings(ctx, store.FindingFilter{HostID: id}, store.Page{Number: 1, Size: 50})
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]store.FindingRow{}
		for _, f := range list {
			out[f.CVEID] = f
		}
		return out
	}

	// Host at the September build: the October CVEs only (KB5042881's fix is in 2700).
	report("10.0.20348.2700")
	got := findings()
	if len(got) != 3 || got["CVE-2024-0001"].PackageName != "KB5044281" || got["CVE-2024-0002"].PackageName != "KB5044281" ||
		got["CVE-2024-0009"].PackageName != "KB5999999" {
		t.Fatalf("findings at 2700: %+v", got)
	}
	if f := got["CVE-2024-0001"]; f.FixedVersion != "10.0.20348.2762" || f.InstalledVersion != "10.0.20348.2700" {
		t.Errorf("versions: %+v", f)
	}
	v, err := st.Vulnerability(ctx, "CVE-2024-0001")
	if err != nil {
		t.Fatal(err)
	}
	if v.Title != "Windows TCP/IP Remote Code Execution Vulnerability" || v.Severity != vuln.SeverityCritical || v.CVSSScore == nil || *v.CVSSScore != 9.8 ||
		v.CVSSVector != vec || v.Source != "msrc" || len(v.References) != 1 {
		t.Errorf("vulnerability: %+v", v)
	}
	if v, _ := st.Vulnerability(ctx, "CVE-2024-0002"); v.Severity != vuln.SeverityHigh || v.CVSSScore != nil {
		t.Errorf("qualitative severity: %+v", v)
	}
	if v, _ := st.Vulnerability(ctx, "CVE-2024-0009"); v.Severity != vuln.SeverityMedium {
		t.Errorf("Windows Update severity: %+v", v)
	}

	// Two months behind: the superseded KBs are followed until the host's build.
	report("10.0.20348.2600")
	got = findings()
	if len(got) != 5 || got["CVE-2024-0003"].PackageName != "KB5044281" || got["CVE-2024-0003"].FixedVersion != "10.0.20348.2762" ||
		got["CVE-2024-0004"].PackageName != "KB5044281" {
		t.Fatalf("findings at 2600: %+v", got)
	}
	if _, ok := got["CVE-2024-0005"]; ok {
		t.Error("a KB of another OS version was followed")
	}

	// KB lookups are cached: a rescan sends no new KB requests.
	before := requests.Load()
	report("10.0.20348.2600")
	if requests.Load() != before {
		t.Errorf("cached KB lookups were fetched again: %d requests", requests.Load()-before)
	}

	// Installing the update resolves the findings.
	info.Kernel = "10.0.20348.2762"
	if err := st.SaveReport(ctx, id, protocol.Report{Host: info}, "Windows"); err != nil {
		t.Fatal(err)
	}
	if err := sc.ScanHost(ctx, id); err != nil {
		t.Fatal(err)
	}
	if got := findings(); len(got) != 0 {
		t.Errorf("findings after install: %+v", got)
	}
}

func TestMSRCHelpers(t *testing.T) {
	for in, want := range map[string]string{"KB5044281": "5044281", "kb890830": "890830", "5044281": "5044281", "KB12": "", "KB50x": "", "": ""} {
		if got := KBNumber(in); got != want {
			t.Errorf("KBNumber(%q) = %q", in, got)
		}
	}
	for _, c := range []struct {
		a, b         string
		newer, known bool
	}{
		{"10.0.20348.2762", "10.0.20348.2700", true, true},
		{"10.0.20348.2700", "10.0.20348.2700", false, true},
		{"10.0.20348.2655", "10.0.20348.2700", false, true},
		{"10.0.17763.9999", "10.0.20348.2700", false, false},
		{"", "10.0.20348.2700", false, false},
	} {
		if n, k := buildNewer(c.a, c.b); n != c.newer || k != c.known {
			t.Errorf("buildNewer(%q, %q) = %v %v", c.a, c.b, n, k)
		}
	}
	if got := strings.Join(splitKBs("5042881; KB5043050,12"), ","); got != "5042881,5043050" {
		t.Errorf("splitKBs: %s", got)
	}
	// The published base score is kept; the vector computes one when missing.
	v := MSRCVulnerability("CVE-2024-1", nil, MSRCKBCVE{Severity: "Important", Score: "8.1", Vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C"})
	if v.CVSSScore == nil || *v.CVSSScore != 8.1 || v.Severity != vuln.SeverityHigh || v.CVSSVersion != "3.1" {
		t.Errorf("published score: %+v", v)
	}
	v = MSRCVulnerability("CVE-2024-1", nil, MSRCKBCVE{Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"})
	if v.CVSSScore == nil || *v.CVSSScore != 9.8 || v.Severity != vuln.SeverityCritical {
		t.Errorf("computed score: %+v", v)
	}
	if v := MSRCVulnerability("CVE-2024-1", nil, MSRCKBCVE{}); v.Severity != vuln.SeverityUnknown {
		t.Errorf("no data: %+v", v)
	}
}

func TestMSRCNextLinkHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"value":[],"@odata.nextLink":"https://elsewhere.example.test/affectedProduct"}`)
	}))
	defer srv.Close()
	if _, err := NewMSRCClient(srv.URL).KB(context.Background(), "5044281"); err == nil {
		t.Error("next link to another host was followed")
	}
}
