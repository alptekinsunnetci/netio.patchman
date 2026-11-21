package agent

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"unicode/utf16"

	"netio.patchman/internal/i18n"
	"netio.patchman/internal/protocol"
)

// wuSample is real helper output from Windows Server 2022 (offline search).
const wuSample = "\ufeff" + `{"updates":[{"name":"KB5128928","title":"2026-10 Cumulative Update for .NET Framework 3.5, 4.8 and 4.8.1 for Microsoft server operating system version 21H2 for x64 (KB5128928)","severity":"Important","categories":["Microsoft Server operating system-21H2","Security Updates"],"class":"Security Updates","category_ids":["71718F13-7324-4B0F-8F9E-2CA9DC978E53","0FA1201D-4330-4FA8-8AE9-B877473B6441"],"cves":[],"date":"2026-10-13","security":true},` +
	`{"name":"KB890830","title":"Windows Malicious Software Removal Tool x64 - v5.147 (KB890830)","severity":"","categories":["Update Rollups","Windows Server 2019"],"class":"Update Rollups","category_ids":[],"cves":[],"date":"2026-11-11","security":false},` +
	`{"name":"KB5131090","title":"2026-11 Cumulative Update for Microsoft server operating system version 21H2 for x64-based Systems (KB5131090)","severity":"","categories":["Security Updates"],"class":"Security Updates","cves":["CVE-2026-1000"," "],"date":"2026-11-10","security":true},` +
	`{"name":"--bad name","title":"x","cves":[],"security":true},{"name":"KB890830","title":"duplicate"}],"reboot_required":true}`

func TestParseWUScan(t *testing.T) {
	ups, reboot, err := parseWUScan([]byte(wuSample))
	if err != nil {
		t.Fatal(err)
	}
	if !reboot || len(ups) != 3 {
		t.Fatalf("reboot=%v updates=%+v", reboot, ups)
	}
	net, mrt, lcu := ups[0], ups[1], ups[2]
	if net.Name != "KB5128928" || !net.Security || net.Severity != "Important" || net.Repository != "Security Updates" || net.AvailableVersion != "2026-10-13" {
		t.Errorf(".NET update: %+v", net)
	}
	if mrt.Security || mrt.Repository != "Update Rollups" || !strings.HasPrefix(mrt.Title, "Windows Malicious Software Removal Tool") {
		t.Errorf("MSRT: %+v", mrt)
	}
	if len(lcu.CVEs) != 1 || lcu.CVEs[0] != "CVE-2026-1000" {
		t.Errorf("CVEs: %+v", lcu.CVEs)
	}

	if _, _, err := parseWUScan([]byte(`{"error":"Exception from HRESULT: 0x8024402C","hresult":"0x8024402C"}`)); err == nil || !strings.Contains(err.Error(), "0x8024402C") {
		t.Errorf("helper error: %v", err)
	}
	if _, _, err := parseWUScan(nil); err == nil {
		t.Error("empty output accepted")
	}
}

func TestWUEncoded(t *testing.T) {
	raw, err := base64.StdEncoding.DecodeString(wuEncoded())
	if err != nil || len(raw)%2 != 0 {
		t.Fatal(err)
	}
	u := make([]uint16, len(raw)/2)
	for i := range u {
		u[i] = uint16(raw[2*i]) | uint16(raw[2*i+1])<<8
	}
	script := string(utf16.Decode(u))
	if !strings.Contains(script, "Microsoft.Update.Session") || strings.Contains(script, "# netio.patchman") {
		t.Errorf("encoded script: %.200q", script)
	}
	// The Windows command line limit is 32767 characters.
	if n := len(wuEncoded()); n > 30000 {
		t.Errorf("encoded command too long: %d", n)
	}
}

func TestWriteWUInstall(t *testing.T) {
	l := i18n.MustLoad().Localizer(i18n.DefaultLocale)
	var out bytes.Buffer
	code := writeWUInstall(l, []byte(`{"results":[{"name":"KB1","title":"Update one","result":2,"hresult":"0x00000000"},{"name":"KB2","title":"Update two","result":4,"hresult":"0x80240022"}],"missing":["KB3"],"reboot_required":true}`), &out)
	s := out.String()
	if code != 0 || !strings.Contains(s, "Kuruldu: KB1 (Update one)") || !strings.Contains(s, "KB2") || !strings.Contains(s, "0x80240022") ||
		!strings.Contains(s, "KB3") || !strings.Contains(s, "yeniden başlatılması") {
		t.Errorf("code %d output:\n%s", code, s)
	}
	out.Reset()
	if code := writeWUInstall(l, []byte(`{"error":"busy","hresult":"0x80240016"}`), &out); code == 0 || !strings.Contains(out.String(), "0x80240016") {
		t.Errorf("error result: %d %s", code, out.String())
	}
}

func TestWindowsJobs(t *testing.T) {
	ctx := context.Background()
	winRunner := func(f *fakeHost) JobRunner {
		r := f.runner(t)
		r.PM = protocol.PMWindowsUpdate
		return r
	}
	// Security job: only security KBs, verified afterwards; one is left.
	f := &fakeHost{pending: []protocol.Update{{Name: "KB5131090", Security: true}, {Name: "KB5128928", Security: true}, {Name: "KB890830"}},
		upgrade: map[string]bool{"KB5131090": true, "KB890830": true}}
	res := winRunner(f).Run(ctx, protocol.Job{Type: protocol.JobUpgradeSecurity})
	if len(f.ran) != 1 || f.ran[0] != "windows-update install KB5131090 KB5128928" {
		t.Errorf("commands: %v", f.ran)
	}
	if !res.Succeeded || strings.Join(res.Remaining, ",") != "KB5128928" {
		t.Errorf("partial security job: %+v", res)
	}

	// Selected KBs that are not pending are skipped.
	f = &fakeHost{pending: []protocol.Update{{Name: "KB5131090", Security: true}}, upgrade: map[string]bool{"KB5131090": true}}
	res = winRunner(f).Run(ctx, protocol.Job{Type: protocol.JobUpgradePackages, Packages: []string{"KB5131090", "KB1234567"}})
	if !res.Succeeded || len(f.ran) != 1 || f.ran[0] != "windows-update install KB5131090" || !strings.Contains(res.Output, "KB1234567") {
		t.Errorf("selected: %+v %v", res, f.ran)
	}

	// Unknown pending list: Windows Update selects by kind.
	r := winRunner(&fakeHost{})
	r.Pending = nil
	f = &fakeHost{}
	r.Exec = f.exec
	r.Run(ctx, protocol.Job{Type: protocol.JobUpgradeSecurity})
	if len(f.ran) != 1 || f.ran[0] != "windows-update install --security" {
		t.Errorf("by kind: %v", f.ran)
	}

	// Reboot uses shutdown.exe with a delay.
	f = &fakeHost{}
	res = winRunner(f).Run(ctx, protocol.Job{Type: protocol.JobReboot})
	if !res.Succeeded || len(f.ran) != 1 || !strings.HasPrefix(f.ran[0], "shutdown.exe /r /t 60 /d p:2:17 /c ") {
		t.Errorf("reboot: %+v %v", res, f.ran)
	}
}

func TestCleanProgram(t *testing.T) {
	p := cleanProgram(protocol.Package{Name: " 7-Zip 26.01 (x64)\x00\r\n", Version: strings.Repeat("9", 150)})
	if p.Name != "7-Zip 26.01 (x64)" || len(p.Version) != 100 {
		t.Errorf("%+v", p)
	}
}
