package web_test

import (
	"context"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"netio.patchman/internal/agent"
	"netio.patchman/internal/protocol"
	"netio.patchman/internal/timeutil"
)

// TestWindowsHost enrolls a Windows Server agent, scans its pending updates
// against the (fake) Security Update Guide and remediates through its KB.
func TestWindowsHost(t *testing.T) {
	e, admin, _ := fleetEnv(t)
	ctx := context.Background()

	token := e.csrf(admin)
	_, body, _ := e.do(admin, "POST", "/agents/tokens", url.Values{"_csrf": {token}, "name": {"win"}, "valid_days": {"7"}, "max_uses": {"0"}})
	m := regexp.MustCompile(`value="([^"]+)" readonly id="new-token"`).FindStringSubmatch(body)
	if m == nil {
		t.Fatal("token not shown")
	}
	// The Windows install command is offered next to the Linux ones.
	status, body, _ := e.do(admin, "GET", "/agents", nil)
	expect(t, "agents page", status, 200, body, "Windows / Windows Server (PowerShell)", "install-agent.ps1", "TrimStart([char]65279)",
		"netio-patchman-agent-windows-amd64.exe", "data-nosudo")

	client, err := agent.NewClient(agent.Config{ServerURL: mustURL(e.srv.URL)})
	if err != nil {
		t.Fatal(err)
	}
	info := protocol.HostInfo{Hostname: "WIN-APP01", FQDN: "WIN-APP01.corp.example.test", MachineID: "52e149cf-5cb8-49c6-833f-ca45ac962c24",
		OSID: protocol.OSWindows, OSVersionID: "10.0.20348", OSVersion: "21H2", OSName: "Windows Server 2022 Standard", Kernel: "10.0.20348.2700",
		Arch: "amd64", PackageManager: protocol.PMWindowsUpdate, AgentVersion: "0.6.0", RemoteUpdates: true, Virtualization: "microsoft"}
	reg, err := client.Register(ctx, html.UnescapeString(m[1]), info)
	if err != nil {
		t.Fatal(err)
	}
	client.SetSecret(reg.AgentSecret)
	if err := client.Report(ctx, protocol.Report{Host: info, CollectedAt: timeutil.Now(), RebootRequired: true,
		Packages: []protocol.Package{{Name: "7-Zip 26.01 (x64)", Version: "26.01", Arch: "x64"}},
		Updates: []protocol.Update{
			{Name: "KB5044281", AvailableVersion: "2024-10-08", Repository: "Security Updates", Security: true,
				Title: "2024-10 Cumulative Update for Microsoft server operating system version 21H2 for x64-based Systems (KB5044281)"},
			{Name: "KB890830", AvailableVersion: "2024-10-08", Repository: "Update Rollups", Title: "Windows Malicious Software Removal Tool x64 - v5.129 (KB890830)"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.scan.ScanHost(ctx, reg.HostID); err != nil {
		t.Fatal(err)
	}
	hostURL := "/servers/" + strconv.FormatInt(reg.HostID, 10)

	status, body, _ = e.do(admin, "GET", hostURL+"?tab=updates", nil)
	expect(t, "windows updates tab", status, 200, body, "Güncelleme (KB)", "Sınıflandırma", "KB5044281", "Cumulative Update for Microsoft server",
		"Update Rollups", "Windows Server 2022 Standard")
	status, body, _ = e.do(admin, "GET", hostURL, nil)
	expect(t, "windows findings", status, 200, body, "CVE-2026-0002", "KB5044281", "10.0.20348.2762")
	status, body, _ = e.do(admin, "GET", "/vulnerabilities/CVE-2026-0002", nil)
	expect(t, "windows vulnerability", status, 200, body, "Windows TCP/IP Remote Code Execution Vulnerability", "9.8", "KB5044281",
		"https://support.microsoft.com/help/5044281", "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-0002",
		"KB5044281 güncellemesini Windows Update ile kurun (düzeltmeyi içeren Windows derlemesi: 10.0.20348.2762 veya daha yeni).")

	// Windows program names have spaces and parentheses.
	status, body, _ = e.do(admin, "GET", hostURL+"?tab=packages", nil)
	expect(t, "windows programs", status, 200, body, `href="/packages/7-Zip%2026.01%20%28x64%29"`)
	status, body, _ = e.do(admin, "GET", "/packages/"+url.PathEscape("7-Zip 26.01 (x64)"), nil)
	expect(t, "program page", status, 200, body, "7-Zip 26.01 (x64)", "WIN-APP01")

	// Remediation installs the KB that fixes the CVE.
	token = e.csrf(admin)
	if status, _, _ = e.do(admin, "POST", "/vulnerabilities/CVE-2026-0002/remediate", url.Values{"_csrf": {token}}); status != http.StatusSeeOther {
		t.Fatalf("remediate: %d", status)
	}
	resp, err := client.Checkin(ctx, info)
	if err != nil {
		t.Fatal(err)
	}
	var kbJob *protocol.Job
	for i, j := range resp.Jobs {
		switch j.Type {
		case protocol.JobUpgradePackages:
			kbJob = &resp.Jobs[i]
		case protocol.JobAgentUpdate:
			if j.Params[protocol.ParamPath] != "/downloads/agent/netio-patchman-agent-windows-amd64.exe" {
				t.Errorf("agent update for Windows: %+v", j.Params)
			}
		}
	}
	if kbJob == nil || strings.Join(kbJob.Packages, ",") != "KB5044281" {
		t.Fatalf("dispatched jobs: %+v", resp.Jobs)
	}

	// Downloads for the Windows install.
	status, body, hdr := e.do(admin, "GET", "/downloads/install-agent.ps1", nil)
	expect(t, "install-agent.ps1", status, 200, body, "param(", "New-Service", "failureflag")
	if !strings.Contains(hdr.Get("Content-Type"), "charset=utf-8") || !strings.HasPrefix(body, "\xef\xbb\xbf") {
		t.Errorf("install-agent.ps1: content type %q, BOM %v", hdr.Get("Content-Type"), strings.HasPrefix(body, "\xef\xbb\xbf"))
	}
	status, body, _ = e.do(admin, "GET", "/downloads/agent/netio-patchman-agent-windows-amd64.exe", nil)
	expect(t, "windows agent binary", status, 200, body, "MZ windows agent")
}
