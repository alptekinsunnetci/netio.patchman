package web_test

import (
	"context"
	"html"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"netio.patchman/internal/agentsign"
	"netio.patchman/internal/protocol"
)

// Agents that trust release signing keys only get updates signed with one of
// them, never older versions; the server's keys reach agents without keys
// once (they pin them), and old agents keep SHA-256-only updates.
func TestSignedAgentUpdates(t *testing.T) {
	e, admin, _ := fleetEnv(t)
	ctx := context.Background()
	otherPub, _, _ := agentsign.GenerateKey()
	otherKey := agentsign.EncodePublicKey(otherPub)
	host := func(name, osID, version string, caps []string, keys ...string) protocol.HostInfo {
		pm := "apt"
		if osID == protocol.OSWindows {
			pm = protocol.PMWindowsUpdate
		}
		return protocol.HostInfo{Hostname: name, MachineID: "sig-" + name, OSID: osID, OSVersionID: "12", Arch: "amd64",
			PackageManager: pm, AgentVersion: version, RemoteUpdates: true, SelfUpdate: true, Capabilities: caps, UpdateKeys: keys}
	}
	signed := []string{protocol.CapSignedUpdate}
	ids := map[string]int64{}
	updateJob := func(info protocol.HostInfo) (protocol.CheckinResponse, *protocol.Job) {
		t.Helper()
		client, id := e.agentFor(info)
		ids[info.Hostname] = id
		resp, err := client.Checkin(ctx, info)
		if err != nil {
			t.Fatal(err)
		}
		for i, j := range resp.Jobs {
			if j.Type == protocol.JobAgentUpdate {
				return resp, &resp.Jobs[i]
			}
		}
		return resp, nil
	}

	// Trusts the release key: a signed job the agent can verify.
	_, job := updateJob(host("sig-trusted", "debian", "1.0.0", signed, e.signKey))
	if job == nil {
		t.Fatal("signed update not queued")
	}
	p := job.Params
	if id, ok := agentsign.Verify(p[protocol.ParamSignature], []string{e.signKey}, p[protocol.ParamVersion], "linux", "amd64", p[protocol.ParamSHA256]); !ok || id == "" {
		t.Errorf("job signature does not verify: %v", p)
	}
	// Another key, an unsigned (Windows) binary, or a newer agent: nothing queued.
	for _, info := range []protocol.HostInfo{
		host("sig-other", "debian", "1.0.0", signed, otherKey),
		host("sig-win", protocol.OSWindows, "1.0.0", signed, e.signKey),
		host("sig-newer", "debian", "10.0.0", signed, e.signKey),
	} {
		if _, job := updateJob(info); job != nil {
			t.Errorf("%s: update queued: %v", info.Hostname, job.Params)
		}
	}
	// Agents without keys keep updating by SHA-256 (unsigned Windows binary too).
	if _, job := updateJob(host("sig-none-win", protocol.OSWindows, "1.0.0", signed)); job == nil || job.Params[protocol.ParamSignature] != "" {
		t.Errorf("update without keys: %+v", job)
	}

	status, body, _ := e.do(admin, "GET", "/agents", nil)
	expect(t, "agents page", status, 200, body, "İmzalı", agentsign.KeyIDs([]string{e.signKey})[0], "(bazı dosyalar imzasız)",
		"İmza bekleniyor", "Yalnızca imzalı", "Tanımlı değil.")

	// A manual update the agent would refuse is not queued.
	_, _, hdr := e.do(admin, "POST", "/servers/"+strconv.FormatInt(ids["sig-other"], 10)+"/jobs", url.Values{"_csrf": {e.csrf(admin)}, "type": {protocol.JobAgentUpdate}})
	status, body, _ = e.do(admin, "GET", hdr.Get("Location"), nil)
	expect(t, "manual unsigned update", status, 200, body, "yalnızca imzalı güncellemeleri kabul ediyor")
	if active, _ := e.st.HasActiveJob(ctx, ids["sig-other"], protocol.JobAgentUpdate); active {
		t.Error("refused manual update queued")
	}

	// Server keys: invalid input is refused, valid keys are saved.
	form := url.Values{"_csrf": {e.csrf(admin)}, "email_min_severity": {"high"}, "email_digest_threshold": {"5"}, "agent_offline_minutes": {"10"},
		"agent_checkin_seconds": {"60"}, "agent_report_minutes": {"60"}, "retention_days": {"90"}, "agent_auto_update": {"1"},
		"agent_update_keys": {"bm90LWEta2V5"}}
	e.do(admin, "POST", "/settings", form)
	if cfg := settingsValues(t, e); len(cfg.AgentUpdateKeys) != 0 {
		t.Fatalf("invalid key saved: %v", cfg.AgentUpdateKeys)
	}
	form.Set("agent_update_keys", e.signKey+"\n"+e.signKey)
	if status, _, _ := e.do(admin, "POST", "/settings", form); status != 303 {
		t.Fatalf("settings: %d", status)
	}
	if cfg := settingsValues(t, e); len(cfg.AgentUpdateKeys) != 1 || cfg.AgentUpdateKeys[0] != e.signKey {
		t.Fatalf("keys: %v", cfg.AgentUpdateKeys)
	}
	status, body, _ = e.do(admin, "GET", "/settings", nil)
	expect(t, "settings page", status, 200, html.UnescapeString(body), "Güncelleme imza anahtarları", e.signKey)

	// An agent without keys receives them to pin, and its update is already
	// signed; an agent with keys of its own does not; an old agent neither.
	resp, job := updateJob(host("sig-pin", "debian", "1.0.0", signed))
	if len(resp.UpdateKeys) != 1 || resp.UpdateKeys[0] != e.signKey || job == nil || job.Params[protocol.ParamSignature] == "" {
		t.Errorf("pinning agent: keys %v job %+v", resp.UpdateKeys, job)
	}
	if resp, _ := updateJob(host("sig-own", "debian", "1.0.0", signed, otherKey)); len(resp.UpdateKeys) != 0 {
		t.Errorf("agent with own keys got %v", resp.UpdateKeys)
	}
	resp, job = updateJob(host("sig-old", "debian", "1.0.0", nil))
	if len(resp.UpdateKeys) != 0 || job == nil {
		t.Errorf("old agent: keys %v job %+v", resp.UpdateKeys, job)
	}
	// Pinning Windows agents wait: their binary is unsigned.
	if resp, job := updateJob(host("sig-pin-win", protocol.OSWindows, "1.0.0", signed)); len(resp.UpdateKeys) != 1 || job != nil {
		t.Errorf("pinning Windows agent: keys %v job %+v", resp.UpdateKeys, job)
	}
}

// saveUpdateKeys stores the server's release signing keys from the settings page.
func saveUpdateKeys(t *testing.T, e *env, admin *http.Client, keys string) {
	t.Helper()
	form := url.Values{"_csrf": {e.csrf(admin)}, "email_min_severity": {"high"}, "email_digest_threshold": {"5"}, "agent_offline_minutes": {"10"},
		"agent_checkin_seconds": {"60"}, "agent_report_minutes": {"60"}, "retention_days": {"90"}, "agent_auto_update": {"1"},
		"agent_update_keys": {keys}}
	if status, _, _ := e.do(admin, "POST", "/settings", form); status != http.StatusSeeOther {
		t.Fatalf("settings: %d", status)
	}
}

// The agents page names the agents that do not trust a matching signing key
// yet and what to do about them; the notice disappears once all of them do.
func TestSigningNotice(t *testing.T) {
	e, admin, dbID := fleetEnv(t)
	ctx := context.Background()
	page := func() string {
		t.Helper()
		status, body, _ := e.do(admin, "GET", "/agents", nil)
		if status != 200 {
			t.Fatalf("agents page: %d", status)
		}
		return html.UnescapeString(body)
	}
	notice := `id="signing-notice"`
	// The release is signed: db-01 runs an agent too old for keys.
	body := page()
	expect(t, "old agent", 200, 200, body, notice, "alert--warning", "İmzalı güncellemeyi desteklemeyen eski ajan: 1", `href="/servers/`+strconv.FormatInt(dbID, 10)+`">db-01`)

	// After its update the agent trusts the release key: nothing left to do.
	db := protocol.HostInfo{Hostname: "db-01", MachineID: "m1", OSID: "debian", OSVersionID: "12", Arch: "amd64", PackageManager: "apt",
		AgentVersion: "9.9.9", Capabilities: []string{protocol.CapSignedUpdate}, UpdateKeys: []string{e.signKey}}
	if _, _, err := e.st.Checkin(ctx, dbID, db, "", time.Hour); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(page(), notice) {
		t.Fatal("notice shown while every agent trusts the release key")
	}

	// A new agent without a key, and no key on the server: assign one.
	info := protocol.HostInfo{Hostname: "web-02", MachineID: "n2", OSID: "debian", OSVersionID: "12", Arch: "amd64", PackageManager: "apt",
		AgentVersion: "9.9.9", Capabilities: []string{protocol.CapSignedUpdate}}
	client, _ := e.agentFor(info)
	if _, err := client.Checkin(ctx, info); err != nil {
		t.Fatal(err)
	}
	body = page()
	expect(t, "missing key", 200, 200, body, notice, "İmza anahtarı olmayan ajan: 1", ">web-02</a>")
	if strings.Contains(body, "PATCHMAN_UPDATE_KEYS=") {
		t.Error("manual line without server keys")
	}

	// With the key on the server it saves it at its next check-in: information only,
	// with the line for assigning the key by hand.
	saveUpdateKeys(t, e, admin, e.signKey)
	body = page()
	expect(t, "pending", 200, 200, body, notice, "alert--info", "Anahtarı bir sonraki bağlantısında kaydedecek ajan: 1",
		`value="PATCHMAN_UPDATE_KEYS=`+e.signKey+`"`)
	resp, err := client.Checkin(ctx, info)
	if err != nil || len(resp.UpdateKeys) != 1 {
		t.Fatalf("keys not sent: %+v %v", resp.UpdateKeys, err)
	}
	info.UpdateKeys = resp.UpdateKeys // the agent pinned them
	if _, err := client.Checkin(ctx, info); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(page(), notice) {
		t.Fatal("notice shown after the agent saved the key")
	}

	// A new server key the agents do not trust: change it on the hosts.
	otherPub, _, _ := agentsign.GenerateKey()
	saveUpdateKeys(t, e, admin, agentsign.EncodePublicKey(otherPub))
	expect(t, "mismatch", 200, 200, page(), notice, "alert--warning", "Farklı bir anahtara güvenen ajan: 2", ">db-01</a>", ">web-02</a>")
	// Both keys during a rotation: the agents still match.
	saveUpdateKeys(t, e, admin, e.signKey+"\n"+agentsign.EncodePublicKey(otherPub))
	if strings.Contains(page(), notice) {
		t.Fatal("notice shown while the agents trust one of the server keys")
	}
}
