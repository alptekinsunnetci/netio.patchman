package web_test

import (
	"context"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"netio.patchman/internal/protocol"
	"netio.patchman/internal/scoring"
	"netio.patchman/internal/settings"
	"netio.patchman/internal/store"
	"netio.patchman/internal/timeutil"
)

func TestSecurityScore(t *testing.T) {
	e, admin, dbID := fleetEnv(t)
	ctx := context.Background()
	// A clean, supported host next to the fleetEnv host (openssl findings).
	info := protocol.HostInfo{Hostname: "clean-01", MachineID: "sc1", OSID: "debian", OSVersionID: "12", OSName: "Debian GNU/Linux 12 (bookworm)",
		Arch: "amd64", PackageManager: "apt", AgentVersion: "0.10.0"}
	client, cleanID := e.agentFor(info)
	if err := client.Report(ctx, protocol.Report{Host: info, CollectedAt: timeutil.Now(),
		Updates: []protocol.Update{{Name: "tzdata", CurrentVersion: "2024a-0+deb12u1", AvailableVersion: "2025b-0+deb12u1", Security: true}}}); err != nil {
		t.Fatal(err)
	}
	var below []store.HostRef
	engine := &scoring.Engine{Store: e.st, EOL: e.eol.Data, OnBelow: func(_ context.Context, hosts []store.HostRef, _ int) { below = append(below, hosts...) }}
	if err := e.st.SaveSettings(ctx, map[string]string{settings.KeyScoreAlertBelow: "99"}); err != nil {
		t.Fatal(err)
	}
	if err := engine.Run(ctx, timeutil.Now()); err != nil {
		t.Fatal(err)
	}
	db, _ := e.st.HostByID(ctx, dbID)
	clean, _ := e.st.HostByID(ctx, cleanID)
	// The clean host only loses the uncovered security update (1 point).
	if clean.SecurityScore != 99 {
		t.Errorf("clean host score: %d", clean.SecurityScore)
	}
	if db.SecurityScore < 0 || db.SecurityScore >= 99 {
		t.Errorf("vulnerable host score: %d", db.SecurityScore)
	}
	if len(below) != 1 || below[0].ID != dbID {
		t.Errorf("below threshold: %+v", below)
	}
	// Notified once until the score recovers.
	below = nil
	_ = engine.Run(ctx, timeutil.Now())
	if len(below) != 0 {
		t.Errorf("repeated alert: %+v", below)
	}

	hostURL := "/servers/" + strconv.FormatInt(dbID, 10)
	status, body, _ := e.do(admin, "GET", hostURL+"/score", nil)
	expect(t, "score page", status, 200, body, "Güvenlik skoru", "Skoru etkileyenler", "Açık güvenlik açıkları", "Skor nasıl hesaplanır?")
	if !strings.Contains(body, `href="/vulnerabilities/CVE-`) {
		t.Errorf("score page lists no CVE")
	}
	status, body, _ = e.do(admin, "GET", hostURL, nil)
	expect(t, "host header score", status, 200, body, `href="`+hostURL+`/score"`, "score score--")

	status, body, _ = e.do(admin, "GET", "/servers?sort=score", nil)
	expect(t, "servers by score", status, 200, body, "db-01", "clean-01")
	if strings.Index(body, ">db-01<") > strings.Index(body, ">clean-01<") {
		t.Errorf("lowest score is not first")
	}
	status, body, _ = e.do(admin, "GET", "/servers?score_below=99", nil)
	if status != 200 || strings.Contains(body, ">clean-01<") || !strings.Contains(body, ">db-01<") {
		t.Errorf("score filter: %d", status)
	}
	if err := e.st.TakeSnapshot(ctx, timeutil.Now()); err != nil {
		t.Fatal(err)
	}
	status, body, _ = e.do(admin, "GET", "/dashboard", nil)
	expect(t, "dashboard score", status, 200, body, "Ortalama güvenlik skoru", "En düşük: "+strconv.Itoa(db.SecurityScore))

	// Weights: make critical findings free, then reset.
	status, body, _ = e.do(admin, "GET", "/settings/score", nil)
	expect(t, "weights page", status, 200, body, "Kritik CVE", "Varsayılan: 10")
	form := url.Values{"_csrf": {e.csrf(admin)}, "alert_below": {"0"}}
	for _, sw := range settings.ScoreWeights {
		form.Set(strings.ReplaceAll(sw.Key, ".", "_"), "0")
	}
	if status, _, _ := e.do(admin, "POST", "/settings/score", form); status != 303 {
		t.Fatalf("save weights: %d", status)
	}
	_ = engine.Run(ctx, timeutil.Now())
	db, _ = e.st.HostByID(ctx, dbID)
	if db.SecurityScore != 100 {
		t.Errorf("score with zero weights: %d", db.SecurityScore)
	}
	form.Set("score_critical", "500")
	if _, _, hdr := e.do(admin, "POST", "/settings/score", form); hdr.Get("Location") != "/settings/score" {
		t.Errorf("invalid weight redirect: %s", hdr.Get("Location"))
	}
	if v, _ := settings.Load(ctx, e.st); v.ScoreWeights.Critical != 0 {
		t.Errorf("invalid weight stored: %v", v.ScoreWeights.Critical)
	}
	if status, _, _ := e.do(admin, "POST", "/settings/score", url.Values{"_csrf": {e.csrf(admin)}, "reset": {"1"}}); status != 303 {
		t.Fatalf("reset: %d", status)
	}
	if v, _ := settings.Load(ctx, e.st); v.ScoreWeights.Critical != 10 {
		t.Errorf("reset weights: %v", v.ScoreWeights.Critical)
	}

	_ = engine.Run(ctx, timeutil.Now())
	key := e.createAPIKey(admin, "score", false)
	code, out := e.apiDo(key, "GET", "/api/v1/hosts/"+strconv.FormatInt(cleanID, 10)+"/score", "")
	if code != 200 || !strings.Contains(out, `"score": 99`) || !strings.Contains(out, `"security_updates"`) {
		t.Errorf("api score: %d %s", code, out)
	}
	code, out = e.apiDo(key, "GET", "/api/v1/hosts/"+strconv.FormatInt(cleanID, 10), "")
	if code != 200 || !strings.Contains(out, `"security_score": 99`) {
		t.Errorf("api host: %d %s", code, out)
	}
}

func TestScoreGroups(t *testing.T) {
	e, admin, dbID := fleetEnv(t)
	ctx := context.Background()
	gid, err := e.st.CreateGroup(ctx, "Veritabanı", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.AddHostsToGroup(ctx, gid, []int64{dbID}); err != nil {
		t.Fatal(err)
	}
	if err := (&scoring.Engine{Store: e.st, EOL: e.eol.Data}).Run(ctx, timeutil.Now()); err != nil {
		t.Fatal(err)
	}
	db, _ := e.st.HostByID(ctx, dbID)
	status, body, _ := e.do(admin, "GET", "/groups", nil)
	expect(t, "groups score", status, 200, body, "Ortalama skor", ">"+strconv.Itoa(db.SecurityScore)+"<")
	status, body, _ = e.do(admin, "GET", "/groups/"+strconv.FormatInt(gid, 10), nil)
	expect(t, "group score", status, 200, body, "Grup güvenlik skoru", "score score--")
	hist, err := e.st.GroupScoreHistory(ctx, gid, timeutil.Now().AddDate(0, 0, -1), timeutil.Now())
	if err != nil || len(hist) != 1 || hist[0].Score != db.SecurityScore {
		t.Errorf("group history: %+v %v", hist, err)
	}
}
