package web_test

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"netio.patchman/internal/store"
)

func TestSelfUpdateFromDashboard(t *testing.T) {
	e := newEnv(t)
	admin := setupAdmin(t, e)
	dir := e.selfUpd.DataDir
	status, body, _ := e.do(admin, "GET", "/settings/system", nil)
	expect(t, "no updater", status, 200, body, "COMPOSE_PROFILES=updater")
	if status, _, _ := e.do(admin, "POST", "/settings/system/self-update", url.Values{"_csrf": {e.csrf(admin)}}); status != http.StatusSeeOther {
		t.Fatalf("request without updater: %d", status)
	}
	if e.selfUpd.Pending() {
		t.Fatal("request written without an updater")
	}

	// The updater container reports its heartbeat.
	write := func(name, s string) {
		_ = os.MkdirAll(filepath.Join(dir, "update"), 0o755)
		if err := os.WriteFile(filepath.Join(dir, "update", name), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	heartbeat := func(at time.Time) {
		write("updater.json", `{"version":"0.7.0","seen_at":`+strconv.FormatInt(at.Unix(), 10)+`}`)
	}
	heartbeat(time.Now())
	// A newer release is known: its notice must not stay up during the update.
	e.latest.Store("0.3.0\n")
	e.do(admin, "POST", "/settings/system/update-check", url.Values{"_csrf": {e.csrf(admin)}})
	// The previous update's output and result are still on disk.
	write("status.json", `{"state":"succeeded","step":"done","started_at":1,"finished_at":2,"from":"0.5.0","to":"0.6.1"}`)
	write("update.log", "previous update\n")
	status, body, _ = e.do(admin, "GET", "/settings/system", nil)
	expect(t, "updater ready", status, 200, body, "Şimdi güncelle", "Yeni sürüm yayımlandı: 0.3.0")
	if status, _, _ := e.do(admin, "POST", "/settings/system/self-update", url.Values{"_csrf": {e.csrf(admin)}}); status != http.StatusSeeOther || !e.selfUpd.Pending() {
		t.Fatalf("request: %d pending=%v", status, e.selfUpd.Pending())
	}
	status, body, _ = e.do(admin, "GET", "/settings/system/self-update/status", nil)
	expect(t, "status json", status, 200, body, `"active":true`, `"step":"queued"`, `"stalled":false`)
	if strings.Contains(body, "previous update") {
		t.Error("previous output shown while queued")
	}
	status, body, _ = e.do(admin, "GET", "/settings/system", nil)
	expect(t, "pending page", status, 200, body, `data-selfupdate="/settings/system/self-update/status"`,
		`class="progress-steps__item is-current" data-step="queued"`, "Güncelleyici isteği birkaç saniye içinde alır.", "Sayfa, güncelleme bitince kendiliğinden yenilenir.")
	for _, s := range []string{"Şimdi güncelle", "Yeni sürüm yayımlandı: 0.3.0", "selfupdate-banner", "previous update", "0.5.0 sürümünden"} {
		if strings.Contains(body, s) {
			t.Errorf("pending page shows %q", s)
		}
	}
	// Every other page carries the progress banner instead of the release notice.
	status, body, _ = e.do(admin, "GET", "/dashboard", nil)
	expect(t, "banner", status, 200, body, "selfupdate-banner", "Sunucu güncelleniyor:", `data-step="queued"`, "İlerlemeyi göster")
	if strings.Contains(body, "0.3.0 sürümü yayımlandı") || strings.Contains(body, "Yeni sürüm: 0.3.0") {
		t.Error("release notice shown during the update")
	}

	// The updater takes the request: until its first status the update still
	// counts as starting (an older updater removes the request first).
	_ = os.Remove(filepath.Join(dir, "update-request.json"))
	status, body, _ = e.do(admin, "GET", "/settings/system/self-update/status", nil)
	expect(t, "taken request", status, 200, body, `"active":true`, `"step":"queued"`)

	// It works.
	started := strconv.FormatInt(time.Now().Unix(), 10)
	write("status.json", `{"state":"running","step":"build","started_at":`+started+`,"finished_at":0,"from":"0.6.1","to":"0.7.0"}`)
	write("update.log", "Step 3/9 : RUN go build\n")
	heartbeat(time.Now().Add(-time.Hour)) // no heartbeat while it works
	status, body, _ = e.do(admin, "GET", "/settings/system", nil)
	expect(t, "running page", status, 200, body, `class="progress-steps__item is-done" data-step="pull"`, `class="progress-steps__item is-current" data-step="build"`,
		`class="progress-steps__item is-todo" data-step="restart"`, "0.6.1 → 0.7.0", "birkaç dakika sürebilir", "Step 3/9")
	if strings.Contains(body, "Şimdi güncelle") || strings.Contains(body, "COMPOSE_PROFILES=updater") {
		t.Error("running page offers a new update")
	}
	status, body, _ = e.do(admin, "GET", "/settings/system/self-update/status", nil)
	expect(t, "running json", status, 200, body, `"step":"build"`, `"from":"0.6.1"`, `"to":"0.7.0"`, `"version":`, "Step 3/9")
	status, body, _ = e.do(admin, "GET", "/servers", nil)
	expect(t, "running banner", status, 200, body, `class="progress-steps__item is-current" data-step="build"`)

	// Operators see neither the banner nor the status.
	e.do(admin, "POST", "/users", url.Values{"_csrf": {e.csrf(admin)}, "name": {"Operatör"}, "email": {"op@example.test"}, "role": {"operator"},
		"password": {"operator-parola-1"}, "password_confirm": {"operator-parola-1"}})
	op := newClient()
	if status, _, _ = e.do(op, "POST", "/login", url.Values{"email": {"op@example.test"}, "password": {"operator-parola-1"}}); status != http.StatusSeeOther {
		t.Fatalf("operator login: %d", status)
	}
	if _, body, _ = e.do(op, "GET", "/dashboard", nil); strings.Contains(body, "selfupdate-banner") {
		t.Error("operator sees the update banner")
	}
	if status, _, _ = e.do(op, "GET", "/settings/system/self-update/status", nil); status != http.StatusForbidden {
		t.Errorf("operator status: %d", status)
	}

	// It finishes.
	finished := time.Now().Unix()
	write("status.json", `{"state":"succeeded","step":"done","started_at":`+started+`,"finished_at":`+strconv.FormatInt(finished, 10)+`,"from":"0.6.1","to":"0.7.0"}`)
	status, body, _ = e.do(admin, "GET", "/settings/system/self-update/status", nil)
	expect(t, "done json", status, 200, body, `"active":false`, `"state":"succeeded"`)
	ctx := context.Background()
	e.notifier.SelfUpdateFinished(ctx, e.selfUpd)
	e.notifier.SelfUpdateFinished(ctx, e.selfUpd)
	notes, _, _ := e.st.ListNotifications(ctx, false, store.Page{Number: 1, Size: 50})
	n := 0
	for _, x := range notes {
		if x.Kind == "self_update_succeeded" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("self_update notifications: %d", n)
	}
	heartbeat(time.Now())
	status, body, _ = e.do(admin, "GET", "/settings/system", nil)
	expect(t, "done page", status, 200, body, "0.6.1 sürümünden 0.7.0 sürümüne güncellendi", "Şimdi güncelle")
	if strings.Contains(body, "selfupdate-banner") || strings.Contains(body, "data-selfupdate=") {
		t.Error("done page still polls")
	}
	// The result stays on the other pages for a while.
	status, body, _ = e.do(admin, "GET", "/dashboard", nil)
	expect(t, "result banner", status, 200, body, "0.6.1 sürümünden 0.7.0 sürümüne güncellendi")
	if strings.Contains(body, "data-selfupdate=") {
		t.Error("result banner polls")
	}
	if !strings.Contains(body, `data-selfupdate-result="`+strconv.FormatInt(finished, 10)+`"`) || !strings.Contains(body, "data-selfupdate-dismiss") {
		t.Error("result banner cannot be closed")
	}
	// Closed by the user (app.js sets the cookie): gone on every page.
	srvURL, _ := url.Parse(e.srv.URL)
	admin.Jar.SetCookies(srvURL, []*http.Cookie{{Name: "np_selfupdate_seen", Value: strconv.FormatInt(finished, 10), Path: "/"}})
	if _, body, _ = e.do(admin, "GET", "/servers", nil); strings.Contains(body, "sürümüne güncellendi") {
		t.Error("closed result shown again")
	}
	if _, body, _ = e.do(admin, "GET", "/settings/system", nil); !strings.Contains(body, "0.6.1 sürümünden 0.7.0 sürümüne güncellendi") {
		t.Error("system page lost the last result")
	}
	admin.Jar.SetCookies(srvURL, []*http.Cookie{{Name: "np_selfupdate_seen", Value: "", Path: "/", MaxAge: -1}})
	// A success goes away after 10 minutes, a failure stays for an hour.
	ago := func(d time.Duration) string { return strconv.FormatInt(time.Now().Add(-d).Unix(), 10) }
	if err := os.WriteFile(filepath.Join(dir, ".update-requested-at"), []byte(ago(2*time.Hour)), 0o644); err != nil {
		t.Fatal(err)
	}
	write("status.json", `{"state":"succeeded","step":"done","started_at":`+ago(12*time.Minute)+`,"finished_at":`+ago(11*time.Minute)+`,"from":"0.7.0","to":"0.7.0"}`)
	if _, body, _ = e.do(admin, "GET", "/dashboard", nil); strings.Contains(body, "sürümüyle yeniden derlenip") {
		t.Error("old success on the dashboard")
	}
	write("status.json", `{"state":"failed","step":"build","started_at":`+ago(31*time.Minute)+`,"finished_at":`+ago(30*time.Minute)+`,"from":"0.7.0","to":"0.7.1"}`)
	if _, body, _ = e.do(admin, "GET", "/dashboard", nil); !strings.Contains(body, "Son güncelleme başarısız oldu") {
		t.Error("recent failure missing on the dashboard")
	}
	write("status.json", `{"state":"failed","step":"build","started_at":`+ago(62*time.Minute)+`,"finished_at":`+ago(61*time.Minute)+`,"from":"0.7.0","to":"0.7.1"}`)
	if _, body, _ = e.do(admin, "GET", "/dashboard", nil); strings.Contains(body, "Son güncelleme başarısız oldu") {
		t.Error("old failure on the dashboard")
	}
	hourAgo := ago(time.Hour)
	write("status.json", `{"state":"succeeded","step":"done","started_at":`+hourAgo+`,"finished_at":`+hourAgo+`,"from":"0.7.0","to":"0.7.0"}`)
	// Nothing new to pull reads as such.
	if _, body, _ = e.do(admin, "GET", "/settings/system", nil); !strings.Contains(body, "Yeni sürüm bulunamadı; sunucu 0.7.0 sürümüyle yeniden derlenip başlatıldı") {
		t.Error("same-version result missing")
	}

	// A request no updater picks up is reported.
	if err := e.selfUpd.Request("admin@example.test"); err != nil {
		t.Fatal(err)
	}
	heartbeat(time.Now().Add(-time.Hour))
	status, body, _ = e.do(admin, "GET", "/settings/system/self-update/status", nil)
	expect(t, "stalled json", status, 200, body, `"stalled":true`)
	status, body, _ = e.do(admin, "GET", "/settings/system", nil)
	expect(t, "stalled page", status, 200, body, "docker compose ps updater")
	if strings.Contains(body, "data-selfupdate-stalled hidden") {
		t.Error("stalled note hidden")
	}
}
