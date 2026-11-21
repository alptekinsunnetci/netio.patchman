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
	write("updater.json", `{"version":"0.7.0","seen_at":`+strconv.FormatInt(time.Now().Unix(), 10)+`}`)
	status, body, _ = e.do(admin, "GET", "/settings/system", nil)
	expect(t, "updater ready", status, 200, body, "Şimdi güncelle")
	if status, _, _ := e.do(admin, "POST", "/settings/system/self-update", url.Values{"_csrf": {e.csrf(admin)}}); status != http.StatusSeeOther || !e.selfUpd.Pending() {
		t.Fatalf("request: %d pending=%v", status, e.selfUpd.Pending())
	}
	status, body, _ = e.do(admin, "GET", "/settings/system/self-update/status", nil)
	expect(t, "status json", status, 200, body, `"active":true`)
	status, body, _ = e.do(admin, "GET", "/settings/system", nil)
	expect(t, "pending page", status, 200, body, "data-selfupdate=", "Güncelleme isteği iletildi")

	// The updater takes the request, works and finishes.
	_ = os.Remove(filepath.Join(dir, "update-request.json"))
	write("status.json", `{"state":"running","step":"build","started_at":1,"finished_at":0,"from":"0.6.1","to":"0.7.0"}`)
	write("update.log", "Step 3/9 : RUN go build\n")
	status, body, _ = e.do(admin, "GET", "/settings/system", nil)
	expect(t, "running page", status, 200, body, "Güncelleme sürüyor: sunucu imajı derleniyor.", "Step 3/9")
	finished := time.Now().Unix()
	write("status.json", `{"state":"succeeded","step":"done","started_at":1,"finished_at":`+strconv.FormatInt(finished, 10)+`,"from":"0.6.1","to":"0.7.0"}`)
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
	status, body, _ = e.do(admin, "GET", "/settings/system", nil)
	expect(t, "done page", status, 200, body, "0.6.1 sürümünden 0.7.0 sürümüne güncellendi")
	if !strings.Contains(body, "Şimdi güncelle") {
		t.Error("button missing after the update")
	}
}
