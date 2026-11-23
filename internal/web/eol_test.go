package web_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"netio.patchman/internal/config"
	"netio.patchman/internal/eol"
	"netio.patchman/internal/i18n"
	"netio.patchman/internal/protocol"
	"netio.patchman/internal/settings"
	"netio.patchman/internal/timeutil"
)

func TestEOLReport(t *testing.T) {
	e, admin, _ := fleetEnv(t)
	ctx := context.Background()
	info := protocol.HostInfo{Hostname: "legacy-01", MachineID: "eol1", OSID: "ubuntu", OSVersionID: "20.04", OSName: "Ubuntu 20.04.6 LTS",
		Arch: "amd64", PackageManager: "apt", AgentVersion: "0.10.0", Capabilities: []string{protocol.CapServices}}
	client, id := e.agentFor(info)
	if err := client.Report(ctx, protocol.Report{Host: info, CollectedAt: timeutil.Now(), Packages: []protocol.Package{
		{Name: "php7.4-common", Version: "7.4.3-4ubuntu2.24", Arch: "amd64", SourceName: "php7.4"},
		{Name: "nginx", Version: "1.18.0-0ubuntu1.5", Arch: "amd64", SourceName: "nginx"},
	}, Services: []protocol.Service{}}); err != nil {
		t.Fatal(err)
	}
	hostURL := "/servers/" + strconv.FormatInt(id, 10)

	status, body, _ := e.do(admin, "GET", hostURL, nil)
	expect(t, "host header", status, 200, body, "İşletim sistemi destek dışı")
	status, body, _ = e.do(admin, "GET", hostURL+"?tab=software", nil)
	expect(t, "host software EOL column", status, 200, body, "Destek bitişi", "Destek dışı")

	status, body, _ = e.do(admin, "GET", "/software?tab=eol", nil)
	expect(t, "EOL report", status, 200, body, "Ubuntu 20.04", "PHP 7.4", "Nginx 1.18", "legacy-01", "Destek dışı işletim sistemi")
	// Debian 12 of the fleetEnv host is supported: not in the default view.
	if strings.Contains(body, "Debian 12") {
		t.Errorf("supported release in the attention view")
	}
	status, body, _ = e.do(admin, "GET", "/software?tab=eol&status=all&kind=os", nil)
	expect(t, "EOL report, all OS", status, 200, body, "Debian 12", "Ubuntu 20.04")
	if strings.Contains(body, "PHP 7.4") {
		t.Errorf("software in the OS view")
	}

	status, body, _ = e.do(admin, "GET", "/dashboard", nil)
	expect(t, "dashboard EOL panel", status, 200, body, "Destek bitişi", "Destek dışı işletim sistemi", "/software?tab=eol&kind=os&status=eol")

	key := e.createAPIKey(admin, "eol", false)
	code, out := e.apiDo(key, "GET", "/api/v1/eol", "")
	if code != 200 || !strings.Contains(out, `"product": "ubuntu"`) || !strings.Contains(out, `"status": "eol"`) {
		t.Errorf("api eol: %d %s", code, out)
	}

	// Notices: once per release and kind.
	now := timeutil.Now()
	notices, err := eol.Notices(ctx, e.st, eol.Embedded(), now, 90*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, n := range notices {
		names[n.Name+" "+n.Cycle+" "+n.Kind] = true
	}
	if !names["Ubuntu 20.04 eol"] || !names["PHP 7.4 eol"] {
		t.Errorf("notices: %v", names)
	}
	again, _ := eol.Notices(ctx, e.st, eol.Embedded(), now, 90*24*time.Hour)
	if len(again) != 0 {
		t.Errorf("repeated notices: %d", len(again))
	}
}

func TestEOLSourceRefresh(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		switch r.URL.Path {
		case "/api/ubuntu.json":
			_, _ = io.WriteString(w, `[{"cycle":"20.04","eol":"2099-01-01","lts":true}]`)
		case "/api/nginx.json":
			w.WriteHeader(http.StatusBadGateway)
		default:
			_, _ = io.WriteString(w, `[{"cycle":"1","eol":false}]`)
		}
	}))
	defer srv.Close()
	live, err := settings.NewLive(ctx, config.Config{EOLURL: srv.URL + "/api"}, e.st)
	if err != nil {
		t.Fatal(err)
	}
	src := &eol.Source{Store: e.st, System: live, L: i18n.MustLoad().Localizer(i18n.DefaultLocale), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := src.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if !src.Due(ctx, timeutil.Now()) {
		t.Errorf("refresh not due before the first one")
	}
	err = src.Refresh(ctx)
	if err == nil || !strings.Contains(err.Error(), "nginx") {
		t.Errorf("refresh error: %v", err)
	}
	if requests != len(eol.Products()) {
		t.Errorf("requests: %d, products %d", requests, len(eol.Products()))
	}
	if r, ok := src.Data().Find("ubuntu", "20.04"); !ok || r.EOL.Year() != 2099 {
		t.Errorf("refreshed ubuntu: %+v", r)
	}
	// The failed product keeps the built-in calendar.
	if len(src.Data()["nginx"]) < 10 {
		t.Errorf("nginx calendar lost")
	}
	if src.Due(ctx, timeutil.Now()) {
		t.Errorf("refresh due right after one")
	}
	// A restart reads the stored calendars.
	src2 := &eol.Source{Store: e.st, System: live}
	if err := src2.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if r, _ := src2.Data().Find("ubuntu", "20.04"); r.EOL.Year() != 2099 {
		t.Errorf("stored calendar not loaded: %+v", r)
	}
}
