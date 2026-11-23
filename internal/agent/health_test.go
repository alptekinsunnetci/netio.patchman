package agent

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"netio.patchman/internal/i18n"
	"netio.patchman/internal/protocol"
)

func testHealth(t *testing.T) HealthRunner {
	t.Helper()
	return HealthRunner{
		L: i18n.MustLoad().Localizer(i18n.DefaultLocale),
		ServiceState: func(_ context.Context, name string) (bool, error) {
			return name == "nginx", nil
		},
		Resources: func(paths []string) (float64, float64, map[string]float64, error) {
			return 35, 91.5, map[string]float64{"/": 42, "/var": 97}, nil
		},
	}
}

func TestHealthChecks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/down" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, "status: ok")
	}))
	defer srv.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	open := ln.Addr().String()
	ln2, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := ln2.Addr().String()
	ln2.Close()
	defer ln.Close()

	h := testHealth(t)
	checks := []protocol.HealthCheck{
		{ID: 1, Name: "web", Type: protocol.HealthHTTP, Target: srv.URL + "/", Contains: "ok"},
		{ID: 2, Name: "web-down", Type: protocol.HealthHTTP, Target: srv.URL + "/down"},
		{ID: 3, Name: "web-text", Type: protocol.HealthHTTP, Target: srv.URL + "/", Contains: "ready"},
		{ID: 4, Name: "web-503", Type: protocol.HealthHTTP, Target: srv.URL + "/down", Expect: 503},
		{ID: 5, Name: "db-port", Type: protocol.HealthTCP, Target: open},
		{ID: 6, Name: "closed-port", Type: protocol.HealthTCP, Target: closed, TimeoutSeconds: 2},
		{ID: 7, Name: "nginx", Type: protocol.HealthService, Target: "nginx"},
		{ID: 8, Name: "mysql", Type: protocol.HealthService, Target: "mysql"},
		{ID: 9, Name: "load", Type: protocol.HealthResources, CPU: 80, Memory: 95, Disk: 90, Paths: []string{"/"}},
		{ID: 10, Name: "disk", Type: protocol.HealthResources, Disk: 90, Paths: []string{"/", "/var", "/missing"}},
		{ID: 11, Name: "bad", Type: protocol.HealthHTTP, Target: "file:///etc/passwd"},
		{ID: 12, Name: "bad-cmd", Type: protocol.HealthCommand, Target: "../../bin/sh"},
		{ID: 13, Name: "odd", Type: "ping"},
	}
	want := map[string]bool{"web": true, "web-down": false, "web-text": false, "web-503": true, "db-port": true, "closed-port": false,
		"nginx": true, "mysql": false, "load": true, "disk": false, "bad": false, "bad-cmd": false, "odd": false}
	res := h.Run(context.Background(), checks)
	if len(res) != len(checks) {
		t.Fatalf("results: %d", len(res))
	}
	for _, r := range res {
		if r.OK != want[r.Name] {
			t.Errorf("%s: ok=%v value=%q message=%q", r.Name, r.OK, r.Value, r.Message)
		}
		if !r.OK && r.Message == "" {
			t.Errorf("%s: failure without a message", r.Name)
		}
	}
	if res[8].Value != "CPU 35% · RAM 92% · / 42%" {
		t.Errorf("resources value: %q", res[8].Value)
	}
	if !strings.Contains(res[9].Message, "/var") || !strings.Contains(res[9].Message, "/missing") {
		t.Errorf("disk message: %q", res[9].Message)
	}
	if res[1].Value != "HTTP 503" {
		t.Errorf("http value: %q", res[1].Value)
	}
	if got := Failed(res); len(got) != 8 {
		t.Errorf("failed: %v", got)
	}
}

func TestHealthCommand(t *testing.T) {
	dir := t.TempDir()
	h := testHealth(t)
	h.Dir = dir
	ok, fail := "ok.sh", "fail.sh"
	okBody, failBody := "#!/bin/sh\necho all good\n", "#!/bin/sh\necho broken\nexit 3\n"
	if runtime.GOOS == "windows" {
		ok, fail = "ok.cmd", "fail.cmd"
		okBody, failBody = "@echo all good\r\n", "@echo broken\r\n@exit 3\r\n"
	}
	if err := os.WriteFile(filepath.Join(dir, ok), []byte(okBody), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, fail), []byte(failBody), 0o755); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		_ = os.Chmod(dir, 0o755)
	}
	res := h.Run(context.Background(), []protocol.HealthCheck{
		{Name: "ok", Type: protocol.HealthCommand, Target: ok},
		{Name: "fail", Type: protocol.HealthCommand, Target: fail},
		{Name: "missing", Type: protocol.HealthCommand, Target: "nope"},
	})
	if !res[0].OK || !strings.Contains(res[0].Value, "all good") {
		t.Errorf("ok command: %+v", res[0])
	}
	if res[1].OK || !strings.Contains(res[1].Value, "broken") || !strings.Contains(res[1].Message, "3") {
		t.Errorf("failing command: %+v", res[1])
	}
	if res[2].OK {
		t.Errorf("missing command passed")
	}
	if runtime.GOOS != "windows" {
		// A file others can write is refused.
		_ = os.Chmod(filepath.Join(dir, ok), 0o777)
		if r := h.Run(context.Background(), []protocol.HealthCheck{{Name: "ok", Type: protocol.HealthCommand, Target: ok}}); r[0].OK {
			t.Errorf("world-writable command ran")
		}
	}
}

func TestParseMeminfo(t *testing.T) {
	v := parseMeminfo(strings.NewReader("MemTotal:        8000000 kB\nMemFree:  100 kB\nMemAvailable:    2000000 kB\n"))
	if v != 75 {
		t.Errorf("memory: %v", v)
	}
	if parseMeminfo(strings.NewReader("junk")) != -1 {
		t.Errorf("unknown memory")
	}
}

func TestJobHealthBeforeAndAfter(t *testing.T) {
	health := testHealth(t)
	var ran []string
	exec := func(_ context.Context, c command, out *tailBuffer) int {
		ran = append(ran, c.name+" "+strings.Join(c.args, " "))
		return 0
	}
	r := JobRunner{L: health.L, PM: protocol.PMApt, RemoteUpdates: true, Exec: exec, Health: health,
		Sleep: func(context.Context, time.Duration) bool { return true }}
	params := func(checks []protocol.HealthCheck, policy string) map[string]string {
		b, _ := json.Marshal(checks)
		return map[string]string{protocol.ParamHealth: string(b), protocol.ParamHealthPolicy: policy}
	}
	failing := []protocol.HealthCheck{{ID: 1, Name: "mysql", Type: protocol.HealthService, Target: "mysql"}}
	passing := []protocol.HealthCheck{{ID: 2, Name: "nginx", Type: protocol.HealthService, Target: "nginx"}}

	// A failed check before the update stops it.
	res := r.Run(context.Background(), protocol.Job{ID: 1, Type: protocol.JobUpgradeAll, Params: params(failing, "")})
	if res.Succeeded || res.Health == nil || !res.Health.Aborted || len(ran) != 0 || len(res.Health.Before) != 1 {
		t.Fatalf("aborted job: %+v ran=%v", res, ran)
	}
	// "continue" runs the update; the checks after it are reported.
	res = r.Run(context.Background(), protocol.Job{ID: 2, Type: protocol.JobUpgradeAll, Params: params(failing, "continue")})
	if !res.Succeeded || len(ran) == 0 || res.Health == nil || len(res.Health.After) != 1 || res.Health.After[0].OK {
		t.Fatalf("continued job: %+v ran=%v", res, ran)
	}
	if !strings.Contains(res.Output, "mysql") {
		t.Errorf("output: %s", res.Output)
	}
	ran = nil
	res = r.Run(context.Background(), protocol.Job{ID: 3, Type: protocol.JobUpgradeAll, Params: params(passing, "")})
	if !res.Succeeded || res.Health == nil || !res.Health.Before[0].OK || !res.Health.After[0].OK {
		t.Fatalf("healthy job: %+v", res)
	}
	// A health_check job runs even with remote updates off and changes nothing.
	r.RemoteUpdates = false
	ran = nil
	res = r.Run(context.Background(), protocol.Job{ID: 4, Type: protocol.JobHealthCheck, Params: params(append(passing, failing...), "")})
	if res.Succeeded || res.Health == nil || len(res.Health.Checks) != 2 || len(ran) != 0 {
		t.Fatalf("health_check job: %+v", res)
	}
	res = r.Run(context.Background(), protocol.Job{ID: 5, Type: protocol.JobHealthCheck, Params: map[string]string{protocol.ParamHealth: "{bad"}})
	if res.Succeeded {
		t.Errorf("invalid checks accepted")
	}
}
