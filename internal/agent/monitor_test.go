package agent

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"netio.patchman/internal/i18n"
	"netio.patchman/internal/protocol"
)

// TestMonitorRoundPosts runs a real monitoring round (platform resource
// readers included) against a fake server.
func TestMonitorRoundPosts(t *testing.T) {
	var mu sync.Mutex
	var got []protocol.HealthStatus
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body io.Reader = r.Body
		if strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip") {
			zr, err := gzip.NewReader(r.Body)
			if err != nil {
				http.Error(w, "gzip", 400)
				return
			}
			body = zr
		}
		var st protocol.HealthStatus
		if err := json.NewDecoder(body).Decode(&st); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		mu.Lock()
		got, paths = append(got, st), append(paths, r.URL.Path)
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	client, err := NewClient(Config{ServerURL: u})
	if err != nil {
		t.Fatal(err)
	}
	client.SetSecret("s")
	// In process: no loopback networking needed (some WSL setups lack it).
	client.http = &http.Client{Transport: handlerTransport{srv.Config.Handler}}
	l := i18n.MustLoad().Localizer(i18n.DefaultLocale)
	var logs strings.Builder
	var logMu sync.Mutex
	r := &Runner{l: l, logger: slog.New(slog.NewTextHandler(lockedWriter{&logMu, &logs}, nil)), client: client, jobs: JobRunner{L: l, Health: HealthRunner{L: l}}}

	// Through the check-in handling, as the main loop calls it.
	if !r.afterCheckin(context.Background(), protocol.CheckinResponse{Health: &protocol.HealthSchedule{IntervalSeconds: 300}}) {
		t.Fatal("afterCheckin stopped the agent")
	}
	deadline := time.Now().Add(20 * time.Second)
	for r.healthBusy.Load() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	// Not due again within the interval.
	r.monitor(context.Background(), &protocol.HealthSchedule{IntervalSeconds: 300})
	for r.healthBusy.Load() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || paths[0] != protocol.PathHealth {
		logMu.Lock()
		defer logMu.Unlock()
		t.Fatalf("posts: %d %v; agent log: %s", len(got), paths, logs.String())
	}
	res := got[0].Resources
	if res == nil || res.CPUs <= 0 || res.MemoryTotal <= 0 || len(res.Disks) == 0 || res.Disks[0].Total <= 0 || res.CPUPercent == nil {
		t.Fatalf("resources: %+v", res)
	}
	t.Logf("resources: %+v", *res)
}

type lockedWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (l lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// handlerTransport serves requests with a handler, without a network.
type handlerTransport struct{ h http.Handler }

func (t handlerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	t.h.ServeHTTP(rec, r)
	return rec.Result(), nil
}
