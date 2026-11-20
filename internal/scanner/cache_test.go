package scanner

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"netio.patchman/internal/i18n"
	"netio.patchman/internal/store"
)

// api.osv.dev reports a different "modified" stamp in querybatch results than
// in the record body; the cache must still hit on the next scan.
func TestRecordCacheUsesQueryStamp(t *testing.T) {
	var gets, fail503 atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gets.Add(1)
		if fail503.Load() > 0 {
			fail503.Add(-1)
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if r.URL.Path == "/v1/vulns/MISSING-1" {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, `{"id":"UBUNTU-CVE-2026-1","modified":"2026-11-13T21:05:52.634632318Z","details":"text"}`)
	}))
	defer srv.Close()

	st, err := store.Open(context.Background(), t.TempDir()+"/t.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	l := i18n.MustLoad().Localizer(i18n.DefaultLocale)
	osv := NewOSVClient(srv.URL)
	osv.RetryDelay = time.Millisecond
	s := New(Options{Store: st, OSV: osv, L: l, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	ctx := context.Background()

	want := map[string]string{"UBUNTU-CVE-2026-1": "2026-11-19T22:50:00.882862Z"}
	fail503.Store(1) // first attempt fails, the retry succeeds
	recs, err := s.loadRecords(ctx, want, 0)
	if err != nil || recs["UBUNTU-CVE-2026-1"].Details != "text" {
		t.Fatalf("first load: %v %+v", err, recs)
	}
	if n := gets.Load(); n != 2 {
		t.Fatalf("GET requests = %d, want 2 (one retry)", n)
	}
	if _, err := s.loadRecords(ctx, want, 0); err != nil {
		t.Fatal(err)
	}
	if n := gets.Load(); n != 2 {
		t.Fatalf("second load fetched again (%d requests): cache missed", n)
	}
	// A new stamp from the query means the record changed upstream.
	want["UBUNTU-CVE-2026-1"] = "2026-11-20T08:00:00Z"
	if _, err := s.loadRecords(ctx, want, 0); err != nil {
		t.Fatal(err)
	}
	if n := gets.Load(); n != 3 {
		t.Fatalf("changed stamp: %d requests, want 3", n)
	}
	// 404 is not retried and not an error.
	recs, err = s.loadRecords(ctx, map[string]string{"MISSING-1": ""}, time.Hour)
	if err != nil || len(recs) != 0 || gets.Load() != 4 {
		t.Fatalf("missing record: %v %v %d", err, recs, gets.Load())
	}
}
