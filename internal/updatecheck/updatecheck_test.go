package updatecheck

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"netio.patchman/internal/i18n"
	"netio.patchman/internal/settings"
	"netio.patchman/internal/store"
)

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"0.2.0", "0.2.0", 0},
		{"0.3.0", "0.2.0", 1},
		{"0.10.0", "0.9.1", 1},
		{"1.0", "1.0.0", 0},
		{"0.2.0", "0.2.0-dev", 1},
		{"0.1.0-dev", "0.2.0", -1},
		{"v0.2.1", "0.2.0", 1},
	}
	for _, c := range cases {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestParse(t *testing.T) {
	cases := []struct {
		body, version, rel string
		ok                 bool
	}{
		{"0.3.0\n", "0.3.0", "", true},
		{"\xef\xbb\xbf0.3.0\r\n", "0.3.0", "", true},
		{"v1.2.3", "1.2.3", "", true},
		{`{"tag_name":"v0.4.0","html_url":"https://github.com/o/r/releases/tag/v0.4.0"}`, "0.4.0", "https://github.com/o/r/releases/tag/v0.4.0", true},
		{`{"tag_name":"v0.4.0","html_url":"javascript:alert(1)"}`, "0.4.0", "", true},
		{"<html>not found</html>", "", "", false},
		{"", "", "", false},
		{`{"message":"Not Found"}`, "", "", false},
	}
	for _, c := range cases {
		v, rel, ok := Parse([]byte(c.body))
		if v != c.version || rel != c.rel || ok != c.ok {
			t.Errorf("Parse(%q) = %q, %q, %v", c.body, v, rel, ok)
		}
	}
}

func TestCheck(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var body atomic.Value
	body.Store("0.3.0\n")
	var ua atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua.Store(r.UserAgent())
		if r.URL.Path == "/missing" {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, body.Load().(string))
	}))
	defer srv.Close()

	live := settings.StaticLive(settings.System{UpdateURL: srv.URL + "/VERSION"})
	l := i18n.MustLoad().Localizer(i18n.DefaultLocale)
	o := Options{Current: "0.2.0", Store: st, System: live, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), L: l}
	c := New(ctx, o)

	s := c.Check(ctx)
	if !s.Available() || s.Latest != "0.3.0" || s.Error != "" || s.CheckedAt.IsZero() {
		t.Fatalf("check: %+v", s)
	}
	if got, _ := ua.Load().(string); got != "netio-patchman-server/0.2.0" {
		t.Errorf("User-Agent = %q", got)
	}
	c.Check(ctx) // same version: no second notification
	if n, _ := st.UnreadNotifications(ctx); n != 1 {
		t.Fatalf("notifications after two checks = %d, want 1", n)
	}
	rows, _, _ := st.ListNotifications(ctx, false, store.Page{Number: 1, Size: 10})
	if rows[0].Kind != NotificationKind || rows[0].Params["version"] != "0.3.0" || rows[0].Params["current"] != "0.2.0" {
		t.Errorf("notification = %+v", rows[0])
	}

	// State survives a restart.
	if s := New(ctx, o).Status(); s.Latest != "0.3.0" || !s.Available() {
		t.Errorf("reloaded status: %+v", s)
	}

	// A failed check keeps the known version and records the error.
	live2 := settings.StaticLive(settings.System{UpdateURL: srv.URL + "/missing"})
	o.System = live2
	c2 := New(ctx, o)
	s = c2.Check(ctx)
	if s.Latest != "0.3.0" || !strings.Contains(s.Error, "404") {
		t.Errorf("failed check: %+v", s)
	}

	// Garbage is rejected.
	body.Store("<html></html>")
	o.System = live
	s = New(ctx, o).Check(ctx)
	if s.Error == "" || s.Latest != "0.3.0" {
		t.Errorf("bad body: %+v", s)
	}

	// Running the latest version: nothing available.
	body.Store("0.3.0")
	o.Current = "0.3.0"
	if s := New(ctx, o).Check(ctx); s.Available() || s.Error != "" {
		t.Errorf("up to date: %+v", s)
	}

	// Disabled: no request.
	ua.Store("")
	o.System = settings.StaticLive(settings.System{})
	if s := New(ctx, o).Check(ctx); s.Enabled {
		t.Errorf("disabled: %+v", s)
	}
	if got, _ := ua.Load().(string); got != "" {
		t.Errorf("request sent while disabled")
	}
}
