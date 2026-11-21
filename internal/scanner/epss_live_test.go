//go:build live

package scanner

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"netio.patchman/internal/config"
	"netio.patchman/internal/i18n"
	"netio.patchman/internal/store"
)

// TestLiveEPSS downloads the real EPSS file: go test -tags live -run LiveEPSS -v ./internal/scanner/
func TestLiveEPSS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	st, err := store.Open(ctx, t.TempDir()+"/live.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	sc := New(Options{Store: st, OSV: NewOSVClient("https://api.osv.dev"), EPSSURL: config.DefaultEPSSURL,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), L: i18n.MustLoad().Localizer(i18n.DefaultLocale)})
	start := time.Now()
	if err := sc.RefreshEPSS(ctx); err != nil {
		t.Fatal(err)
	}
	n, _ := st.EPSSCount(ctx)
	t.Logf("%d EPSS scores in %s", n, time.Since(start).Round(time.Millisecond))
	if n < 100000 {
		t.Errorf("too few scores: %d", n)
	}
}
