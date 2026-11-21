package backup

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"netio.patchman/internal/i18n"
	"netio.patchman/internal/settings"
	"netio.patchman/internal/store"
	"netio.patchman/internal/timeutil"
)

func TestDue(t *testing.T) {
	loc, _ := time.LoadLocation("Europe/Istanbul")
	cfg := settings.Defaults() // 02:30
	at := func(s string) time.Time {
		v, _ := time.ParseInLocation("2006-01-02 15:04", s, loc)
		return v.UTC()
	}
	if Due(cfg, at("2026-11-21 02:29"), loc) && !cfg.BackupLastAt.IsZero() {
		t.Error("due before the backup time")
	}
	cfg.BackupLastAt = at("2026-11-20 02:30")
	if Due(cfg, at("2026-11-21 02:29"), loc) {
		t.Error("due before today's time")
	}
	if !Due(cfg, at("2026-11-21 02:30"), loc) {
		t.Error("not due at the backup time")
	}
	if !Due(cfg, at("2026-11-21 09:00"), loc) {
		t.Error("missed backup not caught up")
	}
	cfg.BackupLastAt = at("2026-11-21 02:31")
	if Due(cfg, at("2026-11-21 23:59"), loc) {
		t.Error("second backup on the same day")
	}
	cfg.BackupEnabled = false
	cfg.BackupLastAt = time.Time{}
	if Due(cfg, at("2026-11-21 09:00"), loc) {
		t.Error("disabled backup due")
	}
}

func TestRunAndPrune(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "db.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.SaveSettings(ctx, map[string]string{"x.marker": "kayıt"}); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "backups")
	r := &Runner{Store: st, Dir: dir, Zone: timeutil.NewZone(time.UTC), L: i18n.MustLoad().Localizer(i18n.DefaultLocale),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	// Older backups and unrelated files in the directory.
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"netio-patchman-20260101-023000.db", "netio-patchman-20260102-023000.db", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	f, err := r.Run(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	files, _ := r.List()
	if len(files) != 2 || files[0].Name != f.Name || files[1].Name != "netio-patchman-20260102-023000.db" {
		t.Fatalf("files after prune: %+v", files)
	}
	if _, err := os.Stat(filepath.Join(dir, "notes.txt")); err != nil {
		t.Error("unrelated file removed")
	}
	// The copy is a readable database with the data.
	p, err := r.Path(f.Name)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", p)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var v string
	if err := db.QueryRow(`SELECT value FROM settings WHERE key = 'x.marker'`).Scan(&v); err != nil || v != "kayıt" {
		t.Errorf("backup content: %q %v", v, err)
	}
	cfg, _ := settings.Load(ctx, st)
	if cfg.BackupLastAt.IsZero() || cfg.BackupLastError != "" {
		t.Errorf("state: %+v", cfg)
	}
	for _, bad := range []string{"../db.db", "netio-patchman-2026.db", "notes.txt", "/etc/passwd"} {
		if _, err := r.Path(bad); err == nil {
			t.Errorf("path accepted %q", bad)
		}
	}
}
