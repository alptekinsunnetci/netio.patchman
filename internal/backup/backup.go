// Package backup takes automatic daily copies of the database.
//
// A backup is a consistent SQLite copy (VACUUM INTO) written as
// netio-patchman-YYYYMMDD-HHMMSS.db (display time zone) into the backup
// directory; the newest N files are kept. The schedule and retention are
// runtime settings (settings.Values.Backup*); the directory is bootstrap
// configuration (PATCHMAN_BACKUP_DIR). A day whose backup time passed while
// the server was down is caught up at the next tick, unlike update schedules,
// because a late backup is better than none.
package backup

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"netio.patchman/internal/i18n"
	"netio.patchman/internal/settings"
	"netio.patchman/internal/store"
	"netio.patchman/internal/timeutil"
)

// File is a stored backup.
type File struct {
	Name    string
	Size    int64
	ModTime time.Time
}

// Runner takes and prunes backups.
type Runner struct {
	Store  *store.Store
	Dir    string
	Zone   *timeutil.Zone
	L      i18n.Localizer
	Logger *slog.Logger
	// OnFailure is called after a failed automatic or manual backup.
	OnFailure func(ctx context.Context, err error)

	mu      sync.Mutex // one backup at a time
	ticking atomic.Bool
}

var nameRE = regexp.MustCompile(`^netio-patchman-[0-9]{8}-[0-9]{6}\.db$`)

// ValidName reports whether name is a backup file name (no paths).
func ValidName(name string) bool { return nameRE.MatchString(name) }

// Due reports whether the daily backup should run at now: today's backup
// time (display zone) has passed and no backup was taken since then.
func Due(cfg settings.Values, now time.Time, loc *time.Location) bool {
	if !cfg.BackupEnabled {
		return false
	}
	lt := now.In(loc)
	at := time.Date(lt.Year(), lt.Month(), lt.Day(), cfg.BackupMinute/60, cfg.BackupMinute%60, 0, 0, loc)
	return !now.Before(at) && cfg.BackupLastAt.Before(at)
}

// Tick runs the daily backup when it is due (called every minute, in its own
// goroutine so a large database does not delay update schedules). A tick
// while a backup is still running does nothing.
func (r *Runner) Tick(ctx context.Context, now time.Time) {
	if !r.ticking.CompareAndSwap(false, true) {
		return
	}
	defer r.ticking.Store(false)
	cfg, err := settings.Load(ctx, r.Store)
	if err != nil || !Due(cfg, now, r.Zone.Location()) {
		return
	}
	if _, err := r.Run(ctx, cfg.BackupKeep); err != nil && r.OnFailure != nil {
		r.OnFailure(ctx, err)
	}
}

// Run takes a backup now and keeps the newest keep files.
func (r *Runner) Run(ctx context.Context, keep int) (File, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	start := timeutil.Now()
	f, err := r.take(ctx, start)
	if err != nil {
		r.Logger.Error(r.L.T("log.backup.failed"), slog.String("dir", r.Dir), slog.String("error", err.Error()))
		_ = r.Store.SaveSettings(ctx, map[string]string{
			settings.KeyBackupLastError: err.Error(), settings.KeyBackupLastErrorAt: strconv.FormatInt(start.Unix(), 10),
		})
		return f, err
	}
	_ = r.Store.SaveSettings(ctx, map[string]string{settings.KeyBackupLastAt: strconv.FormatInt(start.Unix(), 10),
		settings.KeyBackupLastError: "", settings.KeyBackupLastErrorAt: "0"})
	removed := r.prune(keep)
	r.Logger.Info(r.L.T("log.backup.done"), slog.String("file", f.Name), slog.Int64("bytes", f.Size),
		slog.Duration("duration", time.Since(start).Round(time.Millisecond)), slog.Int("removed", removed))
	return f, nil
}

func (r *Runner) take(ctx context.Context, at time.Time) (File, error) {
	if err := os.MkdirAll(r.Dir, 0o750); err != nil {
		return File{}, err
	}
	name := "netio-patchman-" + at.In(r.Zone.Location()).Format("20060102-150405") + ".db"
	final := filepath.Join(r.Dir, name)
	tmp := filepath.Join(r.Dir, "."+name+".tmp")
	_ = os.Remove(tmp) // VACUUM INTO refuses an existing file
	if err := r.Store.Backup(ctx, tmp); err != nil {
		_ = os.Remove(tmp)
		return File{}, err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return File{}, err
	}
	if err := os.Rename(tmp, final); err != nil {
		_ = os.Remove(tmp)
		return File{}, err
	}
	st, err := os.Stat(final)
	if err != nil {
		return File{}, err
	}
	return File{Name: name, Size: st.Size(), ModTime: st.ModTime().UTC()}, nil
}

// List returns the backups, newest first.
func (r *Runner) List() ([]File, error) {
	entries, err := os.ReadDir(r.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []File
	for _, e := range entries {
		if e.IsDir() || !ValidName(e.Name()) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, File{Name: e.Name(), Size: info.Size(), ModTime: info.ModTime().UTC()})
	}
	// The name holds the timestamp, so name order is time order.
	sort.Slice(out, func(i, j int) bool { return out[i].Name > out[j].Name })
	return out, nil
}

// prune deletes all but the newest keep backups and returns how many it removed.
func (r *Runner) prune(keep int) int {
	files, err := r.List()
	if err != nil || keep < 1 {
		return 0
	}
	removed := 0
	for _, f := range files[min(keep, len(files)):] {
		if err := os.Remove(filepath.Join(r.Dir, f.Name)); err == nil {
			removed++
		}
	}
	return removed
}

// Path returns the full path of a backup file, or an error for names that
// are not backups.
func (r *Runner) Path(name string) (string, error) {
	if !ValidName(name) {
		return "", fmt.Errorf("backup: invalid name %q", name)
	}
	p := filepath.Join(r.Dir, name)
	if _, err := os.Stat(p); err != nil {
		return "", err
	}
	return p, nil
}
