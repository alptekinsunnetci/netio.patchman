package eol

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"netio.patchman/internal/brand"
	"netio.patchman/internal/i18n"
	"netio.patchman/internal/settings"
	"netio.patchman/internal/store"
	"netio.patchman/internal/timeutil"
	"netio.patchman/internal/version"
)

// Source holds the current support calendars: the built-in snapshot,
// replaced product by product by stored downloads.
type Source struct {
	Store  *store.Store
	System *settings.Live
	Logger *slog.Logger
	L      i18n.Localizer
	// Client fetches the calendars; nil uses a client with a timeout.
	Client *http.Client

	data atomic.Pointer[Data]
	mu   sync.Mutex // one refresh at a time
}

// Data returns the current calendars.
func (s *Source) Data() Data {
	if d := s.data.Load(); d != nil {
		return *d
	}
	d := Embedded()
	s.data.Store(&d)
	return d
}

// Use replaces the current calendars (tests pin them to a reference date).
func (s *Source) Use(d Data) { s.data.Store(&d) }

// Load reads stored calendars over the built-in snapshot.
func (s *Source) Load(ctx context.Context) error {
	d := Embedded()
	stored, err := s.Store.EOLProducts(ctx)
	if err == nil {
		for p, raw := range stored {
			if rel, err := ParseProduct([]byte(raw)); err == nil {
				d[p] = rel
			}
		}
	}
	s.data.Store(&d)
	return err
}

func (s *Source) url() string {
	if s.System == nil {
		return ""
	}
	return s.System.Get().EOLURL
}

// Refresh downloads every calendar the package uses. A product that fails
// keeps its previous data; the error lists the failures.
func (s *Source) Refresh(ctx context.Context) error {
	base := s.url()
	if base == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	client := s.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	d := Data{}
	for p, r := range s.Data() {
		d[p] = r
	}
	var errs []error
	updated := 0
	for _, p := range Products() {
		raw, err := fetch(ctx, client, base+"/"+p+".json")
		if err == nil {
			var rel []Release
			if rel, err = ParseProduct(raw); err == nil {
				if err = s.Store.SaveEOLProduct(ctx, p, string(raw)); err == nil {
					d[p] = rel
					updated++
				}
			}
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p, err))
		}
		if ctx.Err() != nil {
			break
		}
	}
	s.data.Store(&d)
	if updated > 0 {
		_ = settings.Stamp(ctx, s.Store, settings.KeyEOLUpdatedAt, timeutil.Now())
	}
	if s.Logger != nil {
		s.Logger.Info(s.L.T("log.eol.refreshed"), slog.Int("products", updated), slog.Int("failed", len(errs)))
	}
	return errors.Join(errs...)
}

func fetch(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", brand.Name+"/"+version.Version)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 4<<20))
}

// Due reports whether the daily refresh is due.
func (s *Source) Due(ctx context.Context, now time.Time) bool {
	if s.url() == "" {
		return false
	}
	v, err := settings.Load(ctx, s.Store)
	return err == nil && now.Sub(v.EOLUpdatedAt) >= 24*time.Hour
}

// Notice is a release whose end of support was reached or is near, not
// notified before.
type Notice struct {
	Group
	Kind string // StatusEOL or StatusSoon
}

// Notices assesses all hosts (no user scope) and returns releases to
// notify about: out of support or ending soon, once per release and kind.
// Software the distribution keeps patching is left out.
func Notices(ctx context.Context, st *store.Store, d Data, now time.Time, warn time.Duration) ([]Notice, error) {
	hosts, err := st.EOLHosts(ctx, 0)
	if err != nil {
		return nil, err
	}
	var out []Notice
	for _, g := range GroupItems(Assess(d, now, warn, Inputs(hosts))) {
		if g.Status != StatusEOL && g.Status != StatusSoon {
			continue
		}
		if g.Kind == KindSoftware && g.DistroSupported == len(g.Hosts) {
			continue
		}
		fresh, err := st.MarkEOLNotice(ctx, g.Product, g.Cycle, g.Status)
		if err != nil {
			return out, err
		}
		if fresh {
			out = append(out, Notice{Group: g, Kind: g.Status})
		}
	}
	return out, nil
}

// Inputs converts stored hosts for Assess.
func Inputs(hosts []store.EOLHost) []HostInput {
	out := make([]HostInput, len(hosts))
	for i, h := range hosts {
		in := HostInput{ID: h.ID, Hostname: h.Hostname, OSID: h.OSID, OSVersionID: h.OSVersionID, OSName: h.OSName, Kernel: h.Kernel, PackageManager: h.PackageManager}
		for _, s := range h.Software {
			in.Software = append(in.Software, SoftwareInput{Software: s.Software, Cycle: s.Cycle, Version: s.Version, PackageVersion: s.PackageVersion})
		}
		out[i] = in
	}
	return out
}
