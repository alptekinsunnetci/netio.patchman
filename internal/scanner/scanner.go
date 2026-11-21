// Package scanner matches host inventories against OSV vulnerability data and
// maintains findings. Vulnerability text is stored verbatim; nothing is translated.
package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"netio.patchman/internal/brand"
	"netio.patchman/internal/i18n"
	"netio.patchman/internal/protocol"
	"netio.patchman/internal/settings"
	"netio.patchman/internal/store"
	"netio.patchman/internal/timeutil"
	"netio.patchman/internal/version"
	"netio.patchman/internal/vuln"
)

// Options configures the scanner.
type Options struct {
	Store  *store.Store
	OSV    *OSVClient
	KEVURL string // empty disables KEV
	// MSRCURL is the Security Update Guide API for Windows hosts (empty disables).
	MSRCURL string
	// System, when set, supplies the OSV and KEV addresses (editable at
	// runtime); OSV is then only a template for the HTTP settings.
	System   *settings.Live
	Logger   *slog.Logger
	L        i18n.Localizer
	QueryTTL time.Duration // how long an OSV package query result is reused
	VulnTTL  time.Duration // how long CVE details are reused
	Workers  int
	// AfterScan runs after hosts were scanned (alert dispatch).
	AfterScan func(ctx context.Context)
	// Daily runs once a day (retention, offline checks are separate).
	Daily func(ctx context.Context)
}

// Status is shown on the settings page.
type Status struct {
	LastRunAt   time.Time
	LastError   string
	LastErrorAt time.Time
	Scanning    bool
}

// Scanner is the background vulnerability scanner.
type Scanner struct {
	o       Options
	trigger chan struct{}

	mu     sync.Mutex
	status Status
	osv    *OSVClient // client for the current System OSV address
	msrc   *MSRCClient
}

// sources returns the OSV client and the KEV feed address (empty when the
// feed is disabled) for the current configuration.
func (s *Scanner) sources() (*OSVClient, string) {
	if s.o.System == nil {
		return s.o.OSV, s.o.KEVURL
	}
	sys := s.o.System.Get()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.osv == nil || s.osv.BaseURL != sys.OSVURL {
		c := NewOSVClient(sys.OSVURL)
		if s.o.OSV != nil {
			c.HTTP, c.RetryDelay = s.o.OSV.HTTP, s.o.OSV.RetryDelay
		}
		s.osv = c
	}
	return s.osv, sys.KEVURL
}

// New returns a scanner.
func New(o Options) *Scanner {
	if o.QueryTTL == 0 {
		o.QueryTTL = 12 * time.Hour
	}
	if o.VulnTTL == 0 {
		o.VulnTTL = 7 * 24 * time.Hour
	}
	if o.Workers == 0 {
		o.Workers = 8
	}
	return &Scanner{o: o, trigger: make(chan struct{}, 1)}
}

// Trigger requests a scan cycle soon.
func (s *Scanner) Trigger() {
	select {
	case s.trigger <- struct{}{}:
	default:
	}
}

// Status returns the current status.
func (s *Scanner) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}

func (s *Scanner) setErr(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status.LastError, s.status.LastErrorAt = err.Error(), timeutil.Now()
}

// Run loops until ctx is cancelled.
func (s *Scanner) Run(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	backoffUntil := time.Time{}
	for {
		if time.Now().After(backoffUntil) {
			if err := s.cycle(ctx); err != nil && ctx.Err() == nil {
				s.o.Logger.Error(s.o.L.T("log.scan.failed"), slog.String("error", err.Error()))
				s.setErr(err)
				backoffUntil = time.Now().Add(10 * time.Minute)
				_ = s.o.Store.AddNotification(ctx, store.LevelWarning, "scan_failed", map[string]string{"error": truncate(err.Error(), 300)}, "/settings")
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-s.trigger:
			backoffUntil = time.Time{}
		}
	}
}

func (s *Scanner) cycle(ctx context.Context) error {
	cfg, err := settings.Load(ctx, s.o.Store)
	if err != nil {
		return err
	}
	if time.Since(cfg.ScannerLastDaily) > 24*time.Hour {
		if err := settings.Stamp(ctx, s.o.Store, settings.KeyScannerLastDaily, timeutil.Now()); err != nil {
			return err
		}
		if s.o.Daily != nil {
			s.o.Daily(ctx)
		}
		if cfg.ScanEnabled {
			if err := s.o.Store.MarkAllForScan(ctx); err != nil {
				return err
			}
		}
		if _, kev := s.sources(); kev != "" && cfg.ScanEnabled {
			if err := s.RefreshKEV(ctx); err != nil {
				s.o.Logger.Warn(s.o.L.T("log.scan.kev_failed"), slog.String("error", err.Error()))
			}
		}
	}
	if !cfg.ScanEnabled {
		return nil
	}

	scanned := 0
	defer func() {
		if scanned > 0 && s.o.AfterScan != nil {
			s.o.AfterScan(ctx)
		}
	}()
	for {
		ids, err := s.o.Store.HostsNeedingScan(ctx, 10)
		if err != nil || len(ids) == 0 {
			return err
		}
		for _, id := range ids {
			s.mu.Lock()
			s.status.Scanning = true
			s.mu.Unlock()
			err := s.ScanHost(ctx, id)
			s.mu.Lock()
			s.status.Scanning = false
			s.status.LastRunAt = timeutil.Now()
			if err == nil {
				s.status.LastError = ""
			}
			s.mu.Unlock()
			if err != nil {
				return fmt.Errorf("host %d: %w", id, err)
			}
			scanned++
		}
	}
}

// ScanHost matches one host's inventory and reconciles its findings.
func (s *Scanner) ScanHost(ctx context.Context, hostID int64) error {
	st := s.o.Store
	host, err := st.HostByID(ctx, hostID)
	if err != nil {
		return err
	}
	if host.OSID == protocol.OSWindows {
		return s.scanWindows(ctx, host)
	}
	target := TargetFor(host.HostInfo())
	if !target.Supported() {
		return st.MarkScanned(ctx, hostID)
	}
	pkgs, err := st.HostPackages(ctx, hostID)
	if err != nil {
		return err
	}
	pkgs = ActiveKernelPackages(pkgs, host.Kernel)
	start := time.Now()

	// 1. OSV package queries (cached).
	keySet := map[store.OSVQueryKey]bool{}
	var keys []store.OSVQueryKey
	for _, p := range pkgs {
		name, ver := target.QueryPackage(p)
		if name == "" || ver == "" {
			continue
		}
		for _, eco := range target.Ecosystems {
			k := store.OSVQueryKey{Ecosystem: eco, Name: name, Version: ver}
			if !keySet[k] {
				keySet[k] = true
				keys = append(keys, k)
			}
		}
	}
	cached, err := st.OSVQueries(ctx, keys)
	if err != nil {
		return err
	}
	refs := make(map[store.OSVQueryKey][]store.OSVRef, len(keys))
	var stale []store.OSVQueryKey
	for _, k := range keys {
		if c, ok := cached[k]; ok && time.Since(c.CheckedAt) < s.o.QueryTTL {
			refs[k] = c.Records
		} else {
			stale = append(stale, k)
		}
	}
	if len(stale) > 0 {
		osv, _ := s.sources()
		res, err := osv.QueryBatch(ctx, stale)
		if err != nil {
			return err
		}
		fresh := make(map[store.OSVQueryKey][]store.OSVRef, len(stale))
		for i, k := range stale {
			refs[k] = res[i]
			fresh[k] = res[i]
		}
		if err := st.SaveOSVQueries(ctx, fresh); err != nil {
			return err
		}
	}

	// 2. Records referenced by the results (cached by modified stamp).
	want := map[string]string{}
	for _, list := range refs {
		for _, r := range list {
			want[r.ID] = r.Modified
		}
	}
	records, err := s.loadRecords(ctx, want, 0)
	if err != nil {
		return err
	}

	// 3. Findings and per-CVE evidence.
	type evidence struct {
		distro []Record
		hints  []SeverityHint
	}
	byCVE := map[string]*evidence{}
	detected := map[[2]string]store.DetectedFinding{}
	advisories := map[string]Record{}
	for k, list := range refs {
		for _, ref := range list {
			rec, ok := records[ref.ID]
			if !ok || rec.Withdrawn != "" {
				continue
			}
			fixed := rec.FixedVersion(k.Ecosystem, k.Name)
			hint := rec.SeverityHints(k.Ecosystem, k.Name)
			if rec.IsAdvisory() {
				advisories[rec.ID] = rec
			}
			for _, cve := range rec.CVEIDs() {
				e := byCVE[cve]
				if e == nil {
					e = &evidence{}
					byCVE[cve] = e
				}
				e.distro = append(e.distro, rec)
				e.hints = append(e.hints, hint)
				key := [2]string{cve, k.Name}
				d, exists := detected[key]
				if !exists || (d.FixedVersion == "" && fixed != "") {
					detected[key] = store.DetectedFinding{CVEID: cve, PackageName: k.Name, InstalledVersion: k.Version, FixedVersion: fixed, RecordID: rec.ID}
				}
			}
		}
	}

	// 4. Vulnerability details for CVEs that are new or stale.
	cveIDs := make([]string, 0, len(byCVE))
	for id := range byCVE {
		cveIDs = append(cveIDs, id)
	}
	fetchedAt, err := st.VulnFetchedAt(ctx, cveIDs)
	if err != nil {
		return err
	}
	needCVE := map[string]string{}
	for _, id := range cveIDs {
		if t, ok := fetchedAt[id]; !ok || time.Since(t) > s.o.VulnTTL {
			if IsCVE(id) {
				needCVE[id] = ""
			}
		}
	}
	cveRecords, err := s.loadRecords(ctx, needCVE, s.o.VulnTTL)
	if err != nil {
		return err
	}
	for _, id := range cveIDs {
		if t, ok := fetchedAt[id]; ok && time.Since(t) <= s.o.VulnTTL {
			continue
		}
		var cveRec *Record
		if r, ok := cveRecords[id]; ok {
			cveRec = &r
		}
		e := byCVE[id]
		v := BuildVulnerability(id, cveRec, e.distro, e.hints)
		if err := st.UpsertVulnerability(ctx, v); err != nil {
			return err
		}
	}
	for _, rec := range advisories {
		if err := st.UpsertAdvisory(ctx, vuln.Advisory{ID: rec.ID, Title: rec.Summary, URL: rec.AdvisoryURL()}, "osv", rec.CVEIDs()); err != nil {
			return err
		}
	}

	// 5. Reconcile.
	list := make([]store.DetectedFinding, 0, len(detected))
	for _, d := range detected {
		list = append(list, d)
	}
	created, err := st.ApplyFindings(ctx, hostID, list)
	if err != nil {
		return err
	}
	s.o.Logger.Info(s.o.L.T("log.scan.host_done"),
		slog.String("hostname", host.Hostname), slog.Int("packages", len(pkgs)), slog.Int("queries", len(keys)),
		slog.Int("osv_requests", len(stale)), slog.Int("findings", len(list)), slog.Int("new_findings", created),
		slog.Duration("duration", time.Since(start).Round(time.Millisecond)))
	return st.MarkScanned(ctx, hostID)
}

// loadRecords returns parsed records for ids. A cached record is reused when
// its modified stamp matches (want[id] != "") or, for maxAge > 0, when it was
// fetched within maxAge. Missing records (404) are omitted.
func (s *Scanner) loadRecords(ctx context.Context, want map[string]string, maxAge time.Duration) (map[string]Record, error) {
	out := make(map[string]Record, len(want))
	var fetch []string
	for id, modified := range want {
		cm, data, fetched, err := s.o.Store.OSVRecord(ctx, id)
		if err == nil {
			fresh := (modified != "" && cm == modified) || (maxAge > 0 && time.Since(fetched) < maxAge)
			if fresh {
				if rec, err := ParseRecord(data); err == nil {
					out[id] = rec
					continue
				}
			}
		} else if !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
		fetch = append(fetch, id)
	}
	if len(fetch) == 0 {
		return out, nil
	}
	if len(fetch) >= 100 {
		// A host's first scan can fetch thousands of records (Ubuntu kernel CVEs).
		s.o.Logger.Info(s.o.L.T("log.scan.fetching_records"), slog.Int("count", len(fetch)))
	}

	type result struct {
		id   string
		data []byte
		err  error
	}
	osv, _ := s.sources()
	jobs := make(chan string)
	results := make(chan result)
	var wg sync.WaitGroup
	for range min(s.o.Workers, len(fetch)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range jobs {
				data, err := osv.GetRecord(ctx, id)
				results <- result{id, data, err}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, id := range fetch {
			select {
			case jobs <- id:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() { wg.Wait(); close(results) }()

	var firstErr error
	for r := range results {
		if r.err != nil {
			if !errors.Is(r.err, ErrNotFound) && firstErr == nil {
				firstErr = r.err
			}
			continue
		}
		rec, err := ParseRecord(r.data)
		if err != nil {
			continue
		}
		data, err := rec.Compact()
		if err != nil {
			continue
		}
		// Cache under the stamp the query reported: api.osv.dev's querybatch
		// "modified" differs from the record's own "modified" field, so
		// comparing against the record's field would never hit the cache.
		stamp := want[r.id]
		if stamp == "" {
			stamp = rec.Modified
		}
		if err := s.o.Store.SaveOSVRecord(ctx, r.id, stamp, data); err != nil && firstErr == nil {
			firstErr = err
		}
		out[r.id] = rec
	}
	if firstErr == nil {
		firstErr = ctx.Err()
	}
	return out, firstErr
}

// RefreshKEV downloads the CISA Known Exploited Vulnerabilities catalog.
func (s *Scanner) RefreshKEV(ctx context.Context) error {
	osv, kevURL := s.sources()
	if kevURL == "" {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, kevURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", brand.ServerUserAgent(version.Version))
	resp, err := osv.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("kev: HTTP %d", resp.StatusCode)
	}
	var doc struct {
		Vulnerabilities []struct {
			CVEID      string `json:"cveID"`
			DateAdded  string `json:"dateAdded"`
			DueDate    string `json:"dueDate"`
			Ransomware string `json:"knownRansomwareCampaignUse"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&doc); err != nil {
		return fmt.Errorf("kev: %w", err)
	}
	if len(doc.Vulnerabilities) == 0 {
		return errors.New("kev: empty catalog")
	}
	entries := make([]store.KEVEntry, 0, len(doc.Vulnerabilities))
	for _, v := range doc.Vulnerabilities {
		if IsCVE(v.CVEID) {
			entries = append(entries, store.KEVEntry{CVEID: v.CVEID, DateAdded: v.DateAdded, DueDate: v.DueDate, Ransomware: v.Ransomware})
		}
	}
	if err := s.o.Store.ReplaceKEV(ctx, entries); err != nil {
		return err
	}
	s.o.Logger.Info(s.o.L.T("log.scan.kev_updated"), slog.Int("entries", len(entries)))
	return settings.Stamp(ctx, s.o.Store, settings.KeyKEVUpdatedAt, timeutil.Now())
}
