package scanner

import (
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"netio.patchman/internal/brand"
	"netio.patchman/internal/settings"
	"netio.patchman/internal/store"
	"netio.patchman/internal/timeutil"
	"netio.patchman/internal/version"
)

// epssURL returns the EPSS score file address, empty when disabled.
func (s *Scanner) epssURL() string {
	if s.o.System == nil {
		return s.o.EPSSURL
	}
	return s.o.System.Get().EPSSURL
}

// RefreshEPSS downloads the daily EPSS scores (FIRST.org model) and replaces
// the stored ones. The file is a gzip-compressed CSV:
//
//	#model_version:v2026.06.15,score_date:2026-11-21T12:00:24Z
//	cve,epss,percentile
//	CVE-1999-0001,0.04753,0.92093
func (s *Scanner) RefreshEPSS(ctx context.Context) error {
	u := s.epssURL()
	if u == "" {
		return nil
	}
	osv, _ := s.sources()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
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
		return fmt.Errorf("epss: HTTP %d", resp.StatusCode)
	}
	entries, err := ParseEPSS(io.LimitReader(resp.Body, 256<<20))
	if err != nil {
		return fmt.Errorf("epss: %w", err)
	}
	if err := s.o.Store.ReplaceEPSS(ctx, entries); err != nil {
		return err
	}
	s.o.Logger.Info(s.o.L.T("log.scan.epss_updated"), slog.Int("entries", len(entries)))
	return settings.Stamp(ctx, s.o.Store, settings.KeyEPSSUpdatedAt, timeutil.Now())
}

// ParseEPSS reads the EPSS CSV, gzip-compressed or plain.
func ParseEPSS(r io.Reader) ([]store.EPSSEntry, error) {
	br := bufio.NewReaderSize(r, 64<<10)
	if magic, err := br.Peek(2); err == nil && magic[0] == 0x1f && magic[1] == 0x8b {
		zr, err := gzip.NewReader(br)
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		br = bufio.NewReaderSize(zr, 64<<10)
	}
	sc := bufio.NewScanner(br)
	var out []store.EPSSEntry
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' || strings.HasPrefix(line, "cve,") {
			continue
		}
		f := strings.Split(line, ",")
		if len(f) < 3 || !IsCVE(f[0]) {
			continue
		}
		score, err1 := strconv.ParseFloat(f[1], 64)
		pct, err2 := strconv.ParseFloat(f[2], 64)
		if err1 != nil || err2 != nil || score < 0 || score > 1 || pct < 0 || pct > 1 {
			continue
		}
		out = append(out, store.EPSSEntry{CVEID: f[0], Score: score, Percentile: pct})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, errors.New("no scores")
	}
	return out, nil
}
