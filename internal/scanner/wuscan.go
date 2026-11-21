package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"time"

	"netio.patchman/internal/store"
	"netio.patchman/internal/vuln"
)

// Windows hosts have no package-level vulnerability data: OSV does not cover
// Windows. Their findings come from the pending Windows updates instead. For
// every pending KB the Security Update Guide lists the CVEs it fixes; for a
// cumulative update the KBs it supersedes are followed while their fixed OS
// build is newer than the host's build (the host missed those months too).
// A finding is keyed by (host, CVE, KB): installing the KB resolves it, and
// remediation finds the KB among the host's pending updates.

// maxKBChain bounds how many superseded cumulative updates are followed.
const maxKBChain = 24

// msrcClient returns the Security Update Guide client, nil when disabled.
func (s *Scanner) msrcClient() *MSRCClient {
	base := s.o.MSRCURL
	if s.o.System != nil {
		base = s.o.System.Get().MSRCURL
	}
	if base == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.msrc == nil || s.msrc.BaseURL != strings.TrimRight(base, "/") {
		c := NewMSRCClient(base)
		if s.o.OSV != nil {
			c.HTTP = s.o.OSV.HTTP
		}
		s.msrc = c
	}
	return s.msrc
}

// msrcKB returns a KB lookup from the cache or the API (fetched is true then).
func (s *Scanner) msrcKB(ctx context.Context, c *MSRCClient, kb string) (info MSRCKB, fetched bool, err error) {
	data, at, err := s.o.Store.MSRCKB(ctx, kb)
	if err == nil && time.Since(at) < s.o.QueryTTL {
		if json.Unmarshal(data, &info) == nil {
			return info, false, nil
		}
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		return info, false, err
	}
	info, err = c.KB(ctx, kb)
	if err != nil {
		return info, true, err
	}
	data, _ = json.Marshal(info)
	return info, true, s.o.Store.SaveMSRCKB(ctx, kb, data)
}

// kbCVEs returns the CVEs installing the pending update kb fixes on a host
// running build hostBuild, and the number of API lookups made.
func (s *Scanner) kbCVEs(ctx context.Context, c *MSRCClient, kb, hostBuild string) ([]MSRCKBCVE, int, error) {
	requests := 0
	var out []MSRCKBCVE
	seen := map[string]bool{}
	topBuild := ""
	queue := []string{kb}
	for depth := 0; len(queue) > 0 && depth <= maxKBChain; depth++ {
		var next []string
		for _, k := range queue {
			if seen[k] {
				continue
			}
			seen[k] = true
			info, fetched, err := s.msrcKB(ctx, c, k)
			if fetched {
				requests++
			}
			if err != nil {
				return nil, requests, err
			}
			missing := false // the host lacks fixes of this KB
			for _, e := range info.CVEs {
				newer, comparable := buildNewer(e.FixedBuild, hostBuild)
				switch {
				case comparable && !newer:
					continue // the host's build already contains the fix
				case comparable:
					missing = true
				case k != kb:
					continue // superseded KB of another product or without a build
				}
				if k == kb && comparable && topBuild == "" {
					topBuild = e.FixedBuild
				}
				if k != kb && topBuild != "" {
					e.FixedBuild = topBuild // the pending KB is what fixes it now
				}
				out = append(out, e)
			}
			if missing {
				next = append(next, info.Supersedes...)
			}
		}
		queue = next
	}
	return out, requests, nil
}

// scanWindows reconciles the findings of a Windows host.
func (s *Scanner) scanWindows(ctx context.Context, host store.Host) error {
	st := s.o.Store
	start := time.Now()
	updates, err := st.HostUpdates(ctx, host.ID)
	if err != nil {
		return err
	}
	msrc := s.msrcClient()
	detected := map[[2]string]store.DetectedFinding{}
	best := map[string]MSRCKBCVE{}
	type advisory struct {
		title string
		cves  []string
	}
	advisories := map[string]*advisory{}
	requests := 0
	for _, u := range updates {
		kb := KBNumber(u.Name)
		var cves []MSRCKBCVE
		for _, id := range u.CVEs {
			if IsCVE(id) {
				cves = append(cves, MSRCKBCVE{ID: id, Severity: u.Severity})
			}
		}
		if kb != "" && msrc != nil {
			found, n, err := s.kbCVEs(ctx, msrc, kb, host.Kernel)
			requests += n
			if err != nil {
				return err
			}
			cves = append(cves, found...)
		}
		for _, e := range cves {
			key := [2]string{e.ID, u.Name}
			if _, ok := detected[key]; ok {
				continue
			}
			fixed := e.FixedBuild
			if fixed == "" {
				fixed = u.Name
			}
			detected[key] = store.DetectedFinding{CVEID: e.ID, PackageName: u.Name, InstalledVersion: host.Kernel, FixedVersion: fixed, RecordID: u.Name}
			if prev, ok := best[e.ID]; !ok || msrcRank(e) > msrcRank(prev) {
				best[e.ID] = e
			}
			if kb != "" {
				a := advisories[u.Name]
				if a == nil {
					a = &advisory{title: u.Title}
					advisories[u.Name] = a
				}
				a.cves = append(a.cves, e.ID)
			}
		}
	}

	ids := make([]string, 0, len(best))
	for id := range best {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	fetchedAt, err := st.VulnFetchedAt(ctx, ids)
	if err != nil {
		return err
	}
	var need []string
	for _, id := range ids {
		if t, ok := fetchedAt[id]; !ok || time.Since(t) > s.o.VulnTTL {
			need = append(need, id)
		}
	}
	details := map[string]MSRCVuln{}
	if msrc != nil && len(need) > 0 {
		if details, err = msrc.Vulnerabilities(ctx, need); err != nil {
			return err
		}
		requests += (len(need) + msrcBatch - 1) / msrcBatch
	}
	for _, id := range need {
		var d *MSRCVuln
		if v, ok := details[id]; ok {
			d = &v
		}
		if err := st.UpsertVulnerability(ctx, MSRCVulnerability(id, d, best[id])); err != nil {
			return err
		}
	}
	for name, a := range advisories {
		adv := vuln.Advisory{ID: name, Title: a.title, URL: "https://support.microsoft.com/help/" + KBNumber(name)}
		if err := st.UpsertAdvisory(ctx, adv, "msrc", a.cves); err != nil {
			return err
		}
	}

	list := make([]store.DetectedFinding, 0, len(detected))
	for _, d := range detected {
		list = append(list, d)
	}
	created, err := st.ApplyFindings(ctx, host.ID, list)
	if err != nil {
		return err
	}
	s.o.Logger.Info(s.o.L.T("log.scan.host_done"),
		slog.String("hostname", host.Hostname), slog.Int("packages", len(updates)), slog.Int("queries", len(updates)),
		slog.Int("msrc_requests", requests), slog.Int("findings", len(list)), slog.Int("new_findings", created),
		slog.Duration("duration", time.Since(start).Round(time.Millisecond)))
	return st.MarkScanned(ctx, host.ID)
}

// MSRCVulnerability builds a vulnerability from the Security Update Guide
// entry d (nil when unknown) and the KB row e. Values are verbatim; the base
// score is taken as published, computed from the vector only when missing.
func MSRCVulnerability(id string, d *MSRCVuln, e MSRCKBCVE) vuln.Vulnerability {
	v := vuln.Vulnerability{CVEID: id, DescriptionLang: "en", Source: "msrc"}
	vector, score, severity := e.Vector, e.Score, e.Severity
	if d != nil {
		v.Title = d.Title
		v.PublishedAt = parseTime(d.ReleaseDate)
		if d.Vector != "" {
			vector = d.Vector
		}
		if d.Score != "" {
			score = d.Score
		}
		if d.Severity != "" {
			severity = d.Severity
		}
		v.References = []string{"https://msrc.microsoft.com/update-guide/vulnerability/" + id}
	}
	version := ""
	switch {
	case strings.HasPrefix(vector, "CVSS:3.1/"), strings.HasPrefix(vector, "CVSS:3.0/"):
		version = vector[5:8]
	case strings.HasPrefix(vector, "CVSS:4.0/"):
		version = "4.0"
	}
	if f, err := strconv.ParseFloat(score, 64); err == nil && f > 0 && f <= 10 && version != "" && version != "4.0" {
		v.CVSSScore, v.CVSSVector, v.CVSSVersion = &f, vector, version
		v.Severity = vuln.SeverityFromCVSS(f)
	} else if f, ver, ok := CVSSBaseScore(vector); ok && ver != "2.0" {
		v.CVSSScore, v.CVSSVector, v.CVSSVersion = &f, vector, ver
		v.Severity = vuln.SeverityFromCVSS(f)
	} else {
		if version == "4.0" {
			v.CVSSVector, v.CVSSVersion = vector, version
		}
		v.Severity = qualitative(severity)
	}
	if v.Severity == "" {
		v.Severity = vuln.SeverityUnknown
	}
	return v
}
