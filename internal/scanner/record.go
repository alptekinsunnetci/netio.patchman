package scanner

import (
	"bytes"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"time"

	"netio.patchman/internal/vuln"
)

// Record is the subset of the OSV schema used here. Text fields are kept verbatim.
//
// Fields the scanner does not use are dropped on decode. This matters: Ubuntu
// records for kernel CVEs list every binary package of every affected source
// package (ecosystem_specific.binaries), up to several MB per record.
type Record struct {
	ID         string     `json:"id"`
	Summary    string     `json:"summary,omitempty"`
	Details    string     `json:"details,omitempty"`
	Aliases    []string   `json:"aliases,omitempty"`
	Upstream   []string   `json:"upstream,omitempty"`
	Related    []string   `json:"related,omitempty"`
	Published  string     `json:"published,omitempty"`
	Modified   string     `json:"modified"`
	Withdrawn  string     `json:"withdrawn,omitempty"`
	Severity   []severity `json:"severity,omitempty"`
	Affected   []affected `json:"affected,omitempty"`
	References []struct {
		Type string `json:"type,omitempty"`
		URL  string `json:"url"`
	} `json:"references,omitempty"`
	DatabaseSpecific *specific `json:"database_specific,omitempty"`
}

type severity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type affected struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Ranges []struct {
		Type   string              `json:"type"`
		Events []map[string]string `json:"events"`
	} `json:"ranges,omitempty"`
	Severity          []severity `json:"severity,omitempty"`
	EcosystemSpecific *specific  `json:"ecosystem_specific,omitempty"`
	DatabaseSpecific  *specific  `json:"database_specific,omitempty"`
}

// specific keeps the qualitative ratings from ecosystem_specific and
// database_specific (Debian urgency, distribution severity). The values are
// usually strings but are left untyped so unexpected shapes do not fail decoding.
type specific struct {
	Urgency  any `json:"urgency,omitempty"`
	Severity any `json:"severity,omitempty"`
}

func (s *specific) get(key string) any {
	if s == nil {
		return nil
	}
	if key == "urgency" {
		return s.Urgency
	}
	return s.Severity
}

// ParseRecord decodes raw OSV JSON.
func ParseRecord(data []byte) (Record, error) {
	var r Record
	err := json.Unmarshal(data, &r)
	for i := range r.Affected {
		r.Affected[i].EcosystemSpecific = r.Affected[i].EcosystemSpecific.compact()
		r.Affected[i].DatabaseSpecific = r.Affected[i].DatabaseSpecific.compact()
	}
	r.DatabaseSpecific = r.DatabaseSpecific.compact()
	return r, err
}

func (s *specific) compact() *specific {
	if s == nil || (s.Urgency == nil && s.Severity == nil) {
		return nil
	}
	return s
}

// Compact returns the record re-encoded with only the fields the scanner
// uses, for the record cache. Text fields stay verbatim.
func (r Record) Compact() ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(r); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

var (
	cveRE         = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
	perCVERecord  = regexp.MustCompile(`^[A-Z]+-CVE-\d{4}-\d{4,}$`) // DEBIAN-CVE-…, UBUNTU-CVE-…, ALPINE-CVE-…
	severityWords = map[string]vuln.Severity{
		"critical":    vuln.SeverityCritical,
		"important":   vuln.SeverityHigh,
		"high":        vuln.SeverityHigh,
		"moderate":    vuln.SeverityMedium,
		"medium":      vuln.SeverityMedium,
		"low":         vuln.SeverityLow,
		"negligible":  vuln.SeverityLow,
		"unimportant": vuln.SeverityLow,
	}
)

// IsCVE reports whether id is a CVE identifier.
func IsCVE(id string) bool { return cveRE.MatchString(id) }

// CVEIDs returns the CVE identifiers a record refers to. A record without any
// CVE reference is keyed by its own ID.
func (r Record) CVEIDs() []string {
	if IsCVE(r.ID) {
		return []string{r.ID}
	}
	set := map[string]bool{}
	for _, list := range [][]string{r.Upstream, r.Aliases} {
		for _, id := range list {
			if IsCVE(id) {
				set[id] = true
			}
		}
	}
	if len(set) == 0 {
		for _, id := range r.Related {
			if IsCVE(id) {
				set[id] = true
			}
		}
	}
	if len(set) == 0 {
		return []string{r.ID}
	}
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// IsAdvisory reports whether the record is a vendor advisory (DSA, USN,
// ALSA, RLSA, RHSA, SUSE-SU, …) rather than a per-CVE record.
func (r Record) IsAdvisory() bool {
	return !IsCVE(r.ID) && !perCVERecord.MatchString(r.ID)
}

// AdvisoryURL returns the best reference URL for the record.
func (r Record) AdvisoryURL() string {
	for _, ref := range r.References {
		if ref.Type == "ADVISORY" {
			return ref.URL
		}
	}
	if len(r.References) > 0 {
		return r.References[0].URL
	}
	return ""
}

// FixedVersion returns the first "fixed" event for the package in the
// ecosystem, or "" if no fix is published.
func (r Record) FixedVersion(ecosystem, name string) string {
	for _, a := range r.Affected {
		if a.Package.Ecosystem != ecosystem || a.Package.Name != name {
			continue
		}
		for _, rg := range a.Ranges {
			if rg.Type != "ECOSYSTEM" {
				continue
			}
			for _, ev := range rg.Events {
				if f := ev["fixed"]; f != "" {
					return f
				}
			}
		}
	}
	return ""
}

// SeverityHint is severity evidence from one record.
type SeverityHint struct {
	Vector      string        // CVSS vector, verbatim
	Score       *float64      // computed base score (v2/v3)
	Version     string        // "2.0", "3.0", "3.1", "4.0"
	Qualitative vuln.Severity // distribution rating, "" if none
}

// SeverityHints collects CVSS vectors and qualitative ratings for a package.
func (r Record) SeverityHints(ecosystem, name string) SeverityHint {
	var h SeverityHint
	all := append([]severity{}, r.Severity...)
	for _, a := range r.Affected {
		if ecosystem == "" || (a.Package.Ecosystem == ecosystem && a.Package.Name == name) {
			all = append(all, a.Severity...)
			if q := qualitative(a.EcosystemSpecific.get("urgency")); q != "" && h.Qualitative == "" {
				h.Qualitative = q
			}
			if q := qualitative(a.EcosystemSpecific.get("severity")); q != "" && h.Qualitative == "" {
				h.Qualitative = q
			}
			if q := qualitative(a.DatabaseSpecific.get("severity")); q != "" && h.Qualitative == "" {
				h.Qualitative = q
			}
		}
	}
	h.Vector, h.Score, h.Version = bestVector(all)
	for _, s := range all {
		if s.Type == "Ubuntu" && h.Qualitative == "" {
			h.Qualitative = qualitative(s.Score)
		}
	}
	if h.Qualitative == "" {
		h.Qualitative = qualitative(r.DatabaseSpecific.get("severity"))
	}
	if h.Qualitative == "" {
		// Red Hat style summaries: "Moderate: openssl security update"
		if word, _, ok := strings.Cut(r.Summary, ":"); ok {
			h.Qualitative = qualitative(word)
		}
	}
	return h
}

func qualitative(v any) vuln.Severity {
	s, _ := v.(string)
	s = strings.ToLower(strings.TrimSpace(strings.TrimRight(s, "*")))
	return severityWords[s]
}

// bestVector prefers CVSS v3.x, then v4.0 (vector only), then v2.
func bestVector(list []severity) (string, *float64, string) {
	rank := func(t string) int {
		switch t {
		case "CVSS_V3":
			return 3
		case "CVSS_V4":
			return 2
		case "CVSS_V2":
			return 1
		}
		return 0
	}
	best := -1
	for i, s := range list {
		if rank(s.Type) > 0 && (best < 0 || rank(s.Type) > rank(list[best].Type)) {
			best = i
		}
	}
	if best < 0 {
		return "", nil, ""
	}
	vec := list[best].Score
	score, ver, ok := CVSSBaseScore(vec)
	if !ok {
		if strings.HasPrefix(vec, "CVSS:4.0/") {
			return vec, nil, "4.0"
		}
		return vec, nil, ver
	}
	return vec, &score, ver
}

// BuildVulnerability combines the official CVE record (may be nil) with hints
// from distribution records. Text fields are copied verbatim.
func BuildVulnerability(cveID string, cveRec *Record, distro []Record, hints []SeverityHint) vuln.Vulnerability {
	v := vuln.Vulnerability{CVEID: cveID, DescriptionLang: "en", Source: "osv"}
	var all []SeverityHint
	if cveRec != nil {
		v.Title = strings.TrimSpace(cveRec.Summary)
		v.Description = strings.TrimSpace(cveRec.Details)
		v.PublishedAt = parseTime(cveRec.Published)
		v.ModifiedAt = parseTime(cveRec.Modified)
		for _, ref := range cveRec.References {
			if len(v.References) < 25 {
				v.References = append(v.References, ref.URL)
			}
		}
		all = append(all, cveRec.SeverityHints("", ""))
	}
	all = append(all, hints...)
	if v.Description == "" {
		// Fall back to a per-CVE distribution record (e.g. DEBIAN-CVE-…),
		// whose details is the CVE description verbatim.
		for _, r := range distro {
			if !r.IsAdvisory() && strings.TrimSpace(r.Details) != "" {
				v.Description = strings.TrimSpace(r.Details)
				if v.Title == "" {
					v.Title = strings.TrimSpace(r.Summary)
				}
				break
			}
		}
	}
	if v.Description == "" && v.Title == "" && len(distro) > 0 {
		// Non-CVE vulnerability keyed by an advisory ID.
		v.Title = strings.TrimSpace(distro[0].Summary)
		v.Description = strings.TrimSpace(distro[0].Details)
	}
	if v.PublishedAt.IsZero() {
		for _, r := range distro {
			if t := parseTime(r.Published); !t.IsZero() && (v.PublishedAt.IsZero() || t.Before(v.PublishedAt)) {
				v.PublishedAt = t
			}
		}
	}

	// Severity: first computable CVSS (official record first), then any vector,
	// then distribution rating.
	for _, h := range all {
		if h.Score != nil && h.Version != "2.0" {
			v.CVSSScore, v.CVSSVector, v.CVSSVersion = h.Score, h.Vector, h.Version
			v.Severity = vuln.SeverityFromCVSS(*h.Score)
			break
		}
	}
	if v.Severity == "" {
		for _, h := range all {
			if h.Vector != "" && h.Version == "4.0" {
				v.CVSSVector, v.CVSSVersion = h.Vector, h.Version
				break
			}
		}
		for _, h := range all {
			if h.Qualitative != "" {
				v.Severity = h.Qualitative
				break
			}
		}
	}
	if v.Severity == "" {
		for _, h := range all {
			if h.Score != nil && h.Version == "2.0" {
				v.CVSSScore, v.CVSSVector, v.CVSSVersion = h.Score, h.Vector, h.Version
				v.Severity = severityFromCVSS2(*h.Score)
				break
			}
		}
	}
	if v.Severity == "" {
		v.Severity = vuln.SeverityUnknown
	}
	return v
}

// severityFromCVSS2 uses the NVD v2 scale, which has no "critical" level.
func severityFromCVSS2(score float64) vuln.Severity {
	switch {
	case score >= 7:
		return vuln.SeverityHigh
	case score >= 4:
		return vuln.SeverityMedium
	case score > 0:
		return vuln.SeverityLow
	}
	return vuln.SeverityNone
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}
