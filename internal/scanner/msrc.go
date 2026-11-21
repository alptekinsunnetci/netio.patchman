package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"netio.patchman/internal/brand"
	"netio.patchman/internal/version"
)

// MSRCClient reads the Microsoft Security Update Guide API
// (https://api.msrc.microsoft.com/sug/v2.0/en-US), verified against the live
// service:
//
//	/affectedProduct?$filter=kbArticles/any(kb:kb/articleName eq '5044281')
//	    one row per CVE and product a KB fixes: cveNumber, severity, baseScore,
//	    vectorString, kbArticles[].fixedBuildNumber and .supercedence
//	/vulnerability?$filter=cveNumber eq 'CVE-…' or cveNumber eq 'CVE-…'
//	    per CVE: cveTitle, severity, baseScore, vectorString, releaseDate
//
// Values are kept verbatim.
type MSRCClient struct {
	BaseURL string
	HTTP    *http.Client
}

// NewMSRCClient returns a client for baseURL.
func NewMSRCClient(baseURL string) *MSRCClient {
	return &MSRCClient{BaseURL: strings.TrimRight(baseURL, "/"), HTTP: &http.Client{Timeout: 60 * time.Second}}
}

// MSRCKB is what a KB fixes. Cached per KB in the store as JSON.
type MSRCKB struct {
	// Supersedes are the KB numbers (digits only) this update replaces.
	Supersedes []string    `json:"supersedes,omitempty"`
	CVEs       []MSRCKBCVE `json:"cves"`
}

// MSRCKBCVE is one CVE fixed by a KB (the most severe product row).
type MSRCKBCVE struct {
	ID         string `json:"id"`
	Severity   string `json:"severity,omitempty"`    // Critical, Important, Moderate, Low
	Score      string `json:"score,omitempty"`       // CVSS base score, "8.1"
	Vector     string `json:"vector,omitempty"`      // CVSS:3.1/…
	FixedBuild string `json:"fixed_build,omitempty"` // OS build containing the fix, "10.0.20348.2762"
}

// MSRCVuln is the Security Update Guide entry of a CVE.
type MSRCVuln struct {
	ID          string
	Title       string
	Severity    string
	Score       string
	Vector      string
	ReleaseDate string
}

var kbNumberRE = regexp.MustCompile(`^[0-9]{4,10}$`)

// KBNumber returns the digits of an update name such as "KB5044281", or "".
func KBNumber(name string) string {
	n := strings.TrimPrefix(strings.ToUpper(name), "KB")
	if kbNumberRE.MatchString(n) {
		return n
	}
	return ""
}

// maxMSRCPages bounds paging through one query (500 rows per page).
const maxMSRCPages = 40

// get pages through an OData query and calls fn for every page body.
func (c *MSRCClient) get(ctx context.Context, path string, query url.Values, fn func(data []byte) error) error {
	next := c.BaseURL + path + "?" + strings.ReplaceAll(query.Encode(), "+", "%20")
	base, err := url.Parse(c.BaseURL)
	if err != nil {
		return err
	}
	for page := 0; next != "" && page < maxMSRCPages; page++ {
		// Follow nextLink only on the configured host.
		u, err := url.Parse(next)
		if err != nil || u.Host != base.Host || u.Scheme != base.Scheme {
			return fmt.Errorf("msrc: unexpected next link")
		}
		data, err := c.fetch(ctx, next)
		if err != nil {
			return err
		}
		if err := fn(data); err != nil {
			return err
		}
		var link struct {
			Next string `json:"@odata.nextLink"`
		}
		_ = json.Unmarshal(data, &link)
		next = link.Next
	}
	return nil
}

func (c *MSRCClient) fetch(ctx context.Context, u string) ([]byte, error) {
	var lastErr error
	for attempt := range 3 {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt) * 2 * time.Second):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", brand.ServerUserAgent(version.Version))
		req.Header.Set("Accept", "application/json")
		resp, err := c.HTTP.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			lastErr = err
			continue
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		resp.Body.Close()
		switch {
		case err != nil:
			lastErr = err
		case resp.StatusCode == http.StatusOK:
			return data, nil
		case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
			lastErr = fmt.Errorf("msrc: HTTP %d", resp.StatusCode)
		default:
			return nil, fmt.Errorf("msrc: HTTP %d", resp.StatusCode)
		}
	}
	return nil, lastErr
}

// KB returns the CVEs a KB fixes and the KBs it supersedes. kb is digits only.
func (c *MSRCClient) KB(ctx context.Context, kb string) (MSRCKB, error) {
	if !kbNumberRE.MatchString(kb) {
		return MSRCKB{}, errors.New("msrc: invalid KB number")
	}
	q := url.Values{"$filter": {"kbArticles/any(kb:kb/articleName eq '" + kb + "')"}}
	byCVE := map[string]int{}
	var out MSRCKB
	sup := map[string]bool{}
	err := c.get(ctx, "/affectedProduct", q, func(data []byte) error {
		var doc struct {
			Value []struct {
				CVE        string `json:"cveNumber"`
				Severity   string `json:"severity"`
				BaseScore  string `json:"baseScore"`
				Vector     string `json:"vectorString"`
				KBArticles []struct {
					Name         string `json:"articleName"`
					Supersedence string `json:"supercedence"`
					FixedBuild   string `json:"fixedBuildNumber"`
				} `json:"kbArticles"`
			} `json:"value"`
		}
		if err := json.Unmarshal(data, &doc); err != nil {
			return fmt.Errorf("msrc: %w", err)
		}
		for _, row := range doc.Value {
			if !IsCVE(row.CVE) {
				continue
			}
			e := MSRCKBCVE{ID: row.CVE, Severity: strings.TrimSpace(row.Severity), Score: strings.TrimSpace(row.BaseScore), Vector: strings.TrimSpace(row.Vector)}
			for _, a := range row.KBArticles {
				if a.Name != kb {
					continue
				}
				e.FixedBuild = strings.TrimSpace(a.FixedBuild)
				for _, s := range splitKBs(a.Supersedence) {
					if s != kb && !sup[s] {
						sup[s] = true
						out.Supersedes = append(out.Supersedes, s)
					}
				}
			}
			if i, ok := byCVE[row.CVE]; ok {
				if msrcRank(e) > msrcRank(out.CVEs[i]) {
					out.CVEs[i] = e
				}
				continue
			}
			byCVE[row.CVE] = len(out.CVEs)
			out.CVEs = append(out.CVEs, e)
		}
		return nil
	})
	if out.CVEs == nil {
		out.CVEs = []MSRCKBCVE{}
	}
	return out, err
}

// splitKBs returns the KB numbers in a supercedence value ("5042881",
// "5042881; 5043050", "KB5042881").
func splitKBs(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r < '0' || r > '9' }) {
		if kbNumberRE.MatchString(f) {
			out = append(out, f)
		}
	}
	return out
}

// msrcRank orders product rows of one CVE: higher score, then severity.
func msrcRank(e MSRCKBCVE) float64 {
	s, _ := strconv.ParseFloat(e.Score, 64)
	return s*10 + float64(qualitative(e.Severity).Rank())
}

// msrcBatch is the number of CVEs per vulnerability query (URL length).
const msrcBatch = 20

// Vulnerabilities returns the Security Update Guide entries of the CVEs.
// CVEs unknown to the guide are omitted.
func (c *MSRCClient) Vulnerabilities(ctx context.Context, ids []string) (map[string]MSRCVuln, error) {
	out := map[string]MSRCVuln{}
	for start := 0; start < len(ids); start += msrcBatch {
		var parts []string
		for _, id := range ids[start:min(start+msrcBatch, len(ids))] {
			if IsCVE(id) {
				parts = append(parts, "cveNumber eq '"+id+"'")
			}
		}
		if len(parts) == 0 {
			continue
		}
		q := url.Values{"$filter": {strings.Join(parts, " or ")}}
		err := c.get(ctx, "/vulnerability", q, func(data []byte) error {
			var doc struct {
				Value []struct {
					CVE         string `json:"cveNumber"`
					Title       string `json:"cveTitle"`
					Severity    string `json:"severity"`
					BaseScore   string `json:"baseScore"`
					Vector      string `json:"vectorString"`
					ReleaseDate string `json:"releaseDate"`
				} `json:"value"`
			}
			if err := json.Unmarshal(data, &doc); err != nil {
				return fmt.Errorf("msrc: %w", err)
			}
			for _, v := range doc.Value {
				if IsCVE(v.CVE) {
					out[v.CVE] = MSRCVuln{ID: v.CVE, Title: strings.TrimSpace(v.Title), Severity: strings.TrimSpace(v.Severity),
						Score: strings.TrimSpace(v.BaseScore), Vector: strings.TrimSpace(v.Vector), ReleaseDate: v.ReleaseDate}
				}
			}
			return nil
		})
		if err != nil {
			return out, err
		}
	}
	return out, nil
}

// buildNewer reports whether Windows build a ("10.0.20348.5870") is newer
// than b. Builds of different OS versions (first three parts) are not
// comparable: ok is false.
func buildNewer(a, b string) (newer, ok bool) {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	if len(pa) != 4 || len(pb) != 4 {
		return false, false
	}
	for i := range 4 {
		x, err1 := strconv.Atoi(pa[i])
		y, err2 := strconv.Atoi(pb[i])
		if err1 != nil || err2 != nil {
			return false, false
		}
		if i < 3 && x != y {
			return false, false
		}
		if i == 3 {
			return x > y, true
		}
	}
	return false, false
}
