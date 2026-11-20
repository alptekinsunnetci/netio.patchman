package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"netio.patchman/internal/brand"
	"netio.patchman/internal/store"
	"netio.patchman/internal/version"
)

// ErrNotFound is returned when OSV has no record with the requested ID.
var ErrNotFound = errors.New("osv: not found")

// OSVClient talks to the OSV API (https://google.github.io/osv.dev/api/).
type OSVClient struct {
	BaseURL string
	HTTP    *http.Client
	// RetryDelay is the base delay between retries (default 2s).
	RetryDelay time.Duration
}

// NewOSVClient returns a client for baseURL (e.g. "https://api.osv.dev").
func NewOSVClient(baseURL string) *OSVClient {
	return &OSVClient{
		BaseURL: strings.TrimRight(baseURL, "/"),
		HTTP:    &http.Client{Timeout: 60 * time.Second},
	}
}

type osvQuery struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version   string `json:"version"`
	PageToken string `json:"page_token,omitempty"`
}

type osvBatchResponse struct {
	Results []struct {
		Vulns []struct {
			ID       string `json:"id"`
			Modified string `json:"modified"`
		} `json:"vulns"`
		NextPageToken string `json:"next_page_token"`
	} `json:"results"`
}

const batchSize = 1000

// QueryBatch returns the matching record refs for each key, following
// pagination. Results are in the same order as keys.
func (c *OSVClient) QueryBatch(ctx context.Context, keys []store.OSVQueryKey) ([][]store.OSVRef, error) {
	out := make([][]store.OSVRef, len(keys))
	type pending struct {
		idx   int
		token string
	}
	var queue []pending
	for i := range keys {
		queue = append(queue, pending{idx: i})
	}
	for len(queue) > 0 {
		n := min(batchSize, len(queue))
		chunk := queue[:n]
		queue = queue[n:]
		qs := make([]osvQuery, len(chunk))
		for i, p := range chunk {
			k := keys[p.idx]
			qs[i].Package.Name, qs[i].Package.Ecosystem = k.Name, k.Ecosystem
			qs[i].Version, qs[i].PageToken = k.Version, p.token
		}
		var resp osvBatchResponse
		if err := c.post(ctx, "/v1/querybatch", map[string]any{"queries": qs}, &resp); err != nil {
			return nil, err
		}
		if len(resp.Results) != len(chunk) {
			return nil, fmt.Errorf("osv: querybatch returned %d results for %d queries", len(resp.Results), len(chunk))
		}
		for i, r := range resp.Results {
			idx := chunk[i].idx
			for _, v := range r.Vulns {
				out[idx] = append(out[idx], store.OSVRef{ID: v.ID, Modified: v.Modified})
			}
			if r.NextPageToken != "" {
				queue = append(queue, pending{idx: idx, token: r.NextPageToken})
			}
		}
	}
	return out, nil
}

// GetRecord fetches a record and returns its raw JSON. Transient failures
// (network errors, HTTP 429 and 5xx) are retried: a host's first scan can
// fetch thousands of records, and one failure would abort the whole scan.
func (c *OSVClient) GetRecord(ctx context.Context, id string) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt*attempt) * c.retryDelay()):
			}
		}
		data, retry, err := c.getRecord(ctx, id)
		if err == nil || !retry {
			return data, err
		}
		lastErr = err
	}
	return nil, lastErr
}

func (c *OSVClient) retryDelay() time.Duration {
	if c.RetryDelay > 0 {
		return c.RetryDelay
	}
	return 2 * time.Second
}

func (c *OSVClient) getRecord(ctx context.Context, id string) (data []byte, retry bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/v1/vulns/"+url.PathEscape(id), nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("User-Agent", brand.ServerUserAgent(version.Version))
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, ctx.Err() == nil, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, false, ErrNotFound
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return nil, true, fmt.Errorf("osv: GET %s: HTTP %d", id, resp.StatusCode)
	case resp.StatusCode != http.StatusOK:
		return nil, false, fmt.Errorf("osv: GET %s: HTTP %d", id, resp.StatusCode)
	}
	data, err = io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	return data, err != nil && ctx.Err() == nil, err
}

func (c *OSVClient) post(ctx context.Context, path string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt*attempt) * c.retryDelay()):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+path, bytes.NewReader(b))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", brand.ServerUserAgent(version.Version))
		resp, err := c.HTTP.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 128<<20))
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
			lastErr = fmt.Errorf("osv: POST %s: HTTP %d", path, resp.StatusCode)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("osv: POST %s: HTTP %d: %s", path, resp.StatusCode, truncate(string(data), 300))
		}
		return json.Unmarshal(data, out)
	}
	return lastErr
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
