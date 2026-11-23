package agent

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"netio.patchman/internal/brand"
	"netio.patchman/internal/protocol"
	"netio.patchman/internal/version"
)

// APIError is a non-2xx response from the server.
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("HTTP %d %s: %s", e.Status, e.Code, e.Message)
	}
	return fmt.Sprintf("HTTP %d", e.Status)
}

// IsUnauthorized reports whether err is a 401 response.
func IsUnauthorized(err error) bool {
	var e *APIError
	return errors.As(err, &e) && e.Status == http.StatusUnauthorized
}

// Client talks to the netio.patchman server.
type Client struct {
	base      *url.URL
	http      *http.Client
	userAgent string
	secret    string
}

// NewClient builds a client trusting the system roots plus an optional CA file.
func NewClient(cfg Config) (*Client, error) {
	tlsConf := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CAFile != "" {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, err
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates in %s", cfg.CAFile)
		}
		tlsConf.RootCAs = pool
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsConf
	return &Client{
		base:      cfg.ServerURL,
		http:      &http.Client{Transport: tr, Timeout: 3 * time.Minute},
		userAgent: brand.AgentUserAgent(version.Version, runtime.GOOS, runtime.GOARCH),
	}, nil
}

// SetSecret sets the bearer secret.
func (c *Client) SetSecret(s string) { c.secret = s }

func (c *Client) post(ctx context.Context, path string, body any, compress bool, out any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	if compress {
		zw := gzip.NewWriter(&buf)
		if _, err := zw.Write(raw); err != nil {
			return err
		}
		if err := zw.Close(); err != nil {
			return err
		}
	} else {
		buf.Write(raw)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base.String()+path, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if compress {
		req.Header.Set("Content-Encoding", "gzip")
	}
	if c.secret != "" {
		req.Header.Set("Authorization", "Bearer "+c.secret)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		apiErr := &APIError{Status: resp.StatusCode}
		var e protocol.ErrorResponse
		if json.Unmarshal(data, &e) == nil {
			apiErr.Code, apiErr.Message = e.Code, e.Message
		}
		return apiErr
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

// Register enrolls the agent.
func (c *Client) Register(ctx context.Context, token string, info protocol.HostInfo) (protocol.RegisterResponse, error) {
	var resp protocol.RegisterResponse
	err := c.post(ctx, protocol.PathRegister, protocol.RegisterRequest{EnrollmentToken: token, Host: info}, false, &resp)
	return resp, err
}

// Checkin sends a heartbeat.
func (c *Client) Checkin(ctx context.Context, info protocol.HostInfo) (protocol.CheckinResponse, error) {
	var resp protocol.CheckinResponse
	err := c.post(ctx, protocol.PathCheckin, protocol.CheckinRequest{Host: info}, false, &resp)
	return resp, err
}

// Report uploads the inventory (gzip).
func (c *Client) Report(ctx context.Context, r protocol.Report) error {
	return c.post(ctx, protocol.PathReport, r, true, nil)
}

// JobResult reports a finished job.
func (c *Client) JobResult(ctx context.Context, id int64, r protocol.JobResult) error {
	path := strings.Replace(protocol.PathJobResult, "{id}", strconv.FormatInt(id, 10), 1)
	return c.post(ctx, path, r, true, nil)
}

// Health posts a monitoring round.
func (c *Client) Health(ctx context.Context, st protocol.HealthStatus) error {
	return c.post(ctx, protocol.PathHealth, st, true, nil)
}

// Credentials are the agent's enrolled identity.
type Credentials struct {
	ServerURL   string `json:"server_url"`
	HostID      int64  `json:"host_id"`
	AgentSecret string `json:"agent_secret"`
}

func credentialsPath(stateDir string) string { return filepath.Join(stateDir, "credentials.json") }

// LoadCredentials reads stored credentials for serverURL.
func LoadCredentials(stateDir, serverURL string) (Credentials, bool) {
	b, err := os.ReadFile(credentialsPath(stateDir))
	if err != nil {
		return Credentials{}, false
	}
	var c Credentials
	if json.Unmarshal(b, &c) != nil || c.AgentSecret == "" || c.ServerURL != serverURL {
		return Credentials{}, false
	}
	return c, true
}

// SaveCredentials writes credentials with 0600 permissions.
func SaveCredentials(stateDir string, c Credentials) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	tmp := credentialsPath(stateDir) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, credentialsPath(stateDir))
}

// DeleteCredentials removes stored credentials.
func DeleteCredentials(stateDir string) { _ = os.Remove(credentialsPath(stateDir)) }
