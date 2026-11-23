package agent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"netio.patchman/internal/i18n"
	"netio.patchman/internal/protocol"
)

// HealthDir holds the command checks the host's administrator allows the
// server to run by name. The server can never send a command line.
var HealthDir = filepath.Join(filepath.Dir(DefaultConfigPath), "health.d")

// HealthRunner runs health checks.
type HealthRunner struct {
	L i18n.Localizer
	// Dir is the health.d directory; "" uses HealthDir.
	Dir string
	// ServiceState returns whether a service is running; nil uses the
	// platform's service manager.
	ServiceState func(ctx context.Context, name string) (bool, error)
	// Resources reads CPU load, memory and disk usage in percent; nil uses
	// the platform implementation.
	Resources func(paths []string) (cpu, mem float64, disk map[string]float64, err error)
	// Client is used for HTTP checks; nil builds one per check.
	Client *http.Client
}

// ParseHealthChecks decodes the health parameter of a job.
func ParseHealthChecks(raw string) ([]protocol.HealthCheck, error) {
	if raw == "" {
		return nil, nil
	}
	var checks []protocol.HealthCheck
	if err := json.Unmarshal([]byte(raw), &checks); err != nil {
		return nil, err
	}
	if len(checks) > protocol.MaxHealthChecks {
		checks = checks[:protocol.MaxHealthChecks]
	}
	return checks, nil
}

// Run runs every check and returns the results in order.
func (h HealthRunner) Run(ctx context.Context, checks []protocol.HealthCheck) []protocol.HealthResult {
	out := make([]protocol.HealthResult, 0, len(checks))
	for _, c := range checks {
		out = append(out, h.one(ctx, c))
	}
	return out
}

// Failed lists the names of the failed checks.
func Failed(results []protocol.HealthResult) []string {
	var out []string
	for _, r := range results {
		if !r.OK {
			out = append(out, r.Name)
		}
	}
	return out
}

func (h HealthRunner) one(ctx context.Context, c protocol.HealthCheck) protocol.HealthResult {
	timeout := time.Duration(c.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	timeout = min(timeout, 2*time.Minute)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	r := protocol.HealthResult{ID: c.ID, Name: c.Name, Type: c.Type}
	var err error
	switch c.Type {
	case protocol.HealthResources:
		r.Value, err = h.resources(c)
	case protocol.HealthService:
		err = h.service(ctx, c.Target)
	case protocol.HealthHTTP:
		r.Value, err = h.http(ctx, c, timeout)
	case protocol.HealthTCP:
		err = h.tcp(ctx, c.Target)
	case protocol.HealthCommand:
		r.Value, err = h.command(ctx, c.Target)
	default:
		err = errors.New(h.L.T("agent.health.unknown_type", "type", c.Type))
	}
	if ctx.Err() == context.DeadlineExceeded && err != nil {
		err = errors.New(h.L.T("agent.health.timeout", "seconds", int(timeout.Seconds())))
	}
	r.OK, r.DurationMS = err == nil, time.Since(start).Milliseconds()
	if err != nil {
		r.Message = truncateText(err.Error(), 500)
	}
	r.Value = truncateText(r.Value, 500)
	return r
}

func truncateText(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func (h HealthRunner) resources(c protocol.HealthCheck) (string, error) {
	paths := c.Paths
	if len(paths) == 0 {
		paths = []string{defaultDiskPath()}
	}
	read := h.Resources
	if read == nil {
		read = readResources
	}
	cpu, mem, disk, err := read(paths)
	if err != nil {
		return "", err
	}
	var parts, over []string
	if cpu >= 0 {
		parts = append(parts, fmt.Sprintf("CPU %.0f%%", cpu))
		if c.CPU > 0 && cpu > float64(c.CPU) {
			over = append(over, h.L.T("agent.health.cpu_over", "value", int(cpu), "limit", c.CPU))
		}
	}
	if mem >= 0 {
		parts = append(parts, fmt.Sprintf("RAM %.0f%%", mem))
		if c.Memory > 0 && mem > float64(c.Memory) {
			over = append(over, h.L.T("agent.health.memory_over", "value", int(mem), "limit", c.Memory))
		}
	}
	for _, p := range paths {
		v, ok := disk[p]
		if !ok {
			over = append(over, h.L.T("agent.health.disk_unreadable", "path", p))
			continue
		}
		parts = append(parts, fmt.Sprintf("%s %.0f%%", p, v))
		if c.Disk > 0 && v > float64(c.Disk) {
			over = append(over, h.L.T("agent.health.disk_over", "path", p, "value", int(v), "limit", c.Disk))
		}
	}
	value := strings.Join(parts, " · ")
	if len(over) > 0 {
		return value, errors.New(strings.Join(over, "; "))
	}
	return value, nil
}

func (h HealthRunner) service(ctx context.Context, name string) error {
	if !protocol.ValidServiceName(name) {
		return errors.New(h.L.T("agent.job.invalid_service", "service", name))
	}
	state := h.ServiceState
	if state == nil {
		state = serviceRunning
	}
	running, err := state(ctx, name)
	if err != nil {
		return err
	}
	if !running {
		return errors.New(h.L.T("agent.health.service_down", "service", name))
	}
	return nil
}

func (h HealthRunner) http(ctx context.Context, c protocol.HealthCheck, timeout time.Duration) (string, error) {
	u, err := url.Parse(c.Target)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", errors.New(h.L.T("agent.health.bad_url", "url", c.Target))
	}
	client := h.Client
	if client == nil {
		tr := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{InsecureSkipVerify: c.Insecure}} //nolint:gosec // opt-in per check
		client = &http.Client{Timeout: timeout, Transport: tr,
			// Redirects are followed at most 5 times.
			CheckRedirect: func(_ *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return http.ErrUseLastResponse
				}
				return nil
			}}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "netio-patchman-agent health check")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	value := "HTTP " + strconv.Itoa(resp.StatusCode)
	switch {
	case c.Expect > 0 && resp.StatusCode != c.Expect:
		return value, errors.New(h.L.T("agent.health.http_status", "status", resp.StatusCode, "expect", c.Expect))
	case c.Expect == 0 && (resp.StatusCode < 200 || resp.StatusCode > 399):
		return value, errors.New(h.L.T("agent.health.http_status_range", "status", resp.StatusCode))
	case c.Contains != "" && !bytes.Contains(body, []byte(c.Contains)):
		return value, errors.New(h.L.T("agent.health.http_contains", "text", c.Contains))
	}
	return value, nil
}

func (h HealthRunner) tcp(ctx context.Context, target string) error {
	host, port, err := net.SplitHostPort(target)
	if err != nil || host == "" || port == "" {
		return errors.New(h.L.T("agent.health.bad_address", "address", target))
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return err
	}
	return conn.Close()
}

// command runs <health.d>/<name>. The file must be a regular file that
// only an administrator can change (see checkCommandFile). Exit status 0
// means healthy; the first lines of its output are kept.
func (h HealthRunner) command(ctx context.Context, name string) (string, error) {
	if !protocol.ValidCommandName(name) {
		return "", errors.New(h.L.T("agent.health.bad_command", "name", name))
	}
	dir := h.Dir
	if dir == "" {
		dir = HealthDir
	}
	path := filepath.Join(dir, name)
	if err := checkCommandFile(dir, path); err != nil {
		return "", errors.New(h.L.T("agent.health.command_unsafe", "path", path, "error", err.Error()))
	}
	cmd := commandFor(ctx, path)
	cmd.Env = append(os.Environ(), "LANG=C.UTF-8", "LC_ALL=C.UTF-8")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	cmd.WaitDelay = 5 * time.Second
	err := cmd.Run()
	value := lastLines(out.String(), 5)
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return value, errors.New(h.L.T("agent.health.command_failed", "code", exitErr.ExitCode()))
	}
	return value, err
}

// parseMeminfo returns the memory in use in percent, -1 when unknown.
func parseMeminfo(r interface{ Read([]byte) (int, error) }) float64 {
	var total, avail float64
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 {
			continue
		}
		v, err := strconv.ParseFloat(f[1], 64)
		if err != nil {
			continue
		}
		switch f[0] {
		case "MemTotal:":
			total = v
		case "MemAvailable:":
			avail = v
		}
	}
	if total <= 0 {
		return -1
	}
	return (total - avail) / total * 100
}
