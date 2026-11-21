package agent

import (
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf16"

	"netio.patchman/internal/i18n"
	"netio.patchman/internal/protocol"
)

// Windows hosts use the Windows Update Agent through its COM API. The agent
// runs the embedded PowerShell helper (wu.ps1) with -EncodedCommand; input
// goes in environment variables, the result comes back as JSON on stdout.

//go:embed wu.ps1
var wuScript string

var (
	wuOnce sync.Once
	wuEnc  string
)

// wuEncoded returns the helper as a -EncodedCommand argument (UTF-16LE,
// base64), without comment lines to keep the command line short.
func wuEncoded() string {
	wuOnce.Do(func() {
		var b strings.Builder
		for _, line := range strings.Split(strings.ReplaceAll(wuScript, "\r\n", "\n"), "\n") {
			t := strings.TrimSpace(line)
			if t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			b.WriteString(line)
			b.WriteByte('\n')
		}
		u := utf16.Encode([]rune(b.String()))
		raw := make([]byte, len(u)*2)
		for i, c := range u {
			binary.LittleEndian.PutUint16(raw[i*2:], c)
		}
		wuEnc = base64.StdEncoding.EncodeToString(raw)
	})
	return wuEnc
}

// wuUpdate is one update in the helper's scan output.
type wuUpdate struct {
	Name       string   `json:"name"`
	Title      string   `json:"title"`
	Severity   string   `json:"severity"`
	Categories []string `json:"categories"`
	Class      string   `json:"class"` // classification: Security Updates, Update Rollups, …
	CVEs       []string `json:"cves"`
	Date       string   `json:"date"`
	Security   bool     `json:"security"`
}

type wuScanResult struct {
	Updates        []wuUpdate `json:"updates"`
	RebootRequired bool       `json:"reboot_required"`
	Error          string     `json:"error"`
	HResult        string     `json:"hresult"`
}

type wuInstallResult struct {
	Results []struct {
		Name    string `json:"name"`
		Title   string `json:"title"`
		Result  int    `json:"result"`
		HResult string `json:"hresult"`
	} `json:"results"`
	Missing        []string `json:"missing"`
	RebootRequired bool     `json:"reboot_required"`
	Error          string   `json:"error"`
	HResult        string   `json:"hresult"`
}

// decodeWU parses the helper output (a leading BOM is ignored).
func decodeWU(data []byte, v any) error {
	data = []byte(strings.TrimSpace(strings.TrimPrefix(string(data), "\ufeff")))
	if len(data) == 0 {
		return errors.New("windows update: empty output")
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("windows update: %w", err)
	}
	return nil
}

// wuError formats a helper error.
func wuError(msg, hresult string) error {
	if hresult != "" {
		return fmt.Errorf("windows update: %s (%s)", strings.TrimSpace(msg), hresult)
	}
	return fmt.Errorf("windows update: %s", strings.TrimSpace(msg))
}

// parseWUScan converts the helper's scan output into pending updates.
func parseWUScan(data []byte) ([]protocol.Update, bool, error) {
	var res wuScanResult
	if err := decodeWU(data, &res); err != nil {
		return nil, false, err
	}
	if res.Error != "" {
		return nil, false, wuError(res.Error, res.HResult)
	}
	seen := map[string]bool{}
	var out []protocol.Update
	for _, u := range res.Updates {
		if !protocol.ValidPackageName(u.Name) || seen[u.Name] {
			continue
		}
		seen[u.Name] = true
		var cves []string
		for _, c := range u.CVEs {
			if c = strings.TrimSpace(c); c != "" {
				cves = append(cves, c)
			}
		}
		repo := strings.TrimSpace(u.Class)
		if repo == "" && len(u.Categories) > 0 {
			repo = u.Categories[len(u.Categories)-1]
		}
		out = append(out, protocol.Update{
			Name: u.Name, AvailableVersion: firstNonEmpty(u.Date, u.Name), Repository: repo, Security: u.Security,
			Title: strings.TrimSpace(u.Title), Severity: strings.TrimSpace(u.Severity), CVEs: cves,
		})
	}
	return out, res.RebootRequired, nil
}

// wuScanTimeout bounds a search; an online search can take minutes.
const wuScanTimeout = 30 * time.Minute

// wuPending searches pending updates; online asks the update service,
// otherwise the result of the last automatic detection is used.
func wuPending(ctx context.Context, online bool) ([]protocol.Update, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, wuScanTimeout)
	defer cancel()
	env := []string{"PATCHMAN_WU_MODE=scan", "PATCHMAN_WU_ONLINE=0"}
	if online {
		env[1] = "PATCHMAN_WU_ONLINE=1"
	}
	out, err := runWU(ctx, env)
	if err != nil {
		return nil, false, err
	}
	return parseWUScan(out)
}

// collectWindows gathers installed programs and pending Windows updates.
// The update service is asked at most every refreshEvery; in between the
// local detection result is read.
func (c Collector) collectWindows(ctx context.Context) (pkgs []protocol.Package, updates []protocol.Update, reboot bool, errs []string) {
	var err error
	if pkgs, err = windowsPrograms(); err != nil {
		errs = append(errs, err.Error())
	}
	online := c.refreshDue()
	updates, reboot, err = wuPending(ctx, online)
	if err != nil && online {
		// Offline detection still works without access to the update service.
		errs = append(errs, err.Error())
		updates, reboot, err = wuPending(ctx, false)
	} else if err == nil && online {
		c.markRefreshed()
	}
	if err != nil {
		errs = append(errs, err.Error())
	}
	return pkgs, updates, reboot, errs
}

// cleanProgram trims a registry program entry: no control characters,
// bounded lengths. The text is otherwise kept verbatim.
func cleanProgram(p protocol.Package) protocol.Package {
	clean := func(s string, max int) string {
		s = strings.TrimSpace(strings.Map(func(r rune) rune {
			if unicode.IsControl(r) {
				return -1
			}
			return r
		}, s))
		if len(s) > max {
			s = strings.ToValidUTF8(s[:max], "")
		}
		return s
	}
	p.Name, p.Version = clean(p.Name, 200), clean(p.Version, 100)
	return p
}

// wuResult codes of IUpdateInstaller (OperationResultCode).
const (
	wuSucceeded           = 2
	wuSucceededWithErrors = 3
)

// windowsInstallCommand installs the named updates (or, without names, all
// or only security updates) through Windows Update.
func windowsInstallCommand(l i18n.Localizer, names []string, kind string) command {
	args := append([]string{"install"}, names...)
	if len(names) == 0 {
		args = append(args, "--"+kind)
	}
	env := []string{"PATCHMAN_WU_MODE=install", "PATCHMAN_WU_KBS=" + strings.Join(names, ","), "PATCHMAN_WU_KIND=" + kind}
	return command{name: protocol.PMWindowsUpdate, args: args, fn: func(ctx context.Context, out io.Writer) int {
		data, err := runWU(ctx, env)
		if err != nil {
			fmt.Fprintln(out, l.T("agent.wu.failed", "error", err.Error()))
			return -1
		}
		return writeWUInstall(l, data, out)
	}}
}

// writeWUInstall writes the localized install result and returns the exit
// code: 0 when Windows Update ran (the job verifies what was installed).
func writeWUInstall(l i18n.Localizer, data []byte, out io.Writer) int {
	var res wuInstallResult
	if err := decodeWU(data, &res); err != nil {
		fmt.Fprintln(out, l.T("agent.wu.failed", "error", err.Error()))
		return -1
	}
	if res.Error != "" {
		fmt.Fprintln(out, l.T("agent.wu.failed", "error", wuError(res.Error, res.HResult).Error()))
		return 1
	}
	if len(res.Missing) > 0 {
		fmt.Fprintln(out, l.T("agent.wu.not_found", "packages", listNames(res.Missing)))
	}
	for _, r := range res.Results {
		switch r.Result {
		case wuSucceeded, wuSucceededWithErrors:
			fmt.Fprintln(out, l.T("agent.wu.installed", "name", r.Name, "title", r.Title))
		default:
			fmt.Fprintln(out, l.T("agent.wu.install_failed", "name", r.Name, "title", r.Title, "code", r.Result, "hresult", r.HResult))
		}
	}
	if res.RebootRequired {
		fmt.Fprintln(out, l.T("agent.wu.reboot_required"))
	}
	return 0
}
