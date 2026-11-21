// Package agent implements netio-patchman-agent: host identification,
// package inventory collection, update jobs and the server protocol.
package agent

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"netio.patchman/internal/brand"
	"netio.patchman/internal/i18n"
	"netio.patchman/internal/protocol"
	"netio.patchman/internal/version"
)

// Config is the agent configuration.
type Config struct {
	ServerURL       *url.URL
	EnrollmentToken string
	CAFile          string
	RemoteUpdates   bool
	AutoUpdate      bool
	RefreshLists    bool
	StateDir        string
	// Locale is the language of agent logs and job messages (PATCHMAN_LOCALE).
	Locale string
}

// LoadConfig reads KEY=VALUE pairs from path; environment variables override
// file values. Errors are in Turkish because operators read them.
func LoadConfig(l i18n.Localizer, path string, getenv func(string) string) (Config, error) {
	values := map[string]string{}
	if f, err := os.Open(path); err == nil {
		values, err = parseEnvFile(f)
		f.Close()
		if err != nil {
			return Config{}, errors.New(l.T("config.error.file_unreadable", "path", path))
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return Config{}, errors.New(l.T("config.error.file_unreadable", "path", path))
	}
	get := func(key, def string) string {
		if v := strings.TrimSpace(getenv(brand.EnvPrefix + key)); v != "" {
			return v
		}
		if v, ok := values[brand.EnvPrefix+key]; ok && v != "" {
			return v
		}
		return def
	}
	boolean := func(key string, def bool) bool {
		b, err := strconv.ParseBool(get(key, strconv.FormatBool(def)))
		if err != nil {
			return def
		}
		return b
	}

	var errs []error
	cfg := Config{
		EnrollmentToken: get("ENROLLMENT_TOKEN", ""),
		CAFile:          get("CA_FILE", ""),
		RemoteUpdates:   boolean("REMOTE_UPDATES", true),
		AutoUpdate:      boolean("AUTO_UPDATE", true),
		RefreshLists:    boolean("REFRESH_PACKAGE_LISTS", true),
		StateDir:        get("STATE_DIR", DefaultStateDir),
		Locale:          get("LOCALE", i18n.DefaultLocale),
	}
	raw := get("SERVER_URL", "")
	switch u, err := url.Parse(raw); {
	case raw == "":
		errs = append(errs, errors.New(l.T("config.error.server_url_required")))
	case err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "":
		errs = append(errs, errors.New(l.T("config.error.invalid_server_url", "value", raw)))
	default:
		u.Path = strings.TrimRight(u.Path, "/")
		cfg.ServerURL = u
	}
	if cfg.CAFile != "" {
		if _, err := os.Stat(cfg.CAFile); err != nil {
			errs = append(errs, errors.New(l.T("config.error.file_unreadable", "path", cfg.CAFile)))
		}
	}
	return cfg, errors.Join(errs...)
}

// parseEnvFile parses a systemd-style environment file.
func parseEnvFile(r io.Reader) (map[string]string, error) {
	out := map[string]string{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' && v[len(v)-1] == '"' || v[0] == '\'' && v[len(v)-1] == '\'') {
			v = v[1 : len(v)-1]
		}
		out[strings.TrimSpace(k)] = v
	}
	return out, sc.Err()
}

// osRelease reads /etc/os-release (or /usr/lib/os-release).
func osRelease() (map[string]string, error) {
	for _, p := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		defer f.Close()
		return parseEnvFile(f)
	}
	return nil, os.ErrNotExist
}

// DetectPackageManager returns the package manager in use.
func DetectPackageManager() string {
	if runtime.GOOS == "windows" {
		return protocol.PMWindowsUpdate
	}
	for _, c := range []struct{ bin, pm string }{
		{"dpkg-query", protocol.PMApt},
		{"apk", protocol.PMApk},
		{"zypper", protocol.PMZypper},
		{"dnf", protocol.PMDnf},
		{"yum", protocol.PMYum},
	} {
		if _, err := exec.LookPath(c.bin); err == nil {
			return c.pm
		}
	}
	return ""
}

// ReadHostInfo collects host identification. Values are verbatim.
func ReadHostInfo(remoteUpdates, selfUpdate bool) (protocol.HostInfo, error) {
	h := protocol.HostInfo{
		Arch:          runtime.GOARCH,
		AgentVersion:  version.Version,
		RemoteUpdates: remoteUpdates,
		SelfUpdate:    selfUpdate,
	}
	var err error
	if h.Hostname, err = os.Hostname(); err != nil {
		return h, err
	}
	h.IPAddresses = ipAddresses()
	h.PackageManager = DetectPackageManager()
	h.Virtualization = Virtualization()
	// Machine ID, kernel or build, uptime, FQDN and OS identification.
	return h, readPlatform(&h)
}

// readLinuxPlatform fills the Linux host fields from /etc and /proc.
func readLinuxPlatform(h *protocol.HostInfo) error {
	h.FQDN = fqdn(h.Hostname)
	if b, err := os.ReadFile("/etc/machine-id"); err == nil {
		h.MachineID = strings.TrimSpace(string(b))
	}
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		h.Kernel = strings.TrimSpace(string(b))
	}
	if b, err := os.ReadFile("/proc/uptime"); err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			if v, err := strconv.ParseFloat(f[0], 64); err == nil {
				h.UptimeSeconds = int64(v)
			}
		}
	}
	rel, err := osRelease()
	if err != nil {
		return err
	}
	h.OSID, h.OSIDLike, h.OSVersionID, h.OSVersion, h.OSName = rel["ID"], rel["ID_LIKE"], rel["VERSION_ID"], rel["VERSION"], rel["PRETTY_NAME"]
	return nil
}

func fqdn(hostname string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "hostname", "-f").Output()
	if err == nil {
		if f := strings.TrimSpace(string(out)); f != "" && f != "localhost" {
			return f
		}
	}
	return hostname
}

func ipAddresses() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if strings.HasPrefix(iface.Name, "docker") || strings.HasPrefix(iface.Name, "veth") || strings.HasPrefix(iface.Name, "br-") {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok || ipnet.IP.IsLinkLocalUnicast() {
				continue
			}
			out = append(out, ipnet.IP.String())
		}
	}
	sort.Strings(out)
	return out
}
