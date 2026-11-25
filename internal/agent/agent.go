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

	"netio.patchman/internal/agentsign"
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
	// Winget lists and installs third-party program updates on Windows.
	Winget   bool
	StateDir string
	// Locale is the language of agent logs and job messages (PATCHMAN_LOCALE).
	Locale string
	// UpdateKeys are the release signing keys (PATCHMAN_UPDATE_KEYS, base64
	// Ed25519) agent updates must be signed with. They take precedence over
	// keys pinned from the server (see PinnedUpdateKeys).
	UpdateKeys []string
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
		Winget:          boolean("WINGET", true),
		StateDir:        get("STATE_DIR", DefaultStateDir),
		Locale:          get("LOCALE", i18n.DefaultLocale),
	}
	if keys, err := agentsign.ParsePublicKeys(get("UPDATE_KEYS", "")); err != nil {
		errs = append(errs, errors.New(l.T("config.error.invalid_update_keys", "max", agentsign.MaxKeys)))
	} else {
		cfg.UpdateKeys = keys
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
	rel, _ := osRelease()
	return pickPackageManager(rel, func(bin string) bool {
		_, err := exec.LookPath(bin)
		return err == nil
	})
}

// pickPackageManager chooses by the os-release family (ID, then ID_LIKE)
// first: tools of another family are often installed too, such as dpkg on
// CloudLinux/cPanel servers or rpm on Debian. Without a known family the
// first available package manager wins; apt needs apt-get, not only dpkg.
func pickPackageManager(rel map[string]string, has func(string) bool) string {
	apt := func() string {
		if has("apt-get") && has("dpkg-query") {
			return protocol.PMApt
		}
		return ""
	}
	rpm := func() string {
		if has("dnf") {
			return protocol.PMDnf
		}
		if has("yum") {
			return protocol.PMYum
		}
		return ""
	}
	tool := func(bin, pm string) func() string {
		return func() string {
			if has(bin) {
				return pm
			}
			return ""
		}
	}
	families := map[string]func() string{
		"debian": apt, "ubuntu": apt,
		"rhel": rpm, "fedora": rpm, "centos": rpm,
		"suse": tool("zypper", protocol.PMZypper), "opensuse": tool("zypper", protocol.PMZypper), "sles": tool("zypper", protocol.PMZypper),
		"alpine": tool("apk", protocol.PMApk),
	}
	for _, f := range strings.Fields(strings.ToLower(rel["ID"] + " " + rel["ID_LIKE"])) {
		if pick, ok := families[f]; ok {
			if pm := pick(); pm != "" {
				return pm
			}
		}
	}
	for _, pick := range []func() string{apt, tool("apk", protocol.PMApk), tool("zypper", protocol.PMZypper), rpm} {
		if pm := pick(); pm != "" {
			return pm
		}
	}
	return ""
}

// Capabilities are the optional features this agent implements; the server
// only sends the jobs and parameters behind them to agents that declare them.
func Capabilities(pm string) []string {
	caps := []string{protocol.CapServices, protocol.CapHealth, protocol.CapHealthMonitor, protocol.CapSignedUpdate}
	if protocol.PreviewSupported(pm) {
		caps = append(caps, protocol.CapPreview)
	}
	if protocol.RollbackSupported(pm) {
		caps = append(caps, protocol.CapRollback)
	}
	return caps
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
	h.Capabilities = Capabilities(h.PackageManager)
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
	h.Upstream = upstreamRelease(rel)
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

// upstreamRelease names the Ubuntu or Debian release a derivative (Linux
// Mint, Pop!_OS, Zorin OS, elementary OS, LMDE) is built on.
func upstreamRelease(rel map[string]string) string {
	id := strings.ToLower(rel["ID"])
	if c := strings.ToLower(strings.TrimSpace(rel["UBUNTU_CODENAME"])); c != "" && id != "ubuntu" {
		return protocol.CleanUpstream("ubuntu:" + c)
	}
	if c := strings.ToLower(strings.TrimSpace(rel["DEBIAN_CODENAME"])); c != "" && id != "debian" && id != "ubuntu" {
		return protocol.CleanUpstream("debian:" + c)
	}
	return ""
}
