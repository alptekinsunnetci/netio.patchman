//go:build windows

package agent

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"netio.patchman/internal/protocol"
)

// DefaultConfigPath is the agent's environment file. The install script
// limits the directory to SYSTEM and Administrators.
var DefaultConfigPath = filepath.Join(programData(), "netio-patchman", "agent.env")

// DefaultStateDir holds the agent credentials.
var DefaultStateDir = filepath.Join(programData(), "netio-patchman")

func programData() string {
	if p := os.Getenv("ProgramData"); p != "" {
		return p
	}
	return `C:\ProgramData`
}

func regString(k registry.Key, name string) string {
	v, _, err := k.GetStringValue(name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(v)
}

func regInt(k registry.Key, name string) (uint64, bool) {
	v, _, err := k.GetIntegerValue(name)
	return v, err == nil
}

// readPlatform fills the Windows host fields from the registry. Values are
// verbatim; Kernel is the full OS build ("10.0.20348.2762"), which the
// server compares with the fixed builds of Microsoft security updates.
func readPlatform(h *protocol.HostInfo) error {
	h.OSID = protocol.OSWindows
	h.UptimeSeconds = int64(windows.DurationSinceBoot().Seconds())
	h.FQDN = h.Hostname
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`, registry.QUERY_VALUE); err == nil {
		if d := regString(k, "Domain"); d != "" {
			h.FQDN = h.Hostname + "." + d
		}
		k.Close()
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE|registry.WOW64_64KEY); err == nil {
		h.MachineID = strings.ToLower(regString(k, "MachineGuid"))
		k.Close()
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return err
	}
	defer k.Close()
	product := regString(k, "ProductName")
	build := regString(k, "CurrentBuild")
	major, ok1 := regInt(k, "CurrentMajorVersionNumber")
	minor, ok2 := regInt(k, "CurrentMinorVersionNumber")
	if !ok1 || !ok2 {
		// Windows 8.1 / Server 2012 R2 and older: "6.3".
		if v := regString(k, "CurrentVersion"); v != "" {
			a, b, _ := strings.Cut(v, ".")
			x, _ := strconv.ParseUint(a, 10, 32)
			y, _ := strconv.ParseUint(b, 10, 32)
			major, minor = x, y
		}
	}
	// Windows 11 still reports "Windows 10 …" as ProductName.
	if n, err := strconv.Atoi(build); err == nil && n >= 22000 && strings.HasPrefix(product, "Windows 10") {
		product = "Windows 11" + strings.TrimPrefix(product, "Windows 10")
	}
	display := regString(k, "DisplayVersion")
	if display == "" {
		display = regString(k, "ReleaseId")
	}
	if strings.EqualFold(regString(k, "InstallationType"), "Server Core") {
		product += " (Server Core)"
	}
	h.OSName = product
	h.OSVersion = display
	h.OSVersionID = fmt.Sprintf("%d.%d.%s", major, minor, build)
	h.Kernel = h.OSVersionID
	if ubr, ok := regInt(k, "UBR"); ok {
		h.Kernel += "." + strconv.FormatUint(ubr, 10)
	}
	return nil
}

// platformVirtualization maps the SMBIOS manufacturer and product name.
func platformVirtualization() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\BIOS`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	vendor, product := regString(k, "SystemManufacturer"), regString(k, "SystemProductName")
	if vendor == "" && product == "" {
		return ""
	}
	if id := virtFromDMI(vendor, product); id != "" {
		return id
	}
	return "none"
}

// powershell is the absolute path of Windows PowerShell 5.1 (no PATH lookup).
func powershell() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
}

// runWU runs the embedded Windows Update helper with the given environment
// variables and returns its stdout (one JSON document).
func runWU(ctx context.Context, env []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, powershell(), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", wuEncoded())
	cmd.Env = append(os.Environ(), env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if err != nil && stdout.Len() == 0 {
		return nil, fmt.Errorf("powershell: %w: %s", err, strings.TrimSpace(lastLines(stderr.String(), 3)))
	}
	return stdout.Bytes(), nil
}

// wingetExe returns the newest winget (App Installer) executable. A service
// running as SYSTEM has no WindowsApps alias in PATH, so the package
// directory is searched; servers without App Installer have none.
func wingetExe() string {
	if p, err := exec.LookPath("winget.exe"); err == nil {
		return p
	}
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		pf = `C:\Program Files`
	}
	matches, _ := filepath.Glob(filepath.Join(pf, "WindowsApps", "Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe", "winget.exe"))
	best, bestVer := "", ""
	for _, m := range matches {
		// Microsoft.DesktopAppInstaller_1.29.280.0_x64__8wekyb3d8bbwe
		parts := strings.Split(filepath.Base(filepath.Dir(m)), "_")
		if len(parts) < 2 {
			continue
		}
		if best == "" || rpmVerCmp(parts[1], bestVer) > 0 {
			best, bestVer = m, parts[1]
		}
	}
	return best
}

// wingetList returns the program updates winget offers.
func wingetList(ctx context.Context, exe string) ([]protocol.Update, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, append([]string{"upgrade"}, wingetArgs...)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil && stdout.Len() == 0 {
		return nil, fmt.Errorf("winget: %w: %s", err, strings.TrimSpace(lastLines(stderr.String(), 3)))
	}
	return parseWingetUpgrade(stdout.Bytes()), nil
}

// windowsPrograms lists installed programs from the Uninstall registry keys
// (64-bit and 32-bit views), as shown in "Programs and Features".
func windowsPrograms() ([]protocol.Package, error) {
	type src struct {
		path string
		arch string
	}
	seen := map[string]bool{}
	var out []protocol.Package
	var firstErr error
	for _, s := range []src{
		{`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, "x64"},
		{`SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`, "x86"},
	} {
		root, err := registry.OpenKey(registry.LOCAL_MACHINE, s.path, registry.ENUMERATE_SUB_KEYS|registry.WOW64_64KEY)
		if err != nil {
			if firstErr == nil && s.arch == "x64" {
				firstErr = err
			}
			continue
		}
		names, _ := root.ReadSubKeyNames(-1)
		for _, n := range names {
			k, err := registry.OpenKey(root, n, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			p := programFromKey(k, s.arch)
			k.Close()
			if p.Name == "" {
				continue
			}
			id := p.Name + "\x00" + p.Version + "\x00" + p.Arch
			if !seen[id] {
				seen[id] = true
				out = append(out, p)
			}
		}
		root.Close()
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, firstErr
}

func programFromKey(k registry.Key, arch string) protocol.Package {
	name := regString(k, "DisplayName")
	if name == "" || regString(k, "ParentKeyName") != "" {
		return protocol.Package{}
	}
	if v, ok := regInt(k, "SystemComponent"); ok && v == 1 {
		return protocol.Package{}
	}
	switch strings.ToLower(regString(k, "ReleaseType")) {
	case "update", "hotfix", "security update", "service pack":
		return protocol.Package{}
	}
	return cleanProgram(protocol.Package{Name: name, Version: regString(k, "DisplayVersion"), Arch: arch})
}
