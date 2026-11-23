//go:build !windows

package agent

import (
	"bufio"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"netio.patchman/internal/protocol"
)

// productRoot prefixes the probed paths (tests).
var productRoot = "/"

func productPath(p string) string { return filepath.Join(productRoot, p) }

// ProbeProducts finds hosting panels and web servers installed from their
// own installers.
func ProbeProducts(ctx context.Context) []protocol.Product {
	var out []protocol.Product
	// cPanel & WHM: "11.124.0.15".
	if v, ok := firstLine(productPath("usr/local/cpanel/version")); ok {
		out = append(out, product("cpanel", findVersion(v))...)
	}
	// Plesk: "18.0.65 Ubuntu 22.04 1800241113.14".
	if v, ok := firstLine(productPath("usr/local/psa/version")); ok {
		out = append(out, product("plesk", findVersion(v))...)
	}
	// LiteSpeed Enterprise and OpenLiteSpeed share /usr/local/lsws.
	if v, ok := firstLine(productPath("usr/local/lsws/VERSION")); ok {
		id := "litespeed"
		if _, err := os.Stat(productPath("usr/local/lsws/bin/openlitespeed")); err == nil {
			id = "openlitespeed"
		}
		out = append(out, product(id, findVersion(v))...)
	}
	out = append(out, product("directadmin", directAdminVersion(ctx))...)
	// ConfigServer Security & Firewall: "14.21".
	if v, ok := firstLine(productPath("etc/csf/version.txt")); ok {
		out = append(out, product("csf", findVersion(v))...)
	}
	// Linux Malware Detect: the script sets ver=1.6.5.
	out = append(out, product("maldet", assignment(productPath("usr/local/maldetect/maldet"), "ver="))...)
	// ISPConfig: define('ISPC_APP_VERSION', '3.2.11p2');
	out = append(out, product("ispconfig", assignment(productPath("usr/local/ispconfig/server/lib/config.inc.php"), "ISPC_APP_VERSION"))...)
	return out
}

// assignment returns the version on the first line of a small file that
// contains marker ("ver=1.6.5", "define('ISPC_APP_VERSION', '3.2.11')").
func assignment(path, marker string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(io.LimitReader(f, 1<<20))
	for sc.Scan() {
		line := sc.Text()
		if i := strings.Index(line, marker); i >= 0 {
			return findVersion(line[i+len(marker):])
		}
	}
	return ""
}

// directAdminVersion asks the DirectAdmin binary ("directadmin version" on
// current releases, "directadmin v" on older ones). The binary must be a
// root-owned file that only root can change, like a health.d command.
func directAdminVersion(ctx context.Context) string {
	dir := productPath("usr/local/directadmin")
	bin := filepath.Join(dir, "directadmin")
	if checkCommandFile(dir, bin) != nil {
		return ""
	}
	for _, arg := range []string{"version", "v"} {
		out, code, err := run(ctx, 10*time.Second, bin, arg)
		if err == nil && code == 0 {
			if v := findVersion(string(out)); v != "" {
				return v
			}
		}
	}
	return ""
}
