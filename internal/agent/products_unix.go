//go:build !windows

package agent

import (
	"context"
	"os"
	"path/filepath"
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
	return out
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
