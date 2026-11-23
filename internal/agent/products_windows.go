//go:build windows

package agent

import (
	"context"
	"fmt"

	"golang.org/x/sys/windows/registry"

	"netio.patchman/internal/protocol"
)

// ProbeProducts reads IIS and SQL Server versions from the registry; the
// Uninstall entries of both carry release versions, not the patch level.
func ProbeProducts(ctx context.Context) []protocol.Product {
	var out []protocol.Product
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\InetStp`, registry.QUERY_VALUE|registry.WOW64_64KEY); err == nil {
		major, ok1 := regInt(k, "MajorVersion")
		minor, ok2 := regInt(k, "MinorVersion")
		k.Close()
		if ok1 && ok2 {
			out = append(out, product("iis", fmt.Sprintf("%d.%d", major, minor))...)
		}
	}
	out = append(out, sqlServerInstances()...)
	return out
}

// sqlServerInstances returns the patch level of every SQL Server instance
// ("16.0.4165.4"), one entry per distinct version.
func sqlServerInstances() []protocol.Product {
	const base = `SOFTWARE\Microsoft\Microsoft SQL Server`
	names, err := registry.OpenKey(registry.LOCAL_MACHINE, base+`\Instance Names\SQL`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return nil
	}
	defer names.Close()
	instances, err := names.ReadValueNames(0)
	if err != nil {
		return nil
	}
	var out []protocol.Product
	seen := map[string]bool{}
	for _, inst := range instances {
		id := regString(names, inst) // "MSSQL16.MSSQLSERVER"
		if id == "" {
			continue
		}
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, base+`\`+id+`\Setup`, registry.QUERY_VALUE|registry.WOW64_64KEY)
		if err != nil {
			continue
		}
		v := regString(k, "PatchLevel")
		if v == "" {
			v = regString(k, "Version")
		}
		k.Close()
		if v = findVersion(v); v != "" && !seen[v] {
			seen[v] = true
			out = append(out, protocol.Product{Software: "mssql", Version: v})
		}
	}
	return out
}
