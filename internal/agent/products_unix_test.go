//go:build !windows

package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"netio.patchman/internal/protocol"
)

func TestProbeProducts(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string, mode os.FileMode) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		_ = os.Chmod(filepath.Dir(p), 0o755)
	}
	write("usr/local/cpanel/version", "11.124.0.15\n", 0o644)
	write("usr/local/psa/version", "18.0.65 Ubuntu 22.04 1800241113.14\n", 0o644)
	write("usr/local/lsws/VERSION", "6.3.1\n", 0o644)
	write("usr/local/directadmin/directadmin", "#!/bin/sh\n[ \"$1\" = version ] && echo 'v1.672 3d4bc2f'\n", 0o755)
	old := productRoot
	productRoot = root
	defer func() { productRoot = old }()

	got := map[string]string{}
	for _, p := range ProbeProducts(context.Background()) {
		got[p.Software] = p.Version
	}
	want := map[string]string{"cpanel": "11.124.0.15", "plesk": "18.0.65", "litespeed": "6.3.1", "directadmin": "1.672"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %q, want %q (all: %v)", k, got[k], v, got)
		}
	}
	// OpenLiteSpeed has its own binary; a group-writable DirectAdmin binary is not run.
	write("usr/local/lsws/bin/openlitespeed", "", 0o755)
	if err := os.Chmod(filepath.Join(root, "usr/local/directadmin/directadmin"), 0o775); err != nil {
		t.Fatal(err)
	}
	got = map[string]string{}
	for _, p := range ProbeProducts(context.Background()) {
		got[p.Software] = p.Version
	}
	if got["openlitespeed"] != "6.3.1" || got["litespeed"] != "" || got["directadmin"] != "" {
		t.Errorf("second probe: %v", got)
	}
	if len(protocol.CleanProducts([]protocol.Product{{Software: "cpanel", Version: "11.124.0.15"}, {Software: "x", Version: "1"}, {Software: "plesk", Version: "; rm"}},
		func(id string) bool { return id == "cpanel" || id == "plesk" })) != 1 {
		t.Error("CleanProducts")
	}
}
