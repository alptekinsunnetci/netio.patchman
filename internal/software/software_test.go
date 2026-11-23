package software

import (
	"testing"

	"netio.patchman/internal/protocol"
)

func TestDetectDebian(t *testing.T) {
	pkgs := []protocol.Package{
		{Name: "nginx", Version: "1.22.1-9+deb12u2"},
		{Name: "nginx-common", Version: "1.22.1-9+deb12u2"},
		{Name: "php8.2-common", Version: "8.2.26-1~deb12u1"},
		{Name: "php8.2-fpm", Version: "8.2.26-1~deb12u1"},
		{Name: "php8.1-fpm", Version: "8.1.31-1+0~20241121.98+debian12~1.gbp9d44f7"},
		{Name: "php8.1-common", Version: "8.1.31-1+0~20241121.98+debian12~1.gbp9d44f7"},
		{Name: "postgresql-16", Version: "16.6-1.pgdg120+1"},
		{Name: "postgresql-client-16", Version: "16.6-1.pgdg120+1"},
		{Name: "postgresql-16-postgis-3", Version: "3.5.0+dfsg-1.pgdg120+1"},
		{Name: "mariadb-server", Version: "1:10.11.6-0+deb12u1"},
		{Name: "mariadb-server-core", Version: "1:10.11.6-0+deb12u1"},
		{Name: "openssh-server", Version: "1:9.2p1-2+deb12u3"},
		{Name: "docker-ce", Version: "5:27.3.1-1~debian.12~bookworm"},
		{Name: "redis-tools", Version: "5:7.0.15-1~deb12u1"},
	}
	services := []protocol.Service{
		{Name: "nginx", State: "running", Enabled: true},
		{Name: "php8.2-fpm", State: "running"},
		{Name: "php8.1-fpm", State: "stopped"},
		{Name: "postgresql", State: "stopped", Enabled: true},
		{Name: "postgresql@16-main", State: "running"},
		{Name: "mariadb", State: "failed"},
		{Name: "ssh", State: "running"},
	}
	got := map[string]Installed{}
	for _, in := range Detect(protocol.PMApt, pkgs, nil, services, true) {
		got[in.Software+" "+in.Cycle] = in
	}
	want := map[string]Installed{
		"nginx 1.22":    {Software: "nginx", Cycle: "1.22", Version: "1.22.1", Package: "nginx", PackageVersion: "1.22.1-9+deb12u2", Running: Running, Service: "nginx"},
		"php 8.1":       {Software: "php", Cycle: "8.1", Version: "8.1.31", Package: "php8.1-common", PackageVersion: "8.1.31-1+0~20241121.98+debian12~1.gbp9d44f7", Running: RunningUnknown},
		"php 8.2":       {Software: "php", Cycle: "8.2", Version: "8.2.26", Package: "php8.2-common", PackageVersion: "8.2.26-1~deb12u1", Running: RunningUnknown},
		"php-fpm 8.1":   {Software: "php-fpm", Cycle: "8.1", Version: "8.1.31", Package: "php8.1-fpm", PackageVersion: "8.1.31-1+0~20241121.98+debian12~1.gbp9d44f7", Running: NotRunning, Service: "php8.1-fpm"},
		"php-fpm 8.2":   {Software: "php-fpm", Cycle: "8.2", Version: "8.2.26", Package: "php8.2-fpm", PackageVersion: "8.2.26-1~deb12u1", Running: Running, Service: "php8.2-fpm"},
		"postgresql 16": {Software: "postgresql", Cycle: "16", Version: "16.6", Package: "postgresql-16", PackageVersion: "16.6-1.pgdg120+1", Running: Running, Service: "postgresql@16-main"},
		"mariadb 10.11": {Software: "mariadb", Cycle: "10.11", Version: "10.11.6", Package: "mariadb-server-core", PackageVersion: "1:10.11.6-0+deb12u1", Running: NotRunning, Service: "mariadb"},
		"openssh 9.2":   {Software: "openssh", Cycle: "9.2", Version: "9.2p1", Package: "openssh-server", PackageVersion: "1:9.2p1-2+deb12u3", Running: Running, Service: "ssh"},
		"docker 27":     {Software: "docker", Cycle: "27", Version: "27.3.1", Package: "docker-ce", PackageVersion: "5:27.3.1-1~debian.12~bookworm", Running: NotRunning},
	}
	if len(got) != len(want) {
		t.Errorf("detected %d products: %+v", len(got), got)
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s:\n got %+v\nwant %+v", k, got[k], w)
		}
	}
}

func TestDetectRPMAndUnknownServices(t *testing.T) {
	pkgs := []protocol.Package{
		{Name: "httpd", Version: "2.4.62-1.el9"},
		{Name: "postgresql16-server", Version: "16.4-1PGDG.rhel9"},
		{Name: "postgresql-server", Version: "13.16-1.el9"},
		{Name: "MariaDB-server", Version: "10.6.20-1.el9"},
		{Name: "nodejs", Version: "1:20.16.0-1.module+el9.4.0+2154+2d3a3b26"},
	}
	got := map[string]Installed{}
	for _, in := range Detect(protocol.PMDnf, pkgs, nil, nil, false) {
		got[in.Software+" "+in.Cycle] = in
	}
	for _, k := range []string{"apache 2.4", "postgresql 16", "postgresql 13", "mariadb 10.6", "nodejs 20"} {
		in, ok := got[k]
		if !ok {
			t.Errorf("%s not detected: %v", k, got)
			continue
		}
		if in.Running != RunningUnknown {
			t.Errorf("%s: running %d without services", k, in.Running)
		}
	}
	if len(got) != 5 {
		t.Errorf("detected: %v", got)
	}
}
