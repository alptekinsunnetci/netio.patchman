package agent

import (
	"testing"

	"netio.patchman/internal/protocol"
)

func TestParseSystemd(t *testing.T) {
	units := []byte(`cron.service                 loaded    active   running Regular background program processing daemon
nginx.service                loaded    active   running A high performance web server
● php8.2-fpm.service         loaded    failed   failed  The PHP 8.2 FastCGI Process Manager
systemd-tmpfiles-setup.service loaded  active   exited  Create Volatile Files and Directories
apache2.service              loaded    inactive dead    The Apache HTTP Server
getty@tty1.service           loaded    active   running Getty on tty1
ghost.service                not-found inactive dead    ghost.service
`)
	files := []byte(`apache2.service              enabled         enabled
cron.service                 enabled         enabled
getty@.service               enabled         enabled
nginx.service                enabled         enabled
php8.2-fpm.service           enabled         enabled
redis-server.service         disabled        enabled
systemd-tmpfiles-setup.service static        -
`)
	got := parseSystemd(units, files)
	want := map[string]protocol.Service{
		"apache2":                {Name: "apache2", State: "stopped", Enabled: true},
		"cron":                   {Name: "cron", State: "running", Enabled: true},
		"getty@tty1":             {Name: "getty@tty1", State: "running"},
		"nginx":                  {Name: "nginx", State: "running", Enabled: true},
		"php8.2-fpm":             {Name: "php8.2-fpm", State: "failed", Enabled: true},
		"redis-server":           {Name: "redis-server", State: "stopped"},
		"systemd-tmpfiles-setup": {Name: "systemd-tmpfiles-setup", State: "stopped"},
	}
	if len(got) != len(want) {
		t.Fatalf("services: %+v", got)
	}
	for _, s := range got {
		if want[s.Name] != s {
			t.Errorf("%s: %+v, want %+v", s.Name, s, want[s.Name])
		}
	}
	if got[0].Name != "apache2" {
		t.Errorf("not sorted: %v", got[0].Name)
	}
}

func TestParseOpenRC(t *testing.T) {
	out := []byte(`Runlevel: default
 sshd                                                     [  started  ]
 crond                                                    [  started  ]
Runlevel: boot
 hostname                                                 [  started  ]
Runlevel: shutdown
 killprocs                                                [  stopped  ]
Dynamic Runlevel: hotplugged
Dynamic Runlevel: needed/wanted
 sysfs                                                    [  started  ]
Dynamic Runlevel: manual
 nginx                                                    [  started  ]
 redis                                                    [  crashed  ]
`)
	got := map[string]protocol.Service{}
	for _, s := range parseOpenRC(out) {
		got[s.Name] = s
	}
	for name, want := range map[string]protocol.Service{
		"sshd":      {Name: "sshd", State: "running", Enabled: true},
		"hostname":  {Name: "hostname", State: "running", Enabled: true},
		"killprocs": {Name: "killprocs", State: "stopped"},
		"sysfs":     {Name: "sysfs", State: "running"},
		"nginx":     {Name: "nginx", State: "running"},
		"redis":     {Name: "redis", State: "failed"},
	} {
		if got[name] != want {
			t.Errorf("%s: %+v, want %+v", name, got[name], want)
		}
	}
}
