package agent

import (
	"context"
	"strings"
	"testing"

	"netio.patchman/internal/protocol"
)

func TestJobExclusions(t *testing.T) {
	ctx := context.Background()
	ex := map[string]string{protocol.ParamExclude: "linux-*,mysql-server"}
	pending := func() []protocol.Update {
		return []protocol.Update{{Name: "libssl3", Security: true}, {Name: "linux-image-amd64", Security: true}, {Name: "mysql-server"}, {Name: "tzdata"}}
	}

	// apt: "upgrade all" becomes an explicit list without the excluded packages.
	f := &fakeHost{pending: pending(), upgrade: map[string]bool{"libssl3": true, "tzdata": true, "linux-image-amd64": true, "mysql-server": true}}
	res := f.runner(t).Run(ctx, protocol.Job{Type: protocol.JobUpgradeAll, Params: ex})
	cmd := f.ran[1]
	if !strings.Contains(cmd, "install --only-upgrade libssl3 tzdata") || strings.Contains(cmd, "linux-image") || strings.Contains(cmd, "mysql") {
		t.Errorf("apt all: %v", f.ran)
	}
	if !res.Succeeded || len(res.Remaining) != 0 || !strings.Contains(res.Output, "linux-image-amd64, mysql-server") {
		t.Errorf("apt all result: %+v", res)
	}

	// Security job: excluded security packages are not targeted.
	f = &fakeHost{pending: pending(), upgrade: map[string]bool{"libssl3": true}}
	res = f.runner(t).Run(ctx, protocol.Job{Type: protocol.JobUpgradeSecurity, Params: ex})
	if !strings.HasSuffix(f.ran[1], "--only-upgrade libssl3") || !res.Succeeded {
		t.Errorf("apt security: %v %+v", f.ran, res)
	}

	// Selected packages that are all excluded: nothing runs.
	f = &fakeHost{pending: pending()}
	res = f.runner(t).Run(ctx, protocol.Job{Type: protocol.JobUpgradePackages, Packages: []string{"mysql-server"}, Params: ex})
	if len(f.ran) != 1 || !res.Succeeded || !strings.Contains(res.Output, "mysql-server") {
		t.Errorf("all selected excluded: %v %+v", f.ran, res)
	}

	// dnf passes the patterns as --exclude options.
	f = &fakeHost{pending: pending(), upgrade: map[string]bool{"libssl3": true, "tzdata": true}}
	r := f.runner(t)
	r.PM = protocol.PMDnf
	r.Run(ctx, protocol.Job{Type: protocol.JobUpgradeAll, Params: ex})
	if len(f.ran) != 1 || f.ran[0] != "dnf -y upgrade --exclude=linux-* --exclude=mysql-server" {
		t.Errorf("dnf: %v", f.ran)
	}

	// Windows: KB patterns, case-insensitive.
	f = &fakeHost{pending: []protocol.Update{{Name: "KB5034439", Security: true}, {Name: "KB5131090", Security: true}}, upgrade: map[string]bool{"KB5131090": true}}
	r = f.runner(t)
	r.PM = protocol.PMWindowsUpdate
	res = r.Run(ctx, protocol.Job{Type: protocol.JobUpgradeSecurity, Params: map[string]string{protocol.ParamExclude: "kb5034439"}})
	if len(f.ran) != 1 || f.ran[0] != "windows-update install KB5131090" || !res.Succeeded {
		t.Errorf("windows: %v %+v", f.ran, res)
	}

	// zypper patches cannot exclude packages.
	f = &fakeHost{pending: pending()}
	r = f.runner(t)
	r.PM = protocol.PMZypper
	if res := r.Run(ctx, protocol.Job{Type: protocol.JobUpgradeSecurity, Params: ex}); res.Succeeded || len(f.ran) != 0 {
		t.Errorf("zypper security with exclusions: %+v %v", res, f.ran)
	}
}

func TestParseExcludePatterns(t *testing.T) {
	got, bad := protocol.ParseExcludePatterns("kernel*, mysql-server\nKB5034439;  kernel* ; ../etc/passwd [")
	if strings.Join(got, ",") != "kernel*,mysql-server,KB5034439" || strings.Join(bad, ",") != "../etc/passwd,[" {
		t.Errorf("got %v bad %v", got, bad)
	}
	if !protocol.Excluded(got, "kernel-core") || !protocol.Excluded(got, "kb5034439") || protocol.Excluded(got, "openssl") {
		t.Error("matching")
	}
}
