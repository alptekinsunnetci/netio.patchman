package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"netio.patchman/internal/i18n"
	"netio.patchman/internal/protocol"
)

const aptPolicy = `openssl:
  Installed: 3.0.15-1~deb12u1
  Candidate: 3.0.15-1~deb12u1
  Version table:
 *** 3.0.15-1~deb12u1 500
        500 http://security.debian.org/debian-security bookworm-security/main amd64 Packages
        100 /var/lib/dpkg/status
     3.0.11-1~deb12u2 500
        500 http://deb.debian.org/debian bookworm/main amd64 Packages
     3.0.9-1 100
        100 /var/lib/dpkg/status
`

func TestAvailabilityParsers(t *testing.T) {
	if !aptPolicyHas(aptPolicy, "3.0.11-1~deb12u2") || !aptPolicyHas(aptPolicy, "3.0.15-1~deb12u1") {
		t.Errorf("apt: repository versions not found")
	}
	if aptPolicyHas(aptPolicy, "3.0.9-1") || aptPolicyHas(aptPolicy, "1.0") {
		t.Errorf("apt: a version only in dpkg status counted as available")
	}
	dnf := "Available Packages\nopenssl.x86_64                1:3.0.7-24.el9                baseos\nopenssl.x86_64                1:3.0.7-27.el9                baseos\nopenssl-libs.i686             1:3.0.7-27.el9                baseos\n"
	if !dnfListHas(dnf, "openssl", "x86_64", "1:3.0.7-24.el9") || dnfListHas(dnf, "openssl", "x86_64", "1:3.0.7-20.el9") || dnfListHas(dnf, "openssl-libs", "x86_64", "1:3.0.7-27.el9") {
		t.Errorf("dnf availability")
	}
	if !dnfListHas("bash.x86_64   5.1.8-6.el9   baseos\n", "bash", "x86_64", "0:5.1.8-6.el9") {
		t.Errorf("dnf: zero epoch")
	}
	zyp := "S  | Name      | Type    | Version            | Arch   | Repository\n---+-----------+---------+--------------------+--------+-----------\nv  | openssl-3 | package | 3.1.4-150600.5.7.1 | x86_64 | Main Update Repository\ni+ | openssl-3 | package | 3.1.4-150600.5.15.1 | x86_64 | Main Update Repository\n"
	if !zypperSearchHas(zyp, "openssl-3", "x86_64", "3.1.4-150600.5.7.1") || zypperSearchHas(zyp, "openssl-3", "x86_64", "3.1.4-1") {
		t.Errorf("zypper availability")
	}
}

func TestDiffPackages(t *testing.T) {
	before := []protocol.Package{{Name: "a", Arch: "amd64", Version: "1"}, {Name: "b", Arch: "all", Version: "2"}, {Name: "gone", Version: "3"}}
	after := []protocol.Package{{Name: "a", Arch: "amd64", Version: "1.1"}, {Name: "b", Arch: "all", Version: "2"}, {Name: "new", Version: "4"}}
	got := protocol.DiffPackages(before, after)
	if len(got) != 3 || got[0] != (protocol.PackageChange{Name: "a", Arch: "amd64", From: "1", To: "1.1"}) || got[1].Name != "new" || got[1].From != "" || got[2].Name != "gone" || got[2].To != "" {
		t.Errorf("diff: %+v", got)
	}
}

// pkgDB is a package database the rollback tests change through Exec.
type pkgDB struct {
	versions map[string]string // name -> installed version
	repo     map[string]bool   // "name=version" offered by a repository
	apply    func(f *pkgDB)    // what the real install command does
	ran      []string
}

func (f *pkgDB) runner(t *testing.T) JobRunner {
	return JobRunner{L: i18n.MustLoad().Localizer(i18n.DefaultLocale), PM: protocol.PMApt, RemoteUpdates: true,
		Installed: func(context.Context) ([]protocol.Package, error) {
			var out []protocol.Package
			for n, v := range f.versions {
				out = append(out, protocol.Package{Name: n, Arch: "amd64", Version: v})
			}
			return out, nil
		},
		Available: func(_ context.Context, _, name, _, version string) (bool, error) {
			return f.repo[name+"="+version], nil
		},
		Exec: func(_ context.Context, c command, out *tailBuffer) int {
			line := c.name + " " + strings.Join(c.args, " ")
			f.ran = append(f.ran, line)
			if strings.Contains(line, " -s ") {
				_, _ = out.Write([]byte("Inst openssl [3.0.15-1~deb12u1] (3.0.11-1~deb12u2 Debian:12/stable [amd64])\n"))
				return 0
			}
			if strings.Contains(line, " install ") && f.apply != nil {
				f.apply(f)
			}
			return 0
		}}
}

func rollbackJob(mode string, targets ...protocol.PackageChange) protocol.Job {
	b, _ := json.Marshal(targets)
	return protocol.Job{ID: 9, Type: protocol.JobRollback, Params: map[string]string{protocol.ParamRollbackMode: mode, protocol.ParamRollbackTargets: string(b)}}
}

func TestRollbackJob(t *testing.T) {
	target := protocol.PackageChange{Name: "openssl", Arch: "amd64", To: "3.0.11-1~deb12u2"}
	f := &pkgDB{versions: map[string]string{"openssl": "3.0.15-1~deb12u1"}, repo: map[string]bool{"openssl=3.0.11-1~deb12u2": true},
		apply: func(f *pkgDB) { f.versions["openssl"] = "3.0.11-1~deb12u2" }}
	r := f.runner(t)

	// Check: nothing is installed, the plan is simulated.
	res := r.Run(context.Background(), rollbackJob(protocol.RollbackCheck, target))
	if !res.Succeeded || len(res.Rollback) != 1 || res.Rollback[0].Status != protocol.RollbackAvailable || res.Rollback[0].From != "3.0.15-1~deb12u1" {
		t.Fatalf("check: %+v", res)
	}
	if res.Preview == nil || len(res.Preview.Downgrades) != 1 || f.versions["openssl"] != "3.0.15-1~deb12u1" {
		t.Fatalf("check plan: %+v", res.Preview)
	}
	for _, l := range f.ran {
		if strings.Contains(l, "install") && !strings.Contains(l, " -s ") {
			t.Fatalf("check mode installed something: %s", l)
		}
	}

	// Apply: installed and verified.
	res = r.Run(context.Background(), rollbackJob(protocol.RollbackApply, target))
	if !res.Succeeded || res.Rollback[0].Status != protocol.RollbackDone || len(res.Changes) != 1 || res.Changes[0].To != "3.0.11-1~deb12u2" {
		t.Fatalf("apply: %+v", res)
	}

	// The package manager exits 0 but the version did not change: failed, not done.
	f.versions["openssl"] = "3.0.15-1~deb12u1"
	f.apply = func(*pkgDB) {}
	res = r.Run(context.Background(), rollbackJob(protocol.RollbackApply, target))
	if res.Succeeded || res.Rollback[0].Status != protocol.RollbackFailed || len(res.Remaining) != 1 {
		t.Fatalf("unverified apply: %+v", res)
	}

	// A version no repository offers stops the apply before anything runs.
	f.ran = nil
	gone := protocol.PackageChange{Name: "openssl", Arch: "amd64", To: "3.0.2-1"}
	res = r.Run(context.Background(), rollbackJob(protocol.RollbackApply, gone))
	if res.Succeeded || res.Rollback[0].Status != protocol.RollbackUnavailable {
		t.Fatalf("unavailable apply: %+v", res)
	}
	for _, l := range f.ran {
		if strings.Contains(l, "install") {
			t.Errorf("ran %s for an unavailable version", l)
		}
	}

	// Already at the target version.
	res = r.Run(context.Background(), rollbackJob(protocol.RollbackApply, protocol.PackageChange{Name: "openssl", Arch: "amd64", To: "3.0.15-1~deb12u1"}))
	if !res.Succeeded || res.Rollback[0].Status != protocol.RollbackCurrent {
		t.Fatalf("current: %+v", res)
	}

	// Invalid targets and unsupported package managers.
	bad := rollbackJob(protocol.RollbackApply, protocol.PackageChange{Name: "openssl", To: "1.0; rm -rf /"})
	if res := r.Run(context.Background(), bad); res.Succeeded {
		t.Errorf("invalid version accepted")
	}
	r.PM = protocol.PMApk
	if res := r.Run(context.Background(), rollbackJob(protocol.RollbackCheck, target)); res.Succeeded || res.Rollback[0].Status != protocol.RollbackUnavailable {
		t.Errorf("apk rollback: %+v", res)
	}
}

func TestPackageJobRecordsChanges(t *testing.T) {
	f := &pkgDB{versions: map[string]string{"openssl": "3.0.11-1~deb12u2"},
		apply: func(f *pkgDB) { f.versions["openssl"] = "3.0.15-1~deb12u1" }}
	r := f.runner(t)
	r.Exec = func(_ context.Context, c command, out *tailBuffer) int {
		if strings.Contains(strings.Join(c.args, " "), "upgrade") {
			f.apply(f)
		}
		return 0
	}
	res := r.Run(context.Background(), protocol.Job{ID: 1, Type: protocol.JobUpgradeAll})
	if !res.Succeeded || len(res.Changes) != 1 || res.Changes[0] != (protocol.PackageChange{Name: "openssl", Arch: "amd64", From: "3.0.11-1~deb12u2", To: "3.0.15-1~deb12u1"}) {
		t.Errorf("changes: %+v", res)
	}
}
