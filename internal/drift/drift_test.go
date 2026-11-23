package drift

import "testing"

func TestEvaluate(t *testing.T) {
	h := HostFacts{PM: "apt",
		Packages: map[string][]string{"openssh-server": {"1:9.2p1-2+deb12u3"}, "telnetd": {"0.17+2.4-2"}, "nginx": {"1.22.1-9+deb12u1"}},
		Software: []Installed{
			{Software: "php", Cycle: "8.1", PackageVersion: "8.1.31-1"},
			{Software: "php", Cycle: "8.2", PackageVersion: "8.2.26-1~deb12u1"},
			{Software: "nginx", Cycle: "1.22", PackageVersion: "1.22.1-9+deb12u1", Running: 0},
			{Software: "redis", Cycle: "7.0", PackageVersion: "5:7.0.15-1~deb12u1", Running: -1},
		}}
	rules := []Rule{
		{ID: 1, Kind: KindRequired, SubjectType: SubjectSoftware, Subject: "mariadb"},
		{ID: 2, Kind: KindRequired, SubjectType: SubjectSoftware, Subject: "nginx"},
		{ID: 3, Kind: KindForbidden, SubjectType: SubjectPackage, Subject: "telnetd"},
		{ID: 4, Kind: KindForbidden, SubjectType: SubjectPackage, Subject: "rsh-server"},
		{ID: 5, Kind: KindAllowedCycles, SubjectType: SubjectSoftware, Subject: "php", Value: "8.2, 8.3"},
		// The backported fix (deb12u3) meets a minimum written as the patched distribution version.
		{ID: 6, Kind: KindMinVersion, SubjectType: SubjectPackage, Subject: "openssh-server", Value: "1:9.2p1-2+deb12u3"},
		{ID: 7, Kind: KindMinVersion, SubjectType: SubjectSoftware, Subject: "nginx", Value: "1.22.1-9+deb12u2"},
		{ID: 8, Kind: KindRunning, SubjectType: SubjectSoftware, Subject: "nginx"},
		{ID: 9, Kind: KindRunning, SubjectType: SubjectSoftware, Subject: "redis"},                          // unknown state: no finding
		{ID: 10, Kind: KindAllowedCycles, SubjectType: SubjectSoftware, Subject: "postgresql", Value: "16"}, // not installed
	}
	got := map[int64]string{}
	for _, v := range Evaluate(h, rules) {
		got[v.RuleID] = v.Found
	}
	want := map[int64]string{1: "", 3: "0.17+2.4-2", 5: "8.1", 7: "1.22.1-9+deb12u1", 8: ""}
	if len(got) != len(want) {
		t.Errorf("violations: %v", got)
	}
	for id, f := range want {
		if g, ok := got[id]; !ok || g != f {
			t.Errorf("rule %d: %q (%v), want %q", id, g, ok, f)
		}
	}
}

func TestValid(t *testing.T) {
	for _, c := range []struct {
		r    Rule
		want bool
	}{
		{Rule{Kind: KindRequired, SubjectType: SubjectSoftware, Subject: "nginx"}, true},
		{Rule{Kind: KindRequired, SubjectType: SubjectSoftware, Subject: "nope"}, false},
		{Rule{Kind: KindAllowedCycles, SubjectType: SubjectSoftware, Subject: "php"}, false},
		{Rule{Kind: KindMinVersion, SubjectType: SubjectPackage, Subject: "openssl", Value: "3.0.15-1"}, true},
		{Rule{Kind: KindRunning, SubjectType: SubjectPackage, Subject: "openssl"}, false},
		{Rule{Kind: "other", SubjectType: SubjectPackage, Subject: "openssl"}, false},
	} {
		if Valid(c.r) != c.want {
			t.Errorf("%+v: %v", c.r, !c.want)
		}
	}
}
