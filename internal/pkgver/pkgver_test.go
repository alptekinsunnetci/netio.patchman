package pkgver

import "testing"

func TestCompareDeb(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "1.1", -1},
		{"1.0-1", "1.0-2", -1},
		{"1:1.0", "2.0", 1}, // epoch wins
		{"1.0~rc1", "1.0", -1},
		{"1.0~rc1", "1.0~rc2", -1},
		{"1.0", "1.0+deb12u1", -1},
		{"1.22.1-9", "1.22.1-9+deb12u3", -1},
		{"3.0.11-1~deb12u2", "3.0.17-1~deb12u1", -1},
		{"2.39-0ubuntu8.9", "2.39-0ubuntu8.12", -1},
		{"1.2a", "1.2", 1},
		{"1.2", "1.2.0", -1},
		{"10", "9", 1},
		{"1.01", "1.1", 0},
		{"0:1.0", "1.0", 0},
		{"1.0-1ubuntu1", "1.0-1", 1},
		{"7.4.33-1+deb11u5", "7.4.33-1+deb11u10", -1},
		{"2.4.57-2", "2.4.57-2~bpo11+1", 1},
	} {
		if got := CompareDeb(c.a, c.b); got != c.want {
			t.Errorf("CompareDeb(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
		if got := CompareDeb(c.b, c.a); got != -c.want {
			t.Errorf("CompareDeb(%q, %q) = %d, want %d", c.b, c.a, got, -c.want)
		}
	}
}

func TestCompareRPM(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"1.0-1", "1.0-1", 0},
		{"1.0-1.el9", "1.0-2.el9", -1},
		{"1:3.0.7-24.el9", "3.0.7-25.el9", 1}, // epoch wins
		{"1.20.1-14.el9", "1.20.1-14.el9_2.1", -1},
		{"1.0", "1.0.1", -1},
		{"1.0a", "1.0", 1},
		{"1.0~rc1", "1.0", -1},
		{"1.0^git1", "1.0", 1},
		{"1.0^git1", "1.0.1", -1},
		{"2.0", "10.0", -1},
		{"1.0-1", "1.0", 0}, // a missing release matches any release
		{"8.0.32-1.module+el8.8.0+1283+4b77bdd7", "8.0.32-1.module+el8.8.0+1283+4b77bdd8", -1},
		{"5.4.17-2136.300.7.el8uek", "5.4.17-2136.301.1.el8uek", -1},
		{"a", "1", -1}, // numeric segments are newer than alphabetic ones
	} {
		if got := CompareRPM(c.a, c.b); got != c.want {
			t.Errorf("CompareRPM(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
		if got := CompareRPM(c.b, c.a); got != -c.want {
			t.Errorf("CompareRPM(%q, %q) = %d, want %d", c.b, c.a, got, -c.want)
		}
	}
}

func TestCompareAPK(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"1.2.3-r0", "1.2.3-r1", -1},
		{"1.2.3-r9", "1.2.4-r0", -1},
		{"1.2.3_rc1-r0", "1.2.3-r0", -1},
		{"1.2.3_p1-r0", "1.2.3-r0", 1},
		{"1.2.3a-r0", "1.2.3-r0", 1},
		{"3.1.4-r5", "3.1.4-r5", 0},
		{"1.10", "1.9", 1},
	} {
		if got := CompareAPK(c.a, c.b); got != c.want {
			t.Errorf("CompareAPK(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
		if got := CompareAPK(c.b, c.a); got != -c.want {
			t.Errorf("CompareAPK(%q, %q) = %d, want %d", c.b, c.a, got, -c.want)
		}
	}
}

func TestUpstreamAndMajorMinor(t *testing.T) {
	for _, c := range []struct{ pm, v, up, mm, major string }{
		{"apt", "1:2.4.57-5+deb12u1", "2.4.57", "2.4", "2"},
		{"apt", "8.2.7-1~deb12u1", "8.2.7", "8.2", "8"},
		{"apt", "1:9.6p1-3ubuntu13.5", "9.6p1", "9.6", "9"},
		{"apt", "16.4-0ubuntu0.24.04.1", "16.4", "16.4", "16"},
		{"dnf", "3:10.5.22-1.module+el8.8.0+1460+4f3b2a28", "10.5.22", "10.5", "10"},
		{"dnf", "1.20.1-14.el9_2.1", "1.20.1", "1.20", "1"},
		{"apk", "1.24.0-r15", "1.24.0", "1.24", "1"},
		{"apt", "16", "16", "16", "16"},
		{"apt", "0.08.1-1", "0.08.1", "0.8", "0"},
	} {
		up := Upstream(c.pm, c.v)
		if up != c.up || MajorMinor(up) != c.mm || Major(up) != c.major {
			t.Errorf("%s %q: upstream %q major.minor %q major %q, want %q %q %q", c.pm, c.v, up, MajorMinor(up), Major(up), c.up, c.mm, c.major)
		}
	}
}
