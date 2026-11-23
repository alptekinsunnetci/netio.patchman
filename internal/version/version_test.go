package version

import "testing"

func TestCodename(t *testing.T) {
	for v, want := range map[string]string{"1.0.5": "gökalp", "v1.2.0": "gökalp", "1.10.3": "gökalp", "0.9.0": "", "2.0.0": "", "0.1.0-dev": ""} {
		if got := Codename(v); got != want {
			t.Errorf("%s: %q, want %q", v, got, want)
		}
	}
}
