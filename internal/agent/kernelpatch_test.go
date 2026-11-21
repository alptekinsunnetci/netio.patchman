package agent

import (
	"strings"
	"testing"

	"netio.patchman/internal/protocol"
)

func TestParseLivepatch(t *testing.T) {
	out := []byte(`{"client-version":"10.8.3","machine-id":"x","architecture":"x86_64","cpu-model":"Intel",
"last-check":"2026-11-21T08:00:00Z","boot-time":"2026-11-01T00:00:00Z","uptime":"1000",
"status":[{"kernel":"5.15.0-105.115-generic","running":true,"livepatch":{"checkState":"checked","state":"applied",
"version":"105.2","fixes":"* cve-2024-1086 nf_tables use after free\n* CVE-2024-26581 netfilter\n* cve-2024-1086 duplicate"}}]}`)
	kp := parseLivepatch(out)
	if kp == nil || kp.Provider != protocol.Livepatch || strings.Join(kp.CVEs, ",") != "CVE-2024-1086,CVE-2024-26581" {
		t.Fatalf("applied: %+v", kp)
	}
	if kp := parseLivepatch([]byte(`{"status":[{"livepatch":{"state":"nothing-to-apply","fixes":""}}]}`)); kp != nil {
		t.Errorf("not applied: %+v", kp)
	}
	if kp := parseLivepatch([]byte(`not json`)); kp != nil {
		t.Errorf("invalid: %+v", kp)
	}
}

func TestRPMVerCmp(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"4.18.0-553.40.1.el8_10", "4.18.0-553.40.1.el8_10", 0},
		{"4.18.0-553.40.1.el8_10", "4.18.0-553.22.1.el8_10", 1},
		{"4.18.0-553.9.1.el8_10", "4.18.0-553.22.1.el8_10", -1},
		{"4.18.0-553.40.1.lve.el8", "4.18.0-553.40.1.el8_10", 1}, // letters compare as strings
		{"1.0", "1.0.1", -1},
		{"1.0a", "1.0", 1},
		{"1.0~rc1", "1.0", -1},
		{"2", "10", -1},
	}
	for _, c := range cases {
		if got := rpmVerCmp(c.a, c.b); got != c.want {
			t.Errorf("rpmVerCmp(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestKernelCareCovers(t *testing.T) {
	if !kernelCareCovers("4.18.0-553.40.1.el8_10.x86_64", "4.18.0-553.40.1.el8_10.x86_64") {
		t.Error("same release")
	}
	if !kernelCareCovers("4.18.0-553.44.1.el8_10.x86_64", "4.18.0-553.40.1.el8_10.x86_64") {
		t.Error("newer effective kernel")
	}
	if kernelCareCovers("4.18.0-553.22.1.el8_10.x86_64", "4.18.0-553.40.1.el8_10.x86_64") {
		t.Error("older effective kernel covers a newer package")
	}
	if kernelCareCovers("", "4.18.0-553.40.1.el8_10.x86_64") {
		t.Error("empty effective kernel")
	}
}

func TestNonKernelReasons(t *testing.T) {
	out := []byte("Core libraries or services have been updated since boot-up:\n  * kernel\n  * kernel-core\n  * linux-firmware\n\nReboot is required to fully utilize these updates.\n")
	if r := nonKernelReasons(out); len(r) != 0 {
		t.Errorf("kernel only: %v", r)
	}
	out = []byte("Core libraries or services have been updated since boot-up:\n  * glibc\n  * kernel\n")
	if r := nonKernelReasons(out); strings.Join(r, ",") != "glibc" {
		t.Errorf("glibc: %v", r)
	}
}
