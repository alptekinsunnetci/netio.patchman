package agent

import (
	"strings"
	"testing"
)

func TestParseMounts(t *testing.T) {
	in := `sysfs /sys sysfs rw 0 0
/dev/sda2 /boot ext4 rw,relatime 0 0
/dev/mapper/vg-root / xfs rw 0 0
tmpfs /run tmpfs rw 0 0
/dev/loop3 /snap/core22/1663 squashfs ro 0 0
overlay /var/lib/docker/overlay2/abc/merged overlay rw 0 0
/dev/sdb1 /srv/my\040data ext4 rw 0 0
/dev/sdb1 /srv/my\040data ext4 rw 0 0
/dev/sdc1 /var/lib/docker/volumes ext4 rw 0 0
/dev/sdc1 /var/lib/kubelet/pods/x/volume ext4 rw 0 0
/dev/mapper/vg-root /var/lib/containers/storage xfs rw 0 0
nas:/export /mnt/nas nfs4 rw 0 0
`
	got := parseMounts(strings.NewReader(in))
	want := []string{"/", "/boot", "/srv/my data", "/var/lib/docker/volumes"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("mounts: %q", got)
	}
}

func TestParseLoadAndMeminfo(t *testing.T) {
	if l := parseLoadavg("0.52 0.40 0.30 1/234 5678\n"); len(l) != 3 || l[0] != 0.52 || l[2] != 0.30 {
		t.Errorf("load: %v", l)
	}
	if l := parseLoadavg("garbage"); l != nil {
		t.Errorf("bad load: %v", l)
	}
	m := parseMeminfoBytes(strings.NewReader("MemTotal:        8000000 kB\nMemAvailable:    6000000 kB\nSwapTotal:             0 kB\nHugePages_Total:       0\n"))
	if m["MemTotal"] != 8000000*1024 || m["MemAvailable"] != 6000000*1024 || m["HugePages_Total"] != 0 {
		t.Errorf("meminfo: %v", m)
	}
}

func TestFindVersion(t *testing.T) {
	for in, want := range map[string]string{"DirectAdmin v.1.672": "1.672", "18.0.65 Ubuntu 22.04 1800241113.14": "18.0.65", "11.124.0.15": "11.124.0.15", "none": ""} {
		if got := findVersion(in); got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
}

func TestParseProcStat(t *testing.T) {
	busy, total, ok := parseProcStat("cpu  100 0 50 800 50 0 0 0 0 0\ncpu0 50 0 25 400 25 0 0 0 0 0\n")
	if !ok || total != 1000 || busy != 150 {
		t.Errorf("proc stat: %d %d %v", busy, total, ok)
	}
	if _, _, ok := parseProcStat("intr 1 2 3\n"); ok {
		t.Error("no cpu line accepted")
	}
}
