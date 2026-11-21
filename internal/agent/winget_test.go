package agent

import (
	"context"
	"strings"
	"testing"

	"netio.patchman/internal/protocol"
)

// Real "winget upgrade" output (Windows Server 2022, winget 1.29), with the
// spinner of the source update before the table.
const wingetSample = "\r   - \r   \\ \r" + `Name                                                         Id                              Version      Available
-----------------------------------------------------------------------------------------------------------------------
7-Zip 26.01 (x64)                                            7zip.7zip                       26.01        26.06
Linux için Windows Alt Sistemi                               Microsoft.WSL                   2.6.1.0      3.0.5
Microsoft Visual C++ 2015 Redistributable (x64) - 14.0.24212 Microsoft.VCRedist.2015+.x64    14.0.24212.0 14.52.37029.0
Python Launcher                                              Python.Launcher                 < 3.14.7     3.15.2
Some Very Long Product Name                                  Vendor.SomeVeryLongPackageId…   1.0          2.0
19 upgrades available.

The following packages have an upgrade available, but require explicit targeting for upgrade:
Name      Id            Version Available
-----------------------------------------
Pinned    Vendor.Pinned 1.0     2.0
`

func TestParseWingetUpgrade(t *testing.T) {
	ups := parseWingetUpgrade([]byte(wingetSample))
	var ids []string
	for _, u := range ups {
		ids = append(ids, u.Name)
		if u.Repository != WingetRepository || u.Security {
			t.Errorf("%+v", u)
		}
	}
	if strings.Join(ids, ",") != "7zip.7zip,Microsoft.WSL,Microsoft.VCRedist.2015+.x64,Python.Launcher,Vendor.Pinned" {
		t.Fatalf("ids: %v", ids)
	}
	if ups[1].Title != "Linux için Windows Alt Sistemi" || ups[1].CurrentVersion != "2.6.1.0" || ups[1].AvailableVersion != "3.0.5" {
		t.Errorf("non-ASCII name: %+v", ups[1])
	}
	if ups[3].CurrentVersion != "3.14.7" {
		t.Errorf("version prefix: %+v", ups[3])
	}

	// Localized headers (Turkish display language) parse by position.
	tr := "Ad                Kimlik        Sürüm  Kullanılabilir Kaynak\n" +
		"---------------------------------------------------------------\n" +
		"Git               Git.Git       2.49.0 2.56.1         winget\n"
	if ups := parseWingetUpgrade([]byte(tr)); len(ups) != 1 || ups[0].Name != "Git.Git" || ups[0].AvailableVersion != "2.56.1" {
		t.Errorf("localized: %+v", ups)
	}
	if ups := parseWingetUpgrade([]byte("No installed package found matching input criteria.\n")); len(ups) != 0 {
		t.Errorf("no table: %+v", ups)
	}
}

func TestWindowsJobsWithWinget(t *testing.T) {
	f := &fakeHost{pending: []protocol.Update{
		{Name: "KB5131090", Security: true},
		{Name: "7zip.7zip", Repository: WingetRepository},
		{Name: "Git.Git", Repository: WingetRepository},
	}, upgrade: map[string]bool{"KB5131090": true, "7zip.7zip": true}}
	r := f.runner(t)
	r.PM, r.Winget = protocol.PMWindowsUpdate, `C:\winget.exe`
	res := r.Run(context.Background(), protocol.Job{Type: protocol.JobUpgradeAll})
	if len(f.ran) != 3 || f.ran[0] != "windows-update install KB5131090" || !strings.HasPrefix(f.ran[1], `C:\winget.exe upgrade --id 7zip.7zip --exact --silent`) {
		t.Fatalf("commands: %v", f.ran)
	}
	if !res.Succeeded || strings.Join(res.Remaining, ",") != "Git.Git" {
		t.Errorf("partial: %+v", res)
	}
	// Security jobs leave winget packages alone (no security data).
	f = &fakeHost{pending: []protocol.Update{{Name: "KB5131090", Security: true}, {Name: "7zip.7zip", Repository: WingetRepository}}, upgrade: map[string]bool{"KB5131090": true}}
	r = f.runner(t)
	r.PM, r.Winget = protocol.PMWindowsUpdate, `C:\winget.exe`
	r.Run(context.Background(), protocol.Job{Type: protocol.JobUpgradeSecurity})
	if len(f.ran) != 1 || f.ran[0] != "windows-update install KB5131090" {
		t.Errorf("security: %v", f.ran)
	}
}
