package agent

import (
	"bufio"
	"bytes"
	"strings"
	"unicode"

	"netio.patchman/internal/protocol"
)

// Third-party Windows programs are updated through winget (Windows Package
// Manager) when it is installed. The agent runs as SYSTEM, so it sees the
// programs installed for all users; per-user installations are not listed.
// winget has no machine-readable output for "upgrade", so the table is parsed
// by column positions: the header words are localized, their positions are
// not.

// WingetRepository marks pending updates that winget installs.
const WingetRepository = "winget"

// wingetArgs are the options of every winget call (no prompts, winget source).
var wingetArgs = []string{"--accept-source-agreements", "--disable-interactivity", "--source", "winget"}

// parseWingetUpgrade parses "winget upgrade" output:
//
//	Name               Id               Version      Available Source
//	------------------------------------------------------------------
//	7-Zip 26.01 (x64)  7zip.7zip        26.01        26.06     winget
//	3 upgrades available.
func parseWingetUpgrade(out []byte) []protocol.Update {
	var lines []string
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		l := sc.Text()
		// Progress spinners are overwritten with carriage returns.
		if i := strings.LastIndexByte(l, '\r'); i >= 0 {
			l = l[i+1:]
		}
		lines = append(lines, strings.TrimRightFunc(l, unicode.IsSpace))
	}
	var out2 []protocol.Update
	seen := map[string]bool{}
	for i := 1; i < len(lines); i++ {
		if !isRule(lines[i]) {
			continue
		}
		cols := columnStarts([]rune(lines[i-1]))
		if len(cols) < 4 {
			continue
		}
		for _, l := range lines[i+1:] {
			if l == "" || isRule(l) {
				break
			}
			f := splitColumns([]rune(l), cols)
			if f == nil {
				break
			}
			id, cur, avail := f[1], f[2], f[3]
			// Long values are cut with an ellipsis; such an id cannot be targeted.
			if strings.HasSuffix(id, "…") || !protocol.ValidPackageName(id) || avail == "" || seen[id] {
				continue
			}
			seen[id] = true
			out2 = append(out2, protocol.Update{Name: id, Title: f[0], CurrentVersion: strings.TrimPrefix(cur, "< "),
				AvailableVersion: avail, Repository: WingetRepository})
		}
	}
	return out2
}

func isRule(l string) bool {
	return len(l) >= 10 && strings.Trim(l, "-") == ""
}

// columnStarts returns the rune offsets where header words begin.
func columnStarts(header []rune) []int {
	var starts []int
	for i, r := range header {
		if !unicode.IsSpace(r) && (i == 0 || unicode.IsSpace(header[i-1])) {
			starts = append(starts, i)
		}
	}
	return starts
}

// splitColumns cuts a row at the column offsets; nil if it does not fit.
func splitColumns(row []rune, cols []int) []string {
	if len(row) <= cols[3] {
		return nil
	}
	out := make([]string, len(cols))
	for i, start := range cols {
		end := len(row)
		if i+1 < len(cols) && cols[i+1] < end {
			end = cols[i+1]
		}
		if start >= len(row) {
			break
		}
		out[i] = strings.TrimSpace(string(row[start:end]))
	}
	return out
}

// wingetUpgradeCommand upgrades one package by its exact id.
func wingetUpgradeCommand(exe, id string) command {
	args := append([]string{"upgrade", "--id", id, "--exact", "--silent", "--accept-package-agreements"}, wingetArgs...)
	return command{name: exe, args: args, soft: true}
}
