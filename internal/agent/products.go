package agent

import (
	"bufio"
	"os"
	"regexp"
	"strings"

	"netio.patchman/internal/protocol"
)

// Products are software installs outside the package manager. The probes
// only read fixed files and registry keys (and run one fixed binary for
// DirectAdmin); nothing comes from the server.

var versionRE = regexp.MustCompile(`\d+(?:\.\d+){1,3}`)

// firstLine returns the first non-empty line of a small file.
func firstLine(path string) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4096), 4096)
	for sc.Scan() {
		if s := strings.TrimSpace(sc.Text()); s != "" {
			return s, true
		}
	}
	return "", false
}

// findVersion returns the first dotted version number in s ("DirectAdmin
// v.1.672" -> "1.672", "18.0.65 Ubuntu 22.04 1800241113.14" -> "18.0.65").
func findVersion(s string) string { return versionRE.FindString(s) }

func product(id, version string) []protocol.Product {
	if version == "" {
		return nil
	}
	return []protocol.Product{{Software: id, Version: version}}
}
