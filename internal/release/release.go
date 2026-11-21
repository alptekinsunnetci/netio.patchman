// Package release describes the agent binaries the server distributes and
// rolls out with automatic agent updates.
//
// The distribution directory (PATCHMAN_AGENT_DIST_DIR) contains:
//
//	netio-patchman-agent-linux-<arch>             Linux binaries (amd64, arm64)
//	netio-patchman-agent-windows-amd64.exe        the Windows binary
//	<binary>.sha256                               "<hex>  <name>" (optional, computed if missing)
//	version                                       the agent version (optional, defaults to the server version)
package release

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"

	"netio.patchman/internal/protocol"
)

// Binary is one platform's agent binary.
type Binary struct {
	OS     string
	Arch   string
	Name   string
	SHA256 string
	Size   int64
}

// Release is the agent version the server rolls out.
type Release struct {
	Version string
	// Binaries by platform key "<goos>/<arch>".
	Binaries map[string]Binary
}

func key(goos, arch string) string { return goos + "/" + arch }

// Load reads the distribution directory. A missing directory yields an empty
// release (automatic updates are then unavailable).
func Load(dir, fallbackVersion string) Release {
	r := Release{Version: fallbackVersion, Binaries: map[string]Binary{}}
	if dir == "" {
		return r
	}
	if b, err := os.ReadFile(filepath.Join(dir, "version")); err == nil {
		if v := strings.TrimSpace(string(b)); protocol.ValidVersion(v) {
			r.Version = v
		}
	}
	for _, p := range protocol.AgentPlatforms {
		name := protocol.AgentBinaryName(p[0], p[1])
		path := filepath.Join(dir, name)
		st, err := os.Stat(path)
		if err != nil || st.IsDir() || st.Size() == 0 {
			continue
		}
		sum := readSum(path + ".sha256")
		if sum == "" {
			sum = computeSum(path)
		}
		if sum == "" {
			continue
		}
		r.Binaries[key(p[0], p[1])] = Binary{OS: p[0], Arch: p[1], Name: name, SHA256: sum, Size: st.Size()}
	}
	return r
}

func readSum(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	f := strings.Fields(string(b))
	if len(f) == 0 || len(f[0]) != 64 {
		return ""
	}
	if _, err := hex.DecodeString(f[0]); err != nil {
		return ""
	}
	return strings.ToLower(f[0])
}

func computeSum(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Available reports whether at least one binary can be distributed.
func (r Release) Available() bool { return len(r.Binaries) > 0 }

// For returns the binary for a platform.
func (r Release) For(goos, arch string) (Binary, bool) {
	b, ok := r.Binaries[key(goos, arch)]
	return b, ok
}

// Outdated reports whether an agent with the given version on a host with
// osID and arch should be updated: its version differs and a binary exists.
func (r Release) Outdated(agentVersion, osID, arch string) bool {
	if agentVersion == r.Version {
		return false
	}
	_, ok := r.For(protocol.AgentOS(osID), arch)
	return ok
}

// JobParams returns the agent_update job parameters for a host.
func (r Release) JobParams(osID, arch string) (map[string]string, bool) {
	b, ok := r.For(protocol.AgentOS(osID), arch)
	if !ok {
		return nil, false
	}
	return map[string]string{
		protocol.ParamVersion: r.Version,
		protocol.ParamSHA256:  b.SHA256,
		protocol.ParamPath:    protocol.AgentDownloadPrefix + b.Name,
	}, true
}
