// Package release describes the agent binaries the server distributes and
// rolls out with automatic agent updates.
//
// The distribution directory (PATCHMAN_AGENT_DIST_DIR) contains:
//
//	netio-patchman-agent-linux-<arch>          the binary
//	netio-patchman-agent-linux-<arch>.sha256   "<hex>  <name>" (optional, computed if missing)
//	version                                    the agent version (optional, defaults to the server version)
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

// Binary is one architecture's agent binary.
type Binary struct {
	Arch   string
	Name   string
	SHA256 string
	Size   int64
}

// Release is the agent version the server rolls out.
type Release struct {
	Version  string
	Binaries map[string]Binary
}

// SupportedArchs are the architectures the server builds agents for.
var SupportedArchs = []string{"amd64", "arm64"}

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
	for _, arch := range SupportedArchs {
		name := protocol.AgentBinaryName(arch)
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
		r.Binaries[arch] = Binary{Arch: arch, Name: name, SHA256: sum, Size: st.Size()}
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

// For returns the binary for an architecture.
func (r Release) For(arch string) (Binary, bool) {
	b, ok := r.Binaries[arch]
	return b, ok
}

// Outdated reports whether an agent with the given version and architecture
// should be updated: its version differs and a binary exists for it.
func (r Release) Outdated(agentVersion, arch string) bool {
	if agentVersion == r.Version {
		return false
	}
	_, ok := r.Binaries[arch]
	return ok
}

// JobParams returns the agent_update job parameters for an architecture.
func (r Release) JobParams(arch string) (map[string]string, bool) {
	b, ok := r.Binaries[arch]
	if !ok {
		return nil, false
	}
	return map[string]string{
		protocol.ParamVersion: r.Version,
		protocol.ParamSHA256:  b.SHA256,
		protocol.ParamPath:    protocol.AgentDownloadPrefix + b.Name,
	}, true
}
