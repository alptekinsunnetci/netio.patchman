// Package release describes the agent binaries the server distributes and
// rolls out with automatic agent updates.
//
// The distribution directory (PATCHMAN_AGENT_DIST_DIR) contains:
//
//	netio-patchman-agent-linux-<arch>             Linux binaries (amd64, arm64)
//	netio-patchman-agent-windows-amd64.exe        the Windows binary
//	<binary>.sha256                               "<hex>  <name>" (optional, computed if missing)
//	<binary>.sig                                  release signature (optional, package agentsign)
//	version                                       the agent version (optional, defaults to the server version)
package release

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"netio.patchman/internal/agentsign"
	"netio.patchman/internal/protocol"
	"netio.patchman/internal/version"
)

// Binary is one platform's agent binary.
type Binary struct {
	OS     string
	Arch   string
	Name   string
	SHA256 string
	Size   int64
	// Signature is the content of <binary>.sig ("" when unsigned); KeyID is
	// the key it names.
	Signature string
	KeyID     string
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
		b := Binary{OS: p[0], Arch: p[1], Name: name, SHA256: sum, Size: st.Size()}
		if sig, err := os.ReadFile(path + ".sig"); err == nil {
			if id := agentsign.SignatureKeyID(string(sig)); id != "" {
				b.Signature, b.KeyID = strings.TrimSpace(string(sig)), id
			}
		}
		r.Binaries[key(p[0], p[1])] = b
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

// Installable reports whether an outdated agent that trusts keys (base64
// Ed25519, HostInfo.UpdateKeys) would accept this release: without keys any
// release; with keys only a newer version whose signature one of them
// verifies (agents refuse unsigned updates and downgrades then).
func (r Release) Installable(agentVersion, osID, arch string, keys []string) bool {
	b, ok := r.For(protocol.AgentOS(osID), arch)
	if !ok {
		return false
	}
	if len(keys) == 0 {
		return true
	}
	if version.Compare(r.Version, agentVersion) <= 0 {
		return false
	}
	_, ok = agentsign.Verify(b.Signature, keys, r.Version, b.OS, b.Arch, b.SHA256)
	return ok
}

// Signers returns the ids of the keys the binaries are signed with, sorted.
func (r Release) Signers() []string {
	seen := map[string]bool{}
	out := []string{}
	for _, b := range r.Binaries {
		if b.KeyID != "" && !seen[b.KeyID] {
			seen[b.KeyID] = true
			out = append(out, b.KeyID)
		}
	}
	sort.Strings(out)
	return out
}

// Unsigned reports whether some binaries carry no signature.
func (r Release) Unsigned() bool {
	for _, b := range r.Binaries {
		if b.Signature == "" {
			return true
		}
	}
	return false
}

// JobParams returns the agent_update job parameters for a host.
func (r Release) JobParams(osID, arch string) (map[string]string, bool) {
	b, ok := r.For(protocol.AgentOS(osID), arch)
	if !ok {
		return nil, false
	}
	p := map[string]string{
		protocol.ParamVersion: r.Version,
		protocol.ParamSHA256:  b.SHA256,
		protocol.ParamPath:    protocol.AgentDownloadPrefix + b.Name,
	}
	if b.Signature != "" {
		p[protocol.ParamSignature] = b.Signature
	}
	return p, true
}
