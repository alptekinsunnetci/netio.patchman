package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"netio.patchman/internal/agentsign"
	"netio.patchman/internal/i18n"
	"netio.patchman/internal/protocol"
	"netio.patchman/internal/version"
)

// maxAgentBinary bounds the download size.
const maxAgentBinary = 200 << 20

// Download fetches a server path into dest and returns its hex SHA-256.
func (c *Client) Download(ctx context.Context, path, dest string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base.String()+path, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", c.userAgent)
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", &APIError{Status: resp.StatusCode}
	}
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o700)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, maxAgentBinary+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", err
	}
	if n > maxAgentBinary {
		return "", errors.New("agent binary too large")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// SelfUpdater replaces the running agent binary.
type SelfUpdater struct {
	L       i18n.Localizer
	Client  *Client
	Enabled bool
	// Executable overrides the binary path (tests); empty means os.Executable.
	Executable string
	// Keys are the trusted release signing keys (base64 Ed25519). With keys,
	// an update needs a valid signature and a newer version.
	Keys []string
}

// Update downloads, verifies and installs the agent version described by the
// job. It returns a Turkish message and whether a restart is required.
//
// Steps: validate parameters, check the release signature when the agent
// trusts signing keys (and refuse older versions then), download next to the
// current binary, compare SHA-256, run "<new> -version" and check the version, keep the current
// binary as "<name>.previous", then rename the new file into place (atomic
// on the same filesystem).
func (u SelfUpdater) Update(ctx context.Context, job protocol.Job) (string, bool, error) {
	if !u.Enabled {
		return "", false, errors.New(u.L.T("agent.update.disabled"))
	}
	target := job.Params[protocol.ParamVersion]
	sum := strings.ToLower(job.Params[protocol.ParamSHA256])
	path := job.Params[protocol.ParamPath]
	if !protocol.ValidVersion(target) || len(sum) != 64 || !strings.HasPrefix(path, protocol.AgentDownloadPrefix) ||
		strings.Contains(path, "..") || strings.ContainsAny(path, "?#") {
		return "", false, errors.New(u.L.T("agent.update.invalid_job"))
	}
	if _, err := hex.DecodeString(sum); err != nil {
		return "", false, errors.New(u.L.T("agent.update.invalid_job"))
	}
	if target == version.Version {
		return u.L.T("agent.update.already_current", "version", target), false, nil
	}
	// The signature covers version, platform and SHA-256, and the download
	// must match that SHA-256, so the installed file is the signed one.
	signed := ""
	if len(u.Keys) > 0 {
		sig := job.Params[protocol.ParamSignature]
		if sig == "" {
			return "", false, errors.New(u.L.T("agent.update.signature_missing"))
		}
		id, ok := agentsign.Verify(sig, u.Keys, target, runtime.GOOS, runtime.GOARCH, sum)
		if !ok {
			return "", false, errors.New(u.L.T("agent.update.signature_invalid", "keys", strings.Join(agentsign.KeyIDs(u.Keys), ", ")))
		}
		if version.Compare(target, version.Version) <= 0 {
			return "", false, errors.New(u.L.T("agent.update.downgrade_refused", "from", version.Version, "to", target))
		}
		signed = u.L.T("agent.update.signature_ok", "key", id) + "\n[netio.patchman] "
	}

	exe := u.Executable
	if exe == "" {
		var err error
		if exe, err = os.Executable(); err != nil {
			return "", false, err
		}
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
	}
	dir := filepath.Dir(exe)
	tmp := filepath.Join(dir, "."+filepath.Base(exe)+".new")
	if runtime.GOOS == "windows" {
		tmp += ".exe"
	}
	defer os.Remove(tmp)

	got, err := u.Client.Download(ctx, path, tmp)
	if err != nil {
		return "", false, errors.New(u.L.T("agent.update.download_failed", "error", err.Error()))
	}
	if got != sum {
		return "", false, errors.New(u.L.T("agent.update.checksum_mismatch", "expected", sum, "got", got))
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		return "", false, err
	}

	// The new binary must start and report the expected version. Antivirus
	// software may hold the first start of a new executable for a cloud
	// lookup, hence the generous limit; WaitDelay keeps a killed process from
	// blocking on its output pipe.
	vctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(vctx, tmp, "-version")
	cmd.WaitDelay = 5 * time.Second
	out, err := cmd.CombinedOutput()
	if err != nil || !bytes.Contains(out, []byte(" "+target+" ")) {
		return "", false, errors.New(u.L.T("agent.update.verify_failed", "output", strings.TrimSpace(string(out))))
	}

	previous := exe + ".previous"
	_ = os.Remove(previous)
	if runtime.GOOS == "windows" {
		// A running executable cannot be replaced, but it can be renamed.
		if err := os.Rename(exe, previous); err != nil {
			return "", false, fmt.Errorf("backup: %w", err)
		}
		if err := os.Rename(tmp, exe); err != nil {
			_ = os.Rename(previous, exe)
			return "", false, fmt.Errorf("install: %w", err)
		}
		return signed + u.L.T("agent.update.installed", "from", version.Version, "to", target), true, nil
	}
	if err := os.Link(exe, previous); err != nil {
		// Hard links can fail on some filesystems; fall back to a copy.
		if err := copyFile(exe, previous); err != nil {
			return "", false, fmt.Errorf("backup: %w", err)
		}
	}
	if err := os.Rename(tmp, exe); err != nil {
		return "", false, fmt.Errorf("install: %w", err)
	}
	return signed + u.L.T("agent.update.installed", "from", version.Version, "to", target), true, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
