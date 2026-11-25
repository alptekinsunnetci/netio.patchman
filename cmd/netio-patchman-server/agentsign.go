package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"netio.patchman/internal/agentsign"
	"netio.patchman/internal/i18n"
	"netio.patchman/internal/protocol"
)

// agentKey creates a release signing key pair: the private key goes to out
// (never overwritten, owner-only), the public key is printed for
// PATCHMAN_UPDATE_KEYS and the dashboard setting. Run it away from the
// server; the server never needs the private key.
func agentKey(l i18n.Localizer, out string) int {
	if out == "" {
		fmt.Fprintln(os.Stderr, l.T("cli.agent_key.out_required"))
		return 2
	}
	pub, priv, err := agentsign.GenerateKey()
	if err == nil {
		err = agentsign.WritePrivateKey(out, priv)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, l.T("cli.agent_key.failed", "error", err.Error()))
		return 1
	}
	fmt.Println(l.T("cli.agent_key.done", "path", out, "id", agentsign.KeyID(pub)))
	fmt.Println(agentsign.EncodePublicKey(pub))
	return 0
}

// agentSign signs every agent binary in a distribution directory: it hashes
// the files itself (a .sha256 file that disagrees is an error) and writes
// <binary>.sig for the version in the directory's version file.
func agentSign(l i18n.Localizer, keyPath, dir string) int {
	if keyPath == "" || dir == "" {
		fmt.Fprintln(os.Stderr, l.T("cli.agent_sign.args_required"))
		return 2
	}
	priv, err := agentsign.ReadPrivateKey(keyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, l.T("cli.agent_sign.key_unreadable", "path", keyPath, "error", err.Error()))
		return 1
	}
	b, err := os.ReadFile(filepath.Join(dir, "version"))
	ver := strings.TrimSpace(string(b))
	if err != nil || !protocol.ValidVersion(ver) {
		fmt.Fprintln(os.Stderr, l.T("cli.agent_sign.no_version", "path", filepath.Join(dir, "version")))
		return 1
	}
	id := agentsign.KeyID(priv.Public().(ed25519.PublicKey))
	signed := 0
	for _, p := range protocol.AgentPlatforms {
		name := protocol.AgentBinaryName(p[0], p[1])
		path := filepath.Join(dir, name)
		sum, err := fileSHA256(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, l.T("cli.agent_sign.failed", "file", name, "error", err.Error()))
			return 1
		}
		if listed, err := os.ReadFile(path + ".sha256"); err == nil {
			if f := strings.Fields(string(listed)); len(f) == 0 || !strings.EqualFold(f[0], sum) {
				fmt.Fprintln(os.Stderr, l.T("cli.agent_sign.sum_mismatch", "file", name))
				return 1
			}
		}
		sig := agentsign.Sign(priv, ver, p[0], p[1], sum)
		if err := os.WriteFile(path+".sig", []byte(sig+"\n"), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, l.T("cli.agent_sign.failed", "file", name, "error", err.Error()))
			return 1
		}
		fmt.Println(l.T("cli.agent_sign.signed", "file", name, "version", ver, "sha256", sum))
		signed++
	}
	if signed == 0 {
		fmt.Fprintln(os.Stderr, l.T("cli.agent_sign.none", "dir", dir))
		return 1
	}
	fmt.Println(l.T("cli.agent_sign.done", "n", signed, "id", id))
	return 0
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
