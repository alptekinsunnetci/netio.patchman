package agent

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"netio.patchman/internal/agentsign"
)

// pinnedKeysFile holds the update keys the agent took over from the server
// (CheckinResponse.UpdateKeys), one per line, in the state directory.
const pinnedKeysFile = "update-keys"

// PinnedUpdateKeys reads the keys pinned from the server. A missing file
// means none; a damaged file is an error, so the agent never falls back to
// unsigned updates because of it.
func PinnedUpdateKeys(stateDir string) ([]string, error) {
	b, err := os.ReadFile(filepath.Join(stateDir, pinnedKeysFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	keys, err := agentsign.ParsePublicKeys(string(b))
	if err == nil && len(keys) == 0 {
		err = agentsign.ErrInvalidKey
	}
	return keys, err
}

// PinUpdateKeys stores keys received from the server. It never replaces
// pinned keys: changing them needs access to the host.
func PinUpdateKeys(stateDir string, keys []string) error {
	keys = agentsign.CleanPublicKeys(keys)
	if len(keys) == 0 {
		return agentsign.ErrInvalidKey
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(stateDir, pinnedKeysFile), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, err = f.WriteString(strings.Join(keys, "\n") + "\n")
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		// A damaged file would stop the agent; without one it pins again.
		_ = os.Remove(f.Name())
	}
	return err
}
