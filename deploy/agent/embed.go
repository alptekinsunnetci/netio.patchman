// Package agentdist embeds the agent installation assets so the server can
// serve them under /downloads/.
package agentdist

import _ "embed"

//go:embed install-agent.sh
var InstallScript []byte

//go:embed netio-patchman-agent.service
var SystemdUnit []byte

// Assets maps download names to contents.
func Assets() map[string][]byte {
	return map[string][]byte{
		"install-agent.sh":             InstallScript,
		"netio-patchman-agent.service": SystemdUnit,
	}
}
