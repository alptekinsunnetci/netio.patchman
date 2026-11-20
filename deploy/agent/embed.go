// Package agentdist embeds the agent installation assets so the server can
// serve them under /downloads/.
package agentdist

import _ "embed"

//go:embed install-agent.sh
var InstallScript []byte

//go:embed netio-patchman-agent.service
var SystemdUnit []byte

// OpenRCScript is the init script used on OpenRC systems (Alpine).
//
//go:embed netio-patchman-agent.openrc
var OpenRCScript []byte

// Assets maps download names to contents.
func Assets() map[string][]byte {
	return map[string][]byte{
		"install-agent.sh":             InstallScript,
		"netio-patchman-agent.service": SystemdUnit,
		"netio-patchman-agent.openrc":  OpenRCScript,
	}
}
