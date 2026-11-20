// Package brand is the single source of truth for the product identity.
//
// Every product name, binary name, service name and image name shown to
// users or written to logs must come from this package. Never hard-code the
// product name elsewhere. The Turkish product description lives in the i18n
// catalog under "app.description" because it is translatable text.
package brand

import "fmt"

const (
	// Name is the official product name. Always written in lower case.
	Name = "netio.patchman"

	// ServerBinary is the central server executable name.
	ServerBinary = "netio-patchman-server"

	// AgentBinary is the Linux agent executable name.
	AgentBinary = "netio-patchman-agent"

	// AgentService is the systemd unit name of the agent.
	AgentService = "netio-patchman-agent.service"

	// ComposeProject is the Docker Compose project name.
	ComposeProject = "netio-patchman"

	// ServerImage is the Docker image name of the server.
	ServerImage = "netio-patchman-server"

	// ConfigDir is the default configuration directory on Linux hosts.
	ConfigDir = "/etc/netio-patchman"

	// DefaultSenderName is the display name used in the email From header.
	// The sender address itself is always configurable and has no default.
	DefaultSenderName = Name

	// EnvPrefix is the prefix of every environment variable the product reads.
	EnvPrefix = "PATCHMAN_"
)

// ServerUserAgent returns the User-Agent the server sends on outbound requests.
func ServerUserAgent(version string) string {
	return fmt.Sprintf("%s/%s", ServerBinary, version)
}

// AgentUserAgent returns the User-Agent the agent sends to the server.
func AgentUserAgent(version, goos, goarch string) string {
	return fmt.Sprintf("%s/%s (%s; %s)", AgentBinary, version, goos, goarch)
}
