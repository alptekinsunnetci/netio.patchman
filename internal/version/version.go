// Package version holds the build version, overridden at build time with:
//
//	go build -ldflags "-X netio.patchman/internal/version.Version=1.2.3"
package version

import "strings"

// Version is the product version.
var Version = "0.1.0-dev"

// codenames are the release names per major version; a name is a proper
// noun and stays the same in every language.
var codenames = map[string]string{
	"1": "gökalp",
}

// Codename returns the release name of v's major version ("" if none).
func Codename(v string) string {
	major, _, _ := strings.Cut(strings.TrimPrefix(v, "v"), ".")
	return codenames[major]
}

// CurrentCodename is the release name of the running version.
func CurrentCodename() string { return Codename(Version) }
