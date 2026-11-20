// Package version holds the build version, overridden at build time with:
//
//	go build -ldflags "-X netio.patchman/internal/version.Version=1.2.3"
package version

// Version is the product version.
var Version = "0.1.0-dev"
