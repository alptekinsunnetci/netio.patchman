package web_test

import (
	"testing"

	"netio.patchman/internal/version"
)

// The panel shows the release name of the major version next to the version.
func TestVersionCodename(t *testing.T) {
	old := version.Version
	version.Version = "1.0.5"
	defer func() { version.Version = old }()
	e := newEnv(t)
	admin := setupAdmin(t, e)
	status, body, _ := e.do(admin, "GET", "/dashboard", nil)
	expect(t, "sidebar", status, 200, body, "netio.patchman 1.0.5 “gökalp”")
	status, body, _ = e.do(newClient(), "GET", "/login", nil)
	expect(t, "login", status, 200, body, "1.0.5 “gökalp”")
}
