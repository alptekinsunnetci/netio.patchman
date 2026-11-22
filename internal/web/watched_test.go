package web_test

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

func TestWatchedPackagesAndHostSearch(t *testing.T) {
	e, admin, hostID := fleetEnv(t)
	hostURL := "/servers/" + strconv.FormatInt(hostID, 10)

	watch := func(name, on, back string) (int, http.Header) {
		t.Helper()
		status, _, hdr := e.do(admin, "POST", "/watched", url.Values{"_csrf": {e.csrf(admin)}, "name": {name}, "watch": {on}, "back": {back}})
		return status, hdr
	}

	// Empty state on the dashboard.
	status, body, _ := e.do(admin, "GET", "/dashboard", nil)
	expect(t, "dashboard empty watch list", status, 200, body, "Takip ettiğim paketler", "Henüz paket takip etmiyorsunuz")

	// Watch an installed package and one this host does not have.
	if status, hdr := watch("openssl", "1", hostURL+"?tab=packages"); status != http.StatusSeeOther || hdr.Get("Location") != hostURL+"?tab=packages" {
		t.Fatalf("watch: %d %s", status, hdr.Get("Location"))
	}
	if status, _ := watch("nginx", "1", "/dashboard"); status != http.StatusSeeOther {
		t.Fatalf("watch nginx: %d", status)
	}
	// Watching twice is harmless; a bad name or an outside return path is refused.
	watch("openssl", "1", "/dashboard")
	if _, hdr := watch("bad\x01name", "1", "/dashboard"); hdr.Get("Location") != "/dashboard" {
		t.Errorf("invalid name redirect: %s", hdr.Get("Location"))
	}
	if _, hdr := watch("curl", "1", "//evil.test/x"); hdr.Get("Location") != "/dashboard" {
		t.Errorf("open redirect: %s", hdr.Get("Location"))
	}
	watch("curl", "0", "/dashboard")

	status, body, _ = e.do(admin, "GET", hostURL+"?tab=packages", nil)
	expect(t, "packages tab star", status, 200, body, `class="star is-on"`, "Takip Edilenler <span class=\"tab__count\">1</span>")

	status, body, _ = e.do(admin, "GET", hostURL+"?tab=watched", nil)
	expect(t, "watched tab", status, 200, body, "openssl", "3.0.11-1~deb12u2", "3.0.17-1~deb12u1", "Güvenlik", "Takip ettiğiniz 1 paket bu sunucuda kurulu değil.", `value="watched"`)
	if !strings.Contains(body, "CVE") {
		t.Errorf("watched tab: no vulnerability count for openssl")
	}

	status, body, _ = e.do(admin, "GET", "/dashboard", nil)
	expect(t, "dashboard watch list", status, 200, body, "Takip ettiğim paketler", "openssl", "nginx", "Kurulu değil", "1 sunucuda", "/vulnerabilities?q=openssl")
	if strings.Contains(body, ">curl<") {
		t.Errorf("unwatched package still listed")
	}

	status, body, _ = e.do(admin, "GET", "/packages/openssl", nil)
	expect(t, "package page star", status, 200, body, `class="star is-on"`)

	// Search on the vulnerabilities tab (binary or source package name) and the updates tab.
	_, all, _ := e.do(admin, "GET", hostURL, nil)
	_, found, _ := e.do(admin, "GET", hostURL+"?q=openss", nil)
	if strings.Count(found, `href="/vulnerabilities/CVE-`) != strings.Count(all, `href="/vulnerabilities/CVE-`) || !strings.Contains(found, `value="openss"`) {
		t.Errorf("vuln search lost findings")
	}
	status, body, _ = e.do(admin, "GET", hostURL+"?q=zzz-nothing", nil)
	expect(t, "vuln search no match", status, 200, body, "Bu sunucuda bu ölçütlere uyan güvenlik açığı bulunmuyor.")
	status, body, _ = e.do(admin, "GET", hostURL+"?tab=updates&q=SSL", nil)
	expect(t, "updates search", status, 200, body, "1 güncellemeden 1 tanesi eşleşiyor", `value="openssl"`)
	status, body, _ = e.do(admin, "GET", hostURL+"?tab=updates&q=zzz", nil)
	expect(t, "updates search no match", status, 200, body, "Aramaya uyan bekleyen güncelleme yok.")

	// Unwatch.
	watch("openssl", "0", "/dashboard")
	status, body, _ = e.do(admin, "GET", hostURL+"?tab=watched", nil)
	expect(t, "watched tab after unwatch", status, 200, body, "Takip ettiğiniz paketlerden hiçbiri bu sunucuda kurulu değil")
}
