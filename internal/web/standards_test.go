package web_test

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"netio.patchman/internal/drift"
	"netio.patchman/internal/protocol"
	"netio.patchman/internal/store"
	"netio.patchman/internal/timeutil"
)

func TestStandardsAndDrift(t *testing.T) {
	e, admin, otherID := fleetEnv(t)
	ctx := context.Background()
	info := protocol.HostInfo{Hostname: "web-11", MachineID: "st1", OSID: "debian", OSVersionID: "12", Arch: "amd64", PackageManager: "apt",
		AgentVersion: "0.10.0", RemoteUpdates: true, Capabilities: []string{protocol.CapServices}}
	client, id := e.agentFor(info)
	report := func(pkgs []protocol.Package) {
		t.Helper()
		if err := client.Report(ctx, protocol.Report{Host: info, CollectedAt: timeutil.Now(), Packages: pkgs,
			Updates:  []protocol.Update{{Name: "php8.1-common", CurrentVersion: "8.1.31-1", AvailableVersion: "8.1.32-1"}},
			Services: []protocol.Service{{Name: "nginx", State: "stopped"}}}); err != nil {
			t.Fatal(err)
		}
	}
	base := []protocol.Package{
		{Name: "nginx", Version: "1.22.1-9+deb12u1", Arch: "amd64", SourceName: "nginx"},
		{Name: "php8.1-common", Version: "8.1.31-1", Arch: "amd64", SourceName: "php8.1"},
		{Name: "telnetd", Version: "0.17+2.4-2", Arch: "amd64", SourceName: "inetutils"},
	}
	report(base)
	gid, err := e.st.CreateGroup(ctx, "Web", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.AddHostsToGroup(ctx, gid, []int64{id}); err != nil {
		t.Fatal(err)
	}

	// Invalid rule, then a valid standard for the group.
	form := url.Values{"_csrf": {e.csrf(admin)}, "name": {"Web sunucuları"}, "group_id": {strconv.FormatInt(gid, 10)}, "enabled": {"1"},
		"kind_0": {"running"}, "type_0": {"package"}, "subject_0": {"telnetd"}, "value_0": {""}}
	status, body, _ := e.do(admin, "POST", "/standards", form)
	expect(t, "invalid rule", status, 400, body, "telnetd")
	form = url.Values{"_csrf": {e.csrf(admin)}, "name": {"Web sunucuları"}, "group_id": {strconv.FormatInt(gid, 10)}, "enabled": {"1"},
		"kind_0": {"allowed_cycles"}, "type_0": {"software"}, "subject_0": {"php"}, "value_0": {"8.2, 8.3"},
		"kind_1": {"forbidden"}, "type_1": {"package"}, "subject_1": {"telnetd"},
		"kind_2": {"required"}, "type_2": {"software"}, "subject_2": {"mariadb"},
		"kind_3": {"running"}, "type_3": {"software"}, "subject_3": {"nginx"},
		"kind_4": {"min_version"}, "type_4": {"software"}, "subject_4": {"nginx"}, "value_4": {"1.22.1-9+deb12u1"},
		"kind_5": {"required"}, "type_5": {"software"}, "subject_5": {""}}
	_, _, hdr := e.do(admin, "POST", "/standards", form)
	if !strings.HasPrefix(hdr.Get("Location"), "/standards?tab=drift&standard=") {
		t.Fatalf("save: %s", hdr.Get("Location"))
	}
	list, _ := e.st.ListStandards(ctx)
	if len(list) != 1 || len(list[0].Rules) != 5 || list[0].Deviations != 4 {
		t.Fatalf("standard: %+v", list)
	}
	std := list[0]
	// Saving already evaluated; the maintenance check finds nothing new.
	if fresh, err := drift.Check(ctx, e.st); err != nil || len(fresh) != 0 {
		t.Errorf("recheck: %+v %v", fresh, err)
	}
	status, body, _ = e.do(admin, "GET", "/standards?tab=drift", nil)
	expect(t, "drift report", status, 200, body, "web-11", "Kurulu seri: 8.1", "Kurulu: 0.17&#43;2.4-2", "Kurulu değil", "Servis çalışmıyor", "php8.1-common güncelle")
	if strings.Contains(body, "db-01") {
		t.Errorf("a host outside the group deviates")
	}
	key := e.createAPIKey(admin, "drift", false)
	status, body = e.apiDo(key, "GET", "/api/v1/drift?host="+strconv.FormatInt(id, 10), "")
	var res struct {
		Deviations []struct {
			Hostname, Kind, Subject, Found string
			Update                         string `json:"suggested_update"`
		}
		Pagination struct{ Total int }
	}
	if err := json.Unmarshal([]byte(body), &res); status != 200 || err != nil || res.Pagination.Total != 4 {
		t.Fatalf("drift api: %d %v %s", status, err, body)
	}
	byKind := map[string]string{}
	for _, d := range res.Deviations {
		if d.Hostname != "web-11" {
			t.Errorf("drift api host: %+v", d)
		}
		byKind[d.Kind+" "+d.Subject] = d.Found + "|" + d.Update
	}
	if byKind["forbidden telnetd"] != "0.17+2.4-2|" || !strings.HasSuffix(byKind["allowed_cycles php"], "|php8.1-common") {
		t.Errorf("drift api: %v", byKind)
	}
	status, body, _ = e.do(admin, "GET", "/servers/"+strconv.FormatInt(id, 10)+"?tab=software", nil)
	expect(t, "host drift panel", status, 200, body, "Standart sapmaları", "Web sunucuları")
	_, body, _ = e.do(admin, "GET", "/servers/"+strconv.FormatInt(otherID, 10)+"?tab=software", nil)
	if strings.Contains(body, "Standart sapmaları") {
		t.Errorf("drift panel on a host without deviations")
	}

	// telnetd removed: that deviation goes away; a new one is reported once.
	report(base[:2])
	fresh, err := drift.Check(ctx, e.st)
	if err != nil || len(fresh) != 0 {
		t.Fatalf("after removal: %+v %v", fresh, err)
	}
	rows, total, _ := e.st.ListDrift(ctx, store.DriftFilter{HostID: id}, store.Page{Number: 1, Size: 50})
	if total != 3 {
		t.Errorf("deviations after removal: %d %+v", total, rows)
	}
	// Editing keeps rule ids (and first-seen dates); deleting a rule drops its deviations.
	st, _ := e.st.StandardByID(ctx, std.ID)
	st.Rules = st.Rules[:3]
	if _, err := e.st.SaveStandard(ctx, st); err != nil {
		t.Fatal(err)
	}
	fresh, _ = drift.Check(ctx, e.st)
	if _, total, _ = e.st.ListDrift(ctx, store.DriftFilter{HostID: id}, store.Page{Number: 1, Size: 50}); total != 2 || len(fresh) != 0 {
		t.Errorf("after dropping rules: %d new %d", total, len(fresh))
	}
	// A new rule's deviation is new.
	st, _ = e.st.StandardByID(ctx, std.ID)
	st.Rules = append(st.Rules, store.StandardRule{Kind: drift.KindRunning, SubjectType: drift.SubjectSoftware, Subject: "nginx"})
	if _, err := e.st.SaveStandard(ctx, st); err != nil {
		t.Fatal(err)
	}
	fresh, _ = drift.Check(ctx, e.st)
	if len(fresh) != 1 || fresh[0].HostID != id || fresh[0].Count != 1 || fresh[0].Standards[0] != "Web sunucuları" {
		t.Errorf("new deviation: %+v", fresh)
	}
	e.notifier.DriftDetected(ctx, fresh)
	waitNotification(t, e, "drift_detected", "web-11")

	status, body, _ = e.do(admin, "GET", "/standards", nil)
	expect(t, "standards list", status, 200, body, "Web sunucuları", "İzin verilen sürüm serileri")
	if status, _, _ := e.do(admin, "POST", "/standards/"+strconv.FormatInt(std.ID, 10)+"/delete", url.Values{"_csrf": {e.csrf(admin)}}); status != 303 {
		t.Fatalf("delete: %d", status)
	}
	if _, total, _ := e.st.ListDrift(ctx, store.DriftFilter{}, store.Page{Number: 1, Size: 50}); total != 0 {
		t.Errorf("deviations after delete: %d", total)
	}
}
