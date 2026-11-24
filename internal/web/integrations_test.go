package web_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"netio.patchman/internal/store"
)

// tickets fakes Jira, ServiceNow and GLPI under /jira, /sn and /glpi.
type tickets struct {
	srv      *httptest.Server
	mu       sync.Mutex
	reqs     []hookReq
	glpiFail bool
}

func newTickets(t *testing.T) *tickets {
	tk := &tickets{}
	tk.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		tk.mu.Lock()
		tk.reqs = append(tk.reqs, hookReq{Path: r.URL.Path, Header: r.Header.Clone(), Body: b})
		fail := tk.glpiFail
		tk.mu.Unlock()
		user, pass, _ := r.BasicAuth()
		switch r.URL.Path {
		case "/jira/rest/api/2/issue":
			if user != "ops@example.test" || pass != "jira-token-123" || r.Method != http.MethodPost {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"id":"10001","key":"OPS-1"}`)
		case "/sn/api/now/table/incident":
			if user != "patchman" || pass != "sn-password-1" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"result":{"number":"INC0010001"}}`)
		case "/glpi/initSession":
			if r.Header.Get("App-Token") != "glpi-app-token-1" || r.Header.Get("Authorization") != "user_token glpi-user-token-1" {
				http.Error(w, `["ERROR_GLPI_LOGIN_USER_TOKEN","invalid"]`, http.StatusUnauthorized)
				return
			}
			_, _ = io.WriteString(w, `{"session_token":"sess-1"}`)
		case "/glpi/Ticket":
			if r.Header.Get("Session-Token") != "sess-1" || fail {
				http.Error(w, `["ERROR","server down"]`, http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"id":42}`)
		case "/glpi/killSession":
			_, _ = io.WriteString(w, `true`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(tk.srv.Close)
	return tk
}

func (tk *tickets) find(path string) []hookReq {
	tk.mu.Lock()
	defer tk.mu.Unlock()
	var out []hookReq
	for _, r := range tk.reqs {
		if r.Path == path {
			out = append(out, r)
		}
	}
	return out
}

// fakeZabbix accepts Zabbix sender frames and answers like a server that
// processed the item.
func fakeZabbix(t *testing.T) (string, func() [][]byte) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var mu sync.Mutex
	var got [][]byte
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				head := make([]byte, 13)
				if _, err := io.ReadFull(c, head); err != nil || string(head[:5]) != "ZBXD\x01" {
					return
				}
				body := make([]byte, binary.LittleEndian.Uint64(head[5:]))
				if _, err := io.ReadFull(c, body); err != nil {
					return
				}
				mu.Lock()
				got = append(got, body)
				mu.Unlock()
				resp := []byte(`{"response":"success","info":"processed: 1; failed: 0; total: 1; seconds spent: 0.000055"}`)
				frame := make([]byte, 13)
				copy(frame, "ZBXD\x01")
				binary.LittleEndian.PutUint64(frame[5:], uint64(len(resp)))
				_, _ = c.Write(append(frame, resp...))
			}(conn)
		}
	}()
	return ln.Addr().String(), func() [][]byte {
		mu.Lock()
		defer mu.Unlock()
		return append([][]byte(nil), got...)
	}
}

func TestChannelIntegrations(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	admin := setupAdmin(t, e)
	token := e.csrf(admin)
	tk := newTickets(t)
	zbxAddr, zbxFrames := fakeZabbix(t)

	// Validation of the new types.
	status, body, _ := e.do(admin, "POST", "/settings/channels", url.Values{"_csrf": {token}, "type": {"jira"}, "name": {"Jira"}, "min_level": {"info"},
		"ticket_url": {tk.srv.URL + "/jira"}, "user": {"ops@example.test"}, "ticket_secret": {"jira-token-123"}})
	expect(t, "jira without project", status, 400, body, "Proje anahtarı")
	status, body, _ = e.do(admin, "POST", "/settings/channels", url.Values{"_csrf": {token}, "type": {"servicenow"}, "name": {"SN"}, "min_level": {"info"},
		"ticket_url": {tk.srv.URL + "/sn"}, "user": {"patchman"}, "ticket_secret": {"sn-password-1"}, "table": {"incident; drop"}})
	expect(t, "servicenow bad table", status, 400, body)
	status, body, _ = e.do(admin, "POST", "/settings/channels", url.Values{"_csrf": {token}, "type": {"zabbix"}, "name": {"Zabbix"}, "min_level": {"info"},
		"zabbix_server": {"http://zabbix/x"}, "host": {"patchman"}})
	expect(t, "zabbix bad server", status, 400, body, "adres:port")
	status, body, _ = e.do(admin, "POST", "/settings/channels", url.Values{"_csrf": {token}, "type": {"webhook"}, "name": {"x"}, "min_level": {"info"},
		"url": {e.hooks.srv.URL + "/hook"}, "events": {"no_such_event"}})
	expect(t, "unknown event", status, 400, body)

	for _, f := range []url.Values{
		{"type": {"jira"}, "name": {"Jira OPS"}, "min_level": {"info"}, "ticket_url": {tk.srv.URL + "/jira"}, "user": {"ops@example.test"},
			"ticket_secret": {"jira-token-123"}, "project": {"OPS"}, "events": {"update_failed"}},
		{"type": {"servicenow"}, "name": {"ServiceNow"}, "min_level": {"critical"}, "ticket_url": {tk.srv.URL + "/sn"}, "user": {"patchman"},
			"ticket_secret": {"sn-password-1"}},
		{"type": {"glpi"}, "name": {"GLPI"}, "min_level": {"info"}, "ticket_url": {tk.srv.URL + "/glpi"}, "ticket_secret": {"glpi-user-token-1"},
			"app_token": {"glpi-app-token-1"}, "events": {"host_offline"}},
		{"type": {"zabbix"}, "name": {"Zabbix"}, "min_level": {"info"}, "zabbix_server": {zbxAddr}, "host": {"patchman"},
			"events": {"update_failed", "host_offline"}},
		{"type": {"webhook"}, "name": {"SIEM"}, "min_level": {"info"}, "url": {e.hooks.srv.URL + "/hook"}, "secret": {"s3cret-key"}, "events": {"update_failed"}},
	} {
		f.Set("_csrf", token)
		if status, body, _ := e.do(admin, "POST", "/settings/channels", f); status != http.StatusSeeOther {
			t.Fatalf("create %s: %d %s", f.Get("type"), status, body)
		}
	}
	chans, _ := e.st.ListChannels(ctx)
	ids := map[string]int64{}
	for _, c := range chans {
		ids[c.Name] = c.ID
	}
	if c, _ := e.st.ChannelByID(ctx, ids["Jira OPS"]); c.Config["project"] != "OPS" || c.Config["user"] != "ops@example.test" || len(c.Events) != 1 {
		t.Fatalf("jira channel: %+v", c)
	}
	_, body, _ = e.do(admin, "GET", "/settings/channels", nil)
	expect(t, "channel list", 200, 200, body, "Jira", "ServiceNow", "GLPI", "Zabbix (trapper)", "Seçili olay: 2")
	for _, secret := range []string{"jira-token-123", "sn-password-1", "glpi-user-token-1", "glpi-app-token-1"} {
		if strings.Contains(body, secret) {
			t.Errorf("secret %q shown on the channel list", secret)
		}
	}

	e.st.OnNotification(e.channels.Enqueue)
	go e.channels.Run(ctx)

	// A failed job: Jira, Zabbix and the webhook subscribe to update_failed;
	// ServiceNow wants critical, GLPI only host_offline.
	_ = e.st.AddNotification(ctx, store.LevelWarning, "job_failed", map[string]string{"hostname": "web-01", "id": "7", "job_type": "upgrade_all"}, "/jobs/7")
	waitFor(t, func() bool {
		_, ok := e.hooks.last("/hook")
		return len(tk.find("/jira/rest/api/2/issue")) == 1 && len(zbxFrames()) == 1 && ok
	})
	var issue struct {
		Fields struct {
			Project   struct{ Key string }  `json:"project"`
			Summary   string                `json:"summary"`
			IssueType struct{ Name string } `json:"issuetype"`
			Labels    []string              `json:"labels"`
		} `json:"fields"`
	}
	_ = json.Unmarshal(tk.find("/jira/rest/api/2/issue")[0].Body, &issue)
	if issue.Fields.Project.Key != "OPS" || issue.Fields.IssueType.Name != "Task" || !strings.Contains(issue.Fields.Summary, "web-01") ||
		len(issue.Fields.Labels) != 2 || issue.Fields.Labels[1] != "update_failed" {
		t.Errorf("jira issue: %+v", issue)
	}
	var frame struct {
		Request string `json:"request"`
		Data    []struct{ Host, Key, Value string }
	}
	_ = json.Unmarshal(zbxFrames()[0], &frame)
	if frame.Request != "sender data" || len(frame.Data) != 1 || frame.Data[0].Host != "patchman" || frame.Data[0].Key != "netio.patchman.event" ||
		!strings.Contains(frame.Data[0].Value, `"event":"update_failed"`) {
		t.Errorf("zabbix frame: %s", zbxFrames()[0])
	}
	hook, _ := e.hooks.last("/hook")
	var payload map[string]any
	_ = json.Unmarshal(hook.Body, &payload)
	if payload["event"] != "update_failed" || payload["kind"] != "job_failed" {
		t.Errorf("webhook payload: %s", hook.Body)
	}
	ts := hook.Header.Get("X-Netio-Patchman-Timestamp")
	mac := hmac.New(sha256.New, []byte("s3cret-key"))
	mac.Write([]byte(ts + "."))
	mac.Write(hook.Body)
	if ts == "" || hook.Header.Get("X-Netio-Patchman-Signature-V2") != "t="+ts+",sha256="+hex.EncodeToString(mac.Sum(nil)) {
		t.Errorf("webhook v2 signature: %q", hook.Header.Get("X-Netio-Patchman-Signature-V2"))
	}
	if n := len(tk.find("/sn/api/now/table/incident")) + len(tk.find("/glpi/Ticket")); n != 0 {
		t.Errorf("filtered channels received the job notification (%d)", n)
	}
	waitFor(t, func() bool {
		list, _, _ := e.st.ListDeliveries(ctx, ids["Jira OPS"], store.Page{Number: 1, Size: 10})
		return len(list) == 1
	})
	list, _, _ := e.st.ListDeliveries(ctx, ids["Jira OPS"], store.Page{Number: 1, Size: 10})
	if d := list[0]; !d.OK || d.Event != "update_failed" || d.Kind != "job_failed" || d.Attempts != 1 {
		t.Errorf("jira delivery: %+v", d)
	}

	// A host going offline (critical): ServiceNow, GLPI and Zabbix.
	_ = e.st.AddNotification(ctx, store.LevelCritical, "agent_offline", map[string]string{"hostname": "db-01", "last_seen": "21.11.2026 10:00"}, "/servers/1")
	waitFor(t, func() bool {
		return len(tk.find("/sn/api/now/table/incident")) == 1 && len(tk.find("/glpi/Ticket")) == 1 && len(tk.find("/glpi/killSession")) == 1 && len(zbxFrames()) == 2
	})
	// Deliveries run concurrently: wait until their outcome is recorded, so the
	// next delivery's result is not overwritten by this one.
	waitFor(t, func() bool {
		sn, _, _ := e.st.ListDeliveries(ctx, ids["ServiceNow"], store.Page{Number: 1, Size: 10})
		gl, _, _ := e.st.ListDeliveries(ctx, ids["GLPI"], store.Page{Number: 1, Size: 10})
		zb, _, _ := e.st.ListDeliveries(ctx, ids["Zabbix"], store.Page{Number: 1, Size: 10})
		return len(sn) == 1 && len(gl) == 1 && len(zb) == 2
	})
	var inc map[string]string
	_ = json.Unmarshal(tk.find("/sn/api/now/table/incident")[0].Body, &inc)
	if inc["urgency"] != "1" || !strings.Contains(inc["short_description"], "db-01") {
		t.Errorf("servicenow incident: %v", inc)
	}
	var ticket struct {
		Input struct {
			Name    string `json:"name"`
			Urgency int    `json:"urgency"`
		} `json:"input"`
	}
	_ = json.Unmarshal(tk.find("/glpi/Ticket")[0].Body, &ticket)
	if ticket.Input.Urgency != 5 || !strings.Contains(ticket.Input.Name, "db-01") {
		t.Errorf("glpi ticket: %+v", ticket)
	}
	if len(tk.find("/jira/rest/api/2/issue")) != 1 {
		t.Error("jira received an event it does not subscribe to")
	}

	// A failed GLPI delivery is in the history and can be sent again.
	tk.mu.Lock()
	tk.glpiFail = true
	tk.mu.Unlock()
	_ = e.st.AddNotification(ctx, store.LevelCritical, "agent_offline", map[string]string{"hostname": "db-02", "last_seen": "21.11.2026 10:05"}, "/servers/2")
	var failed store.Delivery
	waitFor(t, func() bool {
		list, _, _ := e.st.ListDeliveries(ctx, ids["GLPI"], store.Page{Number: 1, Size: 10})
		for _, d := range list {
			if !d.OK {
				failed = d
			}
		}
		return len(list) == 2
	})
	if failed.OK || !strings.Contains(failed.Error, "HTTP 500") || strings.Contains(failed.Error, "glpi-user-token-1") {
		t.Errorf("failed delivery: %+v", failed)
	}
	if c, _ := e.st.ChannelByID(ctx, ids["GLPI"]); !c.Failing() {
		t.Error("glpi channel not marked failing")
	}
	status, body, _ = e.do(admin, "GET", "/settings/channels/"+itoa(ids["GLPI"]), nil)
	expect(t, "channel detail", status, 200, body, "Teslimat geçmişi", "Teslim edilemedi", "Teslim edildi", "Sunucu çevrimdışı", "Yeniden gönder", "HTTP 500")
	for _, secret := range []string{"glpi-user-token-1", "glpi-app-token-1"} {
		if strings.Contains(body, secret) {
			t.Errorf("secret %q shown on the channel page", secret)
		}
	}
	key := e.createAPIKey(admin, "prometheus", false)
	status, body = e.apiDo(key, "GET", "/metrics", "")
	expect(t, "metrics", status, 200, body, `netio_patchman_channel_failing{channel="GLPI",type="glpi"} 1`,
		`netio_patchman_channel_failing{channel="Jira OPS",type="jira"} 0`, `netio_patchman_rollouts{status="running"} 0`, `netio_patchman_drift_deviations 0`,
		`netio_patchman_eol{kind="os",status="eol"} 0`)
	tk.mu.Lock()
	tk.glpiFail = false
	tk.mu.Unlock()
	resend := "/settings/channels/" + itoa(ids["GLPI"]) + "/deliveries/" + itoa(failed.ID) + "/resend"
	if status, _, hdr := e.do(admin, "POST", resend, url.Values{"_csrf": {token}}); status != http.StatusSeeOther || strings.Contains(hdr.Get("Location"), "error") {
		t.Fatalf("resend: %d %s", status, hdr.Get("Location"))
	}
	glpi := tk.find("/glpi/Ticket")
	if len(glpi) != 3 || !strings.Contains(string(glpi[2].Body), "db-02") {
		t.Errorf("resent ticket: %d", len(glpi))
	}
	list, _, _ = e.st.ListDeliveries(ctx, ids["GLPI"], store.Page{Number: 1, Size: 10})
	if len(list) != 3 || !list[0].OK {
		t.Errorf("history after resend: %+v", list)
	}
	if c, _ := e.st.ChannelByID(ctx, ids["GLPI"]); c.Failing() {
		t.Error("glpi channel still failing after a successful resend")
	}
	// Another channel's delivery id is not found.
	jiraResend := "/settings/channels/" + itoa(ids["Jira OPS"]) + "/deliveries/" + itoa(failed.ID) + "/resend"
	if status, _, _ := e.do(admin, "POST", jiraResend, url.Values{"_csrf": {token}}); status != http.StatusNotFound {
		t.Errorf("cross-channel resend: %d", status)
	}

	// Event filter edit; unknown events are refused.
	filter := "/settings/channels/" + itoa(ids["Jira OPS"]) + "/filter"
	if status, _, _ := e.do(admin, "POST", filter, url.Values{"_csrf": {token}, "min_level": {"warning"}, "events": {"rollback", "drift"}}); status != http.StatusSeeOther {
		t.Fatalf("filter: %d", status)
	}
	if c, _ := e.st.ChannelByID(ctx, ids["Jira OPS"]); c.MinLevel != store.LevelWarning || strings.Join(c.Events, ",") != "rollback,drift" {
		t.Errorf("filter saved: %+v", c)
	}
	e.do(admin, "POST", filter, url.Values{"_csrf": {token}, "min_level": {"info"}, "events": {"bogus"}})
	if c, _ := e.st.ChannelByID(ctx, ids["Jira OPS"]); c.MinLevel != store.LevelWarning || len(c.Events) != 2 {
		t.Errorf("invalid filter accepted: %+v", c)
	}
	_, body, _ = e.do(admin, "GET", "/settings/channels/"+itoa(ids["Jira OPS"]), nil)
	if !strings.Contains(body, `value="rollback" checked`) || strings.Contains(body, `value="kev" checked`) {
		t.Error("detail page does not show the saved events")
	}

	// Viewers cannot open channel settings.
	viewer := newClient()
	e.do(admin, "POST", "/users", url.Values{"_csrf": {token}, "name": {"İzleyici"}, "email": {"v@example.test"}, "role": {"viewer"}, "password": {"izleyici-parola-1"}, "password_confirm": {"izleyici-parola-1"}})
	e.do(viewer, "POST", "/login", url.Values{"email": {"v@example.test"}, "password": {"izleyici-parola-1"}})
	if status, _, _ := e.do(viewer, "GET", "/settings/channels/"+itoa(ids["GLPI"]), nil); status != http.StatusForbidden {
		t.Errorf("viewer channel page: %d", status)
	}
}
