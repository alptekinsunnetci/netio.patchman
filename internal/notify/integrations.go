package notify

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"netio.patchman/internal/brand"
	"netio.patchman/internal/store"
	"netio.patchman/internal/version"
)

// Events are the event ids a channel can subscribe to, in form order.
var Events = []string{
	"critical_cve", "kev", "vuln", "eol", "update_started", "update_succeeded", "update_failed", "rollback",
	"reboot_required", "health_failed", "sla_overdue", "score_below", "host_offline", "drift", "rollout", "software_changed", "other",
}

// EventOf names the event a notification belongs to (channel filters and
// the "event" field of webhook payloads).
func EventOf(n store.Notification) string {
	switch n.Kind {
	case "vuln_detected", "vulns_detected":
		if n.Params["kev"] != "" && n.Params["kev"] != "0" {
			return "kev"
		}
		if n.Params["severity"] == "critical" {
			return "critical_cve"
		}
		return "vuln"
	case "eol_reached", "eol_approaching":
		return "eol"
	case "job_started":
		return "update_started"
	case "job_succeeded":
		return "update_succeeded"
	case "job_failed", "job_partial":
		return "update_failed"
	case "rollback_done":
		return "rollback"
	case "reboot_required":
		return "reboot_required"
	case "health_regressed", "health_aborted", "health_failed", "health_down", "health_up", "resource_high", "resource_ok":
		return "health_failed"
	case "sla_overdue":
		return "sla_overdue"
	case "score_below":
		return "score_below"
	case "agent_offline":
		return "host_offline"
	case "drift_detected":
		return "drift"
	case "rollout_paused", "rollout_failed", "rollout_completed":
		return "rollout"
	case "software_changed":
		return "software_changed"
	}
	return "other"
}

func (d *Dispatcher) post(ctx context.Context, method, target string, body []byte, headers map[string]string, user, pass string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", brand.Name+"/"+version.Version)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if user != "" || pass != "" {
		req.SetBasicAuth(user, pass)
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		snippet := strings.TrimSpace(string(out))
		if len(snippet) > 300 {
			snippet = snippet[:300]
		}
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, snippet)
	}
	return out, nil
}

// ticket opens an issue (Jira), an incident (ServiceNow) or a ticket (GLPI).
func (d *Dispatcher) ticket(ctx context.Context, c store.Channel, n store.Notification, m Message) error {
	base := strings.TrimRight(c.URL, "/")
	summary := m.Title + ": " + m.Text
	if r := []rune(summary); len(r) > 240 {
		summary = string(r[:240]) + "…"
	}
	text := m.Text
	if m.URL != "" {
		text += "\n\n" + m.URL
	}
	cfg := c.Config
	switch c.Type {
	case store.ChannelJira:
		issueType := cfg["issue_type"]
		if issueType == "" {
			issueType = "Task"
		}
		body, _ := json.Marshal(map[string]any{"fields": map[string]any{
			"project": map[string]string{"key": cfg["project"]}, "summary": summary, "description": text,
			"issuetype": map[string]string{"name": issueType}, "labels": []string{brand.Name, EventOf(n)},
		}})
		_, err := d.post(ctx, http.MethodPost, base+"/rest/api/2/issue", body, nil, cfg["user"], c.Secret)
		return err
	case store.ChannelServiceNow:
		table := cfg["table"]
		if table == "" {
			table = "incident"
		}
		urgency := map[string]string{store.LevelCritical: "1", store.LevelWarning: "2"}[n.Level]
		if urgency == "" {
			urgency = "3"
		}
		body, _ := json.Marshal(map[string]string{"short_description": summary, "description": text, "urgency": urgency, "impact": urgency})
		_, err := d.post(ctx, http.MethodPost, base+"/api/now/table/"+table, body, nil, cfg["user"], c.Secret)
		return err
	case store.ChannelGLPI:
		headers := map[string]string{"App-Token": cfg["app_token"], "Authorization": "user_token " + c.Secret}
		out, err := d.post(ctx, http.MethodGet, base+"/initSession", nil, headers, "", "")
		if err != nil {
			return err
		}
		var sess struct {
			Token string `json:"session_token"`
		}
		if err := json.Unmarshal(out, &sess); err != nil || sess.Token == "" {
			return errors.New("glpi: no session token")
		}
		sh := map[string]string{"App-Token": cfg["app_token"], "Session-Token": sess.Token}
		defer func() {
			_, _ = d.post(context.WithoutCancel(ctx), http.MethodGet, base+"/killSession", nil, sh, "", "")
		}()
		urgency := map[string]int{store.LevelCritical: 5, store.LevelWarning: 4}[n.Level]
		if urgency == 0 {
			urgency = 3
		}
		body, _ := json.Marshal(map[string]any{"input": map[string]any{"name": summary, "content": text, "urgency": urgency, "type": 1}})
		_, err = d.post(ctx, http.MethodPost, base+"/Ticket", body, sh, "", "")
		return err
	}
	return fmt.Errorf("unknown ticket channel %q", c.Type)
}

// zabbix sends the notification as the value of a trapper item with the
// Zabbix sender protocol (TCP, default port 10051).
func (d *Dispatcher) zabbix(ctx context.Context, c store.Channel, n store.Notification, m Message) error {
	addr := strings.TrimSpace(c.URL)
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "10051")
	}
	key := c.Config["key"]
	if key == "" {
		key = "netio.patchman.event"
	}
	value, _ := json.Marshal(map[string]any{"event": EventOf(n), "kind": n.Kind, "level": n.Level, "title": m.Title, "text": m.Text, "url": m.URL,
		"params": n.Params, "time": n.CreatedAt.UTC().Format(time.RFC3339)})
	data, _ := json.Marshal(map[string]any{"request": "sender data", "data": []map[string]string{{"host": c.Config["host"], "key": key, "value": string(value)}}})
	var dialer net.Dialer
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	frame := make([]byte, 13, 13+len(data))
	copy(frame, "ZBXD\x01")
	binary.LittleEndian.PutUint64(frame[5:], uint64(len(data)))
	if _, err := conn.Write(append(frame, data...)); err != nil {
		return err
	}
	resp, err := readZabbix(bufio.NewReader(conn))
	if err != nil {
		return err
	}
	var r struct {
		Response string `json:"response"`
		Info     string `json:"info"`
	}
	if err := json.Unmarshal(resp, &r); err != nil {
		return err
	}
	if r.Response != "success" || !strings.Contains(r.Info, "processed: 1") {
		return fmt.Errorf("zabbix: %s %s", r.Response, r.Info)
	}
	return nil
}

func readZabbix(r io.Reader) ([]byte, error) {
	head := make([]byte, 13)
	if _, err := io.ReadFull(r, head); err != nil {
		return nil, err
	}
	if string(head[:4]) != "ZBXD" {
		return nil, errors.New("zabbix: bad response header")
	}
	n := binary.LittleEndian.Uint64(head[5:])
	if n > 1<<20 {
		return nil, errors.New("zabbix: response too large")
	}
	body := make([]byte, n)
	_, err := io.ReadFull(r, body)
	return body, err
}
