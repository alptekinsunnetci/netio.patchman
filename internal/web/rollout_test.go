package web_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"netio.patchman/internal/i18n"
	"netio.patchman/internal/protocol"
	"netio.patchman/internal/rollout"
	"netio.patchman/internal/store"
	"netio.patchman/internal/timeutil"
)

func TestRollingUpdate(t *testing.T) {
	e, admin, oldID := fleetEnv(t)
	ctx := context.Background()
	// The fleetEnv host is left out by the selection below.
	_ = oldID
	var ids []int64
	for i := 0; i < 4; i++ {
		info := protocol.HostInfo{Hostname: fmt.Sprintf("web-%02d", i+1), MachineID: fmt.Sprintf("ro%d", i), OSID: "debian", OSVersionID: "12", Arch: "amd64",
			PackageManager: "apt", AgentVersion: "0.10.0", RemoteUpdates: true}
		_, id := e.agentFor(info)
		if err := e.st.SaveReport(ctx, id, protocol.Report{Host: info}, ""); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	runner := &rollout.Runner{Store: e.st, L: i18n.MustLoad().Localizer(i18n.DefaultLocale), Notify: func(ctx context.Context, kind, level string, r store.Rollout) {
		if cur, err := e.st.RolloutByID(ctx, r.ID); err == nil {
			r.Counts = cur.Counts
		}
		e.notifier.RolloutEvent(ctx, kind, level, r)
	}}
	form := url.Values{"_csrf": {e.csrf(admin)}, "name": {"Güvenlik turu"}, "job_type": {"upgrade_security"}, "strategy": {"batches"}, "target": {"hosts"},
		"order": {"hostname"}, "canary": {"1"}, "batch": {"2"}, "max_parallel": {"5"}, "wait_minutes": {"0"}, "max_failure_pct": {"50"},
		"job_timeout_minutes": {"60"}, "require_health": {"1"}, "pause_after_canary": {"1"}}
	for _, id := range ids {
		form.Add("host_ids", strconv.FormatInt(id, 10))
	}
	_, _, hdr := e.do(admin, "POST", "/rollouts", form)
	loc := hdr.Get("Location")
	rid, _ := strconv.ParseInt(strings.TrimPrefix(loc, "/rollouts/"), 10, 64)
	ro, err := e.st.RolloutByID(ctx, rid)
	if err != nil || ro.Stages != 3 || ro.Canary != 1 || ro.Counts.Total != 4 || ro.Counts.Queued != 1 {
		t.Fatalf("rollout: %+v %v", ro, err)
	}
	hosts := func() map[int64]store.RolloutHost {
		list, _ := e.st.RolloutHosts(ctx, rid)
		m := map[int64]store.RolloutHost{}
		for _, h := range list {
			m[h.HostID] = h
		}
		return m
	}
	finish := func(hostID int64, res protocol.JobResult) {
		t.Helper()
		h := hosts()[hostID]
		if h.JobID == 0 {
			t.Fatalf("host %d has no job", hostID)
		}
		if _, err := e.st.CompleteJob(ctx, hostID, h.JobID, res); err != nil {
			t.Fatal(err)
		}
	}
	tick := func() { runner.Tick(ctx, timeutil.Now()) }
	ok := protocol.JobResult{Succeeded: true}

	// Canary (web-01) succeeds: the rollout waits for approval.
	if h := hosts()[ids[0]]; h.Status != store.RolloutHostQueued || h.Stage != 0 {
		t.Fatalf("canary: %+v", h)
	}
	job, _ := e.st.JobByID(ctx, hosts()[ids[0]].JobID)
	if job.Type != protocol.JobUpgradeSecurity || job.Params[store.ParamRolloutID] != strconv.FormatInt(rid, 10) || job.ExpiresAt.IsZero() {
		t.Errorf("canary job: %+v", job)
	}
	finish(ids[0], ok)
	tick()
	if ro, _ = e.st.RolloutByID(ctx, rid); ro.Status != store.RolloutPaused || ro.Reason != rollout.ReasonCanaryDone {
		t.Fatalf("after canary: %+v", ro)
	}
	waitNotification(t, e, "rollout_paused", "")
	status, body, _ := e.do(admin, "GET", loc, nil)
	expect(t, "paused page", status, 200, body, "Canary aşaması başarıyla bitti", "Devam ettir", "Canary aşaması", "web-01")

	// Resume: stage 2 (web-02, web-03) starts.
	if status, _, _ := e.do(admin, "POST", loc+"/resume", url.Values{"_csrf": {e.csrf(admin)}}); status != 303 {
		t.Fatalf("resume: %d", status)
	}
	if h := hosts(); h[ids[1]].Status != store.RolloutHostQueued || h[ids[2]].Status != store.RolloutHostQueued || h[ids[3]].Status != store.RolloutHostPending {
		t.Fatalf("stage 2: %+v", h)
	}
	// web-02 succeeds; web-03 updates but its health check breaks: a failure (1 of 3 = 33% < 50%).
	finish(ids[1], ok)
	finish(ids[2], protocol.JobResult{Succeeded: true, Health: &protocol.HealthReport{
		Before: []protocol.HealthResult{{ID: 1, Name: "web", OK: true}}, After: []protocol.HealthResult{{ID: 1, Name: "web", OK: false}}}})
	tick()
	h := hosts()
	if h[ids[2]].Status != store.RolloutHostFailed || !strings.HasPrefix(h[ids[2]].Note, "health_regressed") || h[ids[3]].Status != store.RolloutHostQueued {
		t.Fatalf("stage 2 result: %+v", h)
	}
	finish(ids[3], ok)
	tick()
	if ro, _ = e.st.RolloutByID(ctx, rid); ro.Status != store.RolloutCompleted || ro.Counts.Succeeded != 3 || ro.Counts.Failed != 1 {
		t.Fatalf("completed: %+v", ro)
	}
	waitNotification(t, e, "rollout_completed", "")

	// A failing canary stops the rollout; resuming accepts that failure.
	form.Set("name", "İkinci tur")
	form.Set("_csrf", e.csrf(admin))
	_, _, hdr = e.do(admin, "POST", "/rollouts", form)
	loc2 := hdr.Get("Location")
	rid, _ = strconv.ParseInt(strings.TrimPrefix(loc2, "/rollouts/"), 10, 64)
	finish(ids[0], protocol.JobResult{Succeeded: false, ExitCode: 100})
	tick()
	ro, _ = e.st.RolloutByID(ctx, rid)
	if ro.Status != store.RolloutFailed || ro.Reason != rollout.ReasonCanaryFailed || ro.Counts.Skipped != 3 {
		t.Fatalf("stopped: %+v", ro)
	}
	waitNotification(t, e, "rollout_failed", "")
	if status, _, _ := e.do(admin, "POST", loc2+"/resume", url.Values{"_csrf": {e.csrf(admin)}}); status != 303 {
		t.Fatalf("resume after stop: %d", status)
	}
	ro, _ = e.st.RolloutByID(ctx, rid)
	if ro.Status != store.RolloutRunning || ro.AcceptedFailures != 1 || ro.Counts.Queued != 2 {
		t.Fatalf("resumed: %+v", ro)
	}
	// Cancel: queued jobs are cancelled, nothing else starts.
	if status, _, _ := e.do(admin, "POST", loc2+"/cancel", url.Values{"_csrf": {e.csrf(admin)}}); status != 303 {
		t.Fatalf("cancel: %d", status)
	}
	ro, _ = e.st.RolloutByID(ctx, rid)
	if ro.Status != store.RolloutCancelled || ro.Counts.Queued != 0 {
		t.Fatalf("cancelled: %+v", ro)
	}
	j, _ := e.st.JobByID(ctx, hosts()[ids[1]].JobID)
	if j.Status != protocol.JobCancelled {
		t.Errorf("queued job after cancel: %s", j.Status)
	}
	// Actions in the wrong state are refused.
	if _, _, hdr := e.do(admin, "POST", loc2+"/pause", url.Values{"_csrf": {e.csrf(admin)}}); hdr.Get("Location") != loc2 {
		t.Errorf("pause after cancel")
	}

	status, body, _ = e.do(admin, "GET", "/rollouts", nil)
	expect(t, "rollout list", status, 200, body, "Güvenlik turu", "İkinci tur", "Tamamlandı", "İptal edildi")
	status, body, _ = e.do(admin, "GET", "/rollouts/new", nil)
	expect(t, "new form", status, 200, body, "Yeni kademeli güncelleme", "Canary sunucu sayısı", "Grup sırasına göre")
	_ = time.Second

	key := e.createAPIKey(admin, "rollouts", false)
	status, body = e.apiDo(key, "GET", "/api/v1/rollouts", "")
	var res struct {
		Rollouts []struct {
			Status  string `json:"status"`
			JobType string `json:"job_type"`
			Hosts   struct{ Total int }
		} `json:"rollouts"`
		Pagination struct{ Total int }
	}
	if err := json.Unmarshal([]byte(body), &res); status != 200 || err != nil || res.Pagination.Total != 2 || len(res.Rollouts) != 2 {
		t.Fatalf("rollouts api: %d %v %s", status, err, body)
	}
	got := map[string]bool{}
	for _, ro := range res.Rollouts {
		got[ro.Status] = ro.Hosts.Total > 0
	}
	if !got[store.RolloutCancelled] || !got[store.RolloutCompleted] {
		t.Errorf("rollouts api: %s", body)
	}
}
