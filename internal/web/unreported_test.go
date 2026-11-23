package web_test

import (
	"context"
	"strings"
	"testing"

	"netio.patchman/internal/protocol"
	"netio.patchman/internal/timeutil"
)

// A job still dispatched when its agent checks in again never reported a
// result (the agent stopped or restarted mid-job, or the result was lost):
// the check-in closes it instead of leaving it running until the timeout.
func TestCheckinClosesUnreportedJobs(t *testing.T) {
	e, _, _ := fleetEnv(t)
	ctx := context.Background()
	info := protocol.HostInfo{Hostname: "WIN-UNREPORTED", MachineID: "win-unrep", OSID: "windows", OSVersionID: "10.0.20348", Arch: "amd64",
		PackageManager: protocol.PMWindowsUpdate, AgentVersion: "1.0.3", RemoteUpdates: true, SelfUpdate: true}
	client, id := e.agentFor(info)

	update, err := e.st.CreateJob(ctx, id, protocol.JobAgentUpdate, nil, map[string]string{protocol.ParamVersion: "1.0.4",
		protocol.ParamSHA256: strings.Repeat("a", 64), protocol.ParamPath: protocol.AgentDownloadPrefix + "netio-patchman-agent-windows-amd64.exe"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	refresh, err := e.st.CreateJob(ctx, id, protocol.JobRefresh, nil, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	reported, err := e.st.CreateJob(ctx, id, protocol.JobUpgradeAll, nil, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Checkin(ctx, info)
	if err != nil || len(resp.Jobs) != 3 {
		t.Fatalf("dispatch: %+v %v", resp.Jobs, err)
	}
	// Only the package job reports its result; the agent then restarts as 1.0.4.
	if err := client.JobResult(ctx, reported, protocol.JobResult{Succeeded: true, Output: "ok", StartedAt: timeutil.Now(), FinishedAt: timeutil.Now()}); err != nil {
		t.Fatal(err)
	}
	info.AgentVersion = "1.0.4"
	if resp, err = client.Checkin(ctx, info); err != nil {
		t.Fatal(err)
	}
	for _, j := range resp.Jobs {
		if j.Type == protocol.JobAgentUpdate {
			t.Errorf("agent update queued again: %+v", j)
		}
	}

	want := map[int64]string{update: protocol.JobSucceeded, refresh: protocol.JobFailed, reported: protocol.JobSucceeded}
	for jobID, status := range want {
		j, err := e.st.JobByID(ctx, jobID)
		if err != nil {
			t.Fatal(err)
		}
		if j.Status != status || j.FinishedAt.IsZero() {
			t.Errorf("job %d (%s): status %s, finished %v, want %s", jobID, j.Type, j.Status, j.FinishedAt, status)
		}
		switch jobID {
		case update:
			if !strings.Contains(j.Output, "1.0.4") {
				t.Errorf("agent update output: %q", j.Output)
			}
		case refresh:
			if j.ExitCode != -1 || !strings.HasPrefix(j.Output, "[netio.patchman] ") {
				t.Errorf("unreported job: exit %d output %q", j.ExitCode, j.Output)
			}
		case reported:
			if j.Output != "ok" {
				t.Errorf("reported job changed: %q", j.Output)
			}
		}
	}

	// An update the agent did not apply (still the old version) fails.
	stale, err := e.st.CreateJob(ctx, id, protocol.JobAgentUpdate, nil, map[string]string{protocol.ParamVersion: "1.0.5",
		protocol.ParamSHA256: strings.Repeat("b", 64), protocol.ParamPath: protocol.AgentDownloadPrefix + "netio-patchman-agent-windows-amd64.exe"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Checkin(ctx, info); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Checkin(ctx, info); err != nil {
		t.Fatal(err)
	}
	if j, _ := e.st.JobByID(ctx, stale); j.Status != protocol.JobFailed {
		t.Errorf("stale agent update: %s", j.Status)
	}
}
