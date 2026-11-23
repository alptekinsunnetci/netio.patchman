// Package rollout advances rolling updates: one package job type over many
// hosts in stages (a canary first, then batches or groups), with a limit
// on parallel jobs, a wait between stages, and an automatic stop when
// failures exceed the configured rate. Failures include health checks that
// broke after the update when the rollout requires healthy hosts.
package rollout

import (
	"context"
	"log/slog"
	"sort"
	"strconv"
	"time"

	"netio.patchman/internal/i18n"
	"netio.patchman/internal/protocol"
	"netio.patchman/internal/store"
)

// Stop and pause reasons (catalog key "rollout.reason.<reason>").
const (
	ReasonCanaryFailed = "canary_failed"
	ReasonFailureRate  = "failure_rate"
	ReasonCanaryDone   = "canary_done"
	ReasonManual       = "manual"
)

// Runner advances running rollouts; call Tick every minute.
type Runner struct {
	Store  *store.Store
	L      i18n.Localizer
	Logger *slog.Logger
	// Notify reports state changes (paused, stopped, completed); kind is a
	// notification kind ("rollout_paused", "rollout_failed", "rollout_completed").
	Notify func(ctx context.Context, kind, level string, r store.Rollout)
}

// Tick advances every running rollout.
func (rn *Runner) Tick(ctx context.Context, now time.Time) {
	list, err := rn.Store.RunningRollouts(ctx)
	if err != nil {
		rn.warn(err)
		return
	}
	for _, r := range list {
		// Zero waits move through several stages in one tick.
		for i := 0; i <= r.Stages && ctx.Err() == nil; i++ {
			advanced, err := rn.step(ctx, &r, now)
			if err != nil {
				rn.warn(err)
				break
			}
			if !advanced {
				break
			}
		}
	}
}

func (rn *Runner) warn(err error) {
	if rn.Logger != nil {
		rn.Logger.Warn(rn.L.T("log.rollout.failed"), slog.String("error", err.Error()))
	}
}

// outcome classifies a finished job of the rollout.
func outcome(j store.Job, requireHealth bool) (string, string) {
	switch j.Status {
	case protocol.JobSucceeded:
		if requireHealth {
			if o, checks := j.Data.HealthOutcome(); o == store.HealthRegressed || o == store.HealthFailed || o == store.HealthAborted {
				return store.RolloutHostFailed, "health_" + o + ":" + joinNames(checks)
			}
		}
		return store.RolloutHostSucceeded, ""
	case protocol.JobPartial:
		return store.RolloutHostFailed, "partial:" + joinNames(j.Remaining)
	}
	return store.RolloutHostFailed, "job_" + j.Status
}

func joinNames(n []string) string {
	out := ""
	for i, s := range n {
		if i == 10 {
			out += ", …"
			break
		}
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}

// step does one round of work on a running rollout and reports whether it
// moved to the next stage (so the caller can continue at once).
func (rn *Runner) step(ctx context.Context, r *store.Rollout, now time.Time) (bool, error) {
	hosts, err := rn.Store.RolloutHosts(ctx, r.ID)
	if err != nil {
		return false, err
	}
	// 1. Collect finished jobs.
	for i := range hosts {
		h := &hosts[i]
		if h.Status != store.RolloutHostQueued || h.JobID == 0 {
			continue
		}
		j, err := rn.Store.JobByID(ctx, h.JobID)
		if err != nil {
			return false, err
		}
		if j.Active() {
			continue
		}
		h.Status, h.Note = outcome(j, r.RequireHealth)
		if err := rn.Store.SetRolloutHost(ctx, r.ID, h.HostID, h.Status, 0, h.Note); err != nil {
			return false, err
		}
	}
	// 2. Failure policy (failures accepted by a resume do not count again).
	processed, failed, stageFailed := 0, 0, 0
	for _, h := range hosts {
		switch h.Status {
		case store.RolloutHostSucceeded:
			processed++
		case store.RolloutHostFailed:
			processed++
			failed++
			if h.Stage == r.CurrentStage {
				stageFailed++
			}
		}
	}
	newFailed, newProcessed := failed-r.AcceptedFailures, processed-r.AcceptedProcessed
	if r.Canary > 0 && r.CurrentStage == 0 && newFailed > 0 {
		return false, rn.stop(ctx, r, now, store.RolloutFailed, ReasonCanaryFailed, hosts)
	}
	if newProcessed > 0 && newFailed*100 > r.MaxFailurePct*newProcessed {
		return false, rn.stop(ctx, r, now, store.RolloutFailed, ReasonFailureRate, hosts)
	}
	// 3. Start jobs in the current stage, at most MaxParallel at a time.
	active, pending := 0, 0
	for _, h := range hosts {
		if h.Stage == r.CurrentStage && h.Status == store.RolloutHostQueued {
			active++
		}
	}
	stage := make([]store.RolloutHost, 0)
	for _, h := range hosts {
		if h.Stage == r.CurrentStage && h.Status == store.RolloutHostPending {
			stage = append(stage, h)
		}
	}
	sort.Slice(stage, func(i, j int) bool { return stage[i].Position < stage[j].Position })
	for _, h := range stage {
		if active >= max(r.MaxParallel, 1) {
			pending++
			continue
		}
		host, err := rn.Store.HostByID(ctx, h.HostID)
		if err != nil {
			if err := rn.Store.SetRolloutHost(ctx, r.ID, h.HostID, store.RolloutHostSkipped, 0, "host_missing"); err != nil {
				return false, err
			}
			continue
		}
		if !host.RemoteUpdates {
			if err := rn.Store.SetRolloutHost(ctx, r.ID, h.HostID, store.RolloutHostSkipped, 0, "remote_disabled"); err != nil {
				return false, err
			}
			continue
		}
		params := map[string]string{store.ParamRolloutID: strconv.FormatInt(r.ID, 10)}
		expires := now.Add(time.Duration(max(r.JobTimeoutMinutes, 5)) * time.Minute)
		id, err := rn.Store.CreateJobExpiring(ctx, h.HostID, r.JobType, r.Packages, params, r.CreatedByID, expires)
		if err != nil {
			return false, err
		}
		if err := rn.Store.SetRolloutHost(ctx, r.ID, h.HostID, store.RolloutHostQueued, id, ""); err != nil {
			return false, err
		}
		active++
	}
	if active > 0 || pending > 0 {
		return false, nil
	}
	// 4. The stage is finished.
	if r.CurrentStage >= r.Stages-1 {
		r.Status, r.FinishedAt, r.Reason = store.RolloutCompleted, now, ""
		if err := rn.Store.SaveRolloutState(ctx, *r); err != nil {
			return false, err
		}
		rn.notify(ctx, "rollout_completed", store.LevelInfo, *r)
		return false, nil
	}
	if r.StageFinishedAt.IsZero() {
		r.StageFinishedAt = now
		if r.Canary > 0 && r.CurrentStage == 0 && r.PauseAfterCanary {
			r.Status, r.Reason = store.RolloutPaused, ReasonCanaryDone
			if err := rn.Store.SaveRolloutState(ctx, *r); err != nil {
				return false, err
			}
			rn.notify(ctx, "rollout_paused", store.LevelInfo, *r)
			return false, nil
		}
		if err := rn.Store.SaveRolloutState(ctx, *r); err != nil {
			return false, err
		}
	}
	if now.Sub(r.StageFinishedAt) < time.Duration(r.WaitMinutes)*time.Minute {
		return false, nil
	}
	r.CurrentStage++
	r.StageFinishedAt = time.Time{}
	return true, rn.Store.SaveRolloutState(ctx, *r)
}

// stop ends a rollout: queued jobs not yet dispatched are cancelled and the
// hosts not started are skipped. Running jobs finish on their own.
func (rn *Runner) stop(ctx context.Context, r *store.Rollout, now time.Time, status, reason string, hosts []store.RolloutHost) error {
	for _, h := range hosts {
		if h.Status == store.RolloutHostQueued && h.JobID != 0 {
			if ok, _ := rn.Store.CancelJob(ctx, h.JobID); ok {
				_ = rn.Store.SetRolloutHost(ctx, r.ID, h.HostID, store.RolloutHostSkipped, 0, "cancelled")
			}
		}
	}
	if err := rn.Store.SkipPendingRolloutHosts(ctx, r.ID); err != nil {
		return err
	}
	r.Status, r.Reason, r.FinishedAt = status, reason, now
	if err := rn.Store.SaveRolloutState(ctx, *r); err != nil {
		return err
	}
	if status == store.RolloutFailed {
		rn.notify(ctx, "rollout_failed", store.LevelWarning, *r)
	}
	return nil
}

// Cancel stops a rollout by hand.
func (rn *Runner) Cancel(ctx context.Context, r store.Rollout, now time.Time) error {
	hosts, err := rn.Store.RolloutHosts(ctx, r.ID)
	if err != nil {
		return err
	}
	return rn.stop(ctx, &r, now, store.RolloutCancelled, ReasonManual, hosts)
}

// Pause stops starting new jobs; jobs already queued keep running.
func (rn *Runner) Pause(ctx context.Context, r store.Rollout) error {
	r.Status, r.Reason = store.RolloutPaused, ReasonManual
	return rn.Store.SaveRolloutState(ctx, r)
}

// Resume continues a paused or automatically stopped rollout; the failures
// so far are accepted and do not stop it again. Hosts skipped by the stop
// are started again.
func (rn *Runner) Resume(ctx context.Context, r store.Rollout) error {
	hosts, err := rn.Store.RolloutHosts(ctx, r.ID)
	if err != nil {
		return err
	}
	processed, failed := 0, 0
	stageOpen := false
	for _, h := range hosts {
		if h.Stage == r.CurrentStage && (h.Status == store.RolloutHostPending || h.Status == store.RolloutHostQueued) {
			stageOpen = true
		}
		switch h.Status {
		case store.RolloutHostSucceeded:
			processed++
		case store.RolloutHostFailed:
			processed++
			failed++
		case store.RolloutHostSkipped:
			if r.Status == store.RolloutFailed && (h.Note == "cancelled" || h.Note == "") {
				if err := rn.Store.SetRolloutHost(ctx, r.ID, h.HostID, store.RolloutHostPending, 0, ""); err != nil {
					return err
				}
			}
		}
	}
	r.AcceptedFailures, r.AcceptedProcessed = failed, processed
	// Resuming counts as the approval a finished canary stage waits for.
	if !stageOpen && r.StageFinishedAt.IsZero() {
		r.StageFinishedAt = time.Now()
	}
	r.Status, r.Reason, r.FinishedAt = store.RolloutRunning, "", time.Time{}
	return rn.Store.SaveRolloutState(ctx, r)
}

func (rn *Runner) notify(ctx context.Context, kind, level string, r store.Rollout) {
	if rn.Notify != nil {
		rn.Notify(ctx, kind, level, r)
	}
}
