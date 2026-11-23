package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"netio.patchman/internal/protocol"
	"netio.patchman/internal/store"
)

// Change sources on the job page.
const (
	changesAgent     = "agent"     // the agent compared versions before and after the job
	changesInventory = "inventory" // the inventory at dispatch against the current one
)

// jobChanges returns the package versions a job changed: as reported by
// the agent, or (older agents) the inventory stored at dispatch compared
// with the host's current inventory, which can also contain later changes.
func (s *Server) jobChanges(ctx context.Context, j store.Job) ([]protocol.PackageChange, string) {
	if len(j.Data.Changes) > 0 {
		return j.Data.Changes, changesAgent
	}
	if j.Active() || !isPackageJobType(j.Type) {
		return nil, ""
	}
	before, err := s.st.JobInventory(ctx, j.ID)
	if err != nil {
		return nil, ""
	}
	after, err := s.st.HostPackages(ctx, j.HostID)
	if err != nil {
		return nil, ""
	}
	return protocol.DiffPackages(before, after), changesInventory
}

// revertible reports whether a change can be undone by installing the
// earlier version (packages that were upgraded or downgraded; new and
// removed packages are not part of a rollback).
func revertible(c protocol.PackageChange) bool {
	return c.From != "" && c.To != "" && protocol.ValidPackageName(c.Name) && protocol.ValidPackageVersion(c.From)
}

// rollbackBlocked returns why a rollback cannot be started on a host, "" when it can.
func (s *Server) rollbackBlocked(h store.Host) string {
	switch {
	case !h.CanRollback():
		return s.l.T("job.error.agent_capability", "hostname", h.Hostname)
	case !h.RemoteUpdates:
		return s.l.T("job.error.remote_disabled", "hostname", h.Hostname)
	}
	return ""
}

// selected returns the list entries whose index was ticked in the form.
func selectedIndexes(r *http.Request, n int) map[int]bool {
	_ = r.ParseForm()
	out := map[int]bool{}
	for _, v := range r.PostForm["pkg"] {
		if i, err := strconv.Atoi(v); err == nil && i >= 0 && i < n {
			out[i] = true
		}
	}
	return out
}

func (s *Server) jobAndHost(w http.ResponseWriter, r *http.Request) (store.Job, store.Host, bool) {
	id, ok := pathID(r)
	if !ok {
		s.errorPage(w, r, http.StatusNotFound, "error.not_found")
		return store.Job{}, store.Host{}, false
	}
	j, err := s.st.JobByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, r, http.StatusNotFound, "error.not_found")
		return j, store.Host{}, false
	}
	if err != nil {
		s.serverError(w, r, err)
		return j, store.Host{}, false
	}
	h, err := s.st.HostByID(r.Context(), j.HostID)
	if err != nil {
		s.serverError(w, r, err)
		return j, h, false
	}
	return j, h, true
}

// jobRollbackCheck queues a rollback check for the selected changes of a job.
func (s *Server) jobRollbackCheck(w http.ResponseWriter, r *http.Request) {
	j, h, ok := s.jobAndHost(w, r)
	if !ok {
		return
	}
	back := "/jobs/" + strconv.FormatInt(j.ID, 10)
	if why := s.rollbackBlocked(h); why != "" {
		s.redirect(w, r, back, "error", why)
		return
	}
	changes, _ := s.jobChanges(r.Context(), j)
	sel := selectedIndexes(r, len(changes))
	var targets []protocol.PackageChange
	for i, c := range changes {
		if sel[i] && revertible(c) && len(targets) < protocol.MaxRollbackTargets {
			targets = append(targets, protocol.PackageChange{Name: c.Name, Arch: c.Arch, From: c.To, To: c.From})
		}
	}
	if len(targets) == 0 {
		s.redirect(w, r, back, "error", s.l.T("rollback.error.none_selected"))
		return
	}
	id, err := s.queueRollback(r, h, protocol.RollbackCheck, targets, map[string]string{store.ParamRollbackOf: strconv.FormatInt(j.ID, 10)})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.redirect(w, r, "/jobs/"+strconv.FormatInt(id, 10), "success", s.l.T("rollback.check_queued"))
}

// jobRollbackApply applies an approved rollback check: only the packages
// the check found available and the operator selected.
func (s *Server) jobRollbackApply(w http.ResponseWriter, r *http.Request) {
	j, h, ok := s.jobAndHost(w, r)
	if !ok {
		return
	}
	back := "/jobs/" + strconv.FormatInt(j.ID, 10)
	if j.Type != protocol.JobRollback || j.Params[protocol.ParamRollbackMode] != protocol.RollbackCheck || j.Status != protocol.JobSucceeded {
		s.redirect(w, r, back, "error", s.l.T("rollback.error.not_checked"))
		return
	}
	if why := s.rollbackBlocked(h); why != "" {
		s.redirect(w, r, back, "error", why)
		return
	}
	if j.Data.Preview != nil && len(j.Data.Preview.Conflicts) > 0 {
		s.redirect(w, r, back, "error", s.l.T("preview.error.conflicts"))
		return
	}
	if done, err := s.st.JobFromParam(r.Context(), store.ParamRollbackCheck, strconv.FormatInt(j.ID, 10)); err != nil || done != 0 {
		s.redirect(w, r, back, "error", s.l.T("rollback.error.applied"))
		return
	}
	sel := selectedIndexes(r, len(j.Data.Rollback))
	var targets []protocol.PackageChange
	for i, it := range j.Data.Rollback {
		if sel[i] && it.Status == protocol.RollbackAvailable && protocol.ValidPackageName(it.Name) && protocol.ValidPackageVersion(it.To) {
			targets = append(targets, protocol.PackageChange{Name: it.Name, Arch: it.Arch, From: it.From, To: it.To})
		}
	}
	if len(targets) == 0 {
		s.redirect(w, r, back, "error", s.l.T("rollback.error.none_selected"))
		return
	}
	params := map[string]string{store.ParamRollbackCheck: strconv.FormatInt(j.ID, 10), store.ParamRollbackOf: j.Params[store.ParamRollbackOf]}
	if r.PostFormValue("hold") == "1" {
		params[store.ParamRollbackHold] = "1"
	}
	id, err := s.queueRollback(r, h, protocol.RollbackApply, targets, params)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.redirect(w, r, "/jobs/"+strconv.FormatInt(id, 10), "success", s.l.T("rollback.apply_queued"))
}

func (s *Server) queueRollback(r *http.Request, h store.Host, mode string, targets []protocol.PackageChange, extra map[string]string) (int64, error) {
	b, _ := json.Marshal(targets)
	params := map[string]string{protocol.ParamRollbackMode: mode, protocol.ParamRollbackTargets: string(b)}
	for k, v := range extra {
		if v != "" {
			params[k] = v
		}
	}
	id, err := s.st.CreateJob(r.Context(), h.ID, protocol.JobRollback, nil, params, sessionFrom(r).user.ID)
	if err != nil {
		return 0, err
	}
	names := make([]string, len(targets))
	for i, t := range targets {
		names[i] = t.Name + "=" + t.To
	}
	action := "rollback.check"
	if mode == protocol.RollbackApply {
		action = "rollback.apply"
	}
	details := "job_id=" + strconv.FormatInt(id, 10) + " packages=" + strings.Join(names, ",")
	if extra[store.ParamRollbackHold] == "1" {
		details += " hold=true"
	}
	s.audit(r, action, h.Hostname, details)
	return id, nil
}
