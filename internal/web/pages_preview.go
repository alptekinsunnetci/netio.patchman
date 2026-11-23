package web

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"netio.patchman/internal/protocol"
	"netio.patchman/internal/store"
)

// ParamPreviewJob is a server-side job parameter: the preview a job was
// approved from.
const ParamPreviewJob = "preview_job"

func isPackageJobType(t string) bool {
	return t == protocol.JobUpgradeAll || t == protocol.JobUpgradeSecurity || t == protocol.JobUpgradePackages
}

// queuePreview queues a dry run of a package job; it returns a localized
// error message.
func (s *Server) queuePreview(r *http.Request, h store.Host, typ string, pkgs []string) (int64, string) {
	if !isPackageJobType(typ) {
		return 0, s.l.T("job.error.invalid_type")
	}
	if !h.Supports(protocol.CapPreview) {
		return 0, s.l.T("job.error.agent_capability", "hostname", h.Hostname)
	}
	if typ != protocol.JobUpgradePackages {
		pkgs = nil
	} else if len(pkgs) == 0 {
		return 0, s.l.T("job.error.no_packages")
	}
	for _, p := range pkgs {
		if !protocol.ValidPackageName(p) {
			return 0, s.l.T("job.error.invalid_package", "package", p)
		}
	}
	id, err := s.st.CreateJob(r.Context(), h.ID, protocol.JobPreview, pkgs, map[string]string{protocol.ParamPreviewType: typ}, sessionFrom(r).user.ID)
	if err != nil {
		return 0, s.l.T("error.internal.body")
	}
	details := "job_id=" + strconv.FormatInt(id, 10) + " type=preview preview_type=" + typ
	if len(pkgs) > 0 {
		details += " packages=" + strings.Join(pkgs, ",")
	}
	s.audit(r, "job.create", h.Hostname, details)
	return id, ""
}

// serverPreview starts a dry run from the server page.
func (s *Server) serverPreview(w http.ResponseWriter, r *http.Request) {
	h, ok := s.hostOr404(w, r)
	if !ok {
		return
	}
	id, msg := s.queuePreview(r, h, r.PostFormValue("type"), r.PostForm["packages"])
	if msg != "" {
		s.redirect(w, r, "/servers/"+strconv.FormatInt(h.ID, 10)+"?tab=updates", "error", msg)
		return
	}
	s.redirect(w, r, "/jobs/"+strconv.FormatInt(id, 10), "success", s.l.T("preview.queued"))
}

// previewStale is how old a plan may be before the page warns about it.
const previewStale = 24 * time.Hour

// approvable reports whether a preview job's plan can be applied, with the
// reason when it cannot.
func (s *Server) approvable(j store.Job, h store.Host) (bool, string) {
	switch {
	case j.Type != protocol.JobPreview || j.Status != protocol.JobSucceeded || j.Data.Preview == nil:
		return false, s.l.T("preview.error.not_ready")
	case len(j.Data.Preview.Conflicts) > 0:
		return false, s.l.T("preview.error.conflicts")
	case !h.RemoteUpdates:
		return false, s.l.T("job.error.remote_disabled", "hostname", h.Hostname)
	}
	if done, err := s.st.JobFromParam(context.Background(), ParamPreviewJob, strconv.FormatInt(j.ID, 10)); err != nil || done != 0 {
		return false, s.l.T("preview.error.not_ready")
	}
	return true, ""
}

// jobApprove applies an approved plan: the previewed job is queued.
func (s *Server) jobApprove(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		s.errorPage(w, r, http.StatusNotFound, "error.not_found")
		return
	}
	ctx := r.Context()
	back := "/jobs/" + strconv.FormatInt(id, 10)
	j, err := s.st.JobByID(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, r, http.StatusNotFound, "error.not_found")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	h, err := s.st.HostByID(ctx, j.HostID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if ok, why := s.approvable(j, h); !ok {
		s.redirect(w, r, back, "error", why)
		return
	}
	typ := j.Params[protocol.ParamPreviewType]
	newID, err := s.st.CreateJob(ctx, h.ID, typ, j.Packages, map[string]string{ParamPreviewJob: strconv.FormatInt(j.ID, 10)}, sessionFrom(r).user.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	details := "job_id=" + strconv.FormatInt(newID, 10) + " type=" + typ + " preview_job=" + strconv.FormatInt(j.ID, 10)
	if len(j.Packages) > 0 {
		details += " packages=" + strings.Join(j.Packages, ",")
	}
	s.audit(r, "job.approve", h.Hostname, details)
	s.redirect(w, r, "/jobs/"+strconv.FormatInt(newID, 10), "success", s.l.T("preview.approved"))
}

// previewList is one list of a plan on the job page, in display order.
type previewList struct {
	Kind string
	List []protocol.PackageChange
}
