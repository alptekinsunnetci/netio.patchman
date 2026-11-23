package web

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"netio.patchman/internal/protocol"
	"netio.patchman/internal/rollout"
	"netio.patchman/internal/store"
	"netio.patchman/internal/timeutil"
)

// maxRolloutGroups is how many ordered group stages the form offers.
const maxRolloutGroups = 6

func (s *Server) rolloutRunner() *rollout.Runner {
	if s.o.Rollouts != nil {
		return s.o.Rollouts
	}
	return &rollout.Runner{Store: s.st, L: s.l, Logger: s.logger}
}

func (s *Server) rollouts(w http.ResponseWriter, r *http.Request) {
	pg := pageNumber(r)
	list, total, err := s.st.ListRollouts(r.Context(), store.Page{Number: pg, Size: pageSize})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d := s.page(r, s.l.T("nav.rollouts"), "rollouts")
	d.Data = map[string]any{"Rollouts": list, "Pager": newPager(r, pg, total)}
	s.render(w, r, http.StatusOK, "rollouts", d)
}

// rolloutForm is the "new rollout" form.
type rolloutForm struct {
	Name, JobType, Packages, Target, Strategy, Order string
	GroupID                                          int64
	HostIDs                                          map[int64]bool
	StageGroups                                      []int64
	Canary, Batch, MaxParallel, WaitMinutes          int
	MaxFailurePct, JobTimeoutMinutes                 int
	RequireHealth, PauseAfterCanary                  bool
}

func defaultRolloutForm() rolloutForm {
	return rolloutForm{JobType: protocol.JobUpgradeSecurity, Target: "all", Strategy: "batches", Order: rollout.OrderScoreDesc,
		Canary: 1, Batch: 5, MaxParallel: 5, WaitMinutes: 10, MaxFailurePct: 10, JobTimeoutMinutes: 180, RequireHealth: true, PauseAfterCanary: true,
		HostIDs: map[int64]bool{}, StageGroups: make([]int64, maxRolloutGroups)}
}

func (s *Server) rolloutNew(w http.ResponseWriter, r *http.Request) {
	s.renderRolloutForm(w, r, http.StatusOK, "", defaultRolloutForm())
}

func (s *Server) renderRolloutForm(w http.ResponseWriter, r *http.Request, status int, errMsg string, f rolloutForm) {
	ctx := r.Context()
	hosts, err := s.allHosts(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	groups, err := s.st.ListGroups(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d := s.page(r, s.l.T("rollout.new"), "rollouts")
	d.Error = errMsg
	d.Data = map[string]any{"Form": f, "Hosts": hosts, "Groups": groups,
		"JobTypes": []string{protocol.JobUpgradeSecurity, protocol.JobUpgradeAll, protocol.JobUpgradePackages},
		"Orders":   []string{rollout.OrderScoreDesc, rollout.OrderScoreAsc, rollout.OrderHostname}}
	s.render(w, r, status, "rolloutnew", d)
}

func (s *Server) rolloutCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_ = r.ParseForm()
	in := func(k string) string { return strings.TrimSpace(r.PostFormValue(k)) }
	f := defaultRolloutForm()
	f.Name, f.JobType, f.Packages, f.Target, f.Strategy, f.Order = in("name"), in("job_type"), in("packages"), in("target"), in("strategy"), in("order")
	f.GroupID, _ = strconv.ParseInt(in("group_id"), 10, 64)
	f.RequireHealth, f.PauseAfterCanary = r.PostFormValue("require_health") == "1", r.PostFormValue("pause_after_canary") == "1"
	for _, id := range formIDs(r, "host_ids") {
		f.HostIDs[id] = true
	}
	for i := 0; i < maxRolloutGroups; i++ {
		f.StageGroups[i], _ = strconv.ParseInt(in("stage_group_"+strconv.Itoa(i)), 10, 64)
	}
	var bad []string
	num := func(key, label string, dst *int, lo, hi int) {
		v, err := strconv.Atoi(in(key))
		if err != nil || v < lo || v > hi {
			bad = append(bad, s.l.T("validation.range", "field", s.l.T(label), "min", lo, "max", hi))
			return
		}
		*dst = v
	}
	num("canary", "rollout.field.canary", &f.Canary, 0, 100)
	num("batch", "rollout.field.batch", &f.Batch, 0, 1000)
	num("max_parallel", "rollout.field.max_parallel", &f.MaxParallel, 1, 500)
	num("wait_minutes", "rollout.field.wait", &f.WaitMinutes, 0, 1440)
	num("max_failure_pct", "rollout.field.max_failure", &f.MaxFailurePct, 0, 100)
	num("job_timeout_minutes", "rollout.field.job_timeout", &f.JobTimeoutMinutes, 10, 1440)
	if f.Name == "" || utf8.RuneCountInString(f.Name) > 100 {
		bad = append(bad, s.l.T("validation.required", "field", s.l.T("rollout.field.name")))
	}
	if !isPackageJobType(f.JobType) {
		bad = append(bad, s.l.T("job.error.invalid_type"))
	}
	var pkgs []string
	if f.JobType == protocol.JobUpgradePackages {
		for _, p := range strings.FieldsFunc(f.Packages, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t' }) {
			if !protocol.ValidPackageName(p) {
				bad = append(bad, s.l.T("job.error.invalid_package", "package", p))
				continue
			}
			pkgs = append(pkgs, p)
		}
		if len(pkgs) == 0 {
			bad = append(bad, s.l.T("job.error.no_packages"))
		}
	}
	if f.Order != rollout.OrderHostname && f.Order != rollout.OrderScoreAsc && f.Order != rollout.OrderScoreDesc {
		f.Order = rollout.OrderHostname
	}
	if len(bad) > 0 {
		s.renderRolloutForm(w, r, http.StatusBadRequest, strings.Join(bad, " "), f)
		return
	}
	// Hosts in scope, ordered.
	all, err := s.allHosts(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	rollout.SortHosts(all, f.Order)
	member := func(gid int64) map[int64]bool {
		out := map[int64]bool{}
		for _, h := range all {
			for _, g := range h.Groups {
				if g.ID == gid {
					out[h.ID] = true
				}
			}
		}
		return out
	}
	var stages [][]int64
	switch f.Strategy {
	case "groups":
		var groups [][]int64
		for _, gid := range f.StageGroups {
			if gid <= 0 {
				continue
			}
			in := member(gid)
			var ids []int64
			for _, h := range all {
				if in[h.ID] {
					ids = append(ids, h.ID)
				}
			}
			groups = append(groups, ids)
		}
		stages = rollout.PlanGroups(groups, f.Canary)
	default:
		f.Strategy = "batches"
		var ids []int64
		var in map[int64]bool
		if f.Target == "group" {
			in = member(f.GroupID)
		}
		for _, h := range all {
			switch {
			case f.Target == "group" && !in[h.ID]:
			case f.Target == "hosts" && !f.HostIDs[h.ID]:
			default:
				ids = append(ids, h.ID)
			}
		}
		stages = rollout.PlanBatches(ids, f.Canary, f.Batch)
	}
	if len(stages) == 0 {
		s.renderRolloutForm(w, r, http.StatusBadRequest, s.l.T("rollout.error.no_hosts"), f)
		return
	}
	canary := f.Canary
	if canary > 0 && len(stages) < 2 {
		canary = 0 // a canary that is the whole rollout is just one stage
	}
	ro := store.Rollout{Name: f.Name, JobType: f.JobType, Packages: pkgs, Canary: canary, MaxParallel: f.MaxParallel, WaitMinutes: f.WaitMinutes,
		MaxFailurePct: f.MaxFailurePct, RequireHealth: f.RequireHealth, PauseAfterCanary: f.PauseAfterCanary && canary > 0,
		JobTimeoutMinutes: f.JobTimeoutMinutes, CreatedByID: sessionFrom(r).user.ID}
	id, err := s.st.CreateRollout(ctx, ro, stages)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	total := 0
	for _, st := range stages {
		total += len(st)
	}
	s.audit(r, "rollout.create", f.Name, "rollout_id="+strconv.FormatInt(id, 10)+" type="+f.JobType+" hosts="+strconv.Itoa(total)+" stages="+strconv.Itoa(len(stages)))
	// Start the first stage now instead of at the next minute.
	s.rolloutRunner().Tick(ctx, timeutil.Now())
	s.redirect(w, r, "/rollouts/"+strconv.FormatInt(id, 10), "success", s.l.T("rollout.created"))
}

func (s *Server) rolloutOr404(w http.ResponseWriter, r *http.Request) (store.Rollout, bool) {
	id, ok := pathID(r)
	if !ok {
		s.errorPage(w, r, http.StatusNotFound, "error.not_found")
		return store.Rollout{}, false
	}
	ro, err := s.st.RolloutByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, r, http.StatusNotFound, "error.not_found")
		return ro, false
	}
	if err != nil {
		s.serverError(w, r, err)
		return ro, false
	}
	return ro, true
}

// rolloutStage is one stage on the detail page.
type rolloutStage struct {
	Index int
	Hosts []store.RolloutHost
}

func (s *Server) rolloutDetail(w http.ResponseWriter, r *http.Request) {
	ro, ok := s.rolloutOr404(w, r)
	if !ok {
		return
	}
	hosts, err := s.st.RolloutHosts(r.Context(), ro.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	stages := make([]rolloutStage, ro.Stages)
	for i := range stages {
		stages[i].Index = i
	}
	for _, h := range hosts {
		if h.Stage >= 0 && h.Stage < len(stages) {
			stages[h.Stage].Hosts = append(stages[h.Stage].Hosts, h)
		}
	}
	d := s.page(r, ro.Name, "rollouts")
	d.Data = map[string]any{"R": ro, "Stages": stages}
	s.render(w, r, http.StatusOK, "rollout", d)
}

func (s *Server) rolloutAction(w http.ResponseWriter, r *http.Request) {
	ro, ok := s.rolloutOr404(w, r)
	if !ok {
		return
	}
	back := "/rollouts/" + strconv.FormatInt(ro.ID, 10)
	action := r.PathValue("action")
	runner := s.rolloutRunner()
	var err error
	switch {
	case action == "pause" && ro.Status == store.RolloutRunning:
		err = runner.Pause(r.Context(), ro)
	case action == "resume" && (ro.Status == store.RolloutPaused || ro.Status == store.RolloutFailed):
		err = runner.Resume(r.Context(), ro)
		if err == nil {
			runner.Tick(r.Context(), timeutil.Now())
		}
	case action == "cancel" && ro.Active() || action == "cancel" && ro.Status == store.RolloutFailed:
		err = runner.Cancel(r.Context(), ro, timeutil.Now())
	default:
		s.redirect(w, r, back, "error", s.l.T("rollout.error.action"))
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "rollout."+action, ro.Name, "rollout_id="+strconv.FormatInt(ro.ID, 10))
	s.redirect(w, r, back, "success", s.l.T("rollout.done_"+action))
}
