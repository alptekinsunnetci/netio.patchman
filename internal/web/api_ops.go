package web

import (
	"net/http"
	"strconv"
	"time"

	"netio.patchman/internal/store"
)

// apiDrift lists current deviations from server standards (scoped like the
// hosts): ?standard=, ?host=, ?group=, ?page=.
func (s *Server) apiDrift(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var f store.DriftFilter
	f.StandardID, _ = strconv.ParseInt(q.Get("standard"), 10, 64)
	f.HostID, _ = strconv.ParseInt(q.Get("host"), 10, 64)
	f.GroupID, _ = strconv.ParseInt(q.Get("group"), 10, 64)
	rows, total, err := s.st.ListDrift(r.Context(), f, store.Page{Number: pageNumber(r), Size: pageSize})
	if err != nil {
		s.apiError(w, http.StatusInternalServerError, "internal")
		return
	}
	type item struct {
		HostID      int64     `json:"host_id"`
		Hostname    string    `json:"hostname"`
		StandardID  int64     `json:"standard_id"`
		Standard    string    `json:"standard"`
		RuleID      int64     `json:"rule_id"`
		Kind        string    `json:"kind"`
		SubjectType string    `json:"subject_type"`
		Subject     string    `json:"subject"`
		Expected    string    `json:"expected"`
		Found       string    `json:"found"`
		FirstSeen   time.Time `json:"first_seen"`
		UpdateName  string    `json:"suggested_update,omitempty"`
	}
	out := make([]item, 0, len(rows))
	for _, d := range rows {
		x := item{HostID: d.HostID, Hostname: d.Hostname, StandardID: d.StandardID, Standard: d.Standard, RuleID: d.Rule.ID, Kind: d.Rule.Kind,
			SubjectType: d.Rule.SubjectType, Subject: d.Rule.Subject, Expected: d.Rule.Value, Found: d.Found, FirstSeen: d.FirstSeen.UTC()}
		if d.HasUpdate {
			x.UpdateName = d.UpdateName
		}
		out = append(out, x)
	}
	s.apiJSON(w, http.StatusOK, map[string]any{"deviations": out, "pagination": apiPageOf(r, total)})
}

// apiRollouts lists rolling updates (fleet-wide, not for group-limited keys).
func (s *Server) apiRollouts(w http.ResponseWriter, r *http.Request) {
	if _, limited := store.ScopeFrom(r.Context()); limited {
		s.apiError(w, http.StatusForbidden, "forbidden")
		return
	}
	list, total, err := s.st.ListRollouts(r.Context(), store.Page{Number: pageNumber(r), Size: pageSize})
	if err != nil {
		s.apiError(w, http.StatusInternalServerError, "internal")
		return
	}
	type counts struct {
		Total     int `json:"total"`
		Pending   int `json:"pending"`
		Queued    int `json:"queued"`
		Succeeded int `json:"succeeded"`
		Failed    int `json:"failed"`
		Skipped   int `json:"skipped"`
	}
	type item struct {
		ID           int64      `json:"id"`
		Name         string     `json:"name"`
		JobType      string     `json:"job_type"`
		Packages     []string   `json:"packages"`
		Status       string     `json:"status"`
		Reason       string     `json:"reason,omitempty"`
		Stages       int        `json:"stages"`
		CurrentStage int        `json:"current_stage"`
		Hosts        counts     `json:"hosts"`
		CreatedBy    string     `json:"created_by"`
		CreatedAt    time.Time  `json:"created_at"`
		FinishedAt   *time.Time `json:"finished_at"`
	}
	out := make([]item, 0, len(list))
	for _, ro := range list {
		c := ro.Counts
		x := item{ID: ro.ID, Name: ro.Name, JobType: ro.JobType, Packages: nonNilStrings(ro.Packages), Status: ro.Status, Reason: ro.Reason,
			Stages: ro.Stages, CurrentStage: ro.CurrentStage, Hosts: counts{c.Total, c.Pending, c.Queued, c.Succeeded, c.Failed, c.Skipped},
			CreatedBy: ro.CreatedBy, CreatedAt: ro.CreatedAt.UTC()}
		if !ro.FinishedAt.IsZero() {
			t := ro.FinishedAt.UTC()
			x.FinishedAt = &t
		}
		out = append(out, x)
	}
	s.apiJSON(w, http.StatusOK, map[string]any{"rollouts": out, "pagination": apiPageOf(r, total)})
}

func nonNilStrings(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

// apiHostHealth returns a host's monitored checks and its latest resource
// snapshot (null before the first monitoring round).
func (s *Server) apiHostHealth(w http.ResponseWriter, r *http.Request) {
	h, ok := s.apiHostOr404(w, r)
	if !ok {
		return
	}
	states, err := s.st.HostHealthStates(r.Context(), h.ID)
	if err != nil {
		s.apiError(w, http.StatusInternalServerError, "internal")
		return
	}
	res, at, err := s.st.HostResources(r.Context(), h.ID)
	if err != nil {
		s.apiError(w, http.StatusInternalServerError, "internal")
		return
	}
	type check struct {
		Key       string    `json:"key"`
		CheckID   int64     `json:"check_id"`
		Name      string    `json:"name"`
		Type      string    `json:"type"`
		Builtin   bool      `json:"builtin"`
		OK        bool      `json:"ok"`
		Value     string    `json:"value"`
		Message   string    `json:"message"`
		Since     time.Time `json:"since"`
		CheckedAt time.Time `json:"checked_at"`
	}
	out := make([]check, 0, len(states))
	failing := 0
	for _, st := range states {
		out = append(out, check{Key: st.Key, CheckID: st.CheckID, Name: st.Name, Type: st.Type, Builtin: st.Builtin(), OK: st.OK, Value: st.Value,
			Message: st.Message, Since: st.Since.UTC(), CheckedAt: st.CheckedAt.UTC()})
		if !st.OK {
			failing++
		}
	}
	body := map[string]any{"host_id": h.ID, "hostname": h.Hostname, "failing": failing, "checks": out, "resources": res, "resources_at": nil}
	if res != nil {
		body["resources_at"] = at.UTC()
	}
	s.apiJSON(w, http.StatusOK, body)
}
