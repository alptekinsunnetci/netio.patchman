package web

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"netio.patchman/internal/drift"
	"netio.patchman/internal/protocol"
	"netio.patchman/internal/software"
	"netio.patchman/internal/store"
)

// emptyRuleRows is how many blank rule rows the standard form offers.
const emptyRuleRows = 5

func (s *Server) standards(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	data := map[string]any{"Tab": q.Get("tab")}
	if q.Get("tab") == "drift" {
		sid, _ := strconv.ParseInt(q.Get("standard"), 10, 64)
		gid, _ := strconv.ParseInt(q.Get("group"), 10, 64)
		f := store.DriftFilter{StandardID: max(sid, 0), GroupID: max(gid, 0)}
		pg := pageNumber(r)
		rows, total, err := s.st.ListDrift(ctx, f, store.Page{Number: pg, Size: pageSize})
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		groups, err := s.st.ListGroups(ctx)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		data["Drift"], data["Filter"], data["Pager"], data["Groups"] = rows, f, newPager(r, pg, total), groups
	} else {
		data["Tab"] = "standards"
	}
	list, err := s.st.ListStandards(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	data["Standards"] = list
	d := s.page(r, s.l.T("nav.standards"), "standards")
	d.Data = data
	s.render(w, r, http.StatusOK, "standards", d)
}

// ruleRow is one editable rule on the form.
type ruleRow struct {
	store.StandardRule
	Index int
}

func (s *Server) renderStandardForm(w http.ResponseWriter, r *http.Request, status int, errMsg string, st store.Standard) {
	groups, err := s.st.ListGroups(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	var rows []ruleRow
	for i, ru := range st.Rules {
		rows = append(rows, ruleRow{StandardRule: ru, Index: i})
	}
	for i := 0; i < emptyRuleRows; i++ {
		rows = append(rows, ruleRow{StandardRule: store.StandardRule{SubjectType: drift.SubjectSoftware}, Index: len(st.Rules) + i})
	}
	title := s.l.T("standard.new")
	if st.ID != 0 {
		title = st.Name
	}
	d := s.page(r, title, "standards")
	d.Error = errMsg
	d.Data = map[string]any{"S": st, "Rows": rows, "Groups": groups, "Kinds": drift.Kinds, "Catalog": software.Catalog}
	s.render(w, r, status, "standard", d)
}

func (s *Server) standardNew(w http.ResponseWriter, r *http.Request) {
	s.renderStandardForm(w, r, http.StatusOK, "", store.Standard{Enabled: true})
}

func (s *Server) standardEdit(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		s.errorPage(w, r, http.StatusNotFound, "error.not_found")
		return
	}
	st, err := s.st.StandardByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, r, http.StatusNotFound, "error.not_found")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.renderStandardForm(w, r, http.StatusOK, "", st)
}

// standardForm reads the form; rule rows left empty are ignored.
func (s *Server) standardForm(r *http.Request, id int64) (store.Standard, string) {
	_ = r.ParseForm()
	in := func(k string) string { return strings.TrimSpace(r.PostFormValue(k)) }
	st := store.Standard{ID: id, Name: in("name"), Description: in("description"), Enabled: r.PostFormValue("enabled") == "1"}
	st.GroupID, _ = strconv.ParseInt(in("group_id"), 10, 64)
	if st.Name == "" || utf8.RuneCountInString(st.Name) > 100 {
		return st, s.l.T("validation.required", "field", s.l.T("standard.field.name"))
	}
	if st.GroupID > 0 {
		if _, err := s.st.GroupByID(r.Context(), st.GroupID); err != nil {
			return st, s.l.T("validation.required", "field", s.l.T("host.field.groups"))
		}
	}
	for i := 0; i < 200; i++ {
		k := strconv.Itoa(i)
		subject := in("subject_" + k)
		if _, ok := r.PostForm["kind_"+k]; !ok {
			break
		}
		if subject == "" || r.PostFormValue("delete_"+k) == "1" {
			continue
		}
		ru := store.StandardRule{Kind: in("kind_" + k), SubjectType: in("type_" + k), Subject: subject, Value: in("value_" + k)}
		ru.ID, _ = strconv.ParseInt(in("rule_"+k), 10, 64)
		if ru.SubjectType == drift.SubjectPackage && !protocol.ValidPackageName(ru.Subject) {
			return st, s.l.T("job.error.invalid_package", "package", ru.Subject)
		}
		if ru.Kind == drift.KindMinVersion && !protocol.ValidPackageVersion(ru.Value) {
			return st, s.l.T("standard.error.version", "value", ru.Value)
		}
		if !drift.Valid(drift.Rule{Kind: ru.Kind, SubjectType: ru.SubjectType, Subject: ru.Subject, Value: ru.Value}) {
			return st, s.l.T("standard.error.rule", "subject", ru.Subject)
		}
		st.Rules = append(st.Rules, ru)
	}
	if len(st.Rules) == 0 {
		return st, s.l.T("standard.error.no_rules")
	}
	return st, ""
}

func (s *Server) standardSave(w http.ResponseWriter, r *http.Request) {
	var id int64
	if v := r.PathValue("id"); v != "" {
		var ok bool
		if id, ok = pathID(r); !ok {
			s.errorPage(w, r, http.StatusNotFound, "error.not_found")
			return
		}
	}
	st, msg := s.standardForm(r, id)
	if msg != "" {
		s.renderStandardForm(w, r, http.StatusBadRequest, msg, st)
		return
	}
	newID, err := s.st.SaveStandard(r.Context(), st)
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, r, http.StatusNotFound, "error.not_found")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	action := "standard.update"
	if id == 0 {
		action = "standard.create"
	}
	s.audit(r, action, st.Name, "standard_id="+strconv.FormatInt(newID, 10)+" rules="+strconv.Itoa(len(st.Rules)))
	s.recheckDrift(r)
	s.redirect(w, r, "/standards?tab=drift&standard="+strconv.FormatInt(newID, 10), "success", s.l.T("standard.saved", "name", st.Name))
}

func (s *Server) standardDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		s.errorPage(w, r, http.StatusNotFound, "error.not_found")
		return
	}
	st, err := s.st.StandardByID(r.Context(), id)
	if err != nil {
		s.errorPage(w, r, http.StatusNotFound, "error.not_found")
		return
	}
	if err := s.st.DeleteStandard(r.Context(), id); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "standard.delete", st.Name, "standard_id="+strconv.FormatInt(id, 10))
	s.redirect(w, r, "/standards", "success", s.l.T("standard.deleted", "name", st.Name))
}

// recheckDrift evaluates the standards now so the report reflects a change;
// new deviations are notified by the next maintenance run.
func (s *Server) recheckDrift(r *http.Request) {
	if _, err := drift.Check(r.Context(), s.st); err != nil {
		s.logger.Warn(s.l.T("log.maintenance.failed"), "error", err.Error())
	}
}
