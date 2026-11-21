package web

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"netio.patchman/internal/store"
)

// ---------- host groups ----------

func (s *Server) groups(w http.ResponseWriter, r *http.Request) {
	s.renderGroups(w, r, http.StatusOK, "", map[string]string{})
}

func (s *Server) renderGroups(w http.ResponseWriter, r *http.Request, status int, errMsg string, form map[string]string) {
	list, err := s.st.ListGroups(r.Context())
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d := s.page(r, s.l.T("nav.groups"), "groups")
	d.Error = errMsg
	d.Data = map[string]any{"Groups": list, "Form": form}
	s.render(w, r, status, "groups", d)
}

// validateGroup returns a Turkish validation message or "".
func (s *Server) validateGroup(name, description string) string {
	if name == "" {
		return s.l.T("validation.required", "field", s.l.T("group.field.name"))
	}
	if utf8.RuneCountInString(name) > store.MaxGroupName || utf8.RuneCountInString(description) > 500 {
		return s.l.T("group.error.length", "max", store.MaxGroupName)
	}
	return ""
}

func (s *Server) groupCreate(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PostFormValue("name"))
	desc := strings.TrimSpace(r.PostFormValue("description"))
	form := map[string]string{"name": name, "description": desc}
	if msg := s.validateGroup(name, desc); msg != "" {
		s.renderGroups(w, r, http.StatusBadRequest, msg, form)
		return
	}
	id, err := s.st.CreateGroup(r.Context(), name, desc)
	if errors.Is(err, store.ErrDuplicate) {
		s.renderGroups(w, r, http.StatusConflict, s.l.T("group.error.duplicate", "name", name), form)
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "group.create", name, "group_id="+strconv.FormatInt(id, 10))
	s.redirect(w, r, "/groups/"+strconv.FormatInt(id, 10), "success", s.l.T("group.created", "name", name))
}

func (s *Server) groupOr404(w http.ResponseWriter, r *http.Request) (store.HostGroup, bool) {
	id, ok := pathID(r)
	if !ok {
		s.errorPage(w, r, http.StatusNotFound, "error.not_found")
		return store.HostGroup{}, false
	}
	g, err := s.st.GroupByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, r, http.StatusNotFound, "error.not_found")
		return g, false
	}
	if err != nil {
		s.serverError(w, r, err)
		return g, false
	}
	return g, true
}

func (s *Server) group(w http.ResponseWriter, r *http.Request) {
	g, ok := s.groupOr404(w, r)
	if !ok {
		return
	}
	pg := pageNumber(r)
	hosts, total, err := s.st.ListHosts(r.Context(), store.HostFilter{GroupID: g.ID, OfflineAfter: s.offlineAfter()}, store.Page{Number: pg, Size: pageSize})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	sev, kev, err := s.st.SeverityCountsFor(r.Context(), g.ID)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d := s.page(r, g.Name, "groups")
	d.Data = map[string]any{"G": g, "Hosts": hosts, "Pager": newPager(r, pg, total), "Sev": sev, "KEV": kev}
	s.render(w, r, http.StatusOK, "group", d)
}

func (s *Server) groupUpdate(w http.ResponseWriter, r *http.Request) {
	g, ok := s.groupOr404(w, r)
	if !ok {
		return
	}
	back := "/groups/" + strconv.FormatInt(g.ID, 10)
	name := strings.TrimSpace(r.PostFormValue("name"))
	desc := strings.TrimSpace(r.PostFormValue("description"))
	if msg := s.validateGroup(name, desc); msg != "" {
		s.redirect(w, r, back, "error", msg)
		return
	}
	err := s.st.UpdateGroup(r.Context(), g.ID, name, desc)
	if errors.Is(err, store.ErrDuplicate) {
		s.redirect(w, r, back, "error", s.l.T("group.error.duplicate", "name", name))
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "group.update", name, "group_id="+strconv.FormatInt(g.ID, 10)+" old_name="+g.Name)
	s.redirect(w, r, back, "success", s.l.T("common.saved"))
}

func (s *Server) groupDelete(w http.ResponseWriter, r *http.Request) {
	g, ok := s.groupOr404(w, r)
	if !ok {
		return
	}
	if err := s.st.DeleteGroup(r.Context(), g.ID); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "group.delete", g.Name, "group_id="+strconv.FormatInt(g.ID, 10))
	s.redirect(w, r, "/groups", "success", s.l.T("group.deleted", "name", g.Name))
}

// groupMembers adds or removes hosts selected on the servers or group page.
func (s *Server) groupMembers(w http.ResponseWriter, r *http.Request) {
	ids := formIDs(r, "host_ids")
	back := "/servers"
	if q := r.PostFormValue("back_query"); q != "" {
		back += "?" + q
	}
	if b := r.PostFormValue("back"); strings.HasPrefix(b, "/groups/") {
		back = b
	}
	gid, err := strconv.ParseInt(r.PostFormValue("group_id"), 10, 64)
	if err != nil || gid <= 0 {
		s.redirect(w, r, back, "error", s.l.T("group.error.none_selected"))
		return
	}
	g, err := s.st.GroupByID(r.Context(), gid)
	if errors.Is(err, store.ErrNotFound) {
		s.redirect(w, r, back, "error", s.l.T("group.error.none_selected"))
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	if len(ids) == 0 {
		s.redirect(w, r, back, "error", s.l.T("servers.bulk.none_selected"))
		return
	}
	var n int
	action, key := "group.add_hosts", "group.hosts_added"
	if r.PostFormValue("op") == "remove" {
		action, key = "group.remove_hosts", "group.hosts_removed"
		n, err = s.st.RemoveHostsFromGroup(r.Context(), g.ID, ids)
	} else {
		n, err = s.st.AddHostsToGroup(r.Context(), g.ID, ids)
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, action, g.Name, "group_id="+strconv.FormatInt(g.ID, 10)+" hosts="+strconv.Itoa(n))
	s.redirect(w, r, back, "success", s.l.T(key, "count", n, "name", g.Name))
}

// serverGroups replaces one host's group memberships (server info tab).
func (s *Server) serverGroups(w http.ResponseWriter, r *http.Request) {
	h, ok := s.hostOr404(w, r)
	if !ok {
		return
	}
	ids := formIDs(r, "group_ids")
	if err := s.st.SetHostGroups(r.Context(), h.ID, ids); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "host.groups", h.Hostname, "groups="+strconv.Itoa(len(ids)))
	s.redirect(w, r, "/servers/"+strconv.FormatInt(h.ID, 10)+"?tab=info", "success", s.l.T("common.saved"))
}
