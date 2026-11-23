package web

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"netio.patchman/internal/protocol"
	"netio.patchman/internal/store"
)

func (s *Server) healthChecks(w http.ResponseWriter, r *http.Request) {
	s.renderHealthChecks(w, r, http.StatusOK, "", store.HealthCheckDef{
		HealthCheck: protocol.HealthCheck{Type: protocol.HealthHTTP, TimeoutSeconds: 10}, Scope: store.HealthScopeAll, WithUpdates: true, Monitor: true, Enabled: true})
}

func (s *Server) renderHealthChecks(w http.ResponseWriter, r *http.Request, status int, errMsg string, form store.HealthCheckDef) {
	ctx := r.Context()
	list, err := s.st.ListHealthChecks(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	groups, err := s.st.ListGroups(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	hosts, err := s.allHosts(ctx)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d := s.page(r, s.l.T("health.title"), "settings")
	d.Error = errMsg
	d.Data = map[string]any{"Checks": list, "Form": form, "Groups": groups, "Hosts": hosts,
		"Types": []string{protocol.HealthHTTP, protocol.HealthTCP, protocol.HealthService, protocol.HealthResources, protocol.HealthCommand}}
	s.render(w, r, status, "healthchecks", d)
}

// healthForm reads and validates the definition form; it returns a
// localized error message.
func (s *Server) healthForm(r *http.Request) (store.HealthCheckDef, string) {
	in := func(k string) string { return strings.TrimSpace(r.PostFormValue(k)) }
	num := func(k string, lo, hi int) (int, bool) {
		v := in(k)
		if v == "" {
			return 0, true
		}
		n, err := strconv.Atoi(v)
		return n, err == nil && n >= lo && n <= hi
	}
	c := store.HealthCheckDef{HealthCheck: protocol.HealthCheck{Name: in("name"), Type: in("type"), Target: in("target"), Contains: r.PostFormValue("contains"),
		Insecure: r.PostFormValue("insecure") == "1"}, Scope: in("scope"), WithUpdates: r.PostFormValue("with_updates") == "1", Monitor: r.PostFormValue("monitor") == "1", Enabled: r.PostFormValue("enabled") == "1"}
	c.GroupID, _ = strconv.ParseInt(in("group_id"), 10, 64)
	c.HostID, _ = strconv.ParseInt(in("host_id"), 10, 64)
	var ok [5]bool
	c.Expect, ok[0] = num("expect", 0, 599)
	c.CPU, ok[1] = num("cpu", 0, 1000)
	c.Memory, ok[2] = num("memory", 0, 100)
	c.Disk, ok[3] = num("disk", 0, 100)
	c.TimeoutSeconds, ok[4] = num("timeout_seconds", 1, 120)
	if c.TimeoutSeconds == 0 {
		c.TimeoutSeconds = 10
	}
	for _, p := range strings.FieldsFunc(r.PostFormValue("paths"), func(r rune) bool { return r == ',' || r == '\n' || r == '\r' }) {
		if p = strings.TrimSpace(p); p != "" && len(c.Paths) < 20 {
			c.Paths = append(c.Paths, p)
		}
	}
	switch {
	case c.Name == "" || len([]rune(c.Name)) > 100:
		return c, s.l.T("validation.required", "field", s.l.T("health.field.name"))
	case !ok[0] || !ok[1] || !ok[2] || !ok[3] || !ok[4]:
		return c, s.l.T("health.error.numbers")
	case len(c.Contains) > 200 || len(c.Target) > 500:
		return c, s.l.T("health.error.target", "type", s.l.T("health.type."+c.Type))
	}
	switch c.Type {
	case protocol.HealthHTTP:
		u, err := url.Parse(c.Target)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return c, s.l.T("health.error.target", "type", s.l.T("health.type.http"))
		}
	case protocol.HealthTCP:
		if host, port, err := net.SplitHostPort(c.Target); err != nil || host == "" || port == "" {
			return c, s.l.T("health.error.target", "type", s.l.T("health.type.tcp"))
		}
	case protocol.HealthService:
		if !protocol.ValidServiceName(c.Target) {
			return c, s.l.T("health.error.target", "type", s.l.T("health.type.service"))
		}
	case protocol.HealthCommand:
		if !protocol.ValidCommandName(c.Target) {
			return c, s.l.T("health.error.target", "type", s.l.T("health.type.command"))
		}
	case protocol.HealthResources:
		c.Target = ""
		if c.CPU == 0 && c.Memory == 0 && c.Disk == 0 {
			return c, s.l.T("health.error.resources")
		}
	default:
		return c, s.l.T("validation.required", "field", s.l.T("health.field.type"))
	}
	switch c.Scope {
	case store.HealthScopeAll:
	case store.HealthScopeGroup:
		if _, err := s.st.GroupByID(r.Context(), c.GroupID); err != nil {
			return c, s.l.T("validation.required", "field", s.l.T("host.field.groups"))
		}
	case store.HealthScopeHost:
		if _, err := s.st.HostByID(r.Context(), c.HostID); err != nil {
			return c, s.l.T("validation.required", "field", s.l.T("host.field.hostname"))
		}
	default:
		return c, s.l.T("validation.required", "field", s.l.T("health.field.scope"))
	}
	return c, ""
}

func (s *Server) healthCheckCreate(w http.ResponseWriter, r *http.Request) {
	c, msg := s.healthForm(r)
	if msg != "" {
		s.renderHealthChecks(w, r, http.StatusBadRequest, msg, c)
		return
	}
	id, err := s.st.CreateHealthCheck(r.Context(), c)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "health.create", c.Name, "id="+strconv.FormatInt(id, 10)+" type="+c.Type+" target="+c.Target)
	s.redirect(w, r, "/settings/health", "success", s.l.T("health.created", "name", c.Name))
}

func (s *Server) healthCheckEdit(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		s.errorPage(w, r, http.StatusNotFound, "error.not_found")
		return
	}
	c, err := s.st.HealthCheckByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, r, http.StatusNotFound, "error.not_found")
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.renderHealthChecks(w, r, http.StatusOK, "", c)
}

func (s *Server) healthCheckUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		s.errorPage(w, r, http.StatusNotFound, "error.not_found")
		return
	}
	c, msg := s.healthForm(r)
	c.ID = id
	if msg != "" {
		s.renderHealthChecks(w, r, http.StatusBadRequest, msg, c)
		return
	}
	if err := s.st.UpdateHealthCheck(r.Context(), c); errors.Is(err, store.ErrNotFound) {
		s.errorPage(w, r, http.StatusNotFound, "error.not_found")
		return
	} else if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "health.update", c.Name, "id="+strconv.FormatInt(id, 10)+" type="+c.Type+" target="+c.Target)
	s.redirect(w, r, "/settings/health", "success", s.l.T("health.updated", "name", c.Name))
}

func (s *Server) healthCheckDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		s.errorPage(w, r, http.StatusNotFound, "error.not_found")
		return
	}
	c, err := s.st.HealthCheckByID(r.Context(), id)
	if err != nil {
		s.errorPage(w, r, http.StatusNotFound, "error.not_found")
		return
	}
	if err := s.st.DeleteHealthCheck(r.Context(), id); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "health.delete", c.Name, "id="+strconv.FormatInt(id, 10))
	s.redirect(w, r, "/settings/health", "success", s.l.T("health.deleted", "name", c.Name))
}

// healthRow pairs a check's before and after result on the job page.
type healthRow struct {
	Name          string
	Before, After *protocol.HealthResult
}

// healthRows lines up the before and after results of a job.
func healthRows(rep *protocol.HealthReport) []healthRow {
	if rep == nil {
		return nil
	}
	idx := map[string]int{}
	var out []healthRow
	key := func(r protocol.HealthResult) string { return strconv.FormatInt(r.ID, 10) + "\x00" + r.Name }
	for i := range rep.Before {
		idx[key(rep.Before[i])] = len(out)
		out = append(out, healthRow{Name: rep.Before[i].Name, Before: &rep.Before[i]})
	}
	for i := range rep.After {
		if j, ok := idx[key(rep.After[i])]; ok {
			out[j].After = &rep.After[i]
			continue
		}
		out = append(out, healthRow{Name: rep.After[i].Name, After: &rep.After[i]})
	}
	return out
}
