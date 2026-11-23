package web

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"netio.patchman/internal/eol"
	"netio.patchman/internal/settings"
	"netio.patchman/internal/store"
	"netio.patchman/internal/timeutil"
)

var (
	embeddedEOLOnce sync.Once
	embeddedEOL     eol.Data
)

// eolData returns the current support calendars.
func (s *Server) eolData() eol.Data {
	if s.o.EOL != nil {
		return s.o.EOL.Data()
	}
	embeddedEOLOnce.Do(func() { embeddedEOL = eol.Embedded() })
	return embeddedEOL
}

func (s *Server) eolWarn(ctx context.Context) time.Duration {
	v, _ := settings.Load(ctx, s.st)
	return v.EOLWarn()
}

// assessEOL evaluates the hosts the user may see (optionally one group).
func (s *Server) assessEOL(ctx context.Context, groupID int64) ([]eol.Item, error) {
	hosts, err := s.st.EOLHosts(ctx, groupID)
	if err != nil {
		return nil, err
	}
	return eol.Assess(s.eolData(), timeutil.Now(), s.eolWarn(ctx), eol.Inputs(hosts)), nil
}

// hostEOL evaluates one host: its operating system and the given software.
func (s *Server) hostEOL(ctx context.Context, h store.Host, sw []store.HostSoftwareRow) []eol.Item {
	in := eol.HostInput{ID: h.ID, Hostname: h.Hostname, OSID: h.OSID, OSVersionID: h.OSVersionID, OSName: h.OSName, Kernel: h.Kernel, PackageManager: h.PackageManager}
	for _, r := range sw {
		in.Software = append(in.Software, eol.SoftwareInput{Software: r.Software, Cycle: r.Cycle, Version: r.Version, PackageVersion: r.PackageVersion})
	}
	return eol.Assess(s.eolData(), timeutil.Now(), s.eolWarn(ctx), []eol.HostInput{in})
}

// osEOL returns the operating system item of a host, nil without a calendar.
func osEOL(items []eol.Item) *eol.Item {
	for i := range items {
		if items[i].Kind == eol.KindOS {
			return &items[i]
		}
	}
	return nil
}

// softwareEOL indexes software items by "software cycle".
func softwareEOL(items []eol.Item) map[string]eol.Item {
	out := map[string]eol.Item{}
	for _, it := range items {
		if it.Kind == eol.KindSoftware {
			out[it.Software+" "+it.Cycle] = it
		}
	}
	return out
}

// eolFilter is the EOL report's filter form.
type eolFilter struct {
	Kind, Status, Q string
	GroupID         int64
}

func eolFilterFrom(r *http.Request) eolFilter {
	q := r.URL.Query()
	f := eolFilter{Kind: q.Get("kind"), Status: q.Get("status"), Q: strings.TrimSpace(q.Get("q"))}
	if f.Kind != eol.KindOS && f.Kind != eol.KindSoftware {
		f.Kind = ""
	}
	switch f.Status {
	case "all", eol.StatusEOL, eol.StatusSoon, eol.StatusSupported, eol.StatusUnknown:
	default:
		f.Status = "" // out of support or ending soon
	}
	f.GroupID, _ = strconv.ParseInt(q.Get("group"), 10, 64)
	return f
}

func (f eolFilter) keep(g eol.Group) bool {
	if f.Kind != "" && g.Kind != f.Kind {
		return false
	}
	if f.Q != "" && !strings.Contains(strings.ToLower(g.Name+" "+g.Cycle), strings.ToLower(f.Q)) {
		return false
	}
	switch f.Status {
	case "":
		return g.Status == eol.StatusEOL || g.Status == eol.StatusSoon
	case "all":
		return true
	}
	return g.Status == f.Status
}

// eolTab fills the EOL report of the software page.
func (s *Server) eolTab(r *http.Request, data map[string]any) error {
	ctx := r.Context()
	f := eolFilterFrom(r)
	items, err := s.assessEOL(ctx, max(f.GroupID, 0))
	if err != nil {
		return err
	}
	var groups []eol.Group
	for _, g := range eol.GroupItems(items) {
		if f.keep(g) {
			groups = append(groups, g)
		}
	}
	allGroups, err := s.st.ListGroups(ctx)
	if err != nil {
		return err
	}
	v, _ := settings.Load(ctx, s.st)
	data["EOLGroups"], data["EOLSummary"], data["EOLFilter"], data["Groups"] = groups, eol.Summarize(items), f, allGroups
	data["EOLWarnDays"], data["EOLUpdatedAt"], data["EOLSource"] = v.EOLWarnDays, v.EOLUpdatedAt, s.sys().EOLURL != ""
	return nil
}

func (s *Server) apiEOL(w http.ResponseWriter, r *http.Request) {
	items, err := s.assessEOL(r.Context(), 0)
	if err != nil {
		s.apiError(w, http.StatusInternalServerError, "internal")
		return
	}
	type item struct {
		HostID          int64      `json:"host_id"`
		Hostname        string     `json:"hostname"`
		Kind            string     `json:"kind"`
		Software        string     `json:"software,omitempty"`
		Name            string     `json:"name"`
		Product         string     `json:"product"`
		Cycle           string     `json:"cycle"`
		Via             string     `json:"via,omitempty"`
		Status          string     `json:"status"`
		EOL             *time.Time `json:"eol"`
		DistroSupported bool       `json:"distro_supported"`
	}
	out := make([]item, 0, len(items))
	for _, it := range items {
		x := item{HostID: it.HostID, Hostname: it.Hostname, Kind: it.Kind, Software: it.Software, Name: it.Name, Product: it.Product,
			Cycle: it.Cycle, Via: it.Via, Status: it.Status, DistroSupported: it.DistroSupported}
		if !it.Release.EOL.IsZero() {
			d := it.Release.EOL
			x.EOL = &d
		}
		out = append(out, x)
	}
	s.apiJSON(w, http.StatusOK, map[string]any{"items": out})
}
