package web

import (
	"net/http"
	"sort"
	"strconv"
	"strings"

	"netio.patchman/internal/software"
	"netio.patchman/internal/store"
)

// softwareView is a catalog product with its fleet summary.
type softwareView struct {
	store.SoftwareSummary
	Def software.Def
}

// compareRow is one product release in the comparison of two hosts.
type compareRow struct {
	Software, Cycle string
	A, B            *store.HostSoftwareRow
}

// Same reports whether both hosts run the same package version.
func (c compareRow) Same() bool {
	return c.A != nil && c.B != nil && c.A.PackageVersion == c.B.PackageVersion
}

func (s *Server) softwarePage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	tab := q.Get("tab")
	data := map[string]any{"Tab": tab}
	switch tab {
	case "eol":
		if err := s.eolTab(r, data); err != nil {
			s.serverError(w, r, err)
			return
		}
	case "changes":
		host, _ := strconv.ParseInt(q.Get("host"), 10, 64)
		f := store.SoftwareEventFilter{HostID: max(host, 0), Software: q.Get("software"), Event: q.Get("event")}
		switch f.Event {
		case "", store.SoftwareInstalled, store.SoftwareRemoved, store.SoftwareUpgraded, store.SoftwareDowngraded:
		default:
			f.Event = ""
		}
		pg := pageNumber(r)
		events, total, err := s.st.ListSoftwareEvents(ctx, f, store.Page{Number: pg, Size: pageSize})
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		data["Events"], data["Filter"], data["Pager"], data["Catalog"] = events, f, newPager(r, pg, total), software.Catalog
	case "compare":
		hosts, err := s.allHosts(ctx)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		a, _ := strconv.ParseInt(q.Get("a"), 10, 64)
		b, _ := strconv.ParseInt(q.Get("b"), 10, 64)
		data["Hosts"], data["A"], data["B"] = hosts, a, b
		if a > 0 && b > 0 {
			ra, err := s.st.HostSoftware(ctx, a)
			if err != nil {
				s.serverError(w, r, err)
				return
			}
			rb, err := s.st.HostSoftware(ctx, b)
			if err != nil {
				s.serverError(w, r, err)
				return
			}
			data["Compare"] = compareSoftware(ra, rb)
		}
	default:
		data["Tab"] = "software"
		sums, err := s.st.SoftwareSummaries(ctx)
		if err != nil {
			s.serverError(w, r, err)
			return
		}
		cat, search := q.Get("category"), strings.ToLower(strings.TrimSpace(q.Get("q")))
		var rows []softwareView
		for _, sum := range sums {
			def, ok := software.ByID(sum.Software)
			if !ok || (cat != "" && def.Category != cat) || (search != "" && !strings.Contains(strings.ToLower(def.Name), search)) {
				continue
			}
			rows = append(rows, softwareView{SoftwareSummary: sum, Def: def})
		}
		sort.Slice(rows, func(i, j int) bool { return strings.ToLower(rows[i].Def.Name) < strings.ToLower(rows[j].Def.Name) })
		data["Rows"], data["Category"], data["Q"], data["Categories"] = rows, cat, q.Get("q"), softwareCategories()
	}
	d := s.page(r, s.l.T("nav.software"), "software")
	d.Data = data
	s.render(w, r, http.StatusOK, "software", d)
}

func softwareCategories() []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range software.Catalog {
		if !seen[d.Category] {
			seen[d.Category] = true
			out = append(out, d.Category)
		}
	}
	sort.Strings(out)
	return out
}

// compareSoftware lines up the products of two hosts by product and cycle.
func compareSoftware(a, b []store.HostSoftwareRow) []compareRow {
	idx := map[[2]string]*compareRow{}
	var keys [][2]string
	get := func(r store.HostSoftwareRow) *compareRow {
		k := [2]string{r.Software, r.Cycle}
		if c, ok := idx[k]; ok {
			return c
		}
		c := &compareRow{Software: r.Software, Cycle: r.Cycle}
		idx[k] = c
		keys = append(keys, k)
		return c
	}
	for i := range a {
		get(a[i]).A = &a[i]
	}
	for i := range b {
		get(b[i]).B = &b[i]
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i][0] != keys[j][0] {
			return keys[i][0] < keys[j][0]
		}
		return keys[i][1] < keys[j][1]
	})
	out := make([]compareRow, len(keys))
	for i, k := range keys {
		out[i] = *idx[k]
	}
	return out
}

func (s *Server) softwareDetail(w http.ResponseWriter, r *http.Request) {
	def, ok := software.ByID(r.PathValue("id"))
	if !ok {
		s.errorPage(w, r, http.StatusNotFound, "error.not_found")
		return
	}
	ctx := r.Context()
	all, err := s.st.SoftwareHosts(ctx, def.ID, "")
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	cycle := r.URL.Query().Get("cycle")
	counts := map[string]int{}
	var cycles []string
	var rows []store.HostSoftwareRow
	for _, h := range all {
		if counts[h.Cycle] == 0 {
			cycles = append(cycles, h.Cycle)
		}
		counts[h.Cycle]++
		if cycle == "" || h.Cycle == cycle {
			rows = append(rows, h)
		}
	}
	sort.Strings(cycles)
	events, _, err := s.st.ListSoftwareEvents(ctx, store.SoftwareEventFilter{Software: def.ID}, store.Page{Number: 1, Size: 10})
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	d := s.page(r, def.Name, "software")
	d.Data = map[string]any{"Def": def, "Rows": rows, "Cycles": cycles, "Counts": counts, "Cycle": cycle, "Total": len(all), "Events": events}
	s.render(w, r, http.StatusOK, "softwareitem", d)
}
