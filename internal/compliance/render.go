package compliance

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"netio.patchman/internal/i18n"
	"netio.patchman/internal/timeutil"
)

// Renderer turns stored keys and values into text in one language.
type Renderer struct {
	L i18n.Localizer
	F timeutil.Formatter
}

// Text renders a stored text.
func (r Renderer) Text(t Text) string {
	keys := make([]string, 0, len(t.Params))
	for k := range t.Params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	args := make([]any, 0, 2*len(keys))
	for _, k := range keys {
		v := t.Params[k]
		switch k {
		case "pct":
			v = r.Decimal(v)
		case "type":
			v = r.L.T("compliance.manual." + v)
		case "date":
			if d, err := time.Parse(time.RFC3339, v); err == nil {
				v = r.F.DateTime(d)
			}
		}
		args = append(args, k, v)
	}
	return r.L.T(t.Key, args...)
}

// Decimal replaces the decimal point with the locale's separator.
func (r Renderer) Decimal(v string) string {
	return strings.Replace(v, ".", r.L.T("number.decimal"), 1)
}

// Outcome is the label of an outcome.
func (r Renderer) Outcome(o string) string { return r.L.T("compliance.outcome." + o) }

// Review is the label of a review status.
func (r Renderer) Review(s string) string { return r.L.T("compliance.review." + s) }

// Platform is the label of a platform.
func (r Renderer) Platform(p string) string { return r.L.T("compliance.platform." + p) }

// Kind is the label of an evidence kind.
func (r Renderer) Kind(k string) string { return r.L.T("compliance.kind." + k) }

// Relevance is the label of a relevance.
func (r Renderer) Relevance(k string) string { return r.L.T("compliance.relevance." + k) }

// ProfileName is the name of a profile.
func (r Renderer) ProfileName(id string) string { return r.L.T("compliance.profile." + id) }

// CheckName is the name of a check.
func (r Renderer) CheckName(id string) string { return r.L.T("compliance.check." + id) }

// CheckLabel is the name of a check with its platforms.
func (r Renderer) CheckLabel(check string, platforms []string) string {
	name := r.CheckName(check)
	if len(platforms) == 0 {
		return name
	}
	var ps []string
	for _, p := range platforms {
		ps = append(ps, r.Platform(p))
	}
	return name + " (" + strings.Join(ps, ", ") + ")"
}

// ControlTitle is the title of a control.
func (r Renderer) ControlTitle(profile, id string) string {
	return r.L.T(Control{ID: id}.TitleKey(profile))
}

// ControlDesc is the description of a control.
func (r Renderer) ControlDesc(profile, id string) string {
	return r.L.T(Control{ID: id}.DescKey(profile))
}

// ControlRef is "profile name · CONTROL-ID" for a "profile:control" key.
func (r Renderer) ControlRef(key string) string {
	p, c, _ := strings.Cut(key, ":")
	return r.ProfileName(p) + " · " + c
}

// Metric renders a metric as name and value.
func (r Renderer) Metric(m Metric) (string, string) {
	name := r.L.T("compliance.metric." + m.Key)
	switch m.Unit {
	case UnitPercent:
		return name, r.Decimal(strconv.FormatFloat(m.Value, 'f', 1, 64)) + " %"
	case UnitDays:
		return name, r.L.T("compliance.unit.days", "n", r.Decimal(strconv.FormatFloat(m.Value, 'f', 1, 64)))
	}
	return name, strconv.FormatFloat(m.Value, 'f', 0, 64)
}

// Number formats a float with one decimal in the locale.
func (r Renderer) Number(v float64) string {
	return r.Decimal(strconv.FormatFloat(v, 'f', 1, 64))
}

// Disclaimer is the fixed statement every report carries.
func (r Renderer) Disclaimer() string { return r.L.T("compliance.disclaimer") }
