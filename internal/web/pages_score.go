package web

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"netio.patchman/internal/score"
	"netio.patchman/internal/scoring"
	"netio.patchman/internal/settings"
	"netio.patchman/internal/store"
	"netio.patchman/internal/timeutil"
)

// hostScore shows a host's security score, its explanation and history.
func (s *Server) hostScore(w http.ResponseWriter, r *http.Request) {
	h, ok := s.hostOr404(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	sc, raw, err := s.st.HostScoreDetail(ctx, h.ID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.serverError(w, r, err)
		return
	}
	detail, computed := scoring.Detail(raw)
	to := calendarDay(timeutil.Now())
	from := to.AddDate(0, 0, -89)
	hist, err := s.st.HostScoreHistory(ctx, h.ID, from, to)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	v, _ := settings.Load(ctx, s.st)
	d := s.page(r, h.Hostname, "servers")
	d.Data = map[string]any{"Host": h, "Score": sc, "Detail": detail, "Computed": computed, "Trend": s.scoreTrend(hist, from, to),
		"Weights": v.ScoreWeights}
	s.render(w, r, http.StatusOK, "hostscore", d)
}

// scoreWeightRow is one weight on the settings form.
type scoreWeightRow struct {
	settings.ScoreWeight
	Field   string
	Value   float64
	Default float64
}

func (s *Server) scoreSettings(w http.ResponseWriter, r *http.Request) {
	v, err := settings.Load(r.Context(), s.st)
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	def := score.DefaultWeights()
	rows := make([]scoreWeightRow, 0, len(settings.ScoreWeights))
	for _, sw := range settings.ScoreWeights {
		rows = append(rows, scoreWeightRow{ScoreWeight: sw, Field: strings.ReplaceAll(sw.Key, ".", "_"), Value: *sw.Field(&v.ScoreWeights), Default: *sw.Field(&def)})
	}
	d := s.page(r, s.l.T("score.settings_title"), "settings")
	d.Data = map[string]any{"Rows": rows, "AlertBelow": v.ScoreAlertBelow}
	s.render(w, r, http.StatusOK, "scoresettings", d)
}

func (s *Server) scoreSettingsSave(w http.ResponseWriter, r *http.Request) {
	kv := map[string]string{}
	var bad []string
	if r.PostFormValue("reset") == "1" {
		keys := []string{settings.KeyScoreAlertBelow}
		for _, sw := range settings.ScoreWeights {
			keys = append(keys, sw.Key)
		}
		if err := s.st.DeleteSettings(r.Context(), keys...); err != nil {
			s.serverError(w, r, err)
			return
		}
		s.audit(r, "settings.update", "score", "reset=true")
		s.rescore(r.Context())
		s.redirect(w, r, "/settings/score", "success", s.l.T("score.settings_reset"))
		return
	}
	for _, sw := range settings.ScoreWeights {
		raw := strings.ReplaceAll(strings.TrimSpace(r.PostFormValue(strings.ReplaceAll(sw.Key, ".", "_"))), ",", ".")
		f, err := strconv.ParseFloat(raw, 64)
		if err != nil || f < 0 || f > sw.Max {
			bad = append(bad, s.l.T("validation.range", "field", s.l.T(sw.Label), "min", 0, "max", int(sw.Max)))
			continue
		}
		kv[sw.Key] = strconv.FormatFloat(f, 'f', -1, 64)
	}
	if n, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue("alert_below"))); err == nil && n >= 0 && n <= 100 {
		kv[settings.KeyScoreAlertBelow] = strconv.Itoa(n)
	} else {
		bad = append(bad, s.l.T("validation.range", "field", s.l.T("score.alert_below"), "min", 0, "max", 100))
	}
	if len(bad) > 0 {
		s.redirect(w, r, "/settings/score", "error", strings.Join(bad, " "))
		return
	}
	if err := s.st.SaveSettings(r.Context(), kv); err != nil {
		s.serverError(w, r, err)
		return
	}
	s.audit(r, "settings.update", "score", "")
	s.rescore(r.Context())
	s.redirect(w, r, "/settings/score", "success", s.l.T("score.settings_saved"))
}

// rescore recomputes the scores in the background after a settings change.
func (s *Server) rescore(ctx context.Context) {
	if s.o.Scores == nil {
		return
	}
	go func() { _ = s.o.Scores.Run(context.WithoutCancel(ctx), timeutil.Now()) }()
}

func (s *Server) apiHostScore(w http.ResponseWriter, r *http.Request) {
	h, ok := s.apiHostOr404(w, r)
	if !ok {
		return
	}
	sc, raw, err := s.st.HostScoreDetail(r.Context(), h.ID)
	if err != nil {
		s.apiError(w, http.StatusInternalServerError, "internal")
		return
	}
	detail, computed := scoring.Detail(raw)
	out := map[string]any{"host_id": h.ID, "hostname": h.Hostname, "score": nil, "band": score.Band(sc)}
	if computed {
		out["score"], out["deducted"], out["categories"] = sc, detail.Deducted, detail.Categories
	}
	s.apiJSON(w, http.StatusOK, out)
}
