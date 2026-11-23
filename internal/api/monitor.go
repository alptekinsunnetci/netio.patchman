package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"

	"netio.patchman/internal/protocol"
	"netio.patchman/internal/settings"
	"netio.patchman/internal/store"
)

// monitorSchedule is the monitoring schedule sent with a check-in: the
// host's monitored checks every HealthMonitor minutes; nil when the agent
// cannot run it or monitoring is off.
func (s *Server) monitorSchedule(ctx context.Context, hostID int64, h protocol.HostInfo, cfg settings.Values) *protocol.HealthSchedule {
	if cfg.HealthMonitor <= 0 || !h.Supports(protocol.CapHealthMonitor) {
		return nil
	}
	checks, err := s.o.Store.MonitorChecksForHost(ctx, hostID)
	if err != nil {
		s.o.Logger.Warn(s.o.L.T("log.api.failed"), slog.String("error", err.Error()))
		return nil
	}
	return &protocol.HealthSchedule{IntervalSeconds: cfg.HealthMonitor * 60, Checks: checks}
}

// health stores a monitoring round and notifies checks that started failing
// (after store.MonitorFailures rounds) or recovered.
func (s *Server) health(w http.ResponseWriter, r *http.Request, hostID int64) {
	var st protocol.HealthStatus
	if err := decodeBody(r, 1<<20, &st); err != nil || len(st.Results) > protocol.MaxHealthChecks {
		s.fail(w, http.StatusBadRequest, "bad_request")
		return
	}
	host, err := s.o.Store.HostByID(r.Context(), hostID)
	if err != nil {
		s.internal(w, err)
		return
	}
	cfg, _ := settings.Load(r.Context(), s.o.Store)
	// Only results of checks that still apply to the host count.
	defs, err := s.o.Store.MonitorChecksForHost(r.Context(), hostID)
	if err != nil {
		s.internal(w, err)
		return
	}
	known := map[int64]protocol.HealthCheck{}
	for _, d := range defs {
		known[d.ID] = d
	}
	var results []store.MonitorResult
	for _, res := range st.Results {
		def, ok := known[res.ID]
		if !ok {
			continue
		}
		results = append(results, store.MonitorResult{Key: "c" + strconv.FormatInt(def.ID, 10), CheckID: def.ID, Name: def.Name, Type: def.Type,
			OK: res.OK, Value: res.Value, Message: res.Message})
	}
	if st.Resources != nil {
		st.Resources.Clean()
		results = append(results, BuiltinLimits(*st.Resources, cfg)...)
	}
	changes, err := s.o.Store.SaveMonitoring(r.Context(), hostID, st.Resources, results)
	if err != nil {
		s.internal(w, err)
		return
	}
	if len(changes) > 0 {
		limits := map[string]int{"disk": cfg.HealthDiskWarn, "memory": cfg.HealthMemoryWarn, "cpu": cfg.HealthCPUWarn}
		s.o.Notifier.HealthMonitor(r.Context(), hostID, host.Hostname, changes, limits)
	}
	w.WriteHeader(http.StatusNoContent)
}

// BuiltinLimits evaluates the snapshot against the built-in limits: every
// file system, memory and the load per core (Linux). A limit of 0 is off.
func BuiltinLimits(res protocol.Resources, cfg settings.Values) []store.MonitorResult {
	var out []store.MonitorResult
	pct := func(v float64) string { return fmt.Sprintf("%.0f%%", v) }
	if cfg.HealthDiskWarn > 0 {
		for _, d := range res.Disks {
			if d.Total <= 0 {
				continue
			}
			v := d.Percent()
			out = append(out, store.MonitorResult{Key: store.MonitorDiskPrefix + d.Path, Type: "disk", OK: v < float64(cfg.HealthDiskWarn), Value: pct(v)})
		}
	}
	if v := res.MemoryPercent(); cfg.HealthMemoryWarn > 0 && v >= 0 {
		out = append(out, store.MonitorResult{Key: store.MonitorMemory, Type: "memory", OK: v < float64(cfg.HealthMemoryWarn), Value: pct(v)})
	}
	if v := res.LoadPercent(); cfg.HealthCPUWarn > 0 && v >= 0 {
		out = append(out, store.MonitorResult{Key: store.MonitorCPU, Type: "cpu", OK: v < float64(cfg.HealthCPUWarn), Value: pct(v)})
	}
	return out
}
