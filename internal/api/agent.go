// Package api serves the agent API under /api/v1/agent/ and agent downloads.
package api

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"netio.patchman/internal/auth"
	"netio.patchman/internal/i18n"
	"netio.patchman/internal/notify"
	"netio.patchman/internal/protocol"
	"netio.patchman/internal/release"
	"netio.patchman/internal/scanner"
	"netio.patchman/internal/settings"
	"netio.patchman/internal/store"
)

// Options configures the agent API.
type Options struct {
	Store    *store.Store
	L        i18n.Localizer
	Logger   *slog.Logger
	Scanner  *scanner.Scanner
	Notifier *notify.Notifier
	// AgentDistDir holds the agent binaries (see package release).
	AgentDistDir string
	// Assets serves install-agent.sh and the systemd unit.
	Assets map[string][]byte
	// System supplies runtime configuration (X-Forwarded-For trust).
	System *settings.Live
	// Release is the agent version rolled out by automatic agent updates.
	Release release.Release
}

func (s *Server) trustProxy() bool { return s.o.System != nil && s.o.System.Get().TrustProxy }

// Automatic agent update limits.
const (
	// MaxConcurrentAgentUpdates bounds simultaneous agent downloads.
	MaxConcurrentAgentUpdates = 25
	// AgentUpdateRetryAfter delays a new attempt after a failed update.
	AgentUpdateRetryAfter = 6 * time.Hour
)

// maybeQueueAgentUpdate queues an agent_update job when automatic updates
// are enabled and the agent runs a different version than the server
// distributes. Failed attempts are retried after AgentUpdateRetryAfter.
func (s *Server) maybeQueueAgentUpdate(ctx context.Context, hostID int64, info protocol.HostInfo, cfg settings.Values) {
	rel := s.o.Release
	if !cfg.AgentAutoUpdate || !info.SelfUpdate || !rel.Outdated(info.AgentVersion, info.OSID, info.Arch) {
		return
	}
	st := s.o.Store
	if active, err := st.HasActiveJob(ctx, hostID, protocol.JobAgentUpdate); err != nil || active {
		return
	}
	status, finished, err := st.LastFinishedJob(ctx, hostID, protocol.JobAgentUpdate)
	if err != nil {
		return
	}
	if status != "" && status != protocol.JobSucceeded && status != protocol.JobCancelled && time.Since(finished) < AgentUpdateRetryAfter {
		return
	}
	// A successful update restarts the agent; give it time to come back with the new version.
	if status == protocol.JobSucceeded && time.Since(finished) < 10*time.Minute {
		return
	}
	if n, err := st.CountActiveJobs(ctx, protocol.JobAgentUpdate); err != nil || n >= MaxConcurrentAgentUpdates {
		return
	}
	params, ok := rel.JobParams(info.OSID, info.Arch)
	if !ok {
		return
	}
	id, err := st.CreateJob(ctx, hostID, protocol.JobAgentUpdate, nil, params, 0)
	if err != nil {
		s.o.Logger.Warn(s.o.L.T("log.api.failed"), slog.String("error", err.Error()))
		return
	}
	s.o.Logger.Info(s.o.L.T("log.api.agent_update_queued"), slog.Int64("job_id", id), slog.String("hostname", info.Hostname),
		slog.String("from", info.AgentVersion), slog.String("to", rel.Version))
}

// Server handles agent requests.
type Server struct {
	o       Options
	limiter *auth.Limiter
}

// New returns the agent API server.
func New(o Options) *Server {
	return &Server{o: o, limiter: auth.NewLimiter(10, 15*time.Minute)}
}

// Register mounts the routes on mux.
func (s *Server) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST "+protocol.PathRegister, s.register)
	mux.HandleFunc("POST "+protocol.PathCheckin, s.authed(s.checkin))
	mux.HandleFunc("POST "+protocol.PathReport, s.authed(s.report))
	mux.HandleFunc("POST "+protocol.PathJobResult, s.authed(s.jobResult))
	mux.HandleFunc("GET /downloads/agent/{file}", s.download)
	mux.HandleFunc("GET /downloads/{file}", s.asset)
}

func (s *Server) fail(w http.ResponseWriter, status int, code string, args ...any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(protocol.ErrorResponse{Code: code, Message: s.o.L.T("api.error."+code, args...)})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

// ClientIP returns the request's client address.
func ClientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first, _, _ := strings.Cut(xff, ",")
			return strings.TrimSpace(first)
		}
		if xr := r.Header.Get("X-Real-IP"); xr != "" {
			return strings.TrimSpace(xr)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func decodeBody(r *http.Request, limit int64, v any) error {
	var body io.Reader = http.MaxBytesReader(nil, r.Body, limit)
	if strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip") {
		zr, err := gzip.NewReader(body)
		if err != nil {
			return err
		}
		defer zr.Close()
		body = io.LimitReader(zr, limit*8)
	}
	dec := json.NewDecoder(body)
	return dec.Decode(v)
}

type ctxKey struct{}

func (s *Server) authed(h func(http.ResponseWriter, *http.Request, int64)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		ip := ClientIP(r, s.trustProxy())
		if s.limiter.Blocked("auth:" + ip) {
			s.fail(w, http.StatusTooManyRequests, "rate_limited")
			return
		}
		if !ok || token == "" {
			s.fail(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		id, err := s.o.Store.HostIDBySecret(r.Context(), auth.HashToken(strings.TrimSpace(token)))
		if errors.Is(err, store.ErrNotFound) {
			s.limiter.Fail("auth:" + ip)
			s.fail(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if err != nil {
			s.internal(w, err)
			return
		}
		h(w, r, id)
	}
}

func (s *Server) internal(w http.ResponseWriter, err error) {
	s.o.Logger.Error(s.o.L.T("log.api.failed"), slog.String("error", err.Error()))
	s.fail(w, http.StatusInternalServerError, "internal")
}

func ecosystemString(info protocol.HostInfo) string {
	return strings.Join(scanner.TargetFor(info).Ecosystems, "|")
}

func sanitizeHost(info *protocol.HostInfo) bool {
	info.Hostname = strings.TrimSpace(info.Hostname)
	if info.Hostname == "" || len(info.Hostname) > 253 {
		return false
	}
	if len(info.IPAddresses) > 64 {
		info.IPAddresses = info.IPAddresses[:64]
	}
	return true
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	ip := ClientIP(r, s.trustProxy())
	if s.limiter.Blocked("register:" + ip) {
		s.fail(w, http.StatusTooManyRequests, "rate_limited")
		return
	}
	var req protocol.RegisterRequest
	if err := decodeBody(r, 1<<20, &req); err != nil {
		s.fail(w, http.StatusBadRequest, "bad_request")
		return
	}
	if req.EnrollmentToken == "" || !sanitizeHost(&req.Host) {
		s.fail(w, http.StatusBadRequest, "bad_request")
		return
	}
	secret := auth.RandomToken(32)
	id, reenrolled, err := s.o.Store.RegisterHost(r.Context(), auth.HashToken(strings.TrimSpace(req.EnrollmentToken)), req.Host, ecosystemString(req.Host), auth.HashToken(secret))
	if errors.Is(err, store.ErrTokenInvalid) {
		s.limiter.Fail("register:" + ip)
		s.o.Logger.Warn(s.o.L.T("log.api.enroll_rejected"), slog.String("ip", ip), slog.String("hostname", req.Host.Hostname))
		s.fail(w, http.StatusForbidden, "invalid_token")
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	s.o.Logger.Info(s.o.L.T("log.api.enrolled"), slog.Int64("host_id", id), slog.String("hostname", req.Host.Hostname), slog.String("ip", ip), slog.Bool("reenrolled", reenrolled))
	_ = s.o.Store.Audit(r.Context(), store.AuditEntry{Action: "agent.enroll", Target: req.Host.Hostname, Details: "host_id=" + strconv.FormatInt(id, 10), IP: ip})
	s.o.Notifier.AgentEnrolled(r.Context(), id, req.Host.Hostname, reenrolled)
	writeJSON(w, protocol.RegisterResponse{HostID: id, AgentSecret: secret})
}

func (s *Server) checkin(w http.ResponseWriter, r *http.Request, hostID int64) {
	var req protocol.CheckinRequest
	if err := decodeBody(r, 1<<20, &req); err != nil || !sanitizeHost(&req.Host) {
		s.fail(w, http.StatusBadRequest, "bad_request")
		return
	}
	cfg, _ := settings.Load(r.Context(), s.o.Store)
	reportEvery := time.Duration(cfg.AgentReportMinutes) * time.Minute
	wasOffline, reportDue, err := s.o.Store.Checkin(r.Context(), hostID, req.Host, ecosystemString(req.Host), reportEvery)
	if err != nil {
		s.internal(w, err)
		return
	}
	if wasOffline {
		s.o.Notifier.AgentOnline(r.Context(), hostID, req.Host.Hostname)
	}
	s.maybeQueueAgentUpdate(r.Context(), hostID, req.Host, cfg)
	jobs, err := s.o.Store.DispatchJobs(r.Context(), hostID)
	if err != nil {
		s.internal(w, err)
		return
	}
	if err := s.attachExcludes(r.Context(), hostID, cfg, jobs); err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, protocol.CheckinResponse{
		Jobs:                   jobs,
		ReportRequested:        reportDue,
		CheckinIntervalSeconds: cfg.AgentCheckinSeconds,
		ReportIntervalSeconds:  cfg.AgentReportMinutes * 60,
	})
}

func (s *Server) report(w http.ResponseWriter, r *http.Request, hostID int64) {
	var rep protocol.Report
	if err := decodeBody(r, 16<<20, &rep); err != nil || !sanitizeHost(&rep.Host) {
		s.fail(w, http.StatusBadRequest, "bad_request")
		return
	}
	if len(rep.Packages) > 100000 || len(rep.Updates) > 50000 {
		s.fail(w, http.StatusRequestEntityTooLarge, "too_large")
		return
	}
	if len(rep.Errors) > 20 {
		rep.Errors = rep.Errors[:20]
	}
	if err := s.o.Store.SaveReport(r.Context(), hostID, rep, ecosystemString(rep.Host)); err != nil {
		s.internal(w, err)
		return
	}
	// Schedules with the reboot option restart hosts that still need it
	// after their update job, within the maintenance window.
	if rep.RebootRequired && rep.Host.RemoteUpdates {
		if id, err := s.o.Store.QueueScheduledReboot(r.Context(), hostID); err != nil {
			s.o.Logger.Warn(s.o.L.T("log.api.failed"), slog.String("error", err.Error()))
		} else if id != 0 {
			s.o.Logger.Info(s.o.L.T("log.schedule.reboot_queued"), slog.Int64("host_id", hostID), slog.String("hostname", rep.Host.Hostname), slog.Int64("job_id", id))
		}
	}
	s.o.Logger.Info(s.o.L.T("log.api.report"), slog.Int64("host_id", hostID), slog.String("hostname", rep.Host.Hostname),
		slog.Int("packages", len(rep.Packages)), slog.Int("updates", len(rep.Updates)))
	s.o.Scanner.Trigger()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) jobResult(w http.ResponseWriter, r *http.Request, hostID int64) {
	jobID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		s.fail(w, http.StatusBadRequest, "bad_request")
		return
	}
	var res protocol.JobResult
	if err := decodeBody(r, 2<<20, &res); err != nil {
		s.fail(w, http.StatusBadRequest, "bad_request")
		return
	}
	job, err := s.o.Store.CompleteJob(r.Context(), hostID, jobID, res)
	if errors.Is(err, store.ErrNotFound) {
		s.fail(w, http.StatusNotFound, "job_not_found")
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	s.o.Logger.Info(s.o.L.T("log.api.job_result"), slog.Int64("job_id", jobID), slog.String("hostname", job.Hostname),
		slog.String("status", job.Status), slog.Int("exit_code", job.ExitCode))
	// Run notification work without blocking the agent.
	go s.o.Notifier.JobFinished(context.WithoutCancel(r.Context()), job)
	w.WriteHeader(http.StatusNoContent)
}

// download serves agent binaries (protocol.AgentBinaryName, optional .sha256).
func (s *Server) download(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("file")
	if !validDistName(name) || s.o.AgentDistDir == "" {
		s.fail(w, http.StatusNotFound, "not_found")
		return
	}
	path := filepath.Join(s.o.AgentDistDir, name)
	f, err := os.Open(path)
	if err != nil {
		s.fail(w, http.StatusNotFound, "not_found")
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.IsDir() {
		s.fail(w, http.StatusNotFound, "not_found")
		return
	}
	if strings.HasSuffix(name, ".sha256") {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	} else {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	}
	http.ServeContent(w, r, name, st.ModTime(), f)
}

func validDistName(name string) bool {
	for _, p := range protocol.AgentPlatforms {
		bin := protocol.AgentBinaryName(p[0], p[1])
		if name == bin || name == bin+".sha256" {
			return true
		}
	}
	return false
}

func (s *Server) asset(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("file")
	data, ok := s.o.Assets[name]
	if !ok {
		s.fail(w, http.StatusNotFound, "not_found")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write(data)
}

// attachExcludes passes the host's effective exclusion list (fleet, groups,
// host) to package jobs; the agent leaves matching packages alone.
func (s *Server) attachExcludes(ctx context.Context, hostID int64, cfg settings.Values, jobs []protocol.Job) error {
	var list []string
	for i := range jobs {
		switch jobs[i].Type {
		case protocol.JobUpgradeAll, protocol.JobUpgradeSecurity, protocol.JobUpgradePackages:
		default:
			continue
		}
		if list == nil {
			raw, err := s.o.Store.HostExcludes(ctx, hostID)
			if err != nil {
				return err
			}
			own, _ := protocol.ParseExcludePatterns(raw)
			list, _ = protocol.ParseExcludePatterns(strings.Join(append(slices.Clone(cfg.UpdateExclude), own...), ","))
			if list == nil {
				list = []string{}
			}
		}
		if len(list) == 0 {
			return nil
		}
		if jobs[i].Params == nil {
			jobs[i].Params = map[string]string{}
		}
		jobs[i].Params[protocol.ParamExclude] = strings.Join(list, ",")
	}
	return nil
}
