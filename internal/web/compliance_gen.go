package web

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"netio.patchman/internal/compliance"
	"netio.patchman/internal/store"
	"netio.patchman/internal/timeutil"
)

// Report versions are generated in the background: for a large fleet and a
// long period, generating and storing a version takes longer than a reverse
// proxy waits for a response (BenchmarkGenerateLargeFleet: about 10 s for 500
// hosts over 12 months). The request waits up to genWait; a version that is
// not ready by then appears on the report page when it is.

const (
	defaultGenWait = 20 * time.Second
	maxParallelGen = 2 // generations running at once; more wait for a slot
)

var errGenBusy = errors.New("a version of this report is being generated")

type genJob struct {
	started time.Time
	by      string
	done    chan struct{}
	n       int   // version number, set when done
	err     error // set when done
}

type genState struct {
	mu   sync.Mutex
	jobs map[int64]*genJob // by report id: running, or finished with an error
	sem  chan struct{}
	wait time.Duration // <0: do not wait
}

func newGenState(wait time.Duration) *genState {
	if wait == 0 {
		wait = defaultGenWait
	}
	return &genState{jobs: map[int64]*genJob{}, sem: make(chan struct{}, maxParallelGen), wait: wait}
}

// genStatus reports whether a version of the report is being generated and
// the error of the last generation if it failed.
type genStatus struct {
	Running bool
	Started time.Time
	By      string
	Err     string
}

func (g *genState) status(reportID int64) genStatus {
	g.mu.Lock()
	defer g.mu.Unlock()
	j := g.jobs[reportID]
	if j == nil {
		return genStatus{}
	}
	select {
	case <-j.done:
		if j.err != nil {
			return genStatus{Started: j.started, By: j.by, Err: j.err.Error()}
		}
		return genStatus{}
	default:
		return genStatus{Running: true, Started: j.started, By: j.by}
	}
}

// startVersion generates and stores a new version of rep in the background
// and waits up to the configured time. It returns the version number when it
// finished in time and 0 when it is still running; errGenBusy when a
// generation of the report is already running. The audit entry is written
// when the version is stored; details gets the version number.
func (s *Server) startVersion(r *http.Request, rep store.ComplianceReport, prev []store.ControlAssessment, entry store.AuditEntry,
	details func(n int) string) (int, error) {
	g := s.gen
	u := sessionFrom(r).user
	g.mu.Lock()
	if j := g.jobs[rep.ID]; j != nil {
		select {
		case <-j.done:
		default:
			g.mu.Unlock()
			return 0, errGenBusy
		}
	}
	job := &genJob{started: timeutil.Now(), by: u.Email, done: make(chan struct{})}
	g.jobs[rep.ID] = job
	g.mu.Unlock()

	go func() {
		n, err := s.generateVersion(rep, prev, u.Email)
		g.mu.Lock()
		job.n, job.err = n, err
		if err == nil && g.jobs[rep.ID] == job {
			delete(g.jobs, rep.ID)
		}
		g.mu.Unlock()
		close(job.done)
		if err != nil {
			s.logger.Error(s.l.T("log.compliance.generate_failed"), slog.Int64("report_id", rep.ID), slog.String("error", err.Error()))
			return
		}
		entry.Details = details(n)
		if err := s.st.Audit(context.Background(), entry); err != nil {
			s.logger.Warn(s.l.T("log.audit.failed"), slog.String("error", err.Error()))
		}
	}()

	if g.wait < 0 {
		return 0, nil
	}
	select {
	case <-job.done:
		g.mu.Lock()
		defer g.mu.Unlock()
		return job.n, job.err
	case <-time.After(g.wait):
		return 0, nil
	case <-r.Context().Done():
		return 0, nil
	}
}

// generateVersion computes and stores one version (one slot of the
// semaphore). It runs outside the request, so it has its own context.
func (s *Server) generateVersion(rep store.ComplianceReport, prev []store.ControlAssessment, by string) (n int, err error) {
	s.gen.sem <- struct{}{}
	defer func() { <-s.gen.sem }()
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("compliance report %d: %v", rep.ID, p)
		}
	}()
	res, err := compliance.Generate(s.st, compliance.Request{Report: rep, GeneratedBy: by, Now: timeutil.Now(), Previous: prev})
	if err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	n, _, err = s.st.AddReportVersion(ctx, store.ReportVersion{ReportID: rep.ID, GeneratedAt: res.Report.GeneratedAt, GeneratedBy: by,
		Engine: compliance.EngineVersion, Content: res.Content, SHA256: res.SHA256}, res.Assessments, res.Mapping)
	return n, err
}

func reportURL(id int64, n int) string {
	u := "/compliance/reports/" + strconv.FormatInt(id, 10)
	if n > 0 {
		u += "?v=" + strconv.Itoa(n)
	}
	return u
}
