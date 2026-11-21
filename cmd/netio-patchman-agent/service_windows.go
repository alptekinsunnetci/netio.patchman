//go:build windows

package main

import (
	"context"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/windows/svc"

	"netio.patchman/internal/agent"
	"netio.patchman/internal/brand"
)

// restartExitCode is returned to the service control manager after a
// self-update. The install script sets the recovery actions to "restart"
// and enables them for non-zero exit codes (sc failureflag), so the new
// binary starts a few seconds later.
const restartExitCode = 3

func platformMain(run func(ctx context.Context, logOut io.Writer) int) int {
	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		return run(ctx, os.Stdout)
	}
	h := &service{run: run}
	if err := svc.Run(brand.AgentBinary, h); err != nil {
		return 1
	}
	return h.code
}

type service struct {
	run  func(ctx context.Context, logOut io.Writer) int
	code int
}

// Execute implements svc.Handler.
func (h *service) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	log := openLog(filepath.Join(agent.DefaultStateDir, "agent.log"))
	defer log.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan int, 1)
	go func() { done <- h.run(ctx, log) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending, WaitHint: 30000}
				cancel()
				select {
				case h.code = <-done:
				case <-time.After(25 * time.Second):
				}
				return false, 0
			}
		case h.code = <-done:
			if h.code != 0 {
				// A service-specific exit code triggers the recovery actions.
				return true, uint32(h.code)
			}
			return false, 0
		}
	}
}

// maxLogSize is the size at which agent.log moves to agent.log.1.
const maxLogSize = 10 << 20

// rotatingLog is the service's log file (a service has no console).
type rotatingLog struct {
	mu   sync.Mutex
	path string
	f    *os.File
	size int64
}

func openLog(path string) *rotatingLog {
	l := &rotatingLog{path: path}
	l.open()
	return l
}

func (l *rotatingLog) open() {
	_ = os.MkdirAll(filepath.Dir(l.path), 0o700)
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		l.f = nil
		return
	}
	l.f = f
	if st, err := f.Stat(); err == nil {
		l.size = st.Size()
	}
}

func (l *rotatingLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f != nil && l.size+int64(len(p)) > maxLogSize {
		l.f.Close()
		_ = os.Remove(l.path + ".1")
		_ = os.Rename(l.path, l.path+".1")
		l.size = 0
		l.open()
	}
	if l.f == nil {
		return len(p), nil
	}
	n, err := l.f.Write(p)
	l.size += int64(n)
	return n, err
}

func (l *rotatingLog) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	return l.f.Close()
}
