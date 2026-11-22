package store

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"netio.patchman/internal/protocol"
)

// TestConcurrentWrites: simultaneous check-ins of one host dispatch every
// job exactly once, and parallel reports of many hosts all succeed.
func TestConcurrentWrites(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	host := registerHost(t, s, "c0")
	for i := 0; i < 20; i++ {
		if _, err := s.CreateJob(ctx, host, protocol.JobUpgradeSecurity, nil, nil, 0); err != nil {
			t.Fatal(err)
		}
	}
	var mu sync.Mutex
	seen := map[int64]int{}
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			jobs, err := s.DispatchJobs(ctx, host)
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			for _, j := range jobs {
				seen[j.ID]++
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	if len(seen) != 20 {
		t.Errorf("dispatched %d of 20 jobs", len(seen))
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("job %d dispatched %d times", id, n)
		}
	}

	var hosts []int64
	for i := 1; i <= 16; i++ {
		hosts = append(hosts, registerHost(t, s, fmt.Sprint("c", i)))
	}
	for _, id := range hosts {
		wg.Add(1)
		go func(id int64) {
			defer wg.Done()
			rep := protocol.Report{Host: protocol.HostInfo{Hostname: fmt.Sprint("h", id), MachineID: fmt.Sprint("c", id)}}
			for p := 0; p < 300; p++ {
				rep.Packages = append(rep.Packages, protocol.Package{Name: fmt.Sprint("pkg", p), Version: "1"})
			}
			for round := 0; round < 3; round++ {
				if err := s.SaveReport(ctx, id, rep, "Debian:12"); err != nil {
					t.Error(err)
					return
				}
				if _, err := s.ApplyFindings(ctx, id, []DetectedFinding{{CVEID: "CVE-2026-0001", PackageName: "pkg1", InstalledVersion: "1"}}); err != nil {
					t.Error(err)
					return
				}
			}
		}(id)
	}
	wg.Wait()
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM host_packages`).Scan(&n); err != nil || n != 16*300 {
		t.Errorf("packages: %d %v", n, err)
	}
}
