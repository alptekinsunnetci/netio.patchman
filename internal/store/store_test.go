package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"netio.patchman/internal/protocol"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), t.TempDir()+"/t.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestOSVRecordCompressedAndLegacy(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	rec := []byte(`{"id":"UBUNTU-CVE-2026-1","modified":"m1","details":"verbatim <text> ü"}` + strings.Repeat(" ", 5000))
	if err := s.SaveOSVRecord(ctx, "UBUNTU-CVE-2026-1", "m1", rec); err != nil {
		t.Fatal(err)
	}
	var stored int
	_ = s.db.QueryRow(`SELECT length(data) FROM osv_records WHERE id = 'UBUNTU-CVE-2026-1'`).Scan(&stored)
	if stored == 0 || stored >= len(rec)/4 {
		t.Errorf("stored %d bytes for %d", stored, len(rec))
	}
	mod, data, _, err := s.OSVRecord(ctx, "UBUNTU-CVE-2026-1")
	if err != nil || mod != "m1" || string(data) != string(rec) {
		t.Fatalf("round trip: %q %v %q", mod, err, data)
	}
	// Plain JSON cached by earlier versions.
	if _, err := s.db.Exec(`INSERT INTO osv_records (id, modified, fetched_at, data) VALUES ('CVE-2026-2', 'm2', 1, '{"id":"CVE-2026-2"}')`); err != nil {
		t.Fatal(err)
	}
	if _, data, _, err := s.OSVRecord(ctx, "CVE-2026-2"); err != nil || string(data) != `{"id":"CVE-2026-2"}` {
		t.Fatalf("legacy: %v %q", err, data)
	}
}

func TestNewDatabaseUsesIncrementalVacuum(t *testing.T) {
	s := openTest(t)
	var mode int
	if err := s.db.QueryRow("PRAGMA auto_vacuum").Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if mode != 2 {
		t.Fatalf("auto_vacuum = %d, want 2 (incremental)", mode)
	}
	if err := s.ReclaimSpace(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func registerHost(t *testing.T, s *Store, machineID string) int64 {
	t.Helper()
	ctx := context.Background()
	if _, err := s.CreateEnrollmentToken(ctx, "t", "hash-"+machineID, "npe_", 0, time.Time{}, 0); err != nil {
		t.Fatal(err)
	}
	id, _, err := s.RegisterHost(ctx, "hash-"+machineID, protocol.HostInfo{Hostname: "h-" + machineID, MachineID: machineID}, "Debian:12", "secret-"+machineID)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestFindingLifecycle(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	host := registerHost(t, s, "m1")
	f := DetectedFinding{CVEID: "CVE-2026-0001", PackageName: "openssl", InstalledVersion: "1", FixedVersion: "2"}

	if n, err := s.ApplyFindings(ctx, host, []DetectedFinding{f}); err != nil || n != 1 {
		t.Fatalf("new finding: %d %v", n, err)
	}
	if n, _ := s.ApplyFindings(ctx, host, []DetectedFinding{f}); n != 0 {
		t.Errorf("re-detection counted as new: %d", n)
	}
	rows, _, _ := s.ListFindings(ctx, FindingFilter{HostID: host}, Page{Number: 1})
	if len(rows) != 1 {
		t.Fatalf("rows: %+v", rows)
	}

	// Manual status survives re-detection.
	if err := s.SetFindingStatus(ctx, []int64{rows[0].ID}, StatusAcceptedRisk, "iç ağ", 0); err != nil {
		t.Fatal(err)
	}
	s.ApplyFindings(ctx, host, []DetectedFinding{f})
	rows, _, _ = s.ListFindings(ctx, FindingFilter{HostID: host, Status: "all"}, Page{Number: 1})
	if rows[0].Status != StatusAcceptedRisk {
		t.Errorf("manual status lost: %s", rows[0].Status)
	}

	// Not detected anymore: resolved. Detected again: reopened and counted as new.
	s.ApplyFindings(ctx, host, nil)
	rows, _, _ = s.ListFindings(ctx, FindingFilter{HostID: host, Status: "all"}, Page{Number: 1})
	if rows[0].Status != StatusResolved || rows[0].ResolvedAt.IsZero() {
		t.Errorf("not resolved: %+v", rows[0])
	}
	if n, _ := s.ApplyFindings(ctx, host, []DetectedFinding{f}); n != 1 {
		t.Errorf("reopen not counted: %d", n)
	}
	rows, _, _ = s.ListFindings(ctx, FindingFilter{HostID: host}, Page{Number: 1})
	if len(rows) != 1 || rows[0].Status != StatusOpen {
		t.Errorf("not reopened: %+v", rows)
	}
}

func TestEnrollmentTokenRules(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	info := protocol.HostInfo{Hostname: "a", MachineID: "same"}

	s.CreateEnrollmentToken(ctx, "once", "h-once", "p", 0, time.Time{}, 1)
	if _, _, err := s.RegisterHost(ctx, "h-once", info, "", "s1"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.RegisterHost(ctx, "h-once", info, "", "s2"); err != ErrTokenInvalid {
		t.Errorf("max uses not enforced: %v", err)
	}

	s.CreateEnrollmentToken(ctx, "expired", "h-exp", "p", 0, time.Now().Add(-time.Hour), 0)
	if _, _, err := s.RegisterHost(ctx, "h-exp", info, "", "s3"); err != ErrTokenInvalid {
		t.Errorf("expiry not enforced: %v", err)
	}

	id, _ := s.CreateEnrollmentToken(ctx, "revoked", "h-rev", "p", 0, time.Time{}, 0)
	s.RevokeEnrollmentToken(ctx, id)
	if _, _, err := s.RegisterHost(ctx, "h-rev", info, "", "s4"); err != ErrTokenInvalid {
		t.Errorf("revocation not enforced: %v", err)
	}

	// Same machine ID re-enrolls the existing host and rotates the secret.
	s.CreateEnrollmentToken(ctx, "multi", "h-multi", "p", 0, time.Time{}, 0)
	id2, re, err := s.RegisterHost(ctx, "h-multi", info, "", "s5")
	if err != nil || !re {
		t.Fatalf("re-enroll: %v %v", re, err)
	}
	if _, err := s.HostIDBySecret(ctx, "s1"); err != ErrNotFound {
		t.Error("old secret still valid after re-enrollment")
	}
	if got, _ := s.HostIDBySecret(ctx, "s5"); got != id2 {
		t.Error("new secret not active")
	}
}
