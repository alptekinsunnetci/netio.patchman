package store

import (
	"context"
	"testing"
	"time"

	"netio.patchman/internal/protocol"
)

func TestHostCapabilities(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	if _, err := s.CreateEnrollmentToken(ctx, "t", "tok", "p", 0, time.Time{}, 0); err != nil {
		t.Fatal(err)
	}
	info := protocol.HostInfo{Hostname: "web-01", MachineID: "m1", OSID: "debian",
		Capabilities: []string{protocol.CapHealth, "BAD cap", protocol.CapHealth, protocol.CapPreview}}
	id, _, err := s.RegisterHost(ctx, "tok", info, "", "secret")
	if err != nil {
		t.Fatal(err)
	}
	// Registration does not store capabilities; the first check-in does.
	if err := s.SaveReport(ctx, id, protocol.Report{Host: info}, ""); err != nil {
		t.Fatal(err)
	}
	h, err := s.HostByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Capabilities) != 2 || !h.Supports(protocol.CapHealth) || !h.Supports(protocol.CapPreview) || h.Supports(protocol.CapRollback) {
		t.Errorf("capabilities: %v", h.Capabilities)
	}
	// An agent without the field (before 0.10.0) supports nothing optional.
	info.Capabilities = nil
	if _, _, err := s.Checkin(ctx, id, info, "", time.Hour); err != nil {
		t.Fatal(err)
	}
	h, _ = s.HostByID(ctx, id)
	if len(h.Capabilities) != 0 || h.Supports(protocol.CapHealth) {
		t.Errorf("old agent capabilities: %v", h.Capabilities)
	}
}
