package store

import (
	"context"
	"testing"
	"time"
)

func TestPlatformOf(t *testing.T) {
	for _, c := range []struct{ id, name, ver, want string }{
		{"ubuntu", "Ubuntu", "24.04", PlatformLinux},
		{"windows", "Windows Server 2022 Standard", "10.0.20348", PlatformWindowsServer},
		{"windows", "Windows Server 2019 Datacenter (Server Core)", "10.0.17763", PlatformWindowsServer},
		{"windows", "Windows 11 Pro", "10.0.22631", PlatformWindows11},
		{"windows", "Windows 10 Pro", "10.0.22631", PlatformWindows11}, // old agents
		{"windows", "Windows 10 Enterprise", "10.0.19045", PlatformWindows10},
		{"windows", "Windows 8.1 Pro", "6.3.9600", PlatformWindowsOther},
	} {
		if got := PlatformOf(c.id, c.name, c.ver); got != c.want {
			t.Errorf("PlatformOf(%q, %q, %q) = %q, want %q", c.id, c.name, c.ver, got, c.want)
		}
	}
}

func TestEvidenceChain(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	populate(t, s)
	n, err := s.CollectEvidence(ctx, SLA{Critical: 15, High: 30}, BackupState{LastAt: time.Now().Add(-time.Hour)}, 5000)
	if err != nil || n == 0 {
		t.Fatalf("collect: %d %v", n, err)
	}
	// A second run adds nothing (cursors and the unique source reference).
	if again, err := s.CollectEvidence(ctx, SLA{Critical: 15, High: 30}, BackupState{LastAt: time.Now().Add(-time.Hour)}, 5000); err != nil || again != 0 {
		t.Fatalf("second collect: %d %v", again, err)
	}
	items, err := s.EvidenceItems(ctx, EvidenceFilter{})
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]int{}
	for _, it := range items {
		kinds[it.Kind]++
	}
	for _, k := range []string{EvidenceAudit, EvidenceBackup, EvidenceManual} {
		if kinds[k] == 0 {
			t.Errorf("no %s evidence: %v", k, kinds)
		}
	}
	if kinds[EvidenceUpdateJob]+kinds[EvidenceChangeJob] == 0 {
		t.Errorf("no job evidence: %v", kinds)
	}
	st, err := s.VerifyEvidence(ctx)
	if err != nil || !st.OK || st.Items != len(items) {
		t.Fatalf("verify: %+v %v", st, err)
	}

	check := func(name, reason string) {
		t.Helper()
		st, err := s.VerifyEvidence(ctx)
		if err != nil || st.OK || st.Reason != reason {
			t.Errorf("%s: %+v %v", name, st, err)
		}
	}
	// A changed item, a removed item and a removed last item are all found.
	if _, err := s.db.Exec(`UPDATE evidence_items SET subject = 'değişti' WHERE id = ?`, items[1].ID); err != nil {
		t.Fatal(err)
	}
	check("changed", "content")
	if _, err := s.db.Exec(`UPDATE evidence_items SET subject = ? WHERE id = ?`, items[1].Subject, items[1].ID); err != nil {
		t.Fatal(err)
	}
	if st, _ := s.VerifyEvidence(ctx); !st.OK {
		t.Fatalf("restored: %+v", st)
	}
	if _, err := s.db.Exec(`DELETE FROM evidence_items WHERE id = ?`, items[2].ID); err != nil {
		t.Fatal(err)
	}
	check("removed", "link")
}

func TestEvidenceTailAndPrune(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	var batch []EvidenceItem
	for i, ref := range []string{"a", "b", "c", "d"} {
		batch = append(batch, EvidenceItem{Kind: EvidenceManual, Source: SourceUser, SourceRef: "manual:" + ref, Subject: ref,
			OccurredAt: time.Unix(int64(1700000000+i), 0), Payload: `{"title":"` + ref + `"}`})
	}
	if n, err := s.AddEvidence(ctx, batch); err != nil || n != 4 {
		t.Fatalf("add: %d %v", n, err)
	}
	items, _ := s.EvidenceItems(ctx, EvidenceFilter{})

	// Items used by a final version survive the retention; the chain is
	// checked from the boundary on.
	rep, err := s.CreateComplianceReport(ctx, ComplianceReport{Title: "r", Profiles: []string{"general@1"}, From: time.Unix(1, 0), To: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	_, vid, err := s.AddReportVersion(ctx, ReportVersion{ReportID: rep, GeneratedAt: time.Now(), Engine: "1", Content: "{}", SHA256: "x"},
		[]ControlAssessment{{Profile: "general", Control: "GEN-01", Outcome: "partial", Applicable: true}},
		[]AssessmentEvidence{{Profile: "general", Control: "GEN-01", EvidenceID: items[1].ID, Relevance: "primary"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ReviewControl(ctx, vid, "general", "GEN-01", ReviewAccepted, "uygun", "a@example.test"); err != nil {
		t.Fatal(err)
	}
	if err := s.FinalizeVersion(ctx, vid, "a@example.test", "f"); err != nil {
		t.Fatal(err)
	}
	if err := s.ReviewControl(ctx, vid, "general", "GEN-01", ReviewGap, "", "a@example.test"); err != ErrReportFinal {
		t.Errorf("review of a final version: %v", err)
	}
	if err := s.DeleteComplianceReport(ctx, rep); err != ErrReportFinal {
		t.Errorf("delete of a report with a final version: %v", err)
	}
	if _, err := s.db.Exec(`UPDATE evidence_items SET collected_at = 1000 WHERE id <= ?`, items[2].ID); err != nil {
		t.Fatal(err)
	}
	// collected_at is part of the hash: rehash the moved items as if they had
	// been collected then.
	all, _ := s.EvidenceItems(ctx, EvidenceFilter{})
	prev := ""
	for _, e := range all {
		e.PrevSHA256 = prev
		e.SHA256 = evidenceHash(e)
		if _, err := s.db.Exec(`UPDATE evidence_items SET sha256 = ?, prev_sha256 = ? WHERE id = ?`, e.SHA256, e.PrevSHA256, e.ID); err != nil {
			t.Fatal(err)
		}
		prev = e.SHA256
	}
	if err := s.setSettingValue(ctx, keyEvidenceHead, prev); err != nil {
		t.Fatal(err)
	}
	if err := s.PruneEvidence(ctx, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	left, _ := s.EvidenceItems(ctx, EvidenceFilter{})
	if len(left) != 2 || left[0].ID != items[1].ID || left[1].ID != items[3].ID {
		t.Fatalf("after prune: %+v", left)
	}
	if st, err := s.VerifyEvidence(ctx); err != nil || !st.OK {
		t.Fatalf("verify after prune: %+v %v", st, err)
	}
	// Removing the newest item breaks the head.
	if _, err := s.db.Exec(`DELETE FROM evidence_items WHERE id = ?`, items[3].ID); err != nil {
		t.Fatal(err)
	}
	if st, _ := s.VerifyEvidence(ctx); st.OK || st.Reason != "head" {
		t.Errorf("tail removed: %+v", st)
	}
}
