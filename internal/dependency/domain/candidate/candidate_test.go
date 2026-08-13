package candidate

import (
	"testing"
	"time"

	"github.com/CyberT33N/dependency-authority/internal/dependency/domain/evidence"
)

const validDigest = "sha256:3b8f49c12b24cbbd6a4a0e6e2b2a4a4e8f0e1d2c3b4a59687766554433221100"

func newPending(t *testing.T) Candidate {
	t.Helper()
	candidate, err := New(EcosystemGo, "example.com/module", "v1.2.3", validDigest)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return candidate
}

func approvalEvidence(t *testing.T) evidence.Reference {
	t.Helper()
	reference, err := evidence.NewReference(evidence.TypeApproval, "approvals/1", validDigest, "approver", time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC), nil)
	if err != nil {
		t.Fatalf("NewReference() error = %v", err)
	}
	return reference
}

func scanEvidence(t *testing.T) evidence.Reference {
	t.Helper()
	reference, err := evidence.NewReference(evidence.TypeScan, "scans/1", validDigest, "scanner", time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC), nil)
	if err != nil {
		t.Fatalf("NewReference() error = %v", err)
	}
	return reference
}

func TestEcosystemValidity(t *testing.T) {
	for _, ecosystem := range []Ecosystem{EcosystemGo, EcosystemNPM, EcosystemPython} {
		if !ecosystem.Valid() {
			t.Errorf("Ecosystem(%q).Valid() = false, want true", ecosystem)
		}
	}
	if Ecosystem("ruby").Valid() {
		t.Error("Ecosystem(ruby).Valid() = true, want false")
	}
}

func TestNewRejectsInvalidIdentity(t *testing.T) {
	if _, err := New(Ecosystem("ruby"), "name", "v1", validDigest); err == nil {
		t.Fatal("New() error = nil, want unknown ecosystem error")
	}
	if _, err := New(EcosystemGo, " ", "v1", validDigest); err == nil {
		t.Fatal("New() error = nil, want empty name error")
	}
	if _, err := New(EcosystemGo, "name", "", validDigest); err == nil {
		t.Fatal("New() error = nil, want empty version error")
	}
	if _, err := New(EcosystemGo, "name", "v1", "not-a-digest"); err == nil {
		t.Fatal("New() error = nil, want digest error")
	}
}

func TestNewConstructsPendingCandidate(t *testing.T) {
	candidate := newPending(t)
	if candidate.State() != StatePending {
		t.Fatalf("State() = %q, want %q", candidate.State(), StatePending)
	}
	if candidate.Ecosystem() != EcosystemGo {
		t.Errorf("Ecosystem() = %q, want %q", candidate.Ecosystem(), EcosystemGo)
	}
	if candidate.Name() != "example.com/module" {
		t.Errorf("Name() = %q, want module path", candidate.Name())
	}
	if candidate.Version() != "v1.2.3" {
		t.Errorf("Version() = %q, want v1.2.3", candidate.Version())
	}
	if candidate.Digest() != validDigest {
		t.Errorf("Digest() = %q, want %q", candidate.Digest(), validDigest)
	}
	if len(candidate.Evidence()) != 0 {
		t.Errorf("Evidence() = %d entries, want 0", len(candidate.Evidence()))
	}
}

func TestRecordEvidenceAppendsAndCopies(t *testing.T) {
	candidate := newPending(t)
	if err := candidate.RecordEvidence(scanEvidence(t)); err != nil {
		t.Fatalf("RecordEvidence() error = %v", err)
	}
	trail := candidate.Evidence()
	if len(trail) != 1 || trail[0].Type() != evidence.TypeScan {
		t.Fatalf("Evidence() = %v, want one scan entry", trail)
	}
	trail[0] = evidence.Reference{}
	if candidate.Evidence()[0].Type() != evidence.TypeScan {
		t.Fatal("Evidence() does not return a defensive copy")
	}
}

func TestQuarantineRequiresPendingOrApproved(t *testing.T) {
	candidate := newPending(t)
	if err := candidate.Quarantine(" "); err == nil {
		t.Fatal("Quarantine() error = nil, want empty reason error")
	}
	if err := candidate.Quarantine("policy failure"); err != nil {
		t.Fatalf("Quarantine() error = %v", err)
	}
	if candidate.State() != StateQuarantined {
		t.Fatalf("State() = %q, want %q", candidate.State(), StateQuarantined)
	}
	if err := candidate.Quarantine("again"); err == nil {
		t.Fatal("Quarantine() error = nil, want state guard error")
	}
}

func TestQuarantineFromApproved(t *testing.T) {
	candidate := newPending(t)
	if err := candidate.Approve(approvalEvidence(t)); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	if err := candidate.Quarantine("revalidation failure"); err != nil {
		t.Fatalf("Quarantine() error = %v", err)
	}
	if candidate.State() != StateQuarantined {
		t.Fatalf("State() = %q, want %q", candidate.State(), StateQuarantined)
	}
}

func TestReleaseReturnsToPending(t *testing.T) {
	candidate := newPending(t)
	if err := candidate.Release("early"); err == nil {
		t.Fatal("Release() error = nil, want state guard error")
	}
	if err := candidate.Quarantine("policy failure"); err != nil {
		t.Fatalf("Quarantine() error = %v", err)
	}
	if err := candidate.Release(" "); err == nil {
		t.Fatal("Release() error = nil, want empty reason error")
	}
	if err := candidate.Release("evidence completed"); err != nil {
		t.Fatalf("Release() error = %v", err)
	}
	if candidate.State() != StatePending {
		t.Fatalf("State() = %q, want %q", candidate.State(), StatePending)
	}
}

func TestApproveRequiresPendingAndApprovalEvidence(t *testing.T) {
	candidate := newPending(t)
	if err := candidate.Approve(scanEvidence(t)); err == nil {
		t.Fatal("Approve() error = nil, want evidence type error")
	}
	if err := candidate.Approve(approvalEvidence(t)); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	if candidate.State() != StateApproved {
		t.Fatalf("State() = %q, want %q", candidate.State(), StateApproved)
	}
	if len(candidate.Evidence()) != 1 || candidate.Evidence()[0].Type() != evidence.TypeApproval {
		t.Fatal("Approve() did not record the approval evidence")
	}
	if err := candidate.Approve(approvalEvidence(t)); err == nil {
		t.Fatal("Approve() error = nil, want state guard error")
	}
}

func TestRevokeIsTerminal(t *testing.T) {
	candidate := newPending(t)
	if err := candidate.Revoke(" "); err == nil {
		t.Fatal("Revoke() error = nil, want empty reason error")
	}
	if err := candidate.Revoke("supply chain incident"); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	if candidate.State() != StateRevoked {
		t.Fatalf("State() = %q, want %q", candidate.State(), StateRevoked)
	}
	if err := candidate.Revoke("again"); err == nil {
		t.Fatal("Revoke() error = nil, want terminal guard error")
	}
	if err := candidate.RecordEvidence(scanEvidence(t)); err == nil {
		t.Fatal("RecordEvidence() error = nil, want terminal guard error")
	}
	if err := candidate.Quarantine("too late"); err == nil {
		t.Fatal("Quarantine() error = nil, want terminal guard error")
	}
	if err := candidate.Release("too late"); err == nil {
		t.Fatal("Release() error = nil, want terminal guard error")
	}
	if err := candidate.Approve(approvalEvidence(t)); err == nil {
		t.Fatal("Approve() error = nil, want terminal guard error")
	}
}

func TestRevokeFromQuarantinedAndApproved(t *testing.T) {
	quarantined := newPending(t)
	if err := quarantined.Quarantine("investigation"); err != nil {
		t.Fatalf("Quarantine() error = %v", err)
	}
	if err := quarantined.Revoke("confirmed malicious"); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	if quarantined.State() != StateRevoked {
		t.Fatalf("State() = %q, want %q", quarantined.State(), StateRevoked)
	}

	approved := newPending(t)
	if err := approved.Approve(approvalEvidence(t)); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	if err := approved.Revoke("revoked after approval"); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	if approved.State() != StateRevoked {
		t.Fatalf("State() = %q, want %q", approved.State(), StateRevoked)
	}
}
