package approval

import (
	"testing"
	"time"

	"github.com/CyberT33N/dependency-authority/internal/dependency/domain/evidence"
)

const validDigest = "sha256:3b8f49c12b24cbbd6a4a0e6e2b2a4a4e8f0e1d2c3b4a59687766554433221100"

func evidenceOfType(t *testing.T, evidenceType evidence.Type) evidence.Reference {
	t.Helper()
	reference, err := evidence.NewReference(evidenceType, "ref", validDigest, "issuer", time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC), nil)
	if err != nil {
		t.Fatalf("NewReference() error = %v", err)
	}
	return reference
}

func TestNewValidation(t *testing.T) {
	expiresAt := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	if _, err := New(" ", evidenceOfType(t, evidence.TypeApproval), expiresAt); err == nil {
		t.Fatal("New() error = nil, want empty issuer error")
	}
	if _, err := New("approver", evidenceOfType(t, evidence.TypeScan), expiresAt); err == nil {
		t.Fatal("New() error = nil, want evidence type error")
	}
	if _, err := New("approver", evidenceOfType(t, evidence.TypeApproval), time.Time{}); err == nil {
		t.Fatal("New() error = nil, want zero expiry error")
	}
}

func TestApprovalAccessorsAndValidity(t *testing.T) {
	expiresAt := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	approvalEvidence := evidenceOfType(t, evidence.TypeApproval)
	approval, err := New("approver", approvalEvidence, expiresAt)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if approval.Issuer() != "approver" {
		t.Errorf("Issuer() = %q, want approver", approval.Issuer())
	}
	if approval.Evidence().Digest() != approvalEvidence.Digest() {
		t.Errorf("Evidence().Digest() = %q, want %q", approval.Evidence().Digest(), approvalEvidence.Digest())
	}
	if !approval.ExpiresAt().Equal(expiresAt) {
		t.Errorf("ExpiresAt() = %v, want %v", approval.ExpiresAt(), expiresAt)
	}
	if !approval.Valid(expiresAt.Add(-time.Second)) {
		t.Error("Valid() = false before expiry, want true")
	}
	if approval.Valid(expiresAt) {
		t.Error("Valid() = true at expiry, want false")
	}
	if approval.Valid(expiresAt.Add(time.Second)) {
		t.Error("Valid() = true after expiry, want false")
	}
}
