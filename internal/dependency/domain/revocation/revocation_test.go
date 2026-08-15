package revocation

import (
	"testing"
	"time"

	"github.com/t33n-software/dependency-authority/internal/dependency/domain/evidence"
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

func revokedAt() time.Time {
	return time.Date(2026, 8, 13, 13, 0, 0, 0, time.UTC)
}

func TestNewValidation(t *testing.T) {
	if _, err := New("", evidenceOfType(t, evidence.TypeRevocation), true, revokedAt()); err == nil {
		t.Fatal("New() error = nil, want empty reason error")
	}
	if _, err := New("incident", evidenceOfType(t, evidence.TypeScan), true, revokedAt()); err == nil {
		t.Fatal("New() error = nil, want evidence type error")
	}
	if _, err := New("incident", evidenceOfType(t, evidence.TypeRevocation), false, revokedAt()); err == nil {
		t.Fatal("New() error = nil, want missing download block error")
	}
	if _, err := New("incident", evidenceOfType(t, evidence.TypeRevocation), true, time.Time{}); err == nil {
		t.Fatal("New() error = nil, want zero revocation time error")
	}
}

func TestRevocationAccessors(t *testing.T) {
	revocationEvidence := evidenceOfType(t, evidence.TypeRevocation)
	revocation, err := New("supply chain incident", revocationEvidence, true, revokedAt())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if revocation.Reason() != "supply chain incident" {
		t.Errorf("Reason() = %q, want incident reason", revocation.Reason())
	}
	if revocation.Evidence().Digest() != revocationEvidence.Digest() {
		t.Errorf("Evidence().Digest() = %q, want %q", revocation.Evidence().Digest(), revocationEvidence.Digest())
	}
	if !revocation.DownloadBlock() {
		t.Error("DownloadBlock() = false, want true")
	}
	if !revocation.RevokedAt().Equal(revokedAt()) {
		t.Errorf("RevokedAt() = %v, want %v", revocation.RevokedAt(), revokedAt())
	}
}
