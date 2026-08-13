package evidence

import (
	"strings"
	"testing"
	"time"
)

const validDigest = "sha256:3b8f49c12b24cbbd6a4a0e6e2b2a4a4e8f0e1d2c3b4a59687766554433221100"

func validIssueTime() time.Time {
	return time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
}

func TestTypeValidity(t *testing.T) {
	for _, evidenceType := range []Type{
		TypeSBOM, TypeSignature, TypeProvenance, TypeAttestation, TypeTest,
		TypeScan, TypeApproval, TypeException, TypePolicy, TypeQuality, TypeRevocation,
	} {
		if !evidenceType.Valid() {
			t.Errorf("Type(%q).Valid() = false, want true", evidenceType)
		}
	}
	if Type("bogus").Valid() {
		t.Error("Type(bogus).Valid() = true, want false")
	}
}

func TestNewReferenceRejectsUnknownType(t *testing.T) {
	if _, err := NewReference(Type("bogus"), "ref", validDigest, "issuer", validIssueTime(), nil); err == nil {
		t.Fatal("NewReference() error = nil, want unknown type error")
	}
}

func TestNewReferenceRejectsEmptyReference(t *testing.T) {
	if _, err := NewReference(TypeSBOM, "  ", validDigest, "issuer", validIssueTime(), nil); err == nil {
		t.Fatal("NewReference() error = nil, want empty reference error")
	}
}

func TestNewReferenceRejectsMalformedDigest(t *testing.T) {
	for _, digest := range []string{"", "sha256:xyz", "sha256:ABCDEF", "md5:3b8f49c12b24cbbd6a4a0e6e2b2a4a4e"} {
		if _, err := NewReference(TypeSBOM, "ref", digest, "issuer", validIssueTime(), nil); err == nil {
			t.Fatalf("NewReference(digest=%q) error = nil, want digest error", digest)
		}
	}
}

func TestNewReferenceRejectsEmptyIssuer(t *testing.T) {
	if _, err := NewReference(TypeSBOM, "ref", validDigest, " ", validIssueTime(), nil); err == nil {
		t.Fatal("NewReference() error = nil, want empty issuer error")
	}
}

func TestNewReferenceRejectsZeroIssueTime(t *testing.T) {
	if _, err := NewReference(TypeSBOM, "ref", validDigest, "issuer", time.Time{}, nil); err == nil {
		t.Fatal("NewReference() error = nil, want zero issue time error")
	}
}

func TestNewReferenceRejectsExpiryNotAfterIssueTime(t *testing.T) {
	issuedAt := validIssueTime()
	for _, expiresAt := range []time.Time{issuedAt, issuedAt.Add(-time.Minute)} {
		if _, err := NewReference(TypeSBOM, "ref", validDigest, "issuer", issuedAt, &expiresAt); err == nil {
			t.Fatal("NewReference() error = nil, want expiry ordering error")
		}
	}
}

func TestNewReferenceAccessors(t *testing.T) {
	issuedAt := validIssueTime()
	expiresAt := issuedAt.Add(time.Hour)
	reference, err := NewReference(TypeSignature, "registry/evidence/1", validDigest, "signer", issuedAt, &expiresAt)
	if err != nil {
		t.Fatalf("NewReference() error = %v", err)
	}
	if reference.Type() != TypeSignature {
		t.Errorf("Type() = %q, want %q", reference.Type(), TypeSignature)
	}
	if reference.Reference() != "registry/evidence/1" {
		t.Errorf("Reference() = %q, want locator", reference.Reference())
	}
	if reference.Digest() != validDigest {
		t.Errorf("Digest() = %q, want %q", reference.Digest(), validDigest)
	}
	if reference.Issuer() != "signer" {
		t.Errorf("Issuer() = %q, want signer", reference.Issuer())
	}
	if !reference.IssuedAt().Equal(issuedAt) {
		t.Errorf("IssuedAt() = %v, want %v", reference.IssuedAt(), issuedAt)
	}
	expiry, ok := reference.ExpiresAt()
	if !ok || !expiry.Equal(expiresAt) {
		t.Errorf("ExpiresAt() = %v, %t, want %v, true", expiry, ok, expiresAt)
	}
}

func TestReferenceWithoutExpiry(t *testing.T) {
	reference, err := NewReference(TypeTest, "ref", validDigest, "issuer", validIssueTime(), nil)
	if err != nil {
		t.Fatalf("NewReference() error = %v", err)
	}
	if _, ok := reference.ExpiresAt(); ok {
		t.Error("ExpiresAt() ok = true, want false")
	}
	if reference.Expired(validIssueTime().Add(1000 * time.Hour)) {
		t.Error("Expired() = true, want false without expiry")
	}
}

func TestReferenceExpiryBoundary(t *testing.T) {
	issuedAt := validIssueTime()
	expiresAt := issuedAt.Add(time.Hour)
	reference, err := NewReference(TypeApproval, "ref", validDigest, "issuer", issuedAt, &expiresAt)
	if err != nil {
		t.Fatalf("NewReference() error = %v", err)
	}
	if reference.Expired(expiresAt.Add(-time.Second)) {
		t.Error("Expired() = true before expiry, want false")
	}
	if !reference.Expired(expiresAt) {
		t.Error("Expired() = false at expiry, want true")
	}
	if !reference.Expired(expiresAt.Add(time.Second)) {
		t.Error("Expired() = false after expiry, want true")
	}
}

func TestNewReferenceErrorMessages(t *testing.T) {
	if _, err := NewReference(Type("bogus"), "ref", validDigest, "issuer", validIssueTime(), nil); err == nil ||
		!strings.Contains(err.Error(), "bogus") {
		t.Fatal("unknown type error does not name the type")
	}
	if _, err := NewReference(TypeSBOM, "ref", "bad", "issuer", validIssueTime(), nil); err == nil ||
		!strings.Contains(err.Error(), "sha256:") {
		t.Fatal("digest error does not document the digest contract")
	}
}
