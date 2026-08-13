// Package evidence models immutable, digest-bound evidence references that
// dependency subjects accumulate across the admission lifecycle.
package evidence

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Type classifies an evidence object.
type Type string

const (
	TypeSBOM        Type = "sbom"
	TypeSignature   Type = "signature"
	TypeProvenance  Type = "provenance"
	TypeAttestation Type = "attestation"
	TypeTest        Type = "test"
	TypeScan        Type = "scan"
	TypeApproval    Type = "approval"
	TypeException   Type = "exception"
	TypePolicy      Type = "policy"
	TypeQuality     Type = "quality"
	TypeRevocation  Type = "revocation"
)

// Valid reports whether the evidence type belongs to the canonical set.
func (t Type) Valid() bool {
	switch t {
	case TypeSBOM, TypeSignature, TypeProvenance, TypeAttestation, TypeTest,
		TypeScan, TypeApproval, TypeException, TypePolicy, TypeQuality, TypeRevocation:
		return true
	default:
		return false
	}
}

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// Reference is an immutable pointer to an evidence object.
type Reference struct {
	evidenceType Type
	reference    string
	digest       string
	issuer       string
	issuedAt     time.Time
	expiresAt    *time.Time
}

// NewReference constructs a validated immutable evidence reference.
func NewReference(evidenceType Type, reference string, digest string, issuer string, issuedAt time.Time, expiresAt *time.Time) (Reference, error) {
	if !evidenceType.Valid() {
		return Reference{}, fmt.Errorf("unknown evidence type %q", evidenceType)
	}
	if strings.TrimSpace(reference) == "" {
		return Reference{}, errors.New("immutable reference must not be empty")
	}
	if !digestPattern.MatchString(digest) {
		return Reference{}, fmt.Errorf("digest %q must match sha256:<64 lowercase hex>", digest)
	}
	if strings.TrimSpace(issuer) == "" {
		return Reference{}, errors.New("issuer must not be empty")
	}
	if issuedAt.IsZero() {
		return Reference{}, errors.New("issued-at must not be zero")
	}
	if expiresAt != nil && !expiresAt.After(issuedAt) {
		return Reference{}, errors.New("expires-at must be after issued-at")
	}
	return Reference{
		evidenceType: evidenceType,
		reference:    reference,
		digest:       digest,
		issuer:       issuer,
		issuedAt:     issuedAt,
		expiresAt:    expiresAt,
	}, nil
}

// Type returns the evidence type.
func (r Reference) Type() Type {
	return r.evidenceType
}

// Reference returns the immutable reference locator.
func (r Reference) Reference() string {
	return r.reference
}

// Digest returns the content digest of the referenced evidence object.
func (r Reference) Digest() string {
	return r.digest
}

// Issuer returns the evidence issuer identity.
func (r Reference) Issuer() string {
	return r.issuer
}

// IssuedAt returns the evidence issue time.
func (r Reference) IssuedAt() time.Time {
	return r.issuedAt
}

// ExpiresAt returns the expiry time and whether the reference expires.
func (r Reference) ExpiresAt() (time.Time, bool) {
	if r.expiresAt == nil {
		return time.Time{}, false
	}
	return *r.expiresAt, true
}

// Expired reports whether the reference is expired at the given time.
func (r Reference) Expired(now time.Time) bool {
	if r.expiresAt == nil {
		return false
	}
	return !now.Before(*r.expiresAt)
}
