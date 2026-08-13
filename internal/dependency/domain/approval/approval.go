// Package approval models time-bounded promotion approvals for dependency
// candidates.
package approval

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/CyberT33N/dependency-authority/internal/dependency/domain/evidence"
)

// Approval is a time-bounded promotion approval bound to approval evidence.
type Approval struct {
	issuer    string
	evidence  evidence.Reference
	expiresAt time.Time
}

// New constructs a validated approval.
func New(issuer string, approvalEvidence evidence.Reference, expiresAt time.Time) (Approval, error) {
	if strings.TrimSpace(issuer) == "" {
		return Approval{}, errors.New("issuer must not be empty")
	}
	if approvalEvidence.Type() != evidence.TypeApproval {
		return Approval{}, fmt.Errorf("approval evidence must have type %q", evidence.TypeApproval)
	}
	if expiresAt.IsZero() {
		return Approval{}, errors.New("expires-at must not be zero")
	}
	return Approval{
		issuer:    issuer,
		evidence:  approvalEvidence,
		expiresAt: expiresAt,
	}, nil
}

// Issuer returns the approval issuer identity.
func (a Approval) Issuer() string {
	return a.issuer
}

// Evidence returns the bound approval evidence reference.
func (a Approval) Evidence() evidence.Reference {
	return a.evidence
}

// ExpiresAt returns the approval expiry time.
func (a Approval) ExpiresAt() time.Time {
	return a.expiresAt
}

// Valid reports whether the approval is still valid at the given time.
func (a Approval) Valid(now time.Time) bool {
	return now.Before(a.expiresAt)
}
