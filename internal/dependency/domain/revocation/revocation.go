// Package revocation models active download revocation of dependency
// candidates.
package revocation

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/t33n-software/dependency-authority/internal/dependency/domain/evidence"
)

// Revocation is a revocation decision with an active download block.
type Revocation struct {
	reason        string
	evidence      evidence.Reference
	downloadBlock bool
	revokedAt     time.Time
}

// New constructs a validated revocation. A revocation without an active
// download block is not a revocation and fails closed.
func New(reason string, revocationEvidence evidence.Reference, downloadBlock bool, revokedAt time.Time) (Revocation, error) {
	if strings.TrimSpace(reason) == "" {
		return Revocation{}, errors.New("revocation reason must not be empty")
	}
	if revocationEvidence.Type() != evidence.TypeRevocation {
		return Revocation{}, fmt.Errorf("revocation evidence must have type %q", evidence.TypeRevocation)
	}
	if !downloadBlock {
		return Revocation{}, errors.New("revocation requires an active download block")
	}
	if revokedAt.IsZero() {
		return Revocation{}, errors.New("revoked-at must not be zero")
	}
	return Revocation{
		reason:        reason,
		evidence:      revocationEvidence,
		downloadBlock: downloadBlock,
		revokedAt:     revokedAt,
	}, nil
}

// Reason returns the revocation reason.
func (r Revocation) Reason() string {
	return r.reason
}

// Evidence returns the bound revocation evidence reference.
func (r Revocation) Evidence() evidence.Reference {
	return r.evidence
}

// DownloadBlock reports whether downloads are actively blocked.
func (r Revocation) DownloadBlock() bool {
	return r.downloadBlock
}

// RevokedAt returns the revocation time.
func (r Revocation) RevokedAt() time.Time {
	return r.revokedAt
}
