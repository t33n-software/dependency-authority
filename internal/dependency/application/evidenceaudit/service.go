// Package evidenceaudit implements the evidence-audit use case: the read-only
// proof surface of the internal evidence index. The workload reads the index
// and proves the content-addressed locators a lane report references, and it
// writes nothing.
package evidenceaudit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/t33n-software/dependency-authority/internal/dependency/domain/candidate"
	"github.com/t33n-software/dependency-authority/internal/dependency/domain/evidence"
)

// EvidenceTrail loads the evidence recorded for a candidate.
type EvidenceTrail interface {
	Evidence(ctx context.Context, ecosystem candidate.Ecosystem, name string, version string) ([]evidence.Reference, error)
}

// PayloadProver fetches one referenced evidence payload by its
// content-addressed locator.
type PayloadProver interface {
	FetchPayload(ctx context.Context, reference evidence.Reference) ([]byte, error)
}

// Report is the completed audit proof: the proven references of the
// candidate's evidence trail.
type Report struct {
	references []evidence.Reference
}

// NewReport constructs the audit report of the proven references.
func NewReport(references []evidence.Reference) Report {
	proven := make([]evidence.Reference, len(references))
	copy(proven, references)
	return Report{references: proven}
}

// References returns a defensive copy of the proven references.
func (r Report) References() []evidence.Reference {
	proven := make([]evidence.Reference, len(r.references))
	copy(proven, r.references)
	return proven
}

// Service runs the evidence-audit workload.
type Service struct {
	trail    EvidenceTrail
	payloads PayloadProver
}

// NewService constructs the evidence-audit service and fails closed on
// unbound ports.
func NewService(trail EvidenceTrail, payloads PayloadProver) (Service, error) {
	if trail == nil {
		return Service{}, errors.New("evidence trail port must not be nil")
	}
	if payloads == nil {
		return Service{}, errors.New("payload prover port must not be nil")
	}
	return Service{trail: trail, payloads: payloads}, nil
}

// Prove reads the candidate's evidence trail and proves every referenced
// payload's content identity against its digest-bound reference. A digest
// drift fails closed as a supply-chain anomaly.
func (s Service) Prove(ctx context.Context, ecosystem candidate.Ecosystem, name string, version string) (Report, error) {
	trail, err := s.trail.Evidence(ctx, ecosystem, name, version)
	if err != nil {
		return Report{}, fmt.Errorf("load the evidence trail: %w", err)
	}
	for _, reference := range trail {
		payload, err := s.payloads.FetchPayload(ctx, reference)
		if err != nil {
			return Report{}, fmt.Errorf("fetch the evidence payload %q: %w", reference.Reference(), err)
		}
		sum := sha256.Sum256(payload)
		if digest := "sha256:" + hex.EncodeToString(sum[:]); digest != reference.Digest() {
			return Report{}, fmt.Errorf("evidence payload %q digest %q does not match the recorded reference %q", reference.Reference(), digest, reference.Digest())
		}
	}
	return NewReport(trail), nil
}
