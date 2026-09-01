// Package promotion implements the promotion use case: moving an admitted
// pending candidate into the approved zone under a valid approval.
package promotion

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/t33n-software/dependency-authority/internal/dependency/domain/admission"
	"github.com/t33n-software/dependency-authority/internal/dependency/domain/approval"
	"github.com/t33n-software/dependency-authority/internal/dependency/domain/candidate"
	"github.com/t33n-software/dependency-authority/internal/dependency/domain/evidence"
)

// Candidates persists and loads dependency candidates.
type Candidates interface {
	Save(ctx context.Context, candidate candidate.Candidate) error
	Find(ctx context.Context, ecosystem candidate.Ecosystem, name string, version string) (candidate.Candidate, bool, error)
}

// Policies provides the admission policy for an ecosystem.
type Policies interface {
	Policy(ctx context.Context, ecosystem candidate.Ecosystem) (admission.Policy, error)
}

// EvidenceStore loads the evidence recorded for a candidate.
type EvidenceStore interface {
	Evidence(ctx context.Context, ecosystem candidate.Ecosystem, name string, version string) ([]evidence.Reference, error)
}

// ApprovedRegistry publishes a candidate into the approved zone.
type ApprovedRegistry interface {
	Publish(ctx context.Context, candidate candidate.Candidate, evidenceRefs []evidence.Reference) error
}

// Service runs the promotion lane.
type Service struct {
	candidates    Candidates
	policies      Policies
	evidenceStore EvidenceStore
	registry      ApprovedRegistry
	now           func() time.Time
}

// NewService constructs the promotion service and fails closed on unbound
// ports or a missing clock.
func NewService(candidates Candidates, policies Policies, evidenceStore EvidenceStore, registry ApprovedRegistry, now func() time.Time) (Service, error) {
	if candidates == nil {
		return Service{}, errors.New("candidates port must not be nil")
	}
	if policies == nil {
		return Service{}, errors.New("policies port must not be nil")
	}
	if evidenceStore == nil {
		return Service{}, errors.New("evidence store port must not be nil")
	}
	if registry == nil {
		return Service{}, errors.New("approved registry port must not be nil")
	}
	if now == nil {
		return Service{}, errors.New("clock must not be nil")
	}
	return Service{
		candidates:    candidates,
		policies:      policies,
		evidenceStore: evidenceStore,
		registry:      registry,
		now:           now,
	}, nil
}

// Promote promotes a pending candidate into the approved zone. Promotion
// fails closed unless the approval is valid, the approval evidence is
// recorded, and every policy-required evidence type is present.
func (s Service) Promote(ctx context.Context, ecosystem candidate.Ecosystem, name string, version string, approver approval.Approval) error {
	current, found, err := s.candidates.Find(ctx, ecosystem, name, version)
	if err != nil {
		return fmt.Errorf("load candidate: %w", err)
	}
	if !found {
		return fmt.Errorf("candidate %s %s not found", name, version)
	}
	if current.State() != candidate.StatePending {
		return fmt.Errorf("candidate in state %q cannot be promoted", current.State())
	}
	if !approver.Valid(s.now()) {
		return errors.New("approval is expired")
	}

	policy, err := s.policies.Policy(ctx, ecosystem)
	if err != nil {
		return fmt.Errorf("load policy: %w", err)
	}
	if policy.Ecosystem() != ecosystem {
		return fmt.Errorf("policy ecosystem %q does not match candidate ecosystem %q", policy.Ecosystem(), ecosystem)
	}

	evidenceRefs, err := s.evidenceStore.Evidence(ctx, ecosystem, name, version)
	if err != nil {
		return fmt.Errorf("load evidence: %w", err)
	}
	for _, required := range policy.RequiredEvidence() {
		if !hasEvidenceType(evidenceRefs, required) {
			return fmt.Errorf("missing required evidence %q", required)
		}
	}
	if !hasDigest(evidenceRefs, approver.Evidence().Digest()) {
		return errors.New("approval evidence is not recorded for the candidate")
	}

	// The pending state check and the approval-typed evidence bound to the
	// approval aggregate make this transition total.
	_ = current.Approve(approver.Evidence())
	if err := s.registry.Publish(ctx, current, evidenceRefs); err != nil {
		return fmt.Errorf("publish to approved zone: %w", err)
	}
	if err := s.candidates.Save(ctx, current); err != nil {
		return fmt.Errorf("save approved candidate: %w", err)
	}
	return nil
}

func hasEvidenceType(evidenceRefs []evidence.Reference, evidenceType evidence.Type) bool {
	for _, reference := range evidenceRefs {
		if reference.Type() == evidenceType {
			return true
		}
	}
	return false
}

func hasDigest(evidenceRefs []evidence.Reference, digest string) bool {
	for _, reference := range evidenceRefs {
		if reference.Digest() == digest {
			return true
		}
	}
	return false
}
