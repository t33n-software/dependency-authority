// Package revalidation implements the periodic re-evaluation of approved
// candidates against the current policy and scanner state.
package revalidation

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/CyberT33N/dependency-authority/internal/dependency/domain/admission"
	"github.com/CyberT33N/dependency-authority/internal/dependency/domain/candidate"
	"github.com/CyberT33N/dependency-authority/internal/dependency/domain/evidence"
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

// Scanner scans a candidate and returns the structured result.
type Scanner interface {
	Scan(ctx context.Context, candidate candidate.Candidate) (admission.ScanResult, error)
}

// EvidenceStore loads the evidence recorded for a candidate.
type EvidenceStore interface {
	Evidence(ctx context.Context, ecosystem candidate.Ecosystem, name string, version string) ([]evidence.Reference, error)
}

// Service runs the revalidation lane.
type Service struct {
	candidates    Candidates
	policies      Policies
	scanner       Scanner
	evidenceStore EvidenceStore
}

// NewService constructs the revalidation service and fails closed on unbound
// ports.
func NewService(candidates Candidates, policies Policies, scanner Scanner, evidenceStore EvidenceStore) (Service, error) {
	if candidates == nil {
		return Service{}, errors.New("candidates port must not be nil")
	}
	if policies == nil {
		return Service{}, errors.New("policies port must not be nil")
	}
	if scanner == nil {
		return Service{}, errors.New("scanner port must not be nil")
	}
	if evidenceStore == nil {
		return Service{}, errors.New("evidence store port must not be nil")
	}
	return Service{
		candidates:    candidates,
		policies:      policies,
		scanner:       scanner,
		evidenceStore: evidenceStore,
	}, nil
}

// Revalidate re-evaluates an approved candidate. A quarantine decision moves
// the candidate back into quarantine until the findings are resolved.
func (s Service) Revalidate(ctx context.Context, ecosystem candidate.Ecosystem, name string, version string) (admission.Report, error) {
	current, found, err := s.candidates.Find(ctx, ecosystem, name, version)
	if err != nil {
		return admission.Report{}, fmt.Errorf("load candidate: %w", err)
	}
	if !found {
		return admission.Report{}, fmt.Errorf("candidate %s %s not found", name, version)
	}
	if current.State() != candidate.StateApproved {
		return admission.Report{}, fmt.Errorf("candidate in state %q cannot be revalidated", current.State())
	}

	policy, err := s.policies.Policy(ctx, ecosystem)
	if err != nil {
		return admission.Report{}, fmt.Errorf("load policy: %w", err)
	}
	if policy.Ecosystem() != ecosystem {
		return admission.Report{}, fmt.Errorf("policy ecosystem %q does not match candidate ecosystem %q", policy.Ecosystem(), ecosystem)
	}

	scan, err := s.scanner.Scan(ctx, current)
	if err != nil {
		return admission.Report{}, fmt.Errorf("scan candidate: %w", err)
	}

	evidenceRefs, err := s.evidenceStore.Evidence(ctx, ecosystem, name, version)
	if err != nil {
		return admission.Report{}, fmt.Errorf("load evidence: %w", err)
	}

	report := policy.Evaluate(scan, evidenceRefs)
	if report.Decision() == admission.DecisionQuarantine {
		// The approved state and the non-empty quarantine reasons make this
		// transition total.
		_ = current.Quarantine(strings.Join(report.Reasons(), "; "))
		if err := s.candidates.Save(ctx, current); err != nil {
			return admission.Report{}, fmt.Errorf("save quarantined candidate: %w", err)
		}
	}
	return report, nil
}
