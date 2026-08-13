// Package revocation implements the revocation use case: moving a candidate
// into the terminal revoked state and actively blocking further downloads.
package revocation

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/CyberT33N/dependency-authority/internal/dependency/domain/candidate"
	"github.com/CyberT33N/dependency-authority/internal/dependency/domain/evidence"
	"github.com/CyberT33N/dependency-authority/internal/dependency/domain/revocation"
)

// Candidates persists and loads dependency candidates.
type Candidates interface {
	Save(ctx context.Context, candidate candidate.Candidate) error
	Find(ctx context.Context, ecosystem candidate.Ecosystem, name string, version string) (candidate.Candidate, bool, error)
}

// DownloadGate actively blocks downloads at the approved boundary.
type DownloadGate interface {
	Block(ctx context.Context, candidate candidate.Candidate) error
}

// EvidenceRecorder records evidence for a candidate.
type EvidenceRecorder interface {
	Record(ctx context.Context, candidate candidate.Candidate, reference evidence.Reference) error
}

// Service runs the revocation lane.
type Service struct {
	candidates Candidates
	gate       DownloadGate
	recorder   EvidenceRecorder
	now        func() time.Time
}

// NewService constructs the revocation service and fails closed on unbound
// ports or a missing clock.
func NewService(candidates Candidates, gate DownloadGate, recorder EvidenceRecorder, now func() time.Time) (Service, error) {
	if candidates == nil {
		return Service{}, errors.New("candidates port must not be nil")
	}
	if gate == nil {
		return Service{}, errors.New("download gate port must not be nil")
	}
	if recorder == nil {
		return Service{}, errors.New("evidence recorder port must not be nil")
	}
	if now == nil {
		return Service{}, errors.New("clock must not be nil")
	}
	return Service{
		candidates: candidates,
		gate:       gate,
		recorder:   recorder,
		now:        now,
	}, nil
}

// Revoke revokes a candidate, blocks downloads at the approved boundary, and
// records the revocation evidence. Downloads are blocked before the state is
// persisted so a failure cannot leave an unblocked revoked candidate.
func (s Service) Revoke(ctx context.Context, ecosystem candidate.Ecosystem, name string, version string, reason string, revocationEvidence evidence.Reference) (revocation.Revocation, error) {
	current, found, err := s.candidates.Find(ctx, ecosystem, name, version)
	if err != nil {
		return revocation.Revocation{}, fmt.Errorf("load candidate: %w", err)
	}
	if !found {
		return revocation.Revocation{}, fmt.Errorf("candidate %s %s not found", name, version)
	}

	decision, err := revocation.New(reason, revocationEvidence, true, s.now())
	if err != nil {
		return revocation.Revocation{}, fmt.Errorf("construct revocation: %w", err)
	}
	if err := current.Revoke(reason); err != nil {
		return revocation.Revocation{}, fmt.Errorf("revoke candidate: %w", err)
	}
	if err := s.gate.Block(ctx, current); err != nil {
		return revocation.Revocation{}, fmt.Errorf("block downloads: %w", err)
	}
	if err := s.recorder.Record(ctx, current, revocationEvidence); err != nil {
		return revocation.Revocation{}, fmt.Errorf("record revocation evidence: %w", err)
	}
	if err := s.candidates.Save(ctx, current); err != nil {
		return revocation.Revocation{}, fmt.Errorf("save revoked candidate: %w", err)
	}
	return decision, nil
}
