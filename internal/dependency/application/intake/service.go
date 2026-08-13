// Package intake implements the dependency intake use case: resolving a
// package digest through the controlled upstream boundary and registering a
// pending candidate.
package intake

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/CyberT33N/dependency-authority/internal/dependency/domain/candidate"
)

// Upstream resolves package content digests from the controlled upstream
// boundary of the intake zone.
type Upstream interface {
	FetchDigest(ctx context.Context, ecosystem candidate.Ecosystem, name string, version string) (string, error)
}

// Candidates persists and loads dependency candidates.
type Candidates interface {
	Save(ctx context.Context, candidate candidate.Candidate) error
	Find(ctx context.Context, ecosystem candidate.Ecosystem, name string, version string) (candidate.Candidate, bool, error)
}

// Service runs the intake lane.
type Service struct {
	upstream   Upstream
	candidates Candidates
}

// NewService constructs the intake service and fails closed on unbound ports.
func NewService(upstream Upstream, candidates Candidates) (Service, error) {
	if upstream == nil {
		return Service{}, errors.New("upstream port must not be nil")
	}
	if candidates == nil {
		return Service{}, errors.New("candidates port must not be nil")
	}
	return Service{upstream: upstream, candidates: candidates}, nil
}

// Intake registers a pending candidate for the requested package version.
// The use case is idempotent: an existing candidate with the same digest is
// returned unchanged, while a digest conflict fails closed.
func (s Service) Intake(ctx context.Context, ecosystem candidate.Ecosystem, name string, version string) (candidate.Candidate, error) {
	if !ecosystem.Valid() {
		return candidate.Candidate{}, fmt.Errorf("unknown ecosystem %q", ecosystem)
	}
	if strings.TrimSpace(name) == "" {
		return candidate.Candidate{}, errors.New("name must not be empty")
	}
	if strings.TrimSpace(version) == "" {
		return candidate.Candidate{}, errors.New("version must not be empty")
	}

	digest, err := s.upstream.FetchDigest(ctx, ecosystem, name, version)
	if err != nil {
		return candidate.Candidate{}, fmt.Errorf("fetch upstream digest: %w", err)
	}

	existing, found, err := s.candidates.Find(ctx, ecosystem, name, version)
	if err != nil {
		return candidate.Candidate{}, fmt.Errorf("load candidate: %w", err)
	}
	if found {
		if existing.Digest() != digest {
			return candidate.Candidate{}, fmt.Errorf("candidate %s %s already exists with a different digest", name, version)
		}
		return existing, nil
	}

	registered, err := candidate.New(ecosystem, name, version, digest)
	if err != nil {
		return candidate.Candidate{}, fmt.Errorf("construct candidate: %w", err)
	}
	if err := s.candidates.Save(ctx, registered); err != nil {
		return candidate.Candidate{}, fmt.Errorf("save candidate: %w", err)
	}
	return registered, nil
}
