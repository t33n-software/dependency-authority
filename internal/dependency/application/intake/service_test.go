package intake

import (
	"context"
	"errors"
	"testing"

	"github.com/CyberT33N/dependency-authority/internal/dependency/domain/candidate"
)

const validDigest = "sha256:3b8f49c12b24cbbd6a4a0e6e2b2a4a4e8f0e1d2c3b4a59687766554433221100"

const otherDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type fakeUpstream struct {
	digest string
	err    error
}

func (f fakeUpstream) FetchDigest(context.Context, candidate.Ecosystem, string, string) (string, error) {
	return f.digest, f.err
}

type fakeCandidates struct {
	saved     []candidate.Candidate
	found     candidate.Candidate
	foundOK   bool
	findErr   error
	saveErr   error
	saveCalls int
}

func (f *fakeCandidates) Save(_ context.Context, c candidate.Candidate) error {
	f.saveCalls++
	if f.saveErr != nil {
		return f.saveErr
	}
	f.saved = append(f.saved, c)
	return nil
}

func (f *fakeCandidates) Find(context.Context, candidate.Ecosystem, string, string) (candidate.Candidate, bool, error) {
	return f.found, f.foundOK, f.findErr
}

func newService(t *testing.T, upstream Upstream, candidates Candidates) Service {
	t.Helper()
	service, err := NewService(upstream, candidates)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	return service
}

func TestNewServiceRejectsUnboundPorts(t *testing.T) {
	if _, err := NewService(nil, &fakeCandidates{}); err == nil {
		t.Fatal("NewService() error = nil, want upstream port error")
	}
	if _, err := NewService(fakeUpstream{}, nil); err == nil {
		t.Fatal("NewService() error = nil, want candidates port error")
	}
	if _, err := NewService(fakeUpstream{}, &fakeCandidates{}); err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
}

func TestIntakeRejectsInvalidRequest(t *testing.T) {
	service := newService(t, fakeUpstream{digest: validDigest}, &fakeCandidates{})
	if _, err := service.Intake(context.Background(), candidate.Ecosystem("ruby"), "name", "v1"); err == nil {
		t.Fatal("Intake() error = nil, want ecosystem error")
	}
	if _, err := service.Intake(context.Background(), candidate.EcosystemGo, " ", "v1"); err == nil {
		t.Fatal("Intake() error = nil, want name error")
	}
	if _, err := service.Intake(context.Background(), candidate.EcosystemGo, "name", ""); err == nil {
		t.Fatal("Intake() error = nil, want version error")
	}
}

func TestIntakePropagatesUpstreamError(t *testing.T) {
	service := newService(t, fakeUpstream{err: errors.New("upstream unavailable")}, &fakeCandidates{})
	if _, err := service.Intake(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0"); err == nil {
		t.Fatal("Intake() error = nil, want upstream error")
	}
}

func TestIntakePropagatesFindError(t *testing.T) {
	service := newService(t, fakeUpstream{digest: validDigest}, &fakeCandidates{findErr: errors.New("store unavailable")})
	if _, err := service.Intake(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0"); err == nil {
		t.Fatal("Intake() error = nil, want store error")
	}
}

func TestIntakeRejectsDigestConflict(t *testing.T) {
	existing, err := candidate.New(candidate.EcosystemGo, "example.com/mod", "v1.0.0", otherDigest)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	service := newService(t, fakeUpstream{digest: validDigest}, &fakeCandidates{found: existing, foundOK: true})
	if _, err := service.Intake(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0"); err == nil {
		t.Fatal("Intake() error = nil, want digest conflict error")
	}
}

func TestIntakeIsIdempotentForSameDigest(t *testing.T) {
	existing, err := candidate.New(candidate.EcosystemGo, "example.com/mod", "v1.0.0", validDigest)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	candidates := &fakeCandidates{found: existing, foundOK: true}
	service := newService(t, fakeUpstream{digest: validDigest}, candidates)
	got, err := service.Intake(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("Intake() error = %v", err)
	}
	if got.Digest() != validDigest {
		t.Fatalf("Intake() digest = %q, want %q", got.Digest(), validDigest)
	}
	if candidates.saveCalls != 0 {
		t.Fatalf("Intake() saved %d times, want 0 for an idempotent hit", candidates.saveCalls)
	}
}

func TestIntakeRejectsMalformedUpstreamDigest(t *testing.T) {
	service := newService(t, fakeUpstream{digest: "not-a-digest"}, &fakeCandidates{})
	if _, err := service.Intake(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0"); err == nil {
		t.Fatal("Intake() error = nil, want digest validation error")
	}
}

func TestIntakePropagatesSaveError(t *testing.T) {
	service := newService(t, fakeUpstream{digest: validDigest}, &fakeCandidates{saveErr: errors.New("write failure")})
	if _, err := service.Intake(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0"); err == nil {
		t.Fatal("Intake() error = nil, want save error")
	}
}

func TestIntakeRegistersPendingCandidate(t *testing.T) {
	candidates := &fakeCandidates{}
	service := newService(t, fakeUpstream{digest: validDigest}, candidates)
	got, err := service.Intake(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("Intake() error = %v", err)
	}
	if got.State() != candidate.StatePending {
		t.Fatalf("State() = %q, want %q", got.State(), candidate.StatePending)
	}
	if candidates.saveCalls != 1 {
		t.Fatalf("Intake() saved %d times, want 1", candidates.saveCalls)
	}
}
