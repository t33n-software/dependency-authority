package promotion

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/CyberT33N/dependency-authority/internal/dependency/domain/admission"
	"github.com/CyberT33N/dependency-authority/internal/dependency/domain/approval"
	"github.com/CyberT33N/dependency-authority/internal/dependency/domain/candidate"
	"github.com/CyberT33N/dependency-authority/internal/dependency/domain/evidence"
)

const validDigest = "sha256:3b8f49c12b24cbbd6a4a0e6e2b2a4a4e8f0e1d2c3b4a59687766554433221100"

const approvalDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

var testNow = time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)

type fakeCandidates struct {
	current   candidate.Candidate
	found     bool
	findErr   error
	saveErr   error
	saveCalls int
}

func (f *fakeCandidates) Save(_ context.Context, c candidate.Candidate) error {
	f.saveCalls++
	if f.saveErr != nil {
		return f.saveErr
	}
	f.current = c
	return nil
}

func (f *fakeCandidates) Find(context.Context, candidate.Ecosystem, string, string) (candidate.Candidate, bool, error) {
	return f.current, f.found, f.findErr
}

type fakePolicies struct {
	policy admission.Policy
	err    error
}

func (f fakePolicies) Policy(context.Context, candidate.Ecosystem) (admission.Policy, error) {
	return f.policy, f.err
}

type fakeEvidenceStore struct {
	refs []evidence.Reference
	err  error
}

func (f fakeEvidenceStore) Evidence(context.Context, candidate.Ecosystem, string, string) ([]evidence.Reference, error) {
	return f.refs, f.err
}

type fakeRegistry struct {
	err         error
	publishCall int
}

func (f *fakeRegistry) Publish(context.Context, candidate.Candidate, []evidence.Reference) error {
	f.publishCall++
	return f.err
}

func pendingCandidate(t *testing.T) candidate.Candidate {
	t.Helper()
	c, err := candidate.New(candidate.EcosystemGo, "example.com/mod", "v1.0.0", validDigest)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return c
}

func testPolicy(t *testing.T) admission.Policy {
	t.Helper()
	policy, err := admission.NewPolicy(candidate.EcosystemGo, []evidence.Type{evidence.TypeSBOM}, 7.0, true, nil)
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}
	return policy
}

func approvalEvidenceRef(t *testing.T) evidence.Reference {
	t.Helper()
	reference, err := evidence.NewReference(evidence.TypeApproval, "approvals/1", approvalDigest, "approver", testNow, nil)
	if err != nil {
		t.Fatalf("NewReference() error = %v", err)
	}
	return reference
}

func sbomEvidenceRef(t *testing.T) evidence.Reference {
	t.Helper()
	reference, err := evidence.NewReference(evidence.TypeSBOM, "sboms/1", validDigest, "generator", testNow, nil)
	if err != nil {
		t.Fatalf("NewReference() error = %v", err)
	}
	return reference
}

func validApproval(t *testing.T) approval.Approval {
	t.Helper()
	approver, err := approval.New("approver", approvalEvidenceRef(t), testNow.Add(time.Hour))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return approver
}

func compliantPorts(t *testing.T) (*fakeCandidates, fakePolicies, fakeEvidenceStore, *fakeRegistry) {
	t.Helper()
	return &fakeCandidates{current: pendingCandidate(t), found: true},
		fakePolicies{policy: testPolicy(t)},
		fakeEvidenceStore{refs: []evidence.Reference{sbomEvidenceRef(t), approvalEvidenceRef(t)}},
		&fakeRegistry{}
}

func newService(t *testing.T, candidates Candidates, policies Policies, store EvidenceStore, registry ApprovedRegistry) Service {
	t.Helper()
	service, err := NewService(candidates, policies, store, registry, func() time.Time { return testNow })
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	return service
}

func TestNewServiceRejectsUnboundPorts(t *testing.T) {
	candidates, policies, store, registry := compliantPorts(t)
	now := func() time.Time { return testNow }
	if _, err := NewService(nil, policies, store, registry, now); err == nil {
		t.Fatal("NewService() error = nil, want candidates port error")
	}
	if _, err := NewService(candidates, nil, store, registry, now); err == nil {
		t.Fatal("NewService() error = nil, want policies port error")
	}
	if _, err := NewService(candidates, policies, nil, registry, now); err == nil {
		t.Fatal("NewService() error = nil, want evidence store port error")
	}
	if _, err := NewService(candidates, policies, store, nil, now); err == nil {
		t.Fatal("NewService() error = nil, want registry port error")
	}
	if _, err := NewService(candidates, policies, store, registry, nil); err == nil {
		t.Fatal("NewService() error = nil, want clock error")
	}
	if _, err := NewService(candidates, policies, store, registry, now); err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
}

func TestPromotePropagatesFindError(t *testing.T) {
	_, policies, store, registry := compliantPorts(t)
	service := newService(t, &fakeCandidates{findErr: errors.New("store down")}, policies, store, registry)
	if err := service.Promote(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0", validApproval(t)); err == nil {
		t.Fatal("Promote() error = nil, want load error")
	}
}

func TestPromoteRejectsUnknownCandidate(t *testing.T) {
	_, policies, store, registry := compliantPorts(t)
	service := newService(t, &fakeCandidates{}, policies, store, registry)
	if err := service.Promote(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0", validApproval(t)); err == nil {
		t.Fatal("Promote() error = nil, want not-found error")
	}
}

func TestPromoteRejectsNonPendingState(t *testing.T) {
	quarantined := pendingCandidate(t)
	if err := quarantined.Quarantine("investigation"); err != nil {
		t.Fatalf("Quarantine() error = %v", err)
	}
	_, policies, store, registry := compliantPorts(t)
	service := newService(t, &fakeCandidates{current: quarantined, found: true}, policies, store, registry)
	if err := service.Promote(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0", validApproval(t)); err == nil {
		t.Fatal("Promote() error = nil, want state guard error")
	}
}

func TestPromoteRejectsExpiredApproval(t *testing.T) {
	expired, err := approval.New("approver", approvalEvidenceRef(t), testNow.Add(-time.Second))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	candidates, policies, store, registry := compliantPorts(t)
	service := newService(t, candidates, policies, store, registry)
	if err := service.Promote(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0", expired); err == nil {
		t.Fatal("Promote() error = nil, want expired approval error")
	}
}

func TestPromotePropagatesPolicyError(t *testing.T) {
	candidates, _, store, registry := compliantPorts(t)
	service := newService(t, candidates, fakePolicies{err: errors.New("policy store down")}, store, registry)
	if err := service.Promote(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0", validApproval(t)); err == nil {
		t.Fatal("Promote() error = nil, want policy error")
	}
}

func TestPromoteRejectsPolicyEcosystemMismatch(t *testing.T) {
	mismatched, err := admission.NewPolicy(candidate.EcosystemNPM, []evidence.Type{evidence.TypeSBOM}, 7.0, true, nil)
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}
	candidates, _, store, registry := compliantPorts(t)
	service := newService(t, candidates, fakePolicies{policy: mismatched}, store, registry)
	if err := service.Promote(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0", validApproval(t)); err == nil {
		t.Fatal("Promote() error = nil, want ecosystem mismatch error")
	}
}

func TestPromotePropagatesEvidenceError(t *testing.T) {
	candidates, policies, _, registry := compliantPorts(t)
	service := newService(t, candidates, policies, fakeEvidenceStore{err: errors.New("evidence store down")}, registry)
	if err := service.Promote(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0", validApproval(t)); err == nil {
		t.Fatal("Promote() error = nil, want evidence error")
	}
}

func TestPromoteRejectsMissingRequiredEvidence(t *testing.T) {
	candidates, policies, _, registry := compliantPorts(t)
	store := fakeEvidenceStore{refs: []evidence.Reference{approvalEvidenceRef(t)}}
	service := newService(t, candidates, policies, store, registry)
	if err := service.Promote(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0", validApproval(t)); err == nil {
		t.Fatal("Promote() error = nil, want missing required evidence error")
	}
}

func TestPromoteRejectsUnrecordedApprovalEvidence(t *testing.T) {
	candidates, policies, _, registry := compliantPorts(t)
	store := fakeEvidenceStore{refs: []evidence.Reference{sbomEvidenceRef(t)}}
	service := newService(t, candidates, policies, store, registry)
	if err := service.Promote(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0", validApproval(t)); err == nil {
		t.Fatal("Promote() error = nil, want unrecorded approval evidence error")
	}
}

func TestPromotePropagatesPublishError(t *testing.T) {
	candidates, policies, store, registry := compliantPorts(t)
	registry.err = errors.New("registry unavailable")
	service := newService(t, candidates, policies, store, registry)
	if err := service.Promote(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0", validApproval(t)); err == nil {
		t.Fatal("Promote() error = nil, want publish error")
	}
}

func TestPromotePropagatesSaveError(t *testing.T) {
	candidates, policies, store, registry := compliantPorts(t)
	candidates.saveErr = errors.New("write failure")
	service := newService(t, candidates, policies, store, registry)
	if err := service.Promote(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0", validApproval(t)); err == nil {
		t.Fatal("Promote() error = nil, want save error")
	}
}

func TestPromoteApprovesPublishesAndSaves(t *testing.T) {
	candidates, policies, store, registry := compliantPorts(t)
	service := newService(t, candidates, policies, store, registry)
	if err := service.Promote(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0", validApproval(t)); err != nil {
		t.Fatalf("Promote() error = %v", err)
	}
	if candidates.current.State() != candidate.StateApproved {
		t.Fatalf("State() = %q, want %q", candidates.current.State(), candidate.StateApproved)
	}
	if registry.publishCall != 1 {
		t.Fatalf("publishCall = %d, want 1", registry.publishCall)
	}
	if candidates.saveCalls != 1 {
		t.Fatalf("saveCalls = %d, want 1", candidates.saveCalls)
	}
}
