package revalidation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/CyberT33N/dependency-authority/internal/dependency/domain/admission"
	"github.com/CyberT33N/dependency-authority/internal/dependency/domain/candidate"
	"github.com/CyberT33N/dependency-authority/internal/dependency/domain/evidence"
)

const validDigest = "sha256:3b8f49c12b24cbbd6a4a0e6e2b2a4a4e8f0e1d2c3b4a59687766554433221100"

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

type fakeScanner struct {
	result admission.ScanResult
	err    error
}

func (f fakeScanner) Scan(context.Context, candidate.Candidate) (admission.ScanResult, error) {
	return f.result, f.err
}

type fakeEvidenceStore struct {
	refs []evidence.Reference
	err  error
}

func (f fakeEvidenceStore) Evidence(context.Context, candidate.Ecosystem, string, string) ([]evidence.Reference, error) {
	return f.refs, f.err
}

func approvedCandidate(t *testing.T) candidate.Candidate {
	t.Helper()
	c, err := candidate.New(candidate.EcosystemGo, "example.com/mod", "v1.0.0", validDigest)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	reference, err := evidence.NewReference(evidence.TypeApproval, "approvals/1", validDigest, "approver", time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC), nil)
	if err != nil {
		t.Fatalf("NewReference() error = %v", err)
	}
	if err := c.Approve(reference); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	return c
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

func sbomEvidence(t *testing.T) evidence.Reference {
	t.Helper()
	reference, err := evidence.NewReference(evidence.TypeSBOM, "sboms/1", validDigest, "generator", time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC), nil)
	if err != nil {
		t.Fatalf("NewReference() error = %v", err)
	}
	return reference
}

func compliantPorts(t *testing.T) (*fakeCandidates, fakePolicies, fakeScanner, fakeEvidenceStore) {
	t.Helper()
	return &fakeCandidates{current: approvedCandidate(t), found: true},
		fakePolicies{policy: testPolicy(t)},
		fakeScanner{result: admission.ScanResult{MaxCVSS: 1.0}},
		fakeEvidenceStore{refs: []evidence.Reference{sbomEvidence(t)}}
}

func newService(t *testing.T, candidates Candidates, policies Policies, scanner Scanner, store EvidenceStore) Service {
	t.Helper()
	service, err := NewService(candidates, policies, scanner, store)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	return service
}

func TestNewServiceRejectsUnboundPorts(t *testing.T) {
	candidates, policies, scanner, store := compliantPorts(t)
	if _, err := NewService(nil, policies, scanner, store); err == nil {
		t.Fatal("NewService() error = nil, want candidates port error")
	}
	if _, err := NewService(candidates, nil, scanner, store); err == nil {
		t.Fatal("NewService() error = nil, want policies port error")
	}
	if _, err := NewService(candidates, policies, nil, store); err == nil {
		t.Fatal("NewService() error = nil, want scanner port error")
	}
	if _, err := NewService(candidates, policies, scanner, nil); err == nil {
		t.Fatal("NewService() error = nil, want evidence store port error")
	}
	if _, err := NewService(candidates, policies, scanner, store); err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
}

func TestRevalidatePropagatesFindError(t *testing.T) {
	_, policies, scanner, store := compliantPorts(t)
	service := newService(t, &fakeCandidates{findErr: errors.New("store down")}, policies, scanner, store)
	if _, err := service.Revalidate(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0"); err == nil {
		t.Fatal("Revalidate() error = nil, want load error")
	}
}

func TestRevalidateRejectsUnknownCandidate(t *testing.T) {
	_, policies, scanner, store := compliantPorts(t)
	service := newService(t, &fakeCandidates{}, policies, scanner, store)
	if _, err := service.Revalidate(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0"); err == nil {
		t.Fatal("Revalidate() error = nil, want not-found error")
	}
}

func TestRevalidateRejectsNonApprovedState(t *testing.T) {
	_, policies, scanner, store := compliantPorts(t)
	service := newService(t, &fakeCandidates{current: pendingCandidate(t), found: true}, policies, scanner, store)
	if _, err := service.Revalidate(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0"); err == nil {
		t.Fatal("Revalidate() error = nil, want state guard error")
	}
}

func TestRevalidatePropagatesPolicyError(t *testing.T) {
	candidates, _, scanner, store := compliantPorts(t)
	service := newService(t, candidates, fakePolicies{err: errors.New("policy store down")}, scanner, store)
	if _, err := service.Revalidate(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0"); err == nil {
		t.Fatal("Revalidate() error = nil, want policy error")
	}
}

func TestRevalidateRejectsPolicyEcosystemMismatch(t *testing.T) {
	mismatched, err := admission.NewPolicy(candidate.EcosystemNPM, []evidence.Type{evidence.TypeSBOM}, 7.0, true, nil)
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}
	candidates, _, scanner, store := compliantPorts(t)
	service := newService(t, candidates, fakePolicies{policy: mismatched}, scanner, store)
	if _, err := service.Revalidate(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0"); err == nil {
		t.Fatal("Revalidate() error = nil, want ecosystem mismatch error")
	}
}

func TestRevalidatePropagatesScanError(t *testing.T) {
	candidates, policies, _, store := compliantPorts(t)
	service := newService(t, candidates, policies, fakeScanner{err: errors.New("scanner down")}, store)
	if _, err := service.Revalidate(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0"); err == nil {
		t.Fatal("Revalidate() error = nil, want scan error")
	}
}

func TestRevalidatePropagatesEvidenceError(t *testing.T) {
	candidates, policies, scanner, _ := compliantPorts(t)
	service := newService(t, candidates, policies, scanner, fakeEvidenceStore{err: errors.New("evidence store down")})
	if _, err := service.Revalidate(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0"); err == nil {
		t.Fatal("Revalidate() error = nil, want evidence error")
	}
}

func TestRevalidateKeepsCompliantCandidateApproved(t *testing.T) {
	candidates, policies, scanner, store := compliantPorts(t)
	service := newService(t, candidates, policies, scanner, store)
	report, err := service.Revalidate(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("Revalidate() error = %v", err)
	}
	if report.Decision() != admission.DecisionAdmit {
		t.Fatalf("Decision() = %q, want %q", report.Decision(), admission.DecisionAdmit)
	}
	if candidates.current.State() != candidate.StateApproved {
		t.Fatalf("State() = %q, want %q", candidates.current.State(), candidate.StateApproved)
	}
	if candidates.saveCalls != 0 {
		t.Fatalf("saveCalls = %d, want 0 for a compliant candidate", candidates.saveCalls)
	}
}

func TestRevalidateQuarantinesFailingCandidate(t *testing.T) {
	candidates, policies, _, store := compliantPorts(t)
	failing := fakeScanner{result: admission.ScanResult{MaxCVSS: 9.9}}
	service := newService(t, candidates, policies, failing, store)
	report, err := service.Revalidate(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("Revalidate() error = %v", err)
	}
	if report.Decision() != admission.DecisionQuarantine {
		t.Fatalf("Decision() = %q, want %q", report.Decision(), admission.DecisionQuarantine)
	}
	if candidates.current.State() != candidate.StateQuarantined {
		t.Fatalf("State() = %q, want %q", candidates.current.State(), candidate.StateQuarantined)
	}
	if candidates.saveCalls != 1 {
		t.Fatalf("saveCalls = %d, want 1", candidates.saveCalls)
	}
}

func TestRevalidatePropagatesSaveError(t *testing.T) {
	candidates, policies, _, store := compliantPorts(t)
	candidates.saveErr = errors.New("write failure")
	failing := fakeScanner{result: admission.ScanResult{MaxCVSS: 9.9}}
	service := newService(t, candidates, policies, failing, store)
	if _, err := service.Revalidate(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0"); err == nil {
		t.Fatal("Revalidate() error = nil, want save error")
	}
}
