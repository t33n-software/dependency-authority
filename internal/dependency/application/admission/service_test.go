package admission

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

type fakePolicies struct {
	policy admission.Policy
	err    error
}

func (f fakePolicies) Policy(context.Context, candidate.Ecosystem) (admission.Policy, error) {
	return f.policy, f.err
}

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

func testPolicy(t *testing.T) admission.Policy {
	t.Helper()
	policy, err := admission.NewPolicy(candidate.EcosystemGo, []evidence.Type{evidence.TypeSBOM}, 7.0, true, []string{"GPL-3.0"})
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}
	return policy
}

func pendingCandidate(t *testing.T) candidate.Candidate {
	t.Helper()
	c, err := candidate.New(candidate.EcosystemGo, "example.com/mod", "v1.0.0", validDigest)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return c
}

func quarantinedCandidate(t *testing.T) candidate.Candidate {
	t.Helper()
	c := pendingCandidate(t)
	if err := c.Quarantine("previous failure"); err != nil {
		t.Fatalf("Quarantine() error = %v", err)
	}
	return c
}

func approvedCandidate(t *testing.T) candidate.Candidate {
	t.Helper()
	c := pendingCandidate(t)
	reference, err := evidence.NewReference(evidence.TypeApproval, "approvals/1", validDigest, "approver", time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC), nil)
	if err != nil {
		t.Fatalf("NewReference() error = %v", err)
	}
	if err := c.Approve(reference); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	return c
}

func sbomEvidence(t *testing.T) evidence.Reference {
	t.Helper()
	reference, err := evidence.NewReference(evidence.TypeSBOM, "sboms/1", validDigest, "generator", time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC), nil)
	if err != nil {
		t.Fatalf("NewReference() error = %v", err)
	}
	return reference
}

func newService(t *testing.T, policies Policies, candidates Candidates, scanner Scanner, store EvidenceStore) Service {
	t.Helper()
	service, err := NewService(policies, candidates, scanner, store)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	return service
}

func compliantPorts(t *testing.T, c candidate.Candidate) (fakePolicies, *fakeCandidates, fakeScanner, fakeEvidenceStore) {
	t.Helper()
	return fakePolicies{policy: testPolicy(t)},
		&fakeCandidates{current: c, found: true},
		fakeScanner{result: admission.ScanResult{MaxCVSS: 1.0, Licenses: []string{"MIT"}}},
		fakeEvidenceStore{refs: []evidence.Reference{sbomEvidence(t)}}
}

func TestNewServiceRejectsUnboundPorts(t *testing.T) {
	policies, candidates, scanner, store := compliantPorts(t, pendingCandidate(t))
	if _, err := NewService(nil, candidates, scanner, store); err == nil {
		t.Fatal("NewService() error = nil, want policies port error")
	}
	if _, err := NewService(policies, nil, scanner, store); err == nil {
		t.Fatal("NewService() error = nil, want candidates port error")
	}
	if _, err := NewService(policies, candidates, nil, store); err == nil {
		t.Fatal("NewService() error = nil, want scanner port error")
	}
	if _, err := NewService(policies, candidates, scanner, nil); err == nil {
		t.Fatal("NewService() error = nil, want evidence store port error")
	}
	if _, err := NewService(policies, candidates, scanner, store); err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
}

func TestAdmitPropagatesFindError(t *testing.T) {
	policies, _, scanner, store := compliantPorts(t, pendingCandidate(t))
	service := newService(t, policies, &fakeCandidates{findErr: errors.New("store down")}, scanner, store)
	if _, err := service.Admit(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0"); err == nil {
		t.Fatal("Admit() error = nil, want load error")
	}
}

func TestAdmitRejectsUnknownCandidate(t *testing.T) {
	policies, _, scanner, store := compliantPorts(t, pendingCandidate(t))
	service := newService(t, policies, &fakeCandidates{}, scanner, store)
	if _, err := service.Admit(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0"); err == nil {
		t.Fatal("Admit() error = nil, want not-found error")
	}
}

func TestAdmitRejectsTerminalState(t *testing.T) {
	policies, candidates, scanner, store := compliantPorts(t, approvedCandidate(t))
	service := newService(t, policies, candidates, scanner, store)
	if _, err := service.Admit(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0"); err == nil {
		t.Fatal("Admit() error = nil, want state guard error")
	}
}

func TestAdmitPropagatesPolicyError(t *testing.T) {
	_, candidates, scanner, store := compliantPorts(t, pendingCandidate(t))
	service := newService(t, fakePolicies{err: errors.New("policy store down")}, candidates, scanner, store)
	if _, err := service.Admit(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0"); err == nil {
		t.Fatal("Admit() error = nil, want policy error")
	}
}

func TestAdmitRejectsPolicyEcosystemMismatch(t *testing.T) {
	mismatched, err := admission.NewPolicy(candidate.EcosystemNPM, []evidence.Type{evidence.TypeSBOM}, 7.0, true, nil)
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}
	_, candidates, scanner, store := compliantPorts(t, pendingCandidate(t))
	service := newService(t, fakePolicies{policy: mismatched}, candidates, scanner, store)
	if _, err := service.Admit(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0"); err == nil {
		t.Fatal("Admit() error = nil, want ecosystem mismatch error")
	}
}

func TestAdmitPropagatesScanError(t *testing.T) {
	policies, candidates, _, store := compliantPorts(t, pendingCandidate(t))
	service := newService(t, policies, candidates, fakeScanner{err: errors.New("scanner down")}, store)
	if _, err := service.Admit(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0"); err == nil {
		t.Fatal("Admit() error = nil, want scan error")
	}
}

func TestAdmitPropagatesEvidenceError(t *testing.T) {
	policies, candidates, scanner, _ := compliantPorts(t, pendingCandidate(t))
	service := newService(t, policies, candidates, scanner, fakeEvidenceStore{err: errors.New("evidence store down")})
	if _, err := service.Admit(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0"); err == nil {
		t.Fatal("Admit() error = nil, want evidence error")
	}
}

func TestAdmitQuarantinesPendingCandidate(t *testing.T) {
	policies, candidates, _, _ := compliantPorts(t, pendingCandidate(t))
	failing := fakeScanner{result: admission.ScanResult{MaxCVSS: 9.9, Licenses: []string{"MIT"}}}
	service := newService(t, policies, candidates, failing, fakeEvidenceStore{refs: []evidence.Reference{sbomEvidence(t)}})
	report, err := service.Admit(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("Admit() error = %v", err)
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

func TestAdmitQuarantineDecisionOnQuarantinedCandidateDoesNotSave(t *testing.T) {
	policies, candidates, _, _ := compliantPorts(t, quarantinedCandidate(t))
	failing := fakeScanner{result: admission.ScanResult{MaxCVSS: 9.9}}
	service := newService(t, policies, candidates, failing, fakeEvidenceStore{})
	report, err := service.Admit(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("Admit() error = %v", err)
	}
	if report.Decision() != admission.DecisionQuarantine {
		t.Fatalf("Decision() = %q, want %q", report.Decision(), admission.DecisionQuarantine)
	}
	if candidates.saveCalls != 0 {
		t.Fatalf("saveCalls = %d, want 0 for an already quarantined candidate", candidates.saveCalls)
	}
}

func TestAdmitReleasesQuarantinedCandidate(t *testing.T) {
	policies, candidates, scanner, store := compliantPorts(t, quarantinedCandidate(t))
	service := newService(t, policies, candidates, scanner, store)
	report, err := service.Admit(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("Admit() error = %v", err)
	}
	if report.Decision() != admission.DecisionAdmit {
		t.Fatalf("Decision() = %q, want %q", report.Decision(), admission.DecisionAdmit)
	}
	if candidates.current.State() != candidate.StatePending {
		t.Fatalf("State() = %q, want %q", candidates.current.State(), candidate.StatePending)
	}
	if candidates.saveCalls != 1 {
		t.Fatalf("saveCalls = %d, want 1", candidates.saveCalls)
	}
}

func TestAdmitPropagatesSaveErrors(t *testing.T) {
	policies, _, _, store := compliantPorts(t, pendingCandidate(t))
	quarantineSaveFailure := &fakeCandidates{current: pendingCandidate(t), found: true, saveErr: errors.New("write failure")}
	failing := fakeScanner{result: admission.ScanResult{MaxCVSS: 9.9}}
	service := newService(t, policies, quarantineSaveFailure, failing, store)
	if _, err := service.Admit(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0"); err == nil {
		t.Fatal("Admit() error = nil, want quarantine save error")
	}

	policies, _, scanner, store := compliantPorts(t, quarantinedCandidate(t))
	releaseSaveFailure := &fakeCandidates{current: quarantinedCandidate(t), found: true, saveErr: errors.New("write failure")}
	service = newService(t, policies, releaseSaveFailure, scanner, store)
	if _, err := service.Admit(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0"); err == nil {
		t.Fatal("Admit() error = nil, want release save error")
	}
}

func TestAdmitAdmitsCompliantPendingCandidateWithoutSave(t *testing.T) {
	policies, candidates, scanner, store := compliantPorts(t, pendingCandidate(t))
	service := newService(t, policies, candidates, scanner, store)
	report, err := service.Admit(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("Admit() error = %v", err)
	}
	if report.Decision() != admission.DecisionAdmit {
		t.Fatalf("Decision() = %q, want %q", report.Decision(), admission.DecisionAdmit)
	}
	if candidates.saveCalls != 0 {
		t.Fatalf("saveCalls = %d, want 0 for an unchanged pending candidate", candidates.saveCalls)
	}
}
