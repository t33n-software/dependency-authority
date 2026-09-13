package consumerverification

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/t33n-software/dependency-authority/internal/dependency/domain/candidate"
	"github.com/t33n-software/dependency-authority/internal/dependency/domain/evidence"
	"github.com/t33n-software/dependency-authority/internal/dependency/domain/verification"
)

const validDigest = "sha256:3b8f49c12b24cbbd6a4a0e6e2b2a4a4e8f0e1d2c3b4a59687766554433221100"

const testProbe = "example.invalid/never-admitted@v0.0.0"

type fakeCandidates struct {
	current candidate.Candidate
	found   bool
	findErr error
}

func (f *fakeCandidates) Find(context.Context, candidate.Ecosystem, string, string) (candidate.Candidate, bool, error) {
	return f.current, f.found, f.findErr
}

type fakeEvidenceStore struct {
	trail []evidence.Reference
	err   error
}

func (f fakeEvidenceStore) Evidence(context.Context, candidate.Ecosystem, string, string) ([]evidence.Reference, error) {
	return f.trail, f.err
}

// fakeContract records the proof execution order and injects per-proof
// failures.
type fakeContract struct {
	prepareErr   error
	downloadSum  string
	downloadErr  error
	probeErr     error
	stableErr    error
	verifyErr    error
	buildVersion string
	buildSum     string
	buildErr     error
	releaseCalls int
	events       []string
}

func (f *fakeContract) Prepare(string, string) (string, error) {
	f.events = append(f.events, "prepare")
	return "workspace", f.prepareErr
}

func (f *fakeContract) Release(string) error {
	f.releaseCalls++
	f.events = append(f.events, "release")
	return nil
}

func (f *fakeContract) Download(context.Context, string, string, string) (string, error) {
	f.events = append(f.events, "download")
	return f.downloadSum, f.downloadErr
}

func (f *fakeContract) ProbeFailsClosed(context.Context, string, string) error {
	f.events = append(f.events, "probe")
	return f.probeErr
}

func (f *fakeContract) GraphStable(context.Context, string) error {
	f.events = append(f.events, "stable")
	return f.stableErr
}

func (f *fakeContract) VerifyIntegrity(context.Context, string) error {
	f.events = append(f.events, "verify")
	return f.verifyErr
}

func (f *fakeContract) BuildEvidence(context.Context, string, string) (string, string, error) {
	f.events = append(f.events, "build")
	return f.buildVersion, f.buildSum, f.buildErr
}

func approvedCandidate(t *testing.T) candidate.Candidate {
	t.Helper()
	subject, err := candidate.New(candidate.EcosystemGo, "example.com/mod", "v1.0.0", validDigest)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	reference, err := evidence.NewReference(evidence.TypeApproval, "approvals/1", validDigest, "approver", time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC), nil)
	if err != nil {
		t.Fatalf("NewReference() error = %v", err)
	}
	if err := subject.Approve(reference); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	return subject
}

func approvalTrail(t *testing.T) []evidence.Reference {
	t.Helper()
	reference, err := evidence.NewReference(evidence.TypeApproval, "approvals/1", validDigest, "approver", time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC), nil)
	if err != nil {
		t.Fatalf("NewReference() error = %v", err)
	}
	return []evidence.Reference{reference}
}

// compliantPorts binds the passing contract: the artifact identity matches
// the download sum and the candidate version.
func compliantPorts(t *testing.T) (*fakeCandidates, fakeEvidenceStore, *fakeContract) {
	t.Helper()
	return &fakeCandidates{current: approvedCandidate(t), found: true},
		fakeEvidenceStore{trail: approvalTrail(t)},
		&fakeContract{downloadSum: "h1:abc=", buildVersion: "v1.0.0", buildSum: "h1:abc="}
}

func newService(t *testing.T, candidates Candidates, store EvidenceStore, contract Contract) Service {
	t.Helper()
	service, err := NewService(candidates, store, contract)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	return service
}

func TestNewServiceRejectsUnboundPorts(t *testing.T) {
	candidates, store, contract := compliantPorts(t)
	if _, err := NewService(nil, store, contract); err == nil {
		t.Fatal("NewService() error = nil, want candidates port error")
	}
	if _, err := NewService(candidates, nil, contract); err == nil {
		t.Fatal("NewService() error = nil, want evidence store port error")
	}
	if _, err := NewService(candidates, store, nil); err == nil {
		t.Fatal("NewService() error = nil, want consumer contract port error")
	}
	if _, err := NewService(candidates, store, contract); err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
}

func TestVerifyRejectsAnEmptyNegativeProbe(t *testing.T) {
	candidates, store, contract := compliantPorts(t)
	service := newService(t, candidates, store, contract)
	if _, err := service.Verify(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0", " "); err == nil {
		t.Fatal("Verify() error = nil, want the negative probe error")
	}
}

func TestVerifyPropagatesFindError(t *testing.T) {
	_, store, contract := compliantPorts(t)
	service := newService(t, &fakeCandidates{findErr: errors.New("store down")}, store, contract)
	if _, err := service.Verify(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0", testProbe); err == nil {
		t.Fatal("Verify() error = nil, want load error")
	}
}

func TestVerifyRejectsUnknownCandidate(t *testing.T) {
	_, store, contract := compliantPorts(t)
	service := newService(t, &fakeCandidates{}, store, contract)
	if _, err := service.Verify(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0", testProbe); err == nil {
		t.Fatal("Verify() error = nil, want not-found error")
	}
}

func TestVerifyRejectsANonApprovedCandidate(t *testing.T) {
	pending, err := candidate.New(candidate.EcosystemGo, "example.com/mod", "v1.0.0", validDigest)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, store, contract := compliantPorts(t)
	service := newService(t, &fakeCandidates{current: pending, found: true}, store, contract)
	err = verify(t, service, testProbe)
	if err == nil || !strings.Contains(err.Error(), "not admitted") {
		t.Fatalf("Verify() error = %v, want the not-admitted failure", err)
	}
}

func TestVerifyPropagatesEvidenceError(t *testing.T) {
	candidates, _, contract := compliantPorts(t)
	service := newService(t, candidates, fakeEvidenceStore{err: errors.New("evidence store down")}, contract)
	if _, err := service.Verify(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0", testProbe); err == nil {
		t.Fatal("Verify() error = nil, want evidence error")
	}
}

func TestVerifyRejectsAMissingApprovalEvidence(t *testing.T) {
	candidates, _, contract := compliantPorts(t)
	service := newService(t, candidates, fakeEvidenceStore{}, contract)
	err := verify(t, service, testProbe)
	if err == nil || !strings.Contains(err.Error(), "no approval evidence recorded") {
		t.Fatalf("Verify() error = %v, want the missing approval failure", err)
	}
}

func TestVerifyPropagatesThePrepareFailure(t *testing.T) {
	candidates, store, _ := compliantPorts(t)
	service := newService(t, candidates, store, &fakeContract{prepareErr: errors.New("read-only root")})
	if _, err := service.Verify(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0", testProbe); err == nil {
		t.Fatal("Verify() error = nil, want the prepare failure")
	}
}

// verify runs the use case with the standard inputs.
func verify(t *testing.T, service Service, probe string) error {
	t.Helper()
	_, err := service.Verify(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0", probe)
	return err
}

// wantProofError asserts the lane failed closed at the expected proof.
func wantProofError(t *testing.T, err error, proof verification.Proof) {
	t.Helper()
	if err == nil {
		t.Fatalf("Verify() error = nil, want the %s failure", proof)
	}
	var proofError *verification.ProofError
	if !errors.As(err, &proofError) {
		t.Fatalf("Verify() error = %T, want a *verification.ProofError", err)
	}
	if proofError.Proof() != proof {
		t.Fatalf("ProofError.Proof() = %q, want %q", proofError.Proof(), proof)
	}
}

func TestVerifyFailsClosedAtEveryProof(t *testing.T) {
	for name, mutate := range map[string]func(*fakeContract){
		"positive resolution": func(c *fakeContract) { c.downloadErr = errors.New("not served") },
		"negative resolution": func(c *fakeContract) { c.probeErr = errors.New("the probe resolved") },
		"graph stability":     func(c *fakeContract) { c.stableErr = errors.New("graph mutation") },
		"integrity":           func(c *fakeContract) { c.verifyErr = errors.New("checksum mismatch") },
		"build evidence":      func(c *fakeContract) { c.buildErr = errors.New("does not compile") },
	} {
		t.Run(name, func(t *testing.T) {
			candidates, store, contract := compliantPorts(t)
			mutate(contract)
			service := newService(t, candidates, store, contract)
			wantProofError(t, verify(t, service, testProbe), map[string]verification.Proof{
				"positive resolution": verification.ProofPositiveResolution,
				"negative resolution": verification.ProofNegativeResolution,
				"graph stability":     verification.ProofGraphStability,
				"integrity":           verification.ProofIntegrity,
				"build evidence":      verification.ProofBuildEvidenceCorrespondence,
			}[name])
		})
	}
}

func TestVerifyRejectsACorrespondenceMismatch(t *testing.T) {
	t.Run("version drift", func(t *testing.T) {
		candidates, store, contract := compliantPorts(t)
		contract.buildVersion = "v9.9.9"
		service := newService(t, candidates, store, contract)
		wantProofError(t, verify(t, service, testProbe), verification.ProofBuildEvidenceCorrespondence)
	})
	t.Run("sum drift", func(t *testing.T) {
		candidates, store, contract := compliantPorts(t)
		contract.buildSum = "h1:drift="
		service := newService(t, candidates, store, contract)
		wantProofError(t, verify(t, service, testProbe), verification.ProofBuildEvidenceCorrespondence)
	})
}

func TestVerifyProvesTheConsumerContractInCanonicalOrder(t *testing.T) {
	candidates, store, contract := compliantPorts(t)
	service := newService(t, candidates, store, contract)
	report, err := service.Verify(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0", testProbe)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	wantOrder := []string{"prepare", "download", "probe", "stable", "verify", "build", "release"}
	if len(contract.events) != len(wantOrder) {
		t.Fatalf("contract events = %v, want %v", contract.events, wantOrder)
	}
	for i, event := range wantOrder {
		if contract.events[i] != event {
			t.Fatalf("contract events[%d] = %q, want %q", i, contract.events[i], event)
		}
	}
	if contract.releaseCalls != 1 {
		t.Fatalf("release calls = %d, want the workspace release", contract.releaseCalls)
	}
	results := report.Results()
	if len(results) != len(verification.Proofs()) {
		t.Fatalf("Results() = %d entries, want %d", len(results), len(verification.Proofs()))
	}
	for i, proof := range verification.Proofs() {
		if results[i].Proof() != proof {
			t.Fatalf("Results()[%d] = %q, want %q", i, results[i].Proof(), proof)
		}
	}
	detail, found := report.Detail(verification.ProofPositiveResolution)
	if !found || !strings.Contains(detail, "h1:abc=") {
		t.Fatalf("Detail(positive resolution) = %q, %t, want the attested sum", detail, found)
	}
	if _, found := report.Detail(verification.Proof("bogus")); found {
		t.Fatal("Detail(bogus) = true, want not found")
	}
}
