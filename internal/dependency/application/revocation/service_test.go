package revocation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/CyberT33N/dependency-authority/internal/dependency/domain/candidate"
	"github.com/CyberT33N/dependency-authority/internal/dependency/domain/evidence"
)

const validDigest = "sha256:3b8f49c12b24cbbd6a4a0e6e2b2a4a4e8f0e1d2c3b4a59687766554433221100"

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

type fakeGate struct {
	err        error
	blockCalls int
}

func (f *fakeGate) Block(context.Context, candidate.Candidate) error {
	f.blockCalls++
	return f.err
}

type fakeRecorder struct {
	err         error
	recordCalls int
}

func (f *fakeRecorder) Record(context.Context, candidate.Candidate, evidence.Reference) error {
	f.recordCalls++
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

func revokedCandidate(t *testing.T) candidate.Candidate {
	t.Helper()
	c := pendingCandidate(t)
	if err := c.Revoke("earlier incident"); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	return c
}

func revocationEvidence(t *testing.T) evidence.Reference {
	t.Helper()
	reference, err := evidence.NewReference(evidence.TypeRevocation, "revocations/1", validDigest, "security", testNow, nil)
	if err != nil {
		t.Fatalf("NewReference() error = %v", err)
	}
	return reference
}

func scanEvidence(t *testing.T) evidence.Reference {
	t.Helper()
	reference, err := evidence.NewReference(evidence.TypeScan, "scans/1", validDigest, "scanner", testNow, nil)
	if err != nil {
		t.Fatalf("NewReference() error = %v", err)
	}
	return reference
}

func compliantPorts(t *testing.T) (*fakeCandidates, *fakeGate, *fakeRecorder) {
	t.Helper()
	return &fakeCandidates{current: pendingCandidate(t), found: true}, &fakeGate{}, &fakeRecorder{}
}

func newService(t *testing.T, candidates Candidates, gate DownloadGate, recorder EvidenceRecorder) Service {
	t.Helper()
	service, err := NewService(candidates, gate, recorder, func() time.Time { return testNow })
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	return service
}

func TestNewServiceRejectsUnboundPorts(t *testing.T) {
	candidates, gate, recorder := compliantPorts(t)
	now := func() time.Time { return testNow }
	if _, err := NewService(nil, gate, recorder, now); err == nil {
		t.Fatal("NewService() error = nil, want candidates port error")
	}
	if _, err := NewService(candidates, nil, recorder, now); err == nil {
		t.Fatal("NewService() error = nil, want download gate port error")
	}
	if _, err := NewService(candidates, gate, nil, now); err == nil {
		t.Fatal("NewService() error = nil, want evidence recorder port error")
	}
	if _, err := NewService(candidates, gate, recorder, nil); err == nil {
		t.Fatal("NewService() error = nil, want clock error")
	}
	if _, err := NewService(candidates, gate, recorder, now); err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
}

func TestRevokePropagatesFindError(t *testing.T) {
	_, gate, recorder := compliantPorts(t)
	service := newService(t, &fakeCandidates{findErr: errors.New("store down")}, gate, recorder)
	if _, err := service.Revoke(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0", "incident", revocationEvidence(t)); err == nil {
		t.Fatal("Revoke() error = nil, want load error")
	}
}

func TestRevokeRejectsUnknownCandidate(t *testing.T) {
	_, gate, recorder := compliantPorts(t)
	service := newService(t, &fakeCandidates{}, gate, recorder)
	if _, err := service.Revoke(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0", "incident", revocationEvidence(t)); err == nil {
		t.Fatal("Revoke() error = nil, want not-found error")
	}
}

func TestRevokeRejectsInvalidRevocationEvidence(t *testing.T) {
	candidates, gate, recorder := compliantPorts(t)
	service := newService(t, candidates, gate, recorder)
	if _, err := service.Revoke(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0", "incident", scanEvidence(t)); err == nil {
		t.Fatal("Revoke() error = nil, want evidence type error")
	}
}

func TestRevokeRejectsTerminalCandidate(t *testing.T) {
	_, gate, recorder := compliantPorts(t)
	service := newService(t, &fakeCandidates{current: revokedCandidate(t), found: true}, gate, recorder)
	if _, err := service.Revoke(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0", "incident", revocationEvidence(t)); err == nil {
		t.Fatal("Revoke() error = nil, want terminal guard error")
	}
}

func TestRevokeBlocksBeforeRecordingAndSaving(t *testing.T) {
	candidates, gate, recorder := compliantPorts(t)
	gate.err = errors.New("gate unavailable")
	service := newService(t, candidates, gate, recorder)
	if _, err := service.Revoke(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0", "incident", revocationEvidence(t)); err == nil {
		t.Fatal("Revoke() error = nil, want gate error")
	}
	if recorder.recordCalls != 0 {
		t.Fatalf("recordCalls = %d, want 0 after a gate failure", recorder.recordCalls)
	}
	if candidates.saveCalls != 0 {
		t.Fatalf("saveCalls = %d, want 0 after a gate failure", candidates.saveCalls)
	}
}

func TestRevokePropagatesRecorderError(t *testing.T) {
	candidates, gate, recorder := compliantPorts(t)
	recorder.err = errors.New("evidence store down")
	service := newService(t, candidates, gate, recorder)
	if _, err := service.Revoke(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0", "incident", revocationEvidence(t)); err == nil {
		t.Fatal("Revoke() error = nil, want recorder error")
	}
	if gate.blockCalls != 1 {
		t.Fatalf("blockCalls = %d, want 1", gate.blockCalls)
	}
}

func TestRevokePropagatesSaveError(t *testing.T) {
	candidates, gate, recorder := compliantPorts(t)
	candidates.saveErr = errors.New("write failure")
	service := newService(t, candidates, gate, recorder)
	if _, err := service.Revoke(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0", "incident", revocationEvidence(t)); err == nil {
		t.Fatal("Revoke() error = nil, want save error")
	}
}

func TestRevokeBlocksRecordsAndSaves(t *testing.T) {
	candidates, gate, recorder := compliantPorts(t)
	service := newService(t, candidates, gate, recorder)
	decision, err := service.Revoke(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0", "supply chain incident", revocationEvidence(t))
	if err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	if !decision.DownloadBlock() {
		t.Error("DownloadBlock() = false, want true")
	}
	if decision.Reason() != "supply chain incident" {
		t.Errorf("Reason() = %q, want incident reason", decision.Reason())
	}
	if candidates.current.State() != candidate.StateRevoked {
		t.Fatalf("State() = %q, want %q", candidates.current.State(), candidate.StateRevoked)
	}
	if gate.blockCalls != 1 || recorder.recordCalls != 1 || candidates.saveCalls != 1 {
		t.Fatalf("calls = block %d, record %d, save %d; want 1 each", gate.blockCalls, recorder.recordCalls, candidates.saveCalls)
	}
}
