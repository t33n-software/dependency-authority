package bootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/t33n-software/dependency-authority/internal/dependency/adapters/inbound/config"
	"github.com/t33n-software/dependency-authority/internal/dependency/domain/admission"
	"github.com/t33n-software/dependency-authority/internal/dependency/domain/candidate"
	"github.com/t33n-software/dependency-authority/internal/dependency/domain/evidence"
)

const testDigest = "sha256:3b8f49c12b24cbbd6a4a0e6e2b2a4a4e8f0e1d2c3b4a59687766554433221100"

var laneTime = time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)

type fakeUpstream struct {
	digest string
	err    error
}

func (f fakeUpstream) FetchDigest(context.Context, candidate.Ecosystem, string, string) (string, error) {
	return f.digest, f.err
}

type fakeScanner struct {
	result admission.ScanResult
	err    error
}

func (f fakeScanner) Scan(context.Context, candidate.Candidate) (admission.ScanResult, error) {
	return f.result, f.err
}

type fakePolicies struct {
	policy admission.Policy
	err    error
}

func (f fakePolicies) Policy(context.Context, candidate.Ecosystem) (admission.Policy, error) {
	return f.policy, f.err
}

type fakeCandidates struct {
	stored  candidate.Candidate
	found   bool
	findErr error
	saveErr error
	saved   []candidate.Candidate
}

func (f *fakeCandidates) Save(_ context.Context, subject candidate.Candidate) error {
	if f.saveErr != nil {
		return f.saveErr
	}
	f.saved = append(f.saved, subject)
	return nil
}

func (f *fakeCandidates) Find(context.Context, candidate.Ecosystem, string, string) (candidate.Candidate, bool, error) {
	return f.stored, f.found, f.findErr
}

type fakeEvidenceStore struct {
	trail []evidence.Reference
	err   error
}

func (f fakeEvidenceStore) Evidence(context.Context, candidate.Ecosystem, string, string) ([]evidence.Reference, error) {
	return f.trail, f.err
}

type fakeRegistry struct {
	err       error
	published int
}

func (f *fakeRegistry) Publish(context.Context, candidate.Candidate, []evidence.Reference) error {
	f.published++
	return f.err
}

type fakeGate struct {
	err     error
	blocked int
}

func (f *fakeGate) Block(context.Context, candidate.Candidate) error {
	f.blocked++
	return f.err
}

// fakeJournal mirrors the evidence store contract: content-addressed payload
// publication plus reference indexing.
type fakeJournal struct {
	putErr       error
	recordErr    error
	failOnPut    int
	failOnRecord int
	putCalls     int
	recordCalls  int
	puts         []evidence.Reference
	records      []evidence.Reference
}

func (f *fakeJournal) Put(_ context.Context, _ candidate.Candidate, evidenceType evidence.Type, issuer string, payload []byte, issuedAt time.Time, expiresAt *time.Time) (evidence.Reference, error) {
	f.putCalls++
	if f.putErr != nil {
		return evidence.Reference{}, f.putErr
	}
	if f.failOnPut > 0 && f.putCalls == f.failOnPut {
		return evidence.Reference{}, errors.New("put failed")
	}
	sum := sha256.Sum256(payload)
	reference, err := evidence.NewReference(evidenceType, "evidence://fake/"+hex.EncodeToString(sum[:]), "sha256:"+hex.EncodeToString(sum[:]), issuer, issuedAt, expiresAt)
	if err != nil {
		return evidence.Reference{}, err
	}
	f.puts = append(f.puts, reference)
	return reference, nil
}

func (f *fakeJournal) Record(_ context.Context, _ candidate.Candidate, reference evidence.Reference) error {
	f.recordCalls++
	if f.recordErr != nil {
		return f.recordErr
	}
	if f.failOnRecord > 0 && f.recordCalls == f.failOnRecord {
		return errors.New("record failed")
	}
	f.records = append(f.records, reference)
	return nil
}

func testPolicy(t *testing.T) admission.Policy {
	t.Helper()
	// The required scan evidence and the enforced ceiling make the evaluation
	// deterministic for the lane fixtures.
	policy, err := admission.NewPolicy(candidate.EcosystemGo, []evidence.Type{evidence.TypeScan}, 7.0, true, []string{"AGPL-3.0"})
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}
	return policy
}

func testReference(t *testing.T, evidenceType evidence.Type, locator string, issuedAt time.Time, expiresAt *time.Time) evidence.Reference {
	t.Helper()
	reference, err := evidence.NewReference(evidenceType, locator, testDigest, "dep-admission-controller@example.iam.gserviceaccount.com", issuedAt, expiresAt)
	if err != nil {
		t.Fatalf("NewReference() error = %v", err)
	}
	return reference
}

func pendingCandidate(t *testing.T) candidate.Candidate {
	t.Helper()
	subject, err := candidate.New(candidate.EcosystemGo, "github.com/google/go-cmp", "v0.7.0", testDigest)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return subject
}

func approvedCandidate(t *testing.T) candidate.Candidate {
	t.Helper()
	subject := pendingCandidate(t)
	expiresAt := laneTime.Add(time.Hour)
	if err := subject.Approve(testReference(t, evidence.TypeApproval, "approvals/1", laneTime, &expiresAt)); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	return subject
}

func fullPorts(t *testing.T) Ports {
	t.Helper()
	journal := &fakeJournal{}
	return Ports{
		Upstream:      fakeUpstream{digest: testDigest},
		Scanner:       fakeScanner{result: admission.ScanResult{MaxCVSS: 2.0, Licenses: []string{"MIT"}}},
		Policies:      fakePolicies{policy: testPolicy(t)},
		Candidates:    &fakeCandidates{},
		EvidenceStore: fakeEvidenceStore{},
		Registry:      &fakeRegistry{},
		Gate:          &fakeGate{},
		Recorder:      journal,
		Journal:       journal,
		Now:           func() time.Time { return laneTime },
	}
}

func staticPorts(ports Ports, err error) PortsBuilder {
	return func(func(string) string) (Ports, error) {
		return ports, err
	}
}

func envWith(zone string, ecosystem string) func(string) string {
	return func(key string) string {
		switch key {
		case config.EnvZone:
			return zone
		case config.EnvEcosystem:
			return ecosystem
		default:
			return ""
		}
	}
}

func laneEnv(zone string, values map[string]string) func(string) string {
	return func(key string) string {
		switch key {
		case config.EnvZone:
			return zone
		case config.EnvEcosystem:
			return "go"
		}
		return values[key]
	}
}

func operationInputs() map[string]string {
	return map[string]string{
		config.EnvModule:                  "github.com/google/go-cmp",
		config.EnvVersion:                 "v0.7.0",
		config.EnvLaneIdentity:            "dep-admission-controller@example.iam.gserviceaccount.com",
		config.EnvScannerIdentity:         "osv-scanner 2.2.3",
		config.EnvScannerDatabaseIdentity: "osv-db sha256:aaa",
		config.EnvApprovalTTL:             "72h",
		config.EnvRevocationReason:        "confirmed supply chain incident",
		config.EnvPolicyBundle:            ".build/policy/go.json",
	}
}

func TestRunRejectsInvalidConfiguration(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), OperationIntake, envWith("", ""), staticPorts(fullPorts(t), nil), &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run() = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "load controller configuration") {
		t.Fatalf("stderr = %q, want configuration error", stderr.String())
	}
}

func TestRunRejectsZoneMismatch(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), OperationIntake, envWith("control", "go"), staticPorts(fullPorts(t), nil), &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run() = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "must run in the intake zone") {
		t.Fatalf("stderr = %q, want zone error", stderr.String())
	}
}

func TestRunFailsClosedOnWiringError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), OperationIntake, envWith("intake", "go"), staticPorts(Ports{}, errors.New("bad binding")), &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run() = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "wire dependency-intake-controller") {
		t.Fatalf("stderr = %q, want wiring error", stderr.String())
	}
}

func TestRunFailsClosedOnUnboundPorts(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), OperationIntake, envWith("intake", "go"), staticPorts(Ports{}, nil), &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run() = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "bind dependency-intake-controller") {
		t.Fatalf("stderr = %q, want bind error", stderr.String())
	}
}

func TestRunRejectsInvalidOperationInputs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), OperationIntake, envWith("intake", "go"), staticPorts(fullPorts(t), nil), &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run() = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "load operation inputs") || !strings.Contains(stderr.String(), config.EnvModule) {
		t.Fatalf("stderr = %q, want the operation input error", stderr.String())
	}
}

func TestRunFailsClosedOnExecutionError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	ports := fullPorts(t)
	ports.Upstream = fakeUpstream{err: errors.New("upstream unavailable")}
	code := run(context.Background(), OperationIntake, laneEnv("intake", operationInputs()), staticPorts(ports, nil), &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run() = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "execute dependency-intake-controller") {
		t.Fatalf("stderr = %q, want execution error", stderr.String())
	}
}

func TestRunSuccess(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), OperationIntake, laneEnv("intake", operationInputs()), staticPorts(fullPorts(t), nil), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() = %d, want 0; stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "dependency-intake-controller: candidate go github.com/google/go-cmp v0.7.0 state=pending digest="+testDigest) {
		t.Fatalf("stdout = %q, want the intake result line", stdout.String())
	}
}

func TestLaneWrappers(t *testing.T) {
	stubBundle(t)
	lanes := []struct {
		name  string
		run   func(context.Context, func(string) string, PortsBuilder, io.Writer, io.Writer) int
		zone  string
		ports func(t *testing.T) Ports
		want  string
	}{
		{"intake", RunIntake, "intake", fullPorts, "dependency-intake-controller: candidate"},
		{"admission", RunAdmission, "control", admissionLanePorts, "decision=admit approval=recorded"},
		{"promotion", RunPromotion, "control", promotionLanePorts, "state=approved"},
		{"revalidation", RunRevalidation, "control", revalidationLanePorts, "dependency-revalidation-controller: candidate"},
		{"revocation", RunRevocation, "control", revocationLanePorts, "state=revoked download_block=true"},
	}
	for _, lane := range lanes {
		t.Run(lane.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := lane.run(context.Background(), laneEnv(lane.zone, operationInputs()), staticPorts(lane.ports(t), nil), &stdout, &stderr)
			if code != 0 {
				t.Fatalf("Run() = %d, want 0; stderr = %q", code, stderr.String())
			}
			if !strings.Contains(stdout.String(), lane.want) {
				t.Fatalf("stdout = %q, want %q", stdout.String(), lane.want)
			}
		})
	}
}

func TestCheckZone(t *testing.T) {
	for _, operation := range []Operation{OperationAdmission, OperationPromotion, OperationRevalidation, OperationRevocation} {
		if err := checkZone(operation, config.ZoneControl); err != nil {
			t.Errorf("checkZone(%q, control) error = %v", operation, err)
		}
		if err := checkZone(operation, config.ZoneIntake); err == nil {
			t.Errorf("checkZone(%q, intake) error = nil, want zone error", operation)
		}
	}
	if err := checkZone(OperationIntake, config.ZoneIntake); err != nil {
		t.Errorf("checkZone(intake, intake) error = %v", err)
	}
	if err := checkZone(Operation("bogus"), config.ZoneControl); err == nil {
		t.Error("checkZone(bogus) error = nil, want unknown operation error")
	}
}

func TestZoneForRejectsUnknownOperation(t *testing.T) {
	if _, err := zoneFor(Operation("bogus")); err == nil {
		t.Fatal("zoneFor() error = nil, want unknown operation error")
	}
}

func TestBindFailsClosedOnUnboundPorts(t *testing.T) {
	for _, operation := range []Operation{
		OperationIntake, OperationAdmission, OperationPromotion, OperationRevalidation, OperationRevocation,
	} {
		if _, err := bind(operation, Ports{}); err == nil {
			t.Errorf("bind(%q, empty ports) error = nil, want unbound port error", operation)
		}
	}
}

func TestBindSucceedsWithFullPorts(t *testing.T) {
	for _, operation := range []Operation{
		OperationIntake, OperationAdmission, OperationPromotion, OperationRevalidation, OperationRevocation,
	} {
		if _, err := bind(operation, fullPorts(t)); err != nil {
			t.Errorf("bind(%q, full ports) error = %v", operation, err)
		}
	}
}

func TestBindRejectsUnknownOperation(t *testing.T) {
	if _, err := bind(Operation("bogus"), fullPorts(t)); err == nil {
		t.Fatal("bind() error = nil, want unknown operation error")
	}
}
