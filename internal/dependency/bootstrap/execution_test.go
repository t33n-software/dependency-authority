package bootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/t33n-software/dependency-authority/internal/dependency/adapters/inbound/config"
	"github.com/t33n-software/dependency-authority/internal/dependency/adapters/outbound/policy"
	"github.com/t33n-software/dependency-authority/internal/dependency/application/admission"
	"github.com/t33n-software/dependency-authority/internal/dependency/application/intake"
	"github.com/t33n-software/dependency-authority/internal/dependency/application/promotion"
	"github.com/t33n-software/dependency-authority/internal/dependency/application/revalidation"
	"github.com/t33n-software/dependency-authority/internal/dependency/application/revocation"
	domainadmission "github.com/t33n-software/dependency-authority/internal/dependency/domain/admission"
	"github.com/t33n-software/dependency-authority/internal/dependency/domain/candidate"
	"github.com/t33n-software/dependency-authority/internal/dependency/domain/evidence"
	domaintooling "github.com/t33n-software/dependency-authority/internal/dependency/domain/tooling"
)

func stubBundle(t *testing.T) {
	t.Helper()
	original := readBundle
	t.Cleanup(func() { readBundle = original })
	readBundle = func(path string) ([]byte, error) {
		if path != ".build/policy/go.json" {
			return nil, errors.New("unexpected bundle path " + path)
		}
		return []byte(`{"schema":"dependency-policy/v1","ecosystem":"go"}`), nil
	}
}

func controlConfig(t *testing.T) config.Config {
	t.Helper()
	controllerConfig, err := config.FromEnv(envWith("control", "go"))
	if err != nil {
		t.Fatalf("FromEnv() error = %v", err)
	}
	return controllerConfig
}

func intakeConfig(t *testing.T) config.Config {
	t.Helper()
	controllerConfig, err := config.FromEnv(envWith("intake", "go"))
	if err != nil {
		t.Fatalf("FromEnv() error = %v", err)
	}
	return controllerConfig
}

func laneOperation(t *testing.T, fields ...config.Field) config.Operation {
	t.Helper()
	// The operation inputs and the artifact bindings share the fixed fixture
	// content, so the channel identities the operation carries always match
	// the digests of the materialized artifacts.
	operation, err := config.OperationFromEnv(laneEnv("control", mergedLaneValues(t)), fields...)
	if err != nil {
		t.Fatalf("OperationFromEnv() error = %v", err)
	}
	return operation
}

func laneService(t *testing.T, operation Operation, ports Ports) any {
	t.Helper()
	service, err := bind(operation, ports)
	if err != nil {
		t.Fatalf("bind(%q) error = %v", operation, err)
	}
	return service
}

func admissionLanePorts(t *testing.T) Ports {
	t.Helper()
	ports := fullPorts(t)
	ports.Candidates = &fakeCandidates{stored: pendingCandidate(t), found: true}
	ports.EvidenceStore = fakeEvidenceStore{trail: []evidence.Reference{testReference(t, evidence.TypeScan, "scans/1", laneTime, nil)}}
	return ports
}

func promotionLanePorts(t *testing.T) Ports {
	t.Helper()
	ports := fullPorts(t)
	ports.Candidates = &fakeCandidates{stored: pendingCandidate(t), found: true}
	expiresAt := laneTime.Add(time.Hour)
	ports.EvidenceStore = fakeEvidenceStore{trail: []evidence.Reference{
		testReference(t, evidence.TypeScan, "scans/1", laneTime, nil),
		testReference(t, evidence.TypeApproval, "approvals/1", laneTime, &expiresAt),
	}}
	return ports
}

func revalidationLanePorts(t *testing.T) Ports {
	t.Helper()
	ports := fullPorts(t)
	ports.Candidates = &fakeCandidates{stored: approvedCandidate(t), found: true}
	ports.EvidenceStore = fakeEvidenceStore{trail: []evidence.Reference{testReference(t, evidence.TypeScan, "scans/1", laneTime, nil)}}
	return ports
}

func revocationLanePorts(t *testing.T) Ports {
	t.Helper()
	ports := fullPorts(t)
	ports.Candidates = &fakeCandidates{stored: approvedCandidate(t), found: true}
	return ports
}

func journalOfPorts(t *testing.T, ports Ports) *fakeJournal {
	t.Helper()
	journal, ok := ports.Journal.(*fakeJournal)
	if !ok {
		t.Fatal("ports.Journal is not the fake journal")
	}
	return journal
}

func TestExecuteIntakeRegistersTheCandidate(t *testing.T) {
	ports := fullPorts(t)
	candidates := &fakeCandidates{}
	ports.Candidates = candidates
	service := laneService(t, OperationIntake, ports).(intake.Service)

	var stdout bytes.Buffer
	err := executeIntake(context.Background(), service, intakeConfig(t), laneOperation(t, config.FieldModule, config.FieldVersion), &stdout)
	if err != nil {
		t.Fatalf("executeIntake() error = %v", err)
	}
	if len(candidates.saved) != 1 || candidates.saved[0].State() != candidate.StatePending {
		t.Fatalf("saved candidates = %+v, want one pending candidate", candidates.saved)
	}
	if !strings.Contains(stdout.String(), "state=pending digest="+testDigest) {
		t.Fatalf("stdout = %q, want the registered candidate", stdout.String())
	}
}

func TestExecuteIntakePropagatesTheUseCaseError(t *testing.T) {
	ports := fullPorts(t)
	ports.Upstream = fakeUpstream{err: errors.New("upstream unavailable")}
	service := laneService(t, OperationIntake, ports).(intake.Service)

	var stdout bytes.Buffer
	if err := executeIntake(context.Background(), service, intakeConfig(t), laneOperation(t, config.FieldModule, config.FieldVersion), &stdout); err == nil {
		t.Fatal("executeIntake() error = nil, want the upstream failure")
	}
}

func TestExecuteAdmissionRecordsTheEvidenceChain(t *testing.T) {
	stubBundle(t)
	ports := admissionLanePorts(t)
	journal := journalOfPorts(t, ports)
	service := laneService(t, OperationAdmission, ports).(admission.Service)
	values := mergedLaneValues(t)
	lookup := laneEnv("control", values)

	var stdout bytes.Buffer
	err := executeAdmission(context.Background(), service, ports, controlConfig(t), laneOperation(t, config.FieldModule, config.FieldVersion, config.FieldLaneIdentity, config.FieldScannerIdentity, config.FieldScannerDatabaseIdentity, config.FieldApprovalTTL), lookup, &stdout)
	if err != nil {
		t.Fatalf("executeAdmission() error = %v", err)
	}

	if len(journal.puts) != 3 {
		t.Fatalf("journal puts = %d, want scan, decision, and approval evidence", len(journal.puts))
	}
	if journal.puts[0].Type() != evidence.TypeScan || journal.puts[0].Issuer() != values[config.EnvScannerIdentity] {
		t.Fatalf("scan evidence = %q issued by %q, want the proven tool identity", journal.puts[0].Type(), journal.puts[0].Issuer())
	}
	var scanDocument struct {
		Tool     string `json:"tool"`
		Database string `json:"database"`
	}
	if err := json.Unmarshal(journal.payloads[0], &scanDocument); err != nil {
		t.Fatalf("the scan evidence payload is not decodable: %v", err)
	}
	if scanDocument.Tool != values[config.EnvScannerIdentity] || scanDocument.Database != values[config.EnvScannerDatabaseIdentity] {
		t.Fatalf("the scan evidence carries tool %q and database %q, want the proven channel identities", scanDocument.Tool, scanDocument.Database)
	}
	if journal.puts[1].Type() != evidence.TypePolicy || !strings.HasPrefix(journal.puts[1].Issuer(), policy.SchemaID+"@sha256:") {
		t.Fatalf("decision evidence = %q issued by %q", journal.puts[1].Type(), journal.puts[1].Issuer())
	}
	approvalEvidence := journal.puts[2]
	if approvalEvidence.Type() != evidence.TypeApproval || approvalEvidence.Issuer() != "dep-admission-controller@example.iam.gserviceaccount.com" {
		t.Fatalf("approval evidence = %q issued by %q", approvalEvidence.Type(), approvalEvidence.Issuer())
	}
	expiresAt, ok := approvalEvidence.ExpiresAt()
	if !ok || !expiresAt.Equal(laneTime.Add(72*time.Hour)) {
		t.Fatalf("approval expires-at = %v, %v, want laneTime+72h", expiresAt, ok)
	}
	if len(journal.records) != 3 {
		t.Fatalf("journal records = %d, want every produced reference indexed", len(journal.records))
	}
	if !strings.Contains(stdout.String(), "decision=admit approval=recorded expires_at=2026-08-26T12:00:00Z") {
		t.Fatalf("stdout = %q, want the admit result line", stdout.String())
	}
}

func TestExecuteAdmissionQuarantineRecordsNoApproval(t *testing.T) {
	stubBundle(t)
	ports := admissionLanePorts(t)
	ports.Scanner = fakeScanner{result: domainadmission.ScanResult{MaxCVSS: 9.8}}
	journal := journalOfPorts(t, ports)
	candidates := ports.Candidates.(*fakeCandidates)
	service := laneService(t, OperationAdmission, ports).(admission.Service)
	lookup := laneEnv("control", mergedLaneValues(t))

	var stdout bytes.Buffer
	err := executeAdmission(context.Background(), service, ports, controlConfig(t), laneOperation(t, config.FieldModule, config.FieldVersion, config.FieldLaneIdentity, config.FieldScannerIdentity, config.FieldScannerDatabaseIdentity, config.FieldApprovalTTL), lookup, &stdout)
	if err != nil {
		t.Fatalf("executeAdmission() error = %v", err)
	}
	if len(journal.puts) != 2 {
		t.Fatalf("journal puts = %d, want scan and decision evidence only", len(journal.puts))
	}
	if len(candidates.saved) != 1 || candidates.saved[0].State() != candidate.StateQuarantined {
		t.Fatalf("saved candidates = %+v, want the quarantined candidate", candidates.saved)
	}
	if !strings.Contains(stdout.String(), "decision=quarantine approval=none") {
		t.Fatalf("stdout = %q, want the quarantine result line", stdout.String())
	}
}

func TestExecuteAdmissionFailsClosedOnThePolicyIdentity(t *testing.T) {
	original := readBundle
	t.Cleanup(func() { readBundle = original })
	readBundle = func(string) ([]byte, error) { return nil, errors.New("no bundle") }

	ports := admissionLanePorts(t)
	service := laneService(t, OperationAdmission, ports).(admission.Service)
	lookup := laneEnv("control", mergedLaneValues(t))

	var stdout bytes.Buffer
	err := executeAdmission(context.Background(), service, ports, controlConfig(t), laneOperation(t, config.FieldModule, config.FieldVersion, config.FieldLaneIdentity, config.FieldScannerIdentity, config.FieldScannerDatabaseIdentity, config.FieldApprovalTTL), lookup, &stdout)
	if err == nil || !strings.Contains(err.Error(), "read policy bundle") {
		t.Fatalf("executeAdmission() error = %v, want the bundle read failure", err)
	}
}

func TestExecuteAdmissionFailsClosedWithoutTheJournal(t *testing.T) {
	stubBundle(t)
	ports := admissionLanePorts(t)
	ports.Journal = nil
	service := laneService(t, OperationAdmission, ports).(admission.Service)
	lookup := laneEnv("control", mergedLaneValues(t))

	var stdout bytes.Buffer
	err := executeAdmission(context.Background(), service, ports, controlConfig(t), laneOperation(t, config.FieldModule, config.FieldVersion, config.FieldLaneIdentity, config.FieldScannerIdentity, config.FieldScannerDatabaseIdentity, config.FieldApprovalTTL), lookup, &stdout)
	if err == nil || !strings.Contains(err.Error(), "evidence journal is not bound") {
		t.Fatalf("executeAdmission() error = %v, want the journal guard", err)
	}
}

func TestExecuteAdmissionFailsClosedOnTheCandidateLoad(t *testing.T) {
	stubBundle(t)
	ports := admissionLanePorts(t)
	ports.Candidates = &fakeCandidates{findErr: errors.New("records unavailable")}
	service := laneService(t, OperationAdmission, ports).(admission.Service)
	lookup := laneEnv("control", mergedLaneValues(t))

	var stdout bytes.Buffer
	err := executeAdmission(context.Background(), service, ports, controlConfig(t), laneOperation(t, config.FieldModule, config.FieldVersion, config.FieldLaneIdentity, config.FieldScannerIdentity, config.FieldScannerDatabaseIdentity, config.FieldApprovalTTL), lookup, &stdout)
	if err == nil || !strings.Contains(err.Error(), "load candidate") {
		t.Fatalf("executeAdmission() error = %v, want the candidate load failure", err)
	}
}

func TestExecuteAdmissionFailsClosedOnAnUnknownCandidate(t *testing.T) {
	stubBundle(t)
	ports := admissionLanePorts(t)
	ports.Candidates = &fakeCandidates{found: false}
	service := laneService(t, OperationAdmission, ports).(admission.Service)
	lookup := laneEnv("control", mergedLaneValues(t))

	var stdout bytes.Buffer
	err := executeAdmission(context.Background(), service, ports, controlConfig(t), laneOperation(t, config.FieldModule, config.FieldVersion, config.FieldLaneIdentity, config.FieldScannerIdentity, config.FieldScannerDatabaseIdentity, config.FieldApprovalTTL), lookup, &stdout)
	if err == nil || !strings.Contains(err.Error(), "run the intake lane first") {
		t.Fatalf("executeAdmission() error = %v, want the unknown-candidate failure", err)
	}
}

func TestExecuteAdmissionFailsClosedOnTheScan(t *testing.T) {
	stubBundle(t)
	ports := admissionLanePorts(t)
	ports.Scanner = fakeScanner{err: errors.New("scanner failed")}
	service := laneService(t, OperationAdmission, ports).(admission.Service)
	lookup := laneEnv("control", mergedLaneValues(t))

	var stdout bytes.Buffer
	err := executeAdmission(context.Background(), service, ports, controlConfig(t), laneOperation(t, config.FieldModule, config.FieldVersion, config.FieldLaneIdentity, config.FieldScannerIdentity, config.FieldScannerDatabaseIdentity, config.FieldApprovalTTL), lookup, &stdout)
	if err == nil || !strings.Contains(err.Error(), "scan candidate") {
		t.Fatalf("executeAdmission() error = %v, want the scan failure", err)
	}
}

func TestExecuteAdmissionFailsClosedOnTheScanEvidence(t *testing.T) {
	stubBundle(t)
	ports := admissionLanePorts(t)
	journal := journalOfPorts(t, ports)
	journal.failOnPut = 1
	service := laneService(t, OperationAdmission, ports).(admission.Service)
	lookup := laneEnv("control", mergedLaneValues(t))

	var stdout bytes.Buffer
	err := executeAdmission(context.Background(), service, ports, controlConfig(t), laneOperation(t, config.FieldModule, config.FieldVersion, config.FieldLaneIdentity, config.FieldScannerIdentity, config.FieldScannerDatabaseIdentity, config.FieldApprovalTTL), lookup, &stdout)
	if err == nil || !strings.Contains(err.Error(), "publish scan evidence") {
		t.Fatalf("executeAdmission() error = %v, want the scan evidence failure", err)
	}
}

func TestExecuteAdmissionFailsClosedOnTheScanEvidenceIndex(t *testing.T) {
	stubBundle(t)
	ports := admissionLanePorts(t)
	journal := journalOfPorts(t, ports)
	journal.failOnRecord = 1
	service := laneService(t, OperationAdmission, ports).(admission.Service)
	lookup := laneEnv("control", mergedLaneValues(t))

	var stdout bytes.Buffer
	err := executeAdmission(context.Background(), service, ports, controlConfig(t), laneOperation(t, config.FieldModule, config.FieldVersion, config.FieldLaneIdentity, config.FieldScannerIdentity, config.FieldScannerDatabaseIdentity, config.FieldApprovalTTL), lookup, &stdout)
	if err == nil || !strings.Contains(err.Error(), "index scan evidence") {
		t.Fatalf("executeAdmission() error = %v, want the scan index failure", err)
	}
}

func TestExecuteAdmissionFailsClosedOnTheDecision(t *testing.T) {
	stubBundle(t)
	ports := admissionLanePorts(t)
	ports.Policies = fakePolicies{err: errors.New("bundle unreadable")}
	journal := journalOfPorts(t, ports)
	service := laneService(t, OperationAdmission, ports).(admission.Service)
	lookup := laneEnv("control", mergedLaneValues(t))

	var stdout bytes.Buffer
	err := executeAdmission(context.Background(), service, ports, controlConfig(t), laneOperation(t, config.FieldModule, config.FieldVersion, config.FieldLaneIdentity, config.FieldScannerIdentity, config.FieldScannerDatabaseIdentity, config.FieldApprovalTTL), lookup, &stdout)
	if err == nil || !strings.Contains(err.Error(), "load policy") {
		t.Fatalf("executeAdmission() error = %v, want the policy load failure", err)
	}
	if len(journal.puts) != 1 {
		t.Fatalf("journal puts = %d, want only the scan evidence", len(journal.puts))
	}
}

func TestExecuteAdmissionFailsClosedOnTheDecisionEvidence(t *testing.T) {
	stubBundle(t)
	ports := admissionLanePorts(t)
	journal := journalOfPorts(t, ports)
	journal.failOnPut = 2
	service := laneService(t, OperationAdmission, ports).(admission.Service)
	lookup := laneEnv("control", mergedLaneValues(t))

	var stdout bytes.Buffer
	err := executeAdmission(context.Background(), service, ports, controlConfig(t), laneOperation(t, config.FieldModule, config.FieldVersion, config.FieldLaneIdentity, config.FieldScannerIdentity, config.FieldScannerDatabaseIdentity, config.FieldApprovalTTL), lookup, &stdout)
	if err == nil || !strings.Contains(err.Error(), "publish policy evidence") {
		t.Fatalf("executeAdmission() error = %v, want the decision evidence failure", err)
	}
}

func TestExecuteAdmissionFailsClosedOnTheApprovalEvidence(t *testing.T) {
	stubBundle(t)
	ports := admissionLanePorts(t)
	journal := journalOfPorts(t, ports)
	journal.failOnPut = 3
	service := laneService(t, OperationAdmission, ports).(admission.Service)
	lookup := laneEnv("control", mergedLaneValues(t))

	var stdout bytes.Buffer
	err := executeAdmission(context.Background(), service, ports, controlConfig(t), laneOperation(t, config.FieldModule, config.FieldVersion, config.FieldLaneIdentity, config.FieldScannerIdentity, config.FieldScannerDatabaseIdentity, config.FieldApprovalTTL), lookup, &stdout)
	if err == nil || !strings.Contains(err.Error(), "publish approval evidence") {
		t.Fatalf("executeAdmission() error = %v, want the approval evidence failure", err)
	}
}

func TestExecuteAdmissionMaterializesTheCandidateBeforeScanning(t *testing.T) {
	stubBundle(t)
	var events []string
	ports := admissionLanePorts(t)
	ports.Content = &fakeCandidateContent{events: &events}
	ports.Scanner = scannerFunc(func(context.Context, candidate.Candidate) (domainadmission.ScanResult, error) {
		events = append(events, "scan")
		return domainadmission.ScanResult{}, nil
	})
	service := laneService(t, OperationAdmission, ports).(admission.Service)
	lookup := laneEnv("control", mergedLaneValues(t))

	var stdout bytes.Buffer
	if err := executeAdmission(context.Background(), service, ports, controlConfig(t), laneOperation(t, config.FieldModule, config.FieldVersion, config.FieldLaneIdentity, config.FieldScannerIdentity, config.FieldScannerDatabaseIdentity, config.FieldApprovalTTL), lookup, &stdout); err != nil {
		t.Fatalf("executeAdmission() error = %v", err)
	}
	if len(events) != 3 || events[0] != "materialize" || events[1] != "scan" || events[2] != "scan" {
		t.Fatalf("events = %v, want the materialization before the evidence and policy scans", events)
	}
}

func TestExecuteAdmissionFailsClosedWithoutTheContentPort(t *testing.T) {
	stubBundle(t)
	ports := admissionLanePorts(t)
	ports.Content = nil
	service := laneService(t, OperationAdmission, ports).(admission.Service)
	lookup := laneEnv("control", mergedLaneValues(t))

	var stdout bytes.Buffer
	err := executeAdmission(context.Background(), service, ports, controlConfig(t), laneOperation(t, config.FieldModule, config.FieldVersion, config.FieldLaneIdentity, config.FieldScannerIdentity, config.FieldScannerDatabaseIdentity, config.FieldApprovalTTL), lookup, &stdout)
	if err == nil || !strings.Contains(err.Error(), "candidate content port is not bound") {
		t.Fatalf("executeAdmission() error = %v, want the content port guard", err)
	}
}

func TestExecuteAdmissionFailsClosedOnTheContentMaterialization(t *testing.T) {
	stubBundle(t)
	ports := admissionLanePorts(t)
	ports.Content = &fakeCandidateContent{err: errors.New("intake unavailable")}
	service := laneService(t, OperationAdmission, ports).(admission.Service)
	lookup := laneEnv("control", mergedLaneValues(t))

	var stdout bytes.Buffer
	err := executeAdmission(context.Background(), service, ports, controlConfig(t), laneOperation(t, config.FieldModule, config.FieldVersion, config.FieldLaneIdentity, config.FieldScannerIdentity, config.FieldScannerDatabaseIdentity, config.FieldApprovalTTL), lookup, &stdout)
	if err == nil || !strings.Contains(err.Error(), "materialize candidate content") {
		t.Fatalf("executeAdmission() error = %v, want the materialization failure", err)
	}
}

func TestExecuteAdmissionFailsClosedOnTheScannerIdentityProof(t *testing.T) {
	stubBundle(t)
	ports := admissionLanePorts(t)
	service := laneService(t, OperationAdmission, ports).(admission.Service)
	values := mergedLaneValues(t)
	// The retired free-text form is not a bound channel identity.
	values[config.EnvScannerIdentity] = "osv-scanner 2.2.3"
	lookup := laneEnv("control", values)
	// The operation and the bindings share the lane environment in production;
	// the test binds both to the overridden form.
	operation, err := config.OperationFromEnv(lookup, config.FieldModule, config.FieldVersion, config.FieldLaneIdentity, config.FieldScannerIdentity, config.FieldScannerDatabaseIdentity, config.FieldApprovalTTL)
	if err != nil {
		t.Fatalf("OperationFromEnv() error = %v", err)
	}

	var stdout bytes.Buffer
	err = executeAdmission(context.Background(), service, ports, controlConfig(t), operation, lookup, &stdout)
	if err == nil || !strings.Contains(err.Error(), config.EnvScannerIdentity) {
		t.Fatalf("executeAdmission() error = %v, want the scanner identity failure", err)
	}
}

func TestExecuteAdmissionFailsClosedOnTheScannerDatabaseIdentityProof(t *testing.T) {
	stubBundle(t)
	ports := admissionLanePorts(t)
	service := laneService(t, OperationAdmission, ports).(admission.Service)
	values := mergedLaneValues(t)
	// The retired free-text form is not a bound channel identity.
	values[config.EnvScannerDatabaseIdentity] = "osv-db sha256:aaa"
	lookup := laneEnv("control", values)
	// The operation and the bindings share the lane environment in production;
	// the test binds both to the overridden form.
	operation, err := config.OperationFromEnv(lookup, config.FieldModule, config.FieldVersion, config.FieldLaneIdentity, config.FieldScannerIdentity, config.FieldScannerDatabaseIdentity, config.FieldApprovalTTL)
	if err != nil {
		t.Fatalf("OperationFromEnv() error = %v", err)
	}

	var stdout bytes.Buffer
	err = executeAdmission(context.Background(), service, ports, controlConfig(t), operation, lookup, &stdout)
	if err == nil || !strings.Contains(err.Error(), config.EnvScannerDatabaseIdentity) {
		t.Fatalf("executeAdmission() error = %v, want the scanner database identity failure", err)
	}
}

func TestExecutePromotionPromotesUnderTheRecordedApproval(t *testing.T) {
	ports := promotionLanePorts(t)
	registry := &fakeRegistry{}
	ports.Registry = registry
	candidates := ports.Candidates.(*fakeCandidates)
	service := laneService(t, OperationPromotion, ports).(promotion.Service)

	var stdout bytes.Buffer
	err := executePromotion(context.Background(), service, ports, controlConfig(t), laneOperation(t, config.FieldModule, config.FieldVersion), &stdout)
	if err != nil {
		t.Fatalf("executePromotion() error = %v", err)
	}
	if registry.published != 1 {
		t.Fatalf("registry publishes = %d, want 1", registry.published)
	}
	if len(candidates.saved) != 1 || candidates.saved[0].State() != candidate.StateApproved {
		t.Fatalf("saved candidates = %+v, want the approved candidate", candidates.saved)
	}
	if !strings.Contains(stdout.String(), "state=approved") {
		t.Fatalf("stdout = %q, want the promotion result line", stdout.String())
	}
}

func TestExecutePromotionFailsClosedOnTheTrailLoad(t *testing.T) {
	ports := promotionLanePorts(t)
	ports.EvidenceStore = fakeEvidenceStore{err: errors.New("index unavailable")}
	service := laneService(t, OperationPromotion, ports).(promotion.Service)

	var stdout bytes.Buffer
	err := executePromotion(context.Background(), service, ports, controlConfig(t), laneOperation(t, config.FieldModule, config.FieldVersion), &stdout)
	if err == nil || !strings.Contains(err.Error(), "load evidence trail") {
		t.Fatalf("executePromotion() error = %v, want the trail load failure", err)
	}
}

func TestExecutePromotionFailsClosedWithoutAnApproval(t *testing.T) {
	ports := promotionLanePorts(t)
	ports.EvidenceStore = fakeEvidenceStore{trail: []evidence.Reference{testReference(t, evidence.TypeScan, "scans/1", laneTime, nil)}}
	service := laneService(t, OperationPromotion, ports).(promotion.Service)

	var stdout bytes.Buffer
	err := executePromotion(context.Background(), service, ports, controlConfig(t), laneOperation(t, config.FieldModule, config.FieldVersion), &stdout)
	if err == nil || !strings.Contains(err.Error(), "no approval evidence recorded") {
		t.Fatalf("executePromotion() error = %v, want the missing approval failure", err)
	}
}

func TestExecutePromotionFailsClosedOnAnExpiryLessApproval(t *testing.T) {
	ports := promotionLanePorts(t)
	ports.EvidenceStore = fakeEvidenceStore{trail: []evidence.Reference{
		testReference(t, evidence.TypeApproval, "approvals/1", laneTime, nil),
	}}
	service := laneService(t, OperationPromotion, ports).(promotion.Service)

	var stdout bytes.Buffer
	err := executePromotion(context.Background(), service, ports, controlConfig(t), laneOperation(t, config.FieldModule, config.FieldVersion), &stdout)
	if err == nil || !strings.Contains(err.Error(), "carries no expiry") {
		t.Fatalf("executePromotion() error = %v, want the missing expiry failure", err)
	}
}

func TestExecutePromotionFailsClosedOnAnExpiredApproval(t *testing.T) {
	ports := promotionLanePorts(t)
	expiresAt := laneTime.Add(-time.Hour)
	ports.EvidenceStore = fakeEvidenceStore{trail: []evidence.Reference{
		testReference(t, evidence.TypeApproval, "approvals/1", laneTime.Add(-2*time.Hour), &expiresAt),
	}}
	service := laneService(t, OperationPromotion, ports).(promotion.Service)

	var stdout bytes.Buffer
	err := executePromotion(context.Background(), service, ports, controlConfig(t), laneOperation(t, config.FieldModule, config.FieldVersion), &stdout)
	if err == nil || !strings.Contains(err.Error(), "approval is expired") {
		t.Fatalf("executePromotion() error = %v, want the expired approval failure", err)
	}
}

func TestExecutePromotionFailsClosedOnThePublish(t *testing.T) {
	ports := promotionLanePorts(t)
	ports.Registry = &fakeRegistry{err: errors.New("approved zone unavailable")}
	service := laneService(t, OperationPromotion, ports).(promotion.Service)

	var stdout bytes.Buffer
	err := executePromotion(context.Background(), service, ports, controlConfig(t), laneOperation(t, config.FieldModule, config.FieldVersion), &stdout)
	if err == nil || !strings.Contains(err.Error(), "publish to approved zone") {
		t.Fatalf("executePromotion() error = %v, want the publish failure", err)
	}
}

func TestExecuteRevalidationRecordsTheFreshEvidence(t *testing.T) {
	stubBundle(t)
	ports := revalidationLanePorts(t)
	journal := journalOfPorts(t, ports)
	service := laneService(t, OperationRevalidation, ports).(revalidation.Service)
	lookup := laneEnv("control", mergedLaneValues(t))

	var stdout bytes.Buffer
	err := executeRevalidation(context.Background(), service, ports, controlConfig(t), laneOperation(t, config.FieldModule, config.FieldVersion, config.FieldScannerIdentity, config.FieldScannerDatabaseIdentity), lookup, &stdout)
	if err != nil {
		t.Fatalf("executeRevalidation() error = %v", err)
	}
	if len(journal.puts) != 2 {
		t.Fatalf("journal puts = %d, want scan and decision evidence", len(journal.puts))
	}
	if journal.puts[0].Type() != evidence.TypeScan || journal.puts[1].Type() != evidence.TypePolicy {
		t.Fatalf("journal puts = %q, %q", journal.puts[0].Type(), journal.puts[1].Type())
	}
	if !strings.Contains(stdout.String(), "decision=admit") {
		t.Fatalf("stdout = %q, want the revalidation result line", stdout.String())
	}
}

func TestExecuteRevalidationQuarantinesOnPolicyChange(t *testing.T) {
	stubBundle(t)
	ports := revalidationLanePorts(t)
	ports.Scanner = fakeScanner{result: domainadmission.ScanResult{MaxCVSS: 9.8}}
	candidates := ports.Candidates.(*fakeCandidates)
	service := laneService(t, OperationRevalidation, ports).(revalidation.Service)
	lookup := laneEnv("control", mergedLaneValues(t))

	var stdout bytes.Buffer
	err := executeRevalidation(context.Background(), service, ports, controlConfig(t), laneOperation(t, config.FieldModule, config.FieldVersion, config.FieldScannerIdentity, config.FieldScannerDatabaseIdentity), lookup, &stdout)
	if err != nil {
		t.Fatalf("executeRevalidation() error = %v", err)
	}
	if len(candidates.saved) != 1 || candidates.saved[0].State() != candidate.StateQuarantined {
		t.Fatalf("saved candidates = %+v, want the quarantined candidate", candidates.saved)
	}
	if !strings.Contains(stdout.String(), "decision=quarantine") {
		t.Fatalf("stdout = %q, want the quarantine result line", stdout.String())
	}
}

func TestExecuteRevalidationFailsClosedWithoutTheJournal(t *testing.T) {
	stubBundle(t)
	ports := revalidationLanePorts(t)
	ports.Journal = nil
	service := laneService(t, OperationRevalidation, ports).(revalidation.Service)
	lookup := laneEnv("control", mergedLaneValues(t))

	var stdout bytes.Buffer
	err := executeRevalidation(context.Background(), service, ports, controlConfig(t), laneOperation(t, config.FieldModule, config.FieldVersion, config.FieldScannerIdentity, config.FieldScannerDatabaseIdentity), lookup, &stdout)
	if err == nil || !strings.Contains(err.Error(), "evidence journal is not bound") {
		t.Fatalf("executeRevalidation() error = %v, want the journal guard", err)
	}
}

func TestExecuteRevalidationFailsClosedOnThePolicyIdentity(t *testing.T) {
	original := readBundle
	t.Cleanup(func() { readBundle = original })
	readBundle = func(string) ([]byte, error) { return nil, errors.New("no bundle") }

	ports := revalidationLanePorts(t)
	service := laneService(t, OperationRevalidation, ports).(revalidation.Service)
	lookup := laneEnv("control", mergedLaneValues(t))

	var stdout bytes.Buffer
	err := executeRevalidation(context.Background(), service, ports, controlConfig(t), laneOperation(t, config.FieldModule, config.FieldVersion, config.FieldScannerIdentity, config.FieldScannerDatabaseIdentity), lookup, &stdout)
	if err == nil || !strings.Contains(err.Error(), "read policy bundle") {
		t.Fatalf("executeRevalidation() error = %v, want the bundle read failure", err)
	}
}

func TestExecuteRevalidationFailsClosedOnTheCandidateLoad(t *testing.T) {
	stubBundle(t)
	ports := revalidationLanePorts(t)
	ports.Candidates = &fakeCandidates{findErr: errors.New("records unavailable")}
	service := laneService(t, OperationRevalidation, ports).(revalidation.Service)
	lookup := laneEnv("control", mergedLaneValues(t))

	var stdout bytes.Buffer
	err := executeRevalidation(context.Background(), service, ports, controlConfig(t), laneOperation(t, config.FieldModule, config.FieldVersion, config.FieldScannerIdentity, config.FieldScannerDatabaseIdentity), lookup, &stdout)
	if err == nil || !strings.Contains(err.Error(), "load candidate") {
		t.Fatalf("executeRevalidation() error = %v, want the candidate load failure", err)
	}
}

func TestExecuteRevalidationFailsClosedOnAnUnknownCandidate(t *testing.T) {
	stubBundle(t)
	ports := revalidationLanePorts(t)
	ports.Candidates = &fakeCandidates{found: false}
	service := laneService(t, OperationRevalidation, ports).(revalidation.Service)
	lookup := laneEnv("control", mergedLaneValues(t))

	var stdout bytes.Buffer
	err := executeRevalidation(context.Background(), service, ports, controlConfig(t), laneOperation(t, config.FieldModule, config.FieldVersion, config.FieldScannerIdentity, config.FieldScannerDatabaseIdentity), lookup, &stdout)
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("executeRevalidation() error = %v, want the unknown-candidate failure", err)
	}
}

func TestExecuteRevalidationFailsClosedOnTheScan(t *testing.T) {
	stubBundle(t)
	ports := revalidationLanePorts(t)
	ports.Scanner = fakeScanner{err: errors.New("scanner failed")}
	service := laneService(t, OperationRevalidation, ports).(revalidation.Service)
	lookup := laneEnv("control", mergedLaneValues(t))

	var stdout bytes.Buffer
	err := executeRevalidation(context.Background(), service, ports, controlConfig(t), laneOperation(t, config.FieldModule, config.FieldVersion, config.FieldScannerIdentity, config.FieldScannerDatabaseIdentity), lookup, &stdout)
	if err == nil || !strings.Contains(err.Error(), "scan candidate") {
		t.Fatalf("executeRevalidation() error = %v, want the scan failure", err)
	}
}

func TestExecuteRevalidationFailsClosedOnTheScanEvidence(t *testing.T) {
	stubBundle(t)
	ports := revalidationLanePorts(t)
	journal := journalOfPorts(t, ports)
	journal.failOnPut = 1
	service := laneService(t, OperationRevalidation, ports).(revalidation.Service)
	lookup := laneEnv("control", mergedLaneValues(t))

	var stdout bytes.Buffer
	err := executeRevalidation(context.Background(), service, ports, controlConfig(t), laneOperation(t, config.FieldModule, config.FieldVersion, config.FieldScannerIdentity, config.FieldScannerDatabaseIdentity), lookup, &stdout)
	if err == nil || !strings.Contains(err.Error(), "publish scan evidence") {
		t.Fatalf("executeRevalidation() error = %v, want the scan evidence failure", err)
	}
}

func TestExecuteRevalidationFailsClosedOnTheDecision(t *testing.T) {
	stubBundle(t)
	ports := revalidationLanePorts(t)
	ports.Policies = fakePolicies{err: errors.New("bundle unreadable")}
	service := laneService(t, OperationRevalidation, ports).(revalidation.Service)
	lookup := laneEnv("control", mergedLaneValues(t))

	var stdout bytes.Buffer
	err := executeRevalidation(context.Background(), service, ports, controlConfig(t), laneOperation(t, config.FieldModule, config.FieldVersion, config.FieldScannerIdentity, config.FieldScannerDatabaseIdentity), lookup, &stdout)
	if err == nil || !strings.Contains(err.Error(), "load policy") {
		t.Fatalf("executeRevalidation() error = %v, want the policy load failure", err)
	}
}

func TestExecuteRevalidationFailsClosedOnTheDecisionEvidence(t *testing.T) {
	stubBundle(t)
	ports := revalidationLanePorts(t)
	journal := journalOfPorts(t, ports)
	journal.failOnPut = 2
	service := laneService(t, OperationRevalidation, ports).(revalidation.Service)
	lookup := laneEnv("control", mergedLaneValues(t))

	var stdout bytes.Buffer
	err := executeRevalidation(context.Background(), service, ports, controlConfig(t), laneOperation(t, config.FieldModule, config.FieldVersion, config.FieldScannerIdentity, config.FieldScannerDatabaseIdentity), lookup, &stdout)
	if err == nil || !strings.Contains(err.Error(), "publish policy evidence") {
		t.Fatalf("executeRevalidation() error = %v, want the decision evidence failure", err)
	}
}

func TestExecuteRevalidationMaterializesTheCandidateBeforeScanning(t *testing.T) {
	stubBundle(t)
	var events []string
	ports := revalidationLanePorts(t)
	ports.Content = &fakeCandidateContent{events: &events}
	ports.Scanner = scannerFunc(func(context.Context, candidate.Candidate) (domainadmission.ScanResult, error) {
		events = append(events, "scan")
		return domainadmission.ScanResult{}, nil
	})
	service := laneService(t, OperationRevalidation, ports).(revalidation.Service)
	lookup := laneEnv("control", mergedLaneValues(t))

	var stdout bytes.Buffer
	if err := executeRevalidation(context.Background(), service, ports, controlConfig(t), laneOperation(t, config.FieldModule, config.FieldVersion, config.FieldScannerIdentity, config.FieldScannerDatabaseIdentity), lookup, &stdout); err != nil {
		t.Fatalf("executeRevalidation() error = %v", err)
	}
	if len(events) != 3 || events[0] != "materialize" || events[1] != "scan" || events[2] != "scan" {
		t.Fatalf("events = %v, want the materialization before the evidence and policy scans", events)
	}
}

func TestExecuteRevalidationFailsClosedWithoutTheContentPort(t *testing.T) {
	stubBundle(t)
	ports := revalidationLanePorts(t)
	ports.Content = nil
	service := laneService(t, OperationRevalidation, ports).(revalidation.Service)
	lookup := laneEnv("control", mergedLaneValues(t))

	var stdout bytes.Buffer
	err := executeRevalidation(context.Background(), service, ports, controlConfig(t), laneOperation(t, config.FieldModule, config.FieldVersion, config.FieldScannerIdentity, config.FieldScannerDatabaseIdentity), lookup, &stdout)
	if err == nil || !strings.Contains(err.Error(), "candidate content port is not bound") {
		t.Fatalf("executeRevalidation() error = %v, want the content port guard", err)
	}
}

func TestExecuteRevalidationFailsClosedOnTheContentMaterialization(t *testing.T) {
	stubBundle(t)
	ports := revalidationLanePorts(t)
	ports.Content = &fakeCandidateContent{err: errors.New("intake unavailable")}
	service := laneService(t, OperationRevalidation, ports).(revalidation.Service)
	lookup := laneEnv("control", mergedLaneValues(t))

	var stdout bytes.Buffer
	err := executeRevalidation(context.Background(), service, ports, controlConfig(t), laneOperation(t, config.FieldModule, config.FieldVersion, config.FieldScannerIdentity, config.FieldScannerDatabaseIdentity), lookup, &stdout)
	if err == nil || !strings.Contains(err.Error(), "materialize candidate content") {
		t.Fatalf("executeRevalidation() error = %v, want the materialization failure", err)
	}
}

func TestExecuteRevalidationFailsClosedOnTheScannerIdentityProof(t *testing.T) {
	stubBundle(t)
	ports := revalidationLanePorts(t)
	service := laneService(t, OperationRevalidation, ports).(revalidation.Service)
	values := mergedLaneValues(t)
	// The retired free-text form is not a bound channel identity.
	values[config.EnvScannerIdentity] = "osv-scanner 2.2.3"
	lookup := laneEnv("control", values)
	// The operation and the bindings share the lane environment in production;
	// the test binds both to the overridden form.
	operation, err := config.OperationFromEnv(lookup, config.FieldModule, config.FieldVersion, config.FieldScannerIdentity, config.FieldScannerDatabaseIdentity)
	if err != nil {
		t.Fatalf("OperationFromEnv() error = %v", err)
	}

	var stdout bytes.Buffer
	err = executeRevalidation(context.Background(), service, ports, controlConfig(t), operation, lookup, &stdout)
	if err == nil || !strings.Contains(err.Error(), config.EnvScannerIdentity) {
		t.Fatalf("executeRevalidation() error = %v, want the scanner identity failure", err)
	}
}

func TestExecuteRevalidationFailsClosedOnTheScannerDatabaseIdentityProof(t *testing.T) {
	stubBundle(t)
	ports := revalidationLanePorts(t)
	service := laneService(t, OperationRevalidation, ports).(revalidation.Service)
	values := mergedLaneValues(t)
	// The retired free-text form is not a bound channel identity.
	values[config.EnvScannerDatabaseIdentity] = "osv-db sha256:aaa"
	lookup := laneEnv("control", values)
	// The operation and the bindings share the lane environment in production;
	// the test binds both to the overridden form.
	operation, err := config.OperationFromEnv(lookup, config.FieldModule, config.FieldVersion, config.FieldScannerIdentity, config.FieldScannerDatabaseIdentity)
	if err != nil {
		t.Fatalf("OperationFromEnv() error = %v", err)
	}

	var stdout bytes.Buffer
	err = executeRevalidation(context.Background(), service, ports, controlConfig(t), operation, lookup, &stdout)
	if err == nil || !strings.Contains(err.Error(), config.EnvScannerDatabaseIdentity) {
		t.Fatalf("executeRevalidation() error = %v, want the scanner database identity failure", err)
	}
}

func TestExecuteRevocationBlocksAndRecords(t *testing.T) {
	ports := revocationLanePorts(t)
	gate := &fakeGate{}
	ports.Gate = gate
	journal := journalOfPorts(t, ports)
	candidates := ports.Candidates.(*fakeCandidates)
	service := laneService(t, OperationRevocation, ports).(revocation.Service)

	var stdout bytes.Buffer
	err := executeRevocation(context.Background(), service, ports, controlConfig(t), laneOperation(t, config.FieldModule, config.FieldVersion, config.FieldLaneIdentity, config.FieldRevocationReason), &stdout)
	if err != nil {
		t.Fatalf("executeRevocation() error = %v", err)
	}
	if gate.blocked != 1 {
		t.Fatalf("gate blocks = %d, want 1", gate.blocked)
	}
	if len(journal.puts) != 1 || journal.puts[0].Type() != evidence.TypeRevocation {
		t.Fatalf("journal puts = %+v, want the revocation payload", journal.puts)
	}
	if len(journal.records) != 1 {
		t.Fatalf("journal records = %d, want the use-case-recorded reference", len(journal.records))
	}
	if len(candidates.saved) != 1 || candidates.saved[0].State() != candidate.StateRevoked {
		t.Fatalf("saved candidates = %+v, want the revoked candidate", candidates.saved)
	}
	if !strings.Contains(stdout.String(), "state=revoked download_block=true") {
		t.Fatalf("stdout = %q, want the revocation result line", stdout.String())
	}
}

func TestExecuteRevocationFailsClosedWithoutTheJournal(t *testing.T) {
	ports := revocationLanePorts(t)
	ports.Journal = nil
	service := laneService(t, OperationRevocation, ports).(revocation.Service)

	var stdout bytes.Buffer
	err := executeRevocation(context.Background(), service, ports, controlConfig(t), laneOperation(t, config.FieldModule, config.FieldVersion, config.FieldLaneIdentity, config.FieldRevocationReason), &stdout)
	if err == nil || !strings.Contains(err.Error(), "evidence journal is not bound") {
		t.Fatalf("executeRevocation() error = %v, want the journal guard", err)
	}
}

func TestExecuteRevocationFailsClosedOnTheCandidateLoad(t *testing.T) {
	ports := revocationLanePorts(t)
	ports.Candidates = &fakeCandidates{findErr: errors.New("records unavailable")}
	service := laneService(t, OperationRevocation, ports).(revocation.Service)

	var stdout bytes.Buffer
	err := executeRevocation(context.Background(), service, ports, controlConfig(t), laneOperation(t, config.FieldModule, config.FieldVersion, config.FieldLaneIdentity, config.FieldRevocationReason), &stdout)
	if err == nil || !strings.Contains(err.Error(), "load candidate") {
		t.Fatalf("executeRevocation() error = %v, want the candidate load failure", err)
	}
}

func TestExecuteRevocationFailsClosedOnAnUnknownCandidate(t *testing.T) {
	ports := revocationLanePorts(t)
	ports.Candidates = &fakeCandidates{found: false}
	service := laneService(t, OperationRevocation, ports).(revocation.Service)

	var stdout bytes.Buffer
	err := executeRevocation(context.Background(), service, ports, controlConfig(t), laneOperation(t, config.FieldModule, config.FieldVersion, config.FieldLaneIdentity, config.FieldRevocationReason), &stdout)
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("executeRevocation() error = %v, want the unknown-candidate failure", err)
	}
}

func TestExecuteRevocationFailsClosedOnTheEvidencePublish(t *testing.T) {
	ports := revocationLanePorts(t)
	journal := journalOfPorts(t, ports)
	journal.putErr = errors.New("payload store unavailable")
	service := laneService(t, OperationRevocation, ports).(revocation.Service)

	var stdout bytes.Buffer
	err := executeRevocation(context.Background(), service, ports, controlConfig(t), laneOperation(t, config.FieldModule, config.FieldVersion, config.FieldLaneIdentity, config.FieldRevocationReason), &stdout)
	if err == nil || !strings.Contains(err.Error(), "publish revocation evidence") {
		t.Fatalf("executeRevocation() error = %v, want the payload publish failure", err)
	}
}

func TestExecuteRevocationFailsClosedOnTheDownloadBlock(t *testing.T) {
	ports := revocationLanePorts(t)
	ports.Gate = &fakeGate{err: errors.New("gate unavailable")}
	service := laneService(t, OperationRevocation, ports).(revocation.Service)

	var stdout bytes.Buffer
	err := executeRevocation(context.Background(), service, ports, controlConfig(t), laneOperation(t, config.FieldModule, config.FieldVersion, config.FieldLaneIdentity, config.FieldRevocationReason), &stdout)
	if err == nil || !strings.Contains(err.Error(), "block downloads") {
		t.Fatalf("executeRevocation() error = %v, want the download block failure", err)
	}
}

func TestJournalOfBindsTheJournal(t *testing.T) {
	if _, err := journalOf(Ports{}); err == nil {
		t.Fatal("journalOf(empty) error = nil, want the journal guard")
	}
	journal, err := journalOf(Ports{Journal: &fakeJournal{}})
	if err != nil {
		t.Fatalf("journalOf() error = %v", err)
	}
	if journal == nil {
		t.Fatal("journalOf() = nil, want the bound journal")
	}
}

func TestProduceEvidencePublishesAndIndexes(t *testing.T) {
	journal := &fakeJournal{}
	subject := pendingCandidate(t)
	reference, err := produceEvidence(context.Background(), journal, subject, evidence.TypeScan, "osv-scanner 2.2.3", []byte(`{"ok":true}`), laneTime, nil)
	if err != nil {
		t.Fatalf("produceEvidence() error = %v", err)
	}
	if reference.Type() != evidence.TypeScan {
		t.Fatalf("produceEvidence() type = %q", reference.Type())
	}
	if len(journal.puts) != 1 || len(journal.records) != 1 {
		t.Fatalf("journal calls = %d puts, %d records, want 1/1", len(journal.puts), len(journal.records))
	}

	journal = &fakeJournal{putErr: errors.New("put failed")}
	if _, err := produceEvidence(context.Background(), journal, subject, evidence.TypeScan, "issuer", []byte(`{"ok":true}`), laneTime, nil); err == nil {
		t.Fatal("produceEvidence() error = nil, want the publish failure")
	}

	journal = &fakeJournal{recordErr: errors.New("record failed")}
	if _, err := produceEvidence(context.Background(), journal, subject, evidence.TypeScan, "issuer", []byte(`{"ok":true}`), laneTime, nil); err == nil {
		t.Fatal("produceEvidence() error = nil, want the index failure")
	}
}

func TestLatestApproval(t *testing.T) {
	if _, err := latestApproval(nil, laneTime); err == nil {
		t.Fatal("latestApproval(nil) error = nil, want the missing approval failure")
	}

	trail := []evidence.Reference{testReference(t, evidence.TypeScan, "scans/1", laneTime, nil)}
	if _, err := latestApproval(trail, laneTime); err == nil {
		t.Fatal("latestApproval(scan only) error = nil, want the missing approval failure")
	}

	withoutExpiry := []evidence.Reference{testReference(t, evidence.TypeApproval, "approvals/1", laneTime, nil)}
	if _, err := latestApproval(withoutExpiry, laneTime); err == nil {
		t.Fatal("latestApproval(no expiry) error = nil, want the expiry failure")
	}

	expiredAt := laneTime.Add(-time.Hour)
	expired := []evidence.Reference{testReference(t, evidence.TypeApproval, "approvals/1", laneTime.Add(-2*time.Hour), &expiredAt)}
	if _, err := latestApproval(expired, laneTime); err == nil {
		t.Fatal("latestApproval(expired) error = nil, want the expired failure")
	}

	olderExpiry := laneTime.Add(time.Hour)
	newerExpiry := laneTime.Add(2 * time.Hour)
	trail = []evidence.Reference{
		testReference(t, evidence.TypeApproval, "approvals/newer", laneTime.Add(-time.Hour), &newerExpiry),
		testReference(t, evidence.TypeApproval, "approvals/older", laneTime.Add(-2*time.Hour), &olderExpiry),
	}
	newest, err := latestApproval(trail, laneTime)
	if err != nil {
		t.Fatalf("latestApproval() error = %v", err)
	}
	if newest.Reference() != "approvals/newer" {
		t.Fatalf("latestApproval() = %q, want the newest approval", newest.Reference())
	}
}

func TestPolicyIdentity(t *testing.T) {
	if _, err := policyIdentity(nil); err == nil {
		t.Fatal("policyIdentity(nil) error = nil, want the lookup failure")
	}

	original := readBundle
	t.Cleanup(func() { readBundle = original })
	readBundle = func(string) ([]byte, error) { return nil, errors.New("no bundle") }
	lookup := laneEnv("control", mergedLaneValues(t))
	if _, err := policyIdentity(lookup); err == nil {
		t.Fatal("policyIdentity() error = nil, want the bundle read failure")
	}

	content := []byte(`{"schema":"dependency-policy/v1"}`)
	readBundle = func(string) ([]byte, error) { return content, nil }
	identity, err := policyIdentity(lookup)
	if err != nil {
		t.Fatalf("policyIdentity() error = %v", err)
	}
	sum := sha256.Sum256(content)
	want := policy.SchemaID + "@sha256:" + hex.EncodeToString(sum[:])
	if identity != want {
		t.Fatalf("policyIdentity() = %q, want %q", identity, want)
	}
}

func TestContentOfBindsTheContentPort(t *testing.T) {
	if _, err := contentOf(Ports{}); err == nil {
		t.Fatal("contentOf(empty) error = nil, want the content port guard")
	}
	content, err := contentOf(Ports{Content: &fakeCandidateContent{}})
	if err != nil {
		t.Fatalf("contentOf() error = %v", err)
	}
	if content == nil {
		t.Fatal("contentOf() = nil, want the bound content port")
	}
}

func TestProveChannelIdentity(t *testing.T) {
	values := mergedLaneValues(t)
	identity, err := domaintooling.ParseTool(values[config.EnvScannerIdentity])
	if err != nil {
		t.Fatalf("ParseTool() error = %v", err)
	}
	proven, err := proveChannelIdentity(identity, values[config.EnvScannerTool])
	if err != nil {
		t.Fatalf("proveChannelIdentity() error = %v", err)
	}
	if proven != values[config.EnvScannerIdentity] {
		t.Fatalf("proveChannelIdentity() = %q, want %q", proven, values[config.EnvScannerIdentity])
	}

	t.Run("unreadable artifact", func(t *testing.T) {
		original := readArtifact
		t.Cleanup(func() { readArtifact = original })
		readArtifact = func(string) ([]byte, error) {
			return nil, errors.New("unreadable")
		}
		if _, err := proveChannelIdentity(identity, values[config.EnvScannerTool]); err == nil {
			t.Fatal("proveChannelIdentity() error = nil, want the read failure")
		}
	})

	t.Run("digest mismatch", func(t *testing.T) {
		other := filepath.Join(t.TempDir(), "other")
		if err := os.WriteFile(other, []byte("other content"), 0o644); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}
		if _, err := proveChannelIdentity(identity, other); err == nil {
			t.Fatal("proveChannelIdentity() error = nil, want the digest mismatch")
		}
	})
}

func TestProvenScannerIdentity(t *testing.T) {
	values := mergedLaneValues(t)
	lookup := laneEnv("control", values)
	operation, err := config.OperationFromEnv(lookup, config.FieldScannerIdentity)
	if err != nil {
		t.Fatalf("OperationFromEnv() error = %v", err)
	}
	identity, err := provenScannerIdentity(operation, lookup)
	if err != nil {
		t.Fatalf("provenScannerIdentity() error = %v", err)
	}
	if identity != values[config.EnvScannerIdentity] {
		t.Fatalf("provenScannerIdentity() = %q, want the proven form %q", identity, values[config.EnvScannerIdentity])
	}

	t.Run("malformed identity", func(t *testing.T) {
		values := mergedLaneValues(t)
		values[config.EnvScannerIdentity] = "osv-scanner 2.2.3"
		lookup := laneEnv("control", values)
		operation, err := config.OperationFromEnv(lookup, config.FieldScannerIdentity)
		if err != nil {
			t.Fatalf("OperationFromEnv() error = %v", err)
		}
		if _, err := provenScannerIdentity(operation, lookup); err == nil || !strings.Contains(err.Error(), config.EnvScannerIdentity) {
			t.Fatalf("provenScannerIdentity() error = %v, want the identity failure", err)
		}
	})

	t.Run("nil lookup", func(t *testing.T) {
		if _, err := provenScannerIdentity(operation, nil); err == nil {
			t.Fatal("provenScannerIdentity( nil lookup ) error = nil, want the binding failure")
		}
	})
}

func TestProvenScannerDatabaseIdentity(t *testing.T) {
	values := mergedLaneValues(t)
	lookup := laneEnv("control", values)
	operation, err := config.OperationFromEnv(lookup, config.FieldScannerDatabaseIdentity)
	if err != nil {
		t.Fatalf("OperationFromEnv() error = %v", err)
	}
	identity, err := provenScannerDatabaseIdentity(operation, lookup)
	if err != nil {
		t.Fatalf("provenScannerDatabaseIdentity() error = %v", err)
	}
	if identity != values[config.EnvScannerDatabaseIdentity] {
		t.Fatalf("provenScannerDatabaseIdentity() = %q, want the proven form %q", identity, values[config.EnvScannerDatabaseIdentity])
	}

	t.Run("malformed identity", func(t *testing.T) {
		values := mergedLaneValues(t)
		values[config.EnvScannerDatabaseIdentity] = "osv-db sha256:aaa"
		lookup := laneEnv("control", values)
		operation, err := config.OperationFromEnv(lookup, config.FieldScannerDatabaseIdentity)
		if err != nil {
			t.Fatalf("OperationFromEnv() error = %v", err)
		}
		if _, err := provenScannerDatabaseIdentity(operation, lookup); err == nil || !strings.Contains(err.Error(), config.EnvScannerDatabaseIdentity) {
			t.Fatalf("provenScannerDatabaseIdentity() error = %v, want the identity failure", err)
		}
	})

	t.Run("nil lookup", func(t *testing.T) {
		if _, err := provenScannerDatabaseIdentity(operation, nil); err == nil {
			t.Fatal("provenScannerDatabaseIdentity( nil lookup ) error = nil, want the binding failure")
		}
	})
}

func TestOperationFields(t *testing.T) {
	for _, operation := range []Operation{OperationIntake, OperationAdmission, OperationPromotion, OperationRevalidation, OperationRevocation} {
		if len(operationFields(operation)) == 0 {
			t.Errorf("operationFields(%q) = empty, want the required inputs", operation)
		}
	}
	if got := operationFields(Operation("bogus")); got != nil {
		t.Fatalf("operationFields(bogus) = %v, want nil", got)
	}
}

func TestExecuteRejectsAnUnknownOperation(t *testing.T) {
	var stdout bytes.Buffer
	err := execute(context.Background(), Operation("bogus"), nil, Ports{}, config.Config{}, config.Operation{}, nil, &stdout)
	if err == nil || !strings.Contains(err.Error(), "unknown operation") {
		t.Fatalf("execute() error = %v, want the unknown operation failure", err)
	}
}

func TestExecuteRoutesEveryLane(t *testing.T) {
	stubBundle(t)
	lookup := laneEnv("control", mergedLaneValues(t))
	lanes := []struct {
		operation Operation
		ports     func(t *testing.T) Ports
		fields    []config.Field
		want      string
	}{
		{OperationIntake, fullPorts, []config.Field{config.FieldModule, config.FieldVersion}, "state=pending"},
		{OperationAdmission, admissionLanePorts, []config.Field{config.FieldModule, config.FieldVersion, config.FieldLaneIdentity, config.FieldScannerIdentity, config.FieldScannerDatabaseIdentity, config.FieldApprovalTTL}, "decision=admit"},
		{OperationPromotion, promotionLanePorts, []config.Field{config.FieldModule, config.FieldVersion}, "state=approved"},
		{OperationRevalidation, revalidationLanePorts, []config.Field{config.FieldModule, config.FieldVersion, config.FieldScannerIdentity, config.FieldScannerDatabaseIdentity}, "decision=admit"},
		{OperationRevocation, revocationLanePorts, []config.Field{config.FieldModule, config.FieldVersion, config.FieldLaneIdentity, config.FieldRevocationReason}, "state=revoked"},
	}
	for _, lane := range lanes {
		t.Run(string(lane.operation), func(t *testing.T) {
			ports := lane.ports(t)
			service := laneService(t, lane.operation, ports)
			var stdout bytes.Buffer
			err := execute(context.Background(), lane.operation, service, ports, controlConfig(t), laneOperation(t, lane.fields...), lookup, &stdout)
			if err != nil {
				t.Fatalf("execute() error = %v", err)
			}
			if !strings.Contains(stdout.String(), lane.want) {
				t.Fatalf("stdout = %q, want %q", stdout.String(), lane.want)
			}
		})
	}
}
