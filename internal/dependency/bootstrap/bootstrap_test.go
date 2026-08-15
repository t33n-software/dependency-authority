package bootstrap

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/t33n-software/dependency-authority/internal/dependency/adapters/inbound/config"
	"github.com/t33n-software/dependency-authority/internal/dependency/domain/admission"
	"github.com/t33n-software/dependency-authority/internal/dependency/domain/candidate"
	"github.com/t33n-software/dependency-authority/internal/dependency/domain/evidence"
)

type fakeUpstream struct{}

func (fakeUpstream) FetchDigest(context.Context, candidate.Ecosystem, string, string) (string, error) {
	return "", nil
}

type fakeScanner struct{}

func (fakeScanner) Scan(context.Context, candidate.Candidate) (admission.ScanResult, error) {
	return admission.ScanResult{}, nil
}

type fakePolicies struct{}

func (fakePolicies) Policy(context.Context, candidate.Ecosystem) (admission.Policy, error) {
	return admission.Policy{}, nil
}

type fakeCandidates struct{}

func (fakeCandidates) Save(context.Context, candidate.Candidate) error {
	return nil
}

func (fakeCandidates) Find(context.Context, candidate.Ecosystem, string, string) (candidate.Candidate, bool, error) {
	return candidate.Candidate{}, false, nil
}

type fakeEvidenceStore struct{}

func (fakeEvidenceStore) Evidence(context.Context, candidate.Ecosystem, string, string) ([]evidence.Reference, error) {
	return nil, nil
}

type fakeRegistry struct{}

func (fakeRegistry) Publish(context.Context, candidate.Candidate, []evidence.Reference) error {
	return nil
}

type fakeGate struct{}

func (fakeGate) Block(context.Context, candidate.Candidate) error {
	return nil
}

type fakeRecorder struct{}

func (fakeRecorder) Record(context.Context, candidate.Candidate, evidence.Reference) error {
	return nil
}

func fullPorts() Ports {
	return Ports{
		Upstream:      fakeUpstream{},
		Scanner:       fakeScanner{},
		Policies:      fakePolicies{},
		Candidates:    fakeCandidates{},
		EvidenceStore: fakeEvidenceStore{},
		Registry:      fakeRegistry{},
		Gate:          fakeGate{},
		Recorder:      fakeRecorder{},
		Now:           func() time.Time { return time.Now() },
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

func TestRunRejectsInvalidConfiguration(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), OperationIntake, envWith("", ""), fullPorts(), &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run() = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "load controller configuration") {
		t.Fatalf("stderr = %q, want configuration error", stderr.String())
	}
}

func TestRunRejectsZoneMismatch(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), OperationIntake, envWith("control", "go"), fullPorts(), &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run() = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "must run in the intake zone") {
		t.Fatalf("stderr = %q, want zone error", stderr.String())
	}
}

func TestRunFailsClosedOnUnboundPorts(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), OperationIntake, envWith("intake", "go"), Ports{}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run() = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "bind dependency-intake-controller") {
		t.Fatalf("stderr = %q, want bind error", stderr.String())
	}
}

func TestRunSuccess(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), OperationIntake, envWith("intake", "go"), fullPorts(), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() = %d, want 0; stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "dependency-intake-controller configured for zone intake and ecosystem go") {
		t.Fatalf("stdout = %q, want configured message", stdout.String())
	}
}

func TestLaneWrappers(t *testing.T) {
	lanes := []struct {
		name string
		run  func(context.Context, func(string) string, Ports, io.Writer, io.Writer) int
		zone string
	}{
		{"intake", RunIntake, "intake"},
		{"admission", RunAdmission, "control"},
		{"promotion", RunPromotion, "control"},
		{"revalidation", RunRevalidation, "control"},
		{"revocation", RunRevocation, "control"},
	}
	for _, lane := range lanes {
		t.Run(lane.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := lane.run(context.Background(), envWith(lane.zone, "go"), fullPorts(), &stdout, &stderr)
			if code != 0 {
				t.Fatalf("Run() = %d, want 0; stderr = %q", code, stderr.String())
			}
			if !strings.Contains(stdout.String(), "dependency-"+lane.name+"-controller") {
				t.Fatalf("stdout = %q, want lane name", stdout.String())
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
		if err := bind(operation, Ports{}); err == nil {
			t.Errorf("bind(%q, empty ports) error = nil, want unbound port error", operation)
		}
	}
}

func TestBindSucceedsWithFullPorts(t *testing.T) {
	for _, operation := range []Operation{
		OperationIntake, OperationAdmission, OperationPromotion, OperationRevalidation, OperationRevocation,
	} {
		if err := bind(operation, fullPorts()); err != nil {
			t.Errorf("bind(%q, full ports) error = %v", operation, err)
		}
	}
}

func TestBindRejectsUnknownOperation(t *testing.T) {
	if err := bind(Operation("bogus"), fullPorts()); err == nil {
		t.Fatal("bind() error = nil, want unknown operation error")
	}
}
