package evidenceaudit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/t33n-software/dependency-authority/internal/dependency/domain/candidate"
	"github.com/t33n-software/dependency-authority/internal/dependency/domain/evidence"
)

var auditTime = time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)

type fakeTrail struct {
	references []evidence.Reference
	err        error
}

func (f fakeTrail) Evidence(context.Context, candidate.Ecosystem, string, string) ([]evidence.Reference, error) {
	return f.references, f.err
}

type fakeProver struct {
	payloads map[string][]byte
	err      error
}

func (f fakeProver) FetchPayload(_ context.Context, reference evidence.Reference) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	payload, found := f.payloads[reference.Reference()]
	if !found {
		return nil, errors.New("payload not found")
	}
	return payload, nil
}

// payloadReference builds the digest-bound reference of one payload.
func payloadReference(t *testing.T, locator string, payload []byte) evidence.Reference {
	t.Helper()
	sum := sha256.Sum256(payload)
	reference, err := evidence.NewReference(evidence.TypeScan, locator, "sha256:"+hex.EncodeToString(sum[:]), "issuer", auditTime, nil)
	if err != nil {
		t.Fatalf("NewReference() error = %v", err)
	}
	return reference
}

func TestNewServiceFailsClosedOnUnboundPorts(t *testing.T) {
	if _, err := NewService(nil, fakeProver{}); err == nil {
		t.Fatal("NewService(nil trail) error = nil, want error")
	}
	if _, err := NewService(fakeTrail{}, nil); err == nil {
		t.Fatal("NewService(nil prover) error = nil, want error")
	}
}

func TestProvePassesTheIntactTrail(t *testing.T) {
	payload := []byte(`{"schema":"dependency-authority/scan-evidence/v1"}`)
	reference := payloadReference(t, "evidence://projects/p/locations/l/repositories/r/evidence-payloads-abc/v1/def.json", payload)
	service, err := NewService(fakeTrail{references: []evidence.Reference{reference}}, fakeProver{payloads: map[string][]byte{reference.Reference(): payload}})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	report, err := service.Prove(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("Prove() error = %v", err)
	}
	if len(report.References()) != 1 || report.References()[0].Reference() != reference.Reference() {
		t.Fatalf("Prove() references = %v", report.References())
	}
}

func TestProvePassesAnEmptyTrail(t *testing.T) {
	service, err := NewService(fakeTrail{}, fakeProver{})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	report, err := service.Prove(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("Prove() error = %v", err)
	}
	if len(report.References()) != 0 {
		t.Fatalf("Prove() references = %v, want an empty trail", report.References())
	}
}

func TestReportDefensiveCopies(t *testing.T) {
	reference := payloadReference(t, "evidence://projects/p/locations/l/repositories/r/evidence-payloads-abc/v1/def.json", []byte("payload"))
	references := []evidence.Reference{reference}
	report := NewReport(references)
	references[0] = payloadReference(t, "evidence://projects/p/locations/l/repositories/r/evidence-payloads-abc/v1/mutated.json", []byte("other"))
	if report.References()[0].Reference() != reference.Reference() {
		t.Fatal("NewReport() shares the references slice with the caller")
	}
	first := report.References()
	first[0] = payloadReference(t, "evidence://projects/p/locations/l/repositories/r/evidence-payloads-abc/v1/mutated-again.json", []byte("other"))
	if report.References()[0].Reference() == first[0].Reference() {
		t.Fatal("References() shares its slice with the caller")
	}
}

func TestProveFailsClosedOnTheTrailLoad(t *testing.T) {
	service, err := NewService(fakeTrail{err: errors.New("index unavailable")}, fakeProver{})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	if _, err := service.Prove(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0"); err == nil || !strings.Contains(err.Error(), "load the evidence trail") {
		t.Fatalf("Prove() error = %v, want the trail load failure", err)
	}
}

func TestProveFailsClosedOnThePayloadFetch(t *testing.T) {
	reference := payloadReference(t, "evidence://projects/p/locations/l/repositories/r/evidence-payloads-abc/v1/def.json", []byte("payload"))
	service, err := NewService(fakeTrail{references: []evidence.Reference{reference}}, fakeProver{err: errors.New("store unavailable")})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	if _, err := service.Prove(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0"); err == nil || !strings.Contains(err.Error(), "fetch the evidence payload") {
		t.Fatalf("Prove() error = %v, want the payload fetch failure", err)
	}
}

func TestProveFailsClosedOnDigestDrift(t *testing.T) {
	reference := payloadReference(t, "evidence://projects/p/locations/l/repositories/r/evidence-payloads-abc/v1/def.json", []byte("payload"))
	service, err := NewService(fakeTrail{references: []evidence.Reference{reference}}, fakeProver{payloads: map[string][]byte{reference.Reference(): []byte("drifted")}})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	if _, err := service.Prove(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0"); err == nil || !strings.Contains(err.Error(), "does not match the recorded reference") {
		t.Fatalf("Prove() error = %v, want the digest drift failure", err)
	}
}
