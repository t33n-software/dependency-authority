package evidencewrite

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/t33n-software/dependency-authority/internal/dependency/domain/evidence"
)

var writeTime = time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)

type fakeOperationsJournal struct {
	reference evidence.Reference
	err       error
	records   []evidence.OperationsRecord
}

func (f *fakeOperationsJournal) WriteOperations(_ context.Context, record evidence.OperationsRecord) (evidence.Reference, error) {
	if f.err != nil {
		return evidence.Reference{}, f.err
	}
	f.records = append(f.records, record)
	return f.reference, nil
}

func testReference(t *testing.T) evidence.Reference {
	t.Helper()
	reference, err := evidence.NewReference(evidence.TypeOperations, "evidence://projects/p/locations/l/repositories/r/operations-evidence/v1/abc.json", "sha256:3b8f49c12b24cbbd6a4a0e6e2b2a4a4e8f0e1d2c3b4a59687766554433221100", "dep-evidence-writer@example.iam.gserviceaccount.com", writeTime, nil)
	if err != nil {
		t.Fatalf("NewReference() error = %v", err)
	}
	return reference
}

func testInput() WriteInput {
	return WriteInput{
		RecordType:  evidence.OperationsRecordRevocation,
		SubjectLane: "dep-revocation",
		Execution:   "projects/p/locations/l/jobs/dep-revocation/executions/1",
		Outcome:     evidence.OperationsSucceeded,
		References:  []string{"evidence://projects/p/locations/l/repositories/r/evidence-payloads-abc/v1/def.json"},
		Detail:      "the deliberate revocation of the bound candidate",
		Issuer:      "dep-evidence-writer@example.iam.gserviceaccount.com",
	}
}

func TestNewServiceFailsClosedOnUnboundPorts(t *testing.T) {
	if _, err := NewService(nil, time.Now); err == nil {
		t.Fatal("NewService(nil journal) error = nil, want error")
	}
	if _, err := NewService(&fakeOperationsJournal{}, nil); err == nil {
		t.Fatal("NewService(nil clock) error = nil, want error")
	}
}

func TestWriteRecordsTheValidatedAttestation(t *testing.T) {
	journal := &fakeOperationsJournal{reference: testReference(t)}
	service, err := NewService(journal, func() time.Time { return writeTime })
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	reference, err := service.Write(context.Background(), testInput())
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if reference.Reference() != "evidence://projects/p/locations/l/repositories/r/operations-evidence/v1/abc.json" {
		t.Fatalf("Write() reference = %q", reference.Reference())
	}
	if len(journal.records) != 1 {
		t.Fatalf("journal records = %d, want 1", len(journal.records))
	}
	record := journal.records[0]
	if record.RecordType() != evidence.OperationsRecordRevocation || record.SubjectLane() != "dep-revocation" || record.Outcome() != evidence.OperationsSucceeded {
		t.Fatalf("journal record = %#v", record)
	}
	if record.Issuer() != "dep-evidence-writer@example.iam.gserviceaccount.com" || !record.IssuedAt().Equal(writeTime) {
		t.Fatalf("journal record issuer/issuedAt = %q %v", record.Issuer(), record.IssuedAt())
	}
}

func TestWriteFailsClosedOnAnInvalidEvent(t *testing.T) {
	journal := &fakeOperationsJournal{reference: testReference(t)}
	service, err := NewService(journal, func() time.Time { return writeTime })
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	input := testInput()
	input.RecordType = evidence.OperationsRecordType("bogus")
	if _, err := service.Write(context.Background(), input); err == nil {
		t.Fatal("Write() error = nil, want the record validation failure")
	}
	if len(journal.records) != 0 {
		t.Fatal("Write() wrote a record for an invalid event")
	}
}

func TestWritePropagatesTheJournalFailure(t *testing.T) {
	journal := &fakeOperationsJournal{err: errors.New("store unavailable")}
	service, err := NewService(journal, func() time.Time { return writeTime })
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	_, err = service.Write(context.Background(), testInput())
	if err == nil || !strings.Contains(err.Error(), "write the operations evidence record") {
		t.Fatalf("Write() error = %v, want the journal failure", err)
	}
}
