package evidence

import (
	"strings"
	"testing"
	"time"
)

var operationsTime = time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)

func validOperationsRecord(t *testing.T) OperationsRecord {
	t.Helper()
	record, err := NewOperationsRecord(
		OperationsRecordRevocation,
		"dep-revocation",
		"projects/p/locations/l/jobs/dep-revocation/executions/1",
		OperationsSucceeded,
		[]string{"evidence://projects/p/locations/l/repositories/r/evidence-payloads-abc/v1/def.json"},
		"the deliberate revocation of the bound candidate",
		"dep-evidence-writer@example.iam.gserviceaccount.com",
		operationsTime,
	)
	if err != nil {
		t.Fatalf("NewOperationsRecord() error = %v", err)
	}
	return record
}

func TestOperationsRecordTypeValidity(t *testing.T) {
	for _, recordType := range []OperationsRecordType{
		OperationsRecordLaneRun, OperationsRecordOperation, OperationsRecordRevalidation,
		OperationsRecordRevocation, OperationsRecordQuarantine, OperationsRecordRetention,
	} {
		if !recordType.Valid() {
			t.Errorf("OperationsRecordType(%q).Valid() = false, want true", recordType)
		}
	}
	if OperationsRecordType("bogus").Valid() {
		t.Error("OperationsRecordType(bogus).Valid() = true, want false")
	}
}

func TestOperationsOutcomeValidity(t *testing.T) {
	if !OperationsSucceeded.Valid() || !OperationsFailed.Valid() {
		t.Error("the canonical operations outcomes must be valid")
	}
	if OperationsOutcome("unknown").Valid() {
		t.Error("OperationsOutcome(unknown).Valid() = true, want false")
	}
}

func TestNewOperationsRecordBindsTheValidatedForm(t *testing.T) {
	record := validOperationsRecord(t)
	if record.RecordType() != OperationsRecordRevocation {
		t.Fatalf("RecordType() = %q", record.RecordType())
	}
	if record.SubjectLane() != "dep-revocation" {
		t.Fatalf("SubjectLane() = %q", record.SubjectLane())
	}
	if record.Execution() != "projects/p/locations/l/jobs/dep-revocation/executions/1" {
		t.Fatalf("Execution() = %q", record.Execution())
	}
	if record.Outcome() != OperationsSucceeded {
		t.Fatalf("Outcome() = %q", record.Outcome())
	}
	if len(record.References()) != 1 || record.References()[0] != "evidence://projects/p/locations/l/repositories/r/evidence-payloads-abc/v1/def.json" {
		t.Fatalf("References() = %v", record.References())
	}
	if record.Detail() != "the deliberate revocation of the bound candidate" {
		t.Fatalf("Detail() = %q", record.Detail())
	}
	if record.Issuer() != "dep-evidence-writer@example.iam.gserviceaccount.com" {
		t.Fatalf("Issuer() = %q", record.Issuer())
	}
	if !record.IssuedAt().Equal(operationsTime) {
		t.Fatalf("IssuedAt() = %v", record.IssuedAt())
	}
}

func TestNewOperationsRecordDefensiveCopies(t *testing.T) {
	references := []string{"evidence://projects/p/locations/l/repositories/r/evidence-payloads-abc/v1/def.json"}
	record, err := NewOperationsRecord(OperationsRecordLaneRun, "dep-admission", "executions/1", OperationsSucceeded, references, "", "issuer", operationsTime)
	if err != nil {
		t.Fatalf("NewOperationsRecord() error = %v", err)
	}
	references[0] = "mutated"
	if record.References()[0] == "mutated" {
		t.Fatal("NewOperationsRecord() shares the references slice with the caller")
	}
	first := record.References()
	first[0] = "mutated again"
	if record.References()[0] == "mutated again" {
		t.Fatal("References() shares its slice with the caller")
	}
}

func TestNewOperationsRecordTrimsTheDetail(t *testing.T) {
	record, err := NewOperationsRecord(OperationsRecordLaneRun, "dep-admission", "executions/1", OperationsSucceeded, nil, "  padded  ", "issuer", operationsTime)
	if err != nil {
		t.Fatalf("NewOperationsRecord() error = %v", err)
	}
	if record.Detail() != "padded" {
		t.Fatalf("Detail() = %q, want the trimmed form", record.Detail())
	}
}

func TestNewOperationsRecordFailsClosed(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*OperationsRecord)
		wantErr string
	}{
		{"unknown record type", func(r *OperationsRecord) { r.recordType = "bogus" }, "unknown operations evidence record type"},
		{"empty subject lane", func(r *OperationsRecord) { r.subjectLane = " " }, "subject lane must not be empty"},
		{"empty execution", func(r *OperationsRecord) { r.execution = " " }, "execution reference must not be empty"},
		{"unknown outcome", func(r *OperationsRecord) { r.outcome = "unknown" }, "unknown operations evidence outcome"},
		{"malformed reference", func(r *OperationsRecord) { r.references = []string{"scans/1"} }, "must carry the evidence:// locator form"},
		{"empty issuer", func(r *OperationsRecord) { r.issuer = " " }, "issuer must not be empty"},
		{"zero issued-at", func(r *OperationsRecord) { r.issuedAt = time.Time{} }, "issued-at must not be zero"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			record := validOperationsRecord(t)
			tc.mutate(&record)
			_, err := NewOperationsRecord(record.recordType, record.subjectLane, record.execution, record.outcome, record.references, record.detail, record.issuer, record.issuedAt)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("NewOperationsRecord() error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestTypeOperationsIsValid(t *testing.T) {
	if !TypeOperations.Valid() {
		t.Error("TypeOperations.Valid() = false, want true")
	}
}
