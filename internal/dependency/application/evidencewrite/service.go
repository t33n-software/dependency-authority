// Package evidencewrite implements the operations-evidence write use case:
// the evidence-write workload of the evidence zone is the only writer of the
// operations-evidence class — the identity an attestation describes never
// holds the writer grant for its own attestation.
package evidencewrite

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/t33n-software/dependency-authority/internal/dependency/domain/evidence"
)

// OperationsJournal writes operations-evidence records into the evidence
// store of the evidence zone.
type OperationsJournal interface {
	WriteOperations(ctx context.Context, record evidence.OperationsRecord) (evidence.Reference, error)
}

// Service runs the evidence-write workload.
type Service struct {
	journal OperationsJournal
	now     func() time.Time
}

// NewService constructs the evidence-write service and fails closed on
// unbound ports.
func NewService(journal OperationsJournal, now func() time.Time) (Service, error) {
	if journal == nil {
		return Service{}, errors.New("operations journal port must not be nil")
	}
	if now == nil {
		return Service{}, errors.New("clock port must not be nil")
	}
	return Service{journal: journal, now: now}, nil
}

// WriteInput carries the operation event the lane attests.
type WriteInput struct {
	RecordType  evidence.OperationsRecordType
	SubjectLane string
	Execution   string
	Outcome     evidence.OperationsOutcome
	References  []string
	Detail      string
	Issuer      string
}

// Write validates the operation event and writes its operations-evidence
// record through the evidence-write identity. The store writes the record
// content-addressed, so a repeated attestation of the same event is an
// idempotent success.
func (s Service) Write(ctx context.Context, input WriteInput) (evidence.Reference, error) {
	record, err := evidence.NewOperationsRecord(input.RecordType, input.SubjectLane, input.Execution, input.Outcome, input.References, input.Detail, input.Issuer, s.now())
	if err != nil {
		return evidence.Reference{}, err
	}
	reference, err := s.journal.WriteOperations(ctx, record)
	if err != nil {
		return evidence.Reference{}, fmt.Errorf("write the operations evidence record: %w", err)
	}
	return reference, nil
}
