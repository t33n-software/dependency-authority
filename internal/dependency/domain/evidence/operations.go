package evidence

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// OperationsRecordType is the controlled vocabulary of the operations
// evidence record types: the lane-run markers and the operations,
// revalidation, revocation, quarantine and retention records.
type OperationsRecordType string

const (
	// OperationsRecordLaneRun is the lane-run marker: the attestation that a
	// lane operation executed.
	OperationsRecordLaneRun OperationsRecordType = "lane-run"
	// OperationsRecordOperation is the generic record of a governed
	// operation.
	OperationsRecordOperation OperationsRecordType = "operation"
	// OperationsRecordRevalidation is the record of a revalidation operation.
	OperationsRecordRevalidation OperationsRecordType = "revalidation"
	// OperationsRecordRevocation is the record of a revocation operation.
	OperationsRecordRevocation OperationsRecordType = "revocation"
	// OperationsRecordQuarantine is the record of a quarantine operation.
	OperationsRecordQuarantine OperationsRecordType = "quarantine"
	// OperationsRecordRetention is the record of a retention operation.
	OperationsRecordRetention OperationsRecordType = "retention"
)

// Valid reports whether the record type belongs to the canonical operations
// evidence vocabulary.
func (t OperationsRecordType) Valid() bool {
	switch t {
	case OperationsRecordLaneRun, OperationsRecordOperation, OperationsRecordRevalidation, OperationsRecordRevocation, OperationsRecordQuarantine, OperationsRecordRetention:
		return true
	default:
		return false
	}
}

// OperationsOutcome is the controlled vocabulary of the attested operation
// outcome.
type OperationsOutcome string

const (
	// OperationsSucceeded marks the attested operation as succeeded.
	OperationsSucceeded OperationsOutcome = "succeeded"
	// OperationsFailed marks the attested operation as failed.
	OperationsFailed OperationsOutcome = "failed"
)

// Valid reports whether the outcome belongs to the canonical operations
// evidence vocabulary.
func (o OperationsOutcome) Valid() bool {
	switch o {
	case OperationsSucceeded, OperationsFailed:
		return true
	default:
		return false
	}
}

// OperationsRecord is one validated operations-evidence record: the
// attestation of a governed operation. Only the evidence-write workload
// identity writes this class — the attested lane identity never writes its
// own attestation.
type OperationsRecord struct {
	recordType  OperationsRecordType
	subjectLane string
	execution   string
	outcome     OperationsOutcome
	references  []string
	detail      string
	issuer      string
	issuedAt    time.Time
}

// NewOperationsRecord constructs a validated operations-evidence record and
// fails closed on any contract violation.
func NewOperationsRecord(recordType OperationsRecordType, subjectLane string, execution string, outcome OperationsOutcome, references []string, detail string, issuer string, issuedAt time.Time) (OperationsRecord, error) {
	if !recordType.Valid() {
		return OperationsRecord{}, fmt.Errorf("unknown operations evidence record type %q", recordType)
	}
	if strings.TrimSpace(subjectLane) == "" {
		return OperationsRecord{}, errors.New("the attested subject lane must not be empty")
	}
	if strings.TrimSpace(execution) == "" {
		return OperationsRecord{}, errors.New("the attested execution reference must not be empty")
	}
	if !outcome.Valid() {
		return OperationsRecord{}, fmt.Errorf("unknown operations evidence outcome %q", outcome)
	}
	owned := make([]string, 0, len(references))
	for _, reference := range references {
		if !strings.HasPrefix(reference, "evidence://") {
			return OperationsRecord{}, fmt.Errorf("evidence reference %q must carry the evidence:// locator form", reference)
		}
		owned = append(owned, reference)
	}
	if strings.TrimSpace(issuer) == "" {
		return OperationsRecord{}, errors.New("issuer must not be empty")
	}
	if issuedAt.IsZero() {
		return OperationsRecord{}, errors.New("issued-at must not be zero")
	}
	return OperationsRecord{
		recordType:  recordType,
		subjectLane: subjectLane,
		execution:   execution,
		outcome:     outcome,
		references:  owned,
		detail:      strings.TrimSpace(detail),
		issuer:      issuer,
		issuedAt:    issuedAt,
	}, nil
}

// RecordType returns the operations-evidence record type.
func (r OperationsRecord) RecordType() OperationsRecordType {
	return r.recordType
}

// SubjectLane returns the attested lane operation.
func (r OperationsRecord) SubjectLane() string {
	return r.subjectLane
}

// Execution returns the attested execution reference.
func (r OperationsRecord) Execution() string {
	return r.execution
}

// Outcome returns the attested operation outcome.
func (r OperationsRecord) Outcome() OperationsOutcome {
	return r.outcome
}

// References returns a defensive copy of the evidence locators the operation
// produced.
func (r OperationsRecord) References() []string {
	owned := make([]string, len(r.references))
	copy(owned, r.references)
	return owned
}

// Detail returns the optional free-text detail of the attestation.
func (r OperationsRecord) Detail() string {
	return r.detail
}

// Issuer returns the evidence-write identity that issued the attestation.
func (r OperationsRecord) Issuer() string {
	return r.issuer
}

// IssuedAt returns the attestation issue time.
func (r OperationsRecord) IssuedAt() time.Time {
	return r.issuedAt
}
