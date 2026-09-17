package config

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	// EnvModule names the module path of the candidate the lane operates on.
	EnvModule = "DEPENDENCY_AUTHORITY_MODULE"
	// EnvVersion names the candidate version the lane operates on.
	EnvVersion = "DEPENDENCY_AUTHORITY_VERSION"
	// EnvLaneIdentity names the identity the lane issues evidence under.
	EnvLaneIdentity = "DEPENDENCY_AUTHORITY_LANE_IDENTITY"
	// EnvScannerIdentity names the pinned scanner tool identity recorded in
	// the scan evidence.
	EnvScannerIdentity = "DEPENDENCY_AUTHORITY_SCANNER_IDENTITY"
	// EnvScannerDatabaseIdentity names the scanner database snapshot identity
	// recorded in the scan evidence.
	EnvScannerDatabaseIdentity = "DEPENDENCY_AUTHORITY_SCANNER_DATABASE_IDENTITY"
	// EnvApprovalTTL names the validity window of the automatic approval the
	// admission lane records on a policy pass.
	EnvApprovalTTL = "DEPENDENCY_AUTHORITY_APPROVAL_TTL"
	// EnvRevocationReason names the revocation reason the revocation lane
	// binds into the revocation evidence.
	EnvRevocationReason = "DEPENDENCY_AUTHORITY_REVOCATION_REASON"
	// EnvNegativeProbe names the never-admitted reference the consumer
	// verification lane proves fail-closed at the approved endpoint.
	EnvNegativeProbe = "DEPENDENCY_AUTHORITY_NEGATIVE_PROBE"
	// EnvRecordType names the operations-evidence record type the
	// evidence-write lane attests.
	EnvRecordType = "DEPENDENCY_AUTHORITY_RECORD_TYPE"
	// EnvSubjectLane names the lane operation the evidence-write lane
	// attests.
	EnvSubjectLane = "DEPENDENCY_AUTHORITY_SUBJECT_LANE"
	// EnvExecution names the execution reference the evidence-write lane
	// attests.
	EnvExecution = "DEPENDENCY_AUTHORITY_EXECUTION"
	// EnvOutcome names the operation outcome the evidence-write lane attests.
	EnvOutcome = "DEPENDENCY_AUTHORITY_OUTCOME"
	// EnvEvidenceReferences names the comma-separated evidence locators the
	// attested operation produced.
	EnvEvidenceReferences = "DEPENDENCY_AUTHORITY_EVIDENCE_REFERENCES"
	// EnvDetail names the optional free-text detail of the operations
	// attestation.
	EnvDetail = "DEPENDENCY_AUTHORITY_DETAIL"
)

// Field identifies one lane operation input binding.
type Field int

const (
	// FieldModule is the candidate module path input.
	FieldModule Field = iota + 1
	// FieldVersion is the candidate version input.
	FieldVersion
	// FieldLaneIdentity is the lane identity input.
	FieldLaneIdentity
	// FieldScannerIdentity is the pinned scanner tool identity input.
	FieldScannerIdentity
	// FieldScannerDatabaseIdentity is the scanner database snapshot identity
	// input.
	FieldScannerDatabaseIdentity
	// FieldApprovalTTL is the automatic approval validity window input.
	FieldApprovalTTL
	// FieldRevocationReason is the revocation reason input.
	FieldRevocationReason
	// FieldNegativeProbe is the never-admitted reference input of the consumer
	// verification lane.
	FieldNegativeProbe
	// FieldRecordType is the operations-evidence record type input of the
	// evidence-write lane.
	FieldRecordType
	// FieldSubjectLane is the attested lane operation input of the
	// evidence-write lane.
	FieldSubjectLane
	// FieldExecution is the attested execution reference input of the
	// evidence-write lane.
	FieldExecution
	// FieldOutcome is the attested operation outcome input of the
	// evidence-write lane.
	FieldOutcome
	// FieldEvidenceReferences is the evidence locator list input of the
	// evidence-write lane.
	FieldEvidenceReferences
	// FieldDetail is the optional attestation detail input of the
	// evidence-write lane.
	FieldDetail
)

// env names the environment variable carrying the field.
func (f Field) env() string {
	switch f {
	case FieldModule:
		return EnvModule
	case FieldVersion:
		return EnvVersion
	case FieldLaneIdentity:
		return EnvLaneIdentity
	case FieldScannerIdentity:
		return EnvScannerIdentity
	case FieldScannerDatabaseIdentity:
		return EnvScannerDatabaseIdentity
	case FieldApprovalTTL:
		return EnvApprovalTTL
	case FieldRevocationReason:
		return EnvRevocationReason
	case FieldNegativeProbe:
		return EnvNegativeProbe
	case FieldRecordType:
		return EnvRecordType
	case FieldSubjectLane:
		return EnvSubjectLane
	case FieldExecution:
		return EnvExecution
	case FieldOutcome:
		return EnvOutcome
	case FieldEvidenceReferences:
		return EnvEvidenceReferences
	case FieldDetail:
		return EnvDetail
	default:
		return ""
	}
}

// Operation carries the validated operation inputs of one lane execution.
type Operation struct {
	module                  string
	version                 string
	laneIdentity            string
	scannerIdentity         string
	scannerDatabaseIdentity string
	approvalTTL             time.Duration
	revocationReason        string
	negativeProbe           string
	recordType              string
	subjectLane             string
	execution               string
	outcome                 string
	evidenceReferences      []string
	detail                  string
}

// OperationFromEnv loads the operation inputs from the process environment
// and fails closed on any absent or invalid required field.
func OperationFromEnv(lookup func(string) string, required ...Field) (Operation, error) {
	if lookup == nil {
		return Operation{}, errors.New("environment lookup must not be nil")
	}
	operation := Operation{
		module:                  strings.TrimSpace(lookup(EnvModule)),
		version:                 strings.TrimSpace(lookup(EnvVersion)),
		laneIdentity:            strings.TrimSpace(lookup(EnvLaneIdentity)),
		scannerIdentity:         strings.TrimSpace(lookup(EnvScannerIdentity)),
		scannerDatabaseIdentity: strings.TrimSpace(lookup(EnvScannerDatabaseIdentity)),
		revocationReason:        strings.TrimSpace(lookup(EnvRevocationReason)),
		negativeProbe:           strings.TrimSpace(lookup(EnvNegativeProbe)),
		recordType:              strings.TrimSpace(lookup(EnvRecordType)),
		subjectLane:             strings.TrimSpace(lookup(EnvSubjectLane)),
		execution:               strings.TrimSpace(lookup(EnvExecution)),
		outcome:                 strings.TrimSpace(lookup(EnvOutcome)),
		evidenceReferences:      splitReferences(lookup(EnvEvidenceReferences)),
		detail:                  strings.TrimSpace(lookup(EnvDetail)),
	}
	if raw := strings.TrimSpace(lookup(EnvApprovalTTL)); raw != "" {
		ttl, err := time.ParseDuration(raw)
		if err != nil || ttl <= 0 {
			return Operation{}, fmt.Errorf("%s must be a positive Go duration", EnvApprovalTTL)
		}
		operation.approvalTTL = ttl
	}
	for _, field := range required {
		if err := operation.require(field); err != nil {
			return Operation{}, err
		}
	}
	return operation, nil
}

// require fails closed when the required field is absent or invalid.
func (o Operation) require(field Field) error {
	env := field.env()
	if env == "" {
		return fmt.Errorf("unknown operation field %d", int(field))
	}
	if field == FieldApprovalTTL {
		if o.approvalTTL <= 0 {
			return fmt.Errorf("%s must be set to a positive Go duration", env)
		}
		return nil
	}
	if o.value(field) == "" {
		return fmt.Errorf("%s must not be empty", env)
	}
	return nil
}

// value returns the raw field value.
func (o Operation) value(field Field) string {
	switch field {
	case FieldModule:
		return o.module
	case FieldVersion:
		return o.version
	case FieldLaneIdentity:
		return o.laneIdentity
	case FieldScannerIdentity:
		return o.scannerIdentity
	case FieldScannerDatabaseIdentity:
		return o.scannerDatabaseIdentity
	case FieldRevocationReason:
		return o.revocationReason
	case FieldNegativeProbe:
		return o.negativeProbe
	case FieldRecordType:
		return o.recordType
	case FieldSubjectLane:
		return o.subjectLane
	case FieldExecution:
		return o.execution
	case FieldOutcome:
		return o.outcome
	case FieldEvidenceReferences:
		return strings.Join(o.evidenceReferences, ",")
	case FieldDetail:
		return o.detail
	default:
		return ""
	}
}

// Module returns the candidate module path.
func (o Operation) Module() string {
	return o.module
}

// Version returns the candidate version.
func (o Operation) Version() string {
	return o.version
}

// LaneIdentity returns the identity the lane issues evidence under.
func (o Operation) LaneIdentity() string {
	return o.laneIdentity
}

// ScannerIdentity returns the pinned scanner tool identity.
func (o Operation) ScannerIdentity() string {
	return o.scannerIdentity
}

// ScannerDatabaseIdentity returns the scanner database snapshot identity.
func (o Operation) ScannerDatabaseIdentity() string {
	return o.scannerDatabaseIdentity
}

// ApprovalTTL returns the automatic approval validity window.
func (o Operation) ApprovalTTL() time.Duration {
	return o.approvalTTL
}

// RevocationReason returns the revocation reason.
func (o Operation) RevocationReason() string {
	return o.revocationReason
}

// NegativeProbe returns the never-admitted reference the consumer
// verification lane proves fail-closed.
func (o Operation) NegativeProbe() string {
	return o.negativeProbe
}

// RecordType returns the operations-evidence record type the evidence-write
// lane attests.
func (o Operation) RecordType() string {
	return o.recordType
}

// SubjectLane returns the lane operation the evidence-write lane attests.
func (o Operation) SubjectLane() string {
	return o.subjectLane
}

// Execution returns the execution reference the evidence-write lane attests.
func (o Operation) Execution() string {
	return o.execution
}

// Outcome returns the operation outcome the evidence-write lane attests.
func (o Operation) Outcome() string {
	return o.outcome
}

// EvidenceReferences returns a defensive copy of the evidence locators the
// attested operation produced.
func (o Operation) EvidenceReferences() []string {
	owned := make([]string, len(o.evidenceReferences))
	copy(owned, o.evidenceReferences)
	return owned
}

// Detail returns the optional free-text detail of the operations attestation.
func (o Operation) Detail() string {
	return o.detail
}

// splitReferences parses the comma-separated evidence reference list binding:
// every entry is trimmed, and empty entries are dropped.
func splitReferences(raw string) []string {
	references := make([]string, 0)
	for _, part := range strings.Split(raw, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			references = append(references, trimmed)
		}
	}
	return references
}
