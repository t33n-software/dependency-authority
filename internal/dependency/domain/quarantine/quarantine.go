// Package quarantine models quarantine records for dependency candidates
// under investigation.
package quarantine

import (
	"errors"
	"strings"
	"time"
)

// Record documents why and when a candidate entered quarantine.
type Record struct {
	reason    string
	enteredAt time.Time
}

// NewRecord constructs a validated quarantine record.
func NewRecord(reason string, enteredAt time.Time) (Record, error) {
	if strings.TrimSpace(reason) == "" {
		return Record{}, errors.New("quarantine reason must not be empty")
	}
	if enteredAt.IsZero() {
		return Record{}, errors.New("entered-at must not be zero")
	}
	return Record{reason: reason, enteredAt: enteredAt}, nil
}

// Reason returns the quarantine reason.
func (r Record) Reason() string {
	return r.reason
}

// EnteredAt returns the quarantine entry time.
func (r Record) EnteredAt() time.Time {
	return r.enteredAt
}
