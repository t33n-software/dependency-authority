package quarantine

import (
	"testing"
	"time"
)

func TestNewRecordValidation(t *testing.T) {
	enteredAt := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	if _, err := NewRecord("", enteredAt); err == nil {
		t.Fatal("NewRecord() error = nil, want empty reason error")
	}
	if _, err := NewRecord("policy failure", time.Time{}); err == nil {
		t.Fatal("NewRecord() error = nil, want zero entry time error")
	}
}

func TestRecordAccessors(t *testing.T) {
	enteredAt := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	record, err := NewRecord("policy failure", enteredAt)
	if err != nil {
		t.Fatalf("NewRecord() error = %v", err)
	}
	if record.Reason() != "policy failure" {
		t.Errorf("Reason() = %q, want policy failure", record.Reason())
	}
	if !record.EnteredAt().Equal(enteredAt) {
		t.Errorf("EnteredAt() = %v, want %v", record.EnteredAt(), enteredAt)
	}
}
