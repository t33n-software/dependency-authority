package config

import (
	"strings"
	"testing"
	"time"
)

func operationEnv(values map[string]string) func(string) string {
	return func(key string) string {
		return values[key]
	}
}

func fullOperationEnv() map[string]string {
	return map[string]string{
		EnvModule:                  "github.com/google/go-cmp",
		EnvVersion:                 "v0.7.0",
		EnvLaneIdentity:            "dep-admission-controller@example.iam.gserviceaccount.com",
		EnvScannerIdentity:         "osv-scanner 2.2.3",
		EnvScannerDatabaseIdentity: "osv-db sha256:aaa",
		EnvApprovalTTL:             "72h",
		EnvRevocationReason:        "confirmed supply chain incident",
	}
}

func TestOperationFromEnvRejectsANilLookup(t *testing.T) {
	if _, err := OperationFromEnv(nil); err == nil {
		t.Fatal("OperationFromEnv(nil) error = nil, want error")
	}
}

func TestOperationFromEnvLoadsTheTrimmedInputs(t *testing.T) {
	operation, err := OperationFromEnv(operationEnv(map[string]string{
		EnvModule:  "  github.com/google/go-cmp  ",
		EnvVersion: " v0.7.0 ",
	}))
	if err != nil {
		t.Fatalf("OperationFromEnv() error = %v", err)
	}
	if operation.Module() != "github.com/google/go-cmp" || operation.Version() != "v0.7.0" {
		t.Fatalf("OperationFromEnv() = %q %q, want the trimmed inputs", operation.Module(), operation.Version())
	}
	if operation.LaneIdentity() != "" || operation.ScannerIdentity() != "" || operation.ScannerDatabaseIdentity() != "" || operation.RevocationReason() != "" {
		t.Fatal("OperationFromEnv() bound an absent input")
	}
	if operation.ApprovalTTL() != 0 {
		t.Fatalf("ApprovalTTL() = %v, want zero without the binding", operation.ApprovalTTL())
	}
}

func TestOperationFromEnvBindsEveryField(t *testing.T) {
	operation, err := OperationFromEnv(operationEnv(fullOperationEnv()),
		FieldModule, FieldVersion, FieldLaneIdentity, FieldScannerIdentity, FieldScannerDatabaseIdentity, FieldApprovalTTL, FieldRevocationReason)
	if err != nil {
		t.Fatalf("OperationFromEnv() error = %v", err)
	}
	if operation.Module() != "github.com/google/go-cmp" {
		t.Fatalf("Module() = %q", operation.Module())
	}
	if operation.Version() != "v0.7.0" {
		t.Fatalf("Version() = %q", operation.Version())
	}
	if operation.LaneIdentity() != "dep-admission-controller@example.iam.gserviceaccount.com" {
		t.Fatalf("LaneIdentity() = %q", operation.LaneIdentity())
	}
	if operation.ScannerIdentity() != "osv-scanner 2.2.3" {
		t.Fatalf("ScannerIdentity() = %q", operation.ScannerIdentity())
	}
	if operation.ScannerDatabaseIdentity() != "osv-db sha256:aaa" {
		t.Fatalf("ScannerDatabaseIdentity() = %q", operation.ScannerDatabaseIdentity())
	}
	if operation.ApprovalTTL() != 72*time.Hour {
		t.Fatalf("ApprovalTTL() = %v, want 72h", operation.ApprovalTTL())
	}
	if operation.RevocationReason() != "confirmed supply chain incident" {
		t.Fatalf("RevocationReason() = %q", operation.RevocationReason())
	}
}

func TestOperationFromEnvRejectsAnInvalidApprovalTTL(t *testing.T) {
	for name, raw := range map[string]string{
		"not a duration": "soon",
		"negative":       "-1h",
		"zero":           "0s",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := OperationFromEnv(operationEnv(map[string]string{EnvApprovalTTL: raw})); err == nil {
				t.Fatal("OperationFromEnv() error = nil, want a positive-duration error")
			}
		})
	}
}

func TestOperationFromEnvRequiresTheDeclaredFields(t *testing.T) {
	for name, tc := range map[string]struct {
		field Field
		env   string
	}{
		"module":            {FieldModule, EnvModule},
		"version":           {FieldVersion, EnvVersion},
		"lane identity":     {FieldLaneIdentity, EnvLaneIdentity},
		"scanner identity":  {FieldScannerIdentity, EnvScannerIdentity},
		"database identity": {FieldScannerDatabaseIdentity, EnvScannerDatabaseIdentity},
		"revocation reason": {FieldRevocationReason, EnvRevocationReason},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := OperationFromEnv(operationEnv(map[string]string{}), tc.field); err == nil {
				t.Fatal("OperationFromEnv() error = nil, want a required-field error")
			} else if !strings.Contains(err.Error(), tc.env) {
				t.Fatalf("OperationFromEnv() error = %q, want the %s reference", err, tc.env)
			}
		})
	}
}

func TestOperationFromEnvRequiresTheApprovalTTL(t *testing.T) {
	if _, err := OperationFromEnv(operationEnv(map[string]string{}), FieldApprovalTTL); err == nil {
		t.Fatal("OperationFromEnv() error = nil, want a required approval TTL error")
	} else if !strings.Contains(err.Error(), EnvApprovalTTL) {
		t.Fatalf("OperationFromEnv() error = %q, want the %s reference", err, EnvApprovalTTL)
	}
}

func TestOperationRequireRejectsAnUnknownField(t *testing.T) {
	operation := Operation{}
	if err := operation.require(Field(0)); err == nil {
		t.Fatal("require(unknown) error = nil, want error")
	}
}

func TestOperationInternalsRejectAnUnknownField(t *testing.T) {
	operation := Operation{}
	if got := operation.value(Field(99)); got != "" {
		t.Fatalf("value(unknown) = %q, want empty", got)
	}
	if got := Field(99).env(); got != "" {
		t.Fatalf("env(unknown) = %q, want empty", got)
	}
}
