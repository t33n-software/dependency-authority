package admission

import (
	"testing"
	"time"

	"github.com/t33n-software/dependency-authority/internal/dependency/domain/candidate"
	"github.com/t33n-software/dependency-authority/internal/dependency/domain/evidence"
)

const validDigest = "sha256:3b8f49c12b24cbbd6a4a0e6e2b2a4a4e8f0e1d2c3b4a59687766554433221100"

func evidenceOfType(t *testing.T, evidenceType evidence.Type) evidence.Reference {
	t.Helper()
	reference, err := evidence.NewReference(evidenceType, "ref/"+string(evidenceType), validDigest, "issuer", time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC), nil)
	if err != nil {
		t.Fatalf("NewReference() error = %v", err)
	}
	return reference
}

func validPolicy(t *testing.T) Policy {
	t.Helper()
	policy, err := NewPolicy(candidate.EcosystemGo, []evidence.Type{evidence.TypeSBOM, evidence.TypeScan}, 7.0, true, []string{"GPL-3.0"})
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}
	return policy
}

func TestNewPolicyValidation(t *testing.T) {
	if _, err := NewPolicy(candidate.Ecosystem("ruby"), []evidence.Type{evidence.TypeSBOM}, 0, false, nil); err == nil {
		t.Fatal("NewPolicy() error = nil, want unknown ecosystem error")
	}
	if _, err := NewPolicy(candidate.EcosystemGo, nil, 0, false, nil); err == nil {
		t.Fatal("NewPolicy() error = nil, want empty required evidence error")
	}
	if _, err := NewPolicy(candidate.EcosystemGo, []evidence.Type{evidence.Type("bogus")}, 0, false, nil); err == nil {
		t.Fatal("NewPolicy() error = nil, want unknown evidence type error")
	}
	if _, err := NewPolicy(candidate.EcosystemGo, []evidence.Type{evidence.TypeSBOM}, -0.1, true, nil); err == nil {
		t.Fatal("NewPolicy() error = nil, want negative CVSS error")
	}
	if _, err := NewPolicy(candidate.EcosystemGo, []evidence.Type{evidence.TypeSBOM}, 10.1, true, nil); err == nil {
		t.Fatal("NewPolicy() error = nil, want CVSS range error")
	}
	if _, err := NewPolicy(candidate.EcosystemGo, []evidence.Type{evidence.TypeSBOM}, 10.0, true, nil); err != nil {
		t.Fatalf("NewPolicy(maxCVSS=10) error = %v, want boundary acceptance", err)
	}
	if _, err := NewPolicy(candidate.EcosystemGo, []evidence.Type{evidence.TypeSBOM}, 0, false, []string{" "}); err == nil {
		t.Fatal("NewPolicy() error = nil, want empty blocked license error")
	}
}

func TestPolicyAccessorsReturnCopies(t *testing.T) {
	policy := validPolicy(t)
	if policy.Ecosystem() != candidate.EcosystemGo {
		t.Fatalf("Ecosystem() = %q, want %q", policy.Ecosystem(), candidate.EcosystemGo)
	}
	required := policy.RequiredEvidence()
	required[0] = evidence.TypeRevocation
	if policy.RequiredEvidence()[0] != evidence.TypeSBOM {
		t.Fatal("RequiredEvidence() does not return a defensive copy")
	}
	maxCVSS, enforced := policy.MaxCVSS()
	if !enforced || maxCVSS != 7.0 {
		t.Fatalf("MaxCVSS() = %v, %t, want 7.0, true", maxCVSS, enforced)
	}
	blocked := policy.BlockedLicenses()
	blocked[0] = "MIT"
	if policy.BlockedLicenses()[0] != "GPL-3.0" {
		t.Fatal("BlockedLicenses() does not return a defensive copy")
	}
}

func TestEvaluateAdmitsCompliantCandidate(t *testing.T) {
	policy := validPolicy(t)
	report := policy.Evaluate(
		ScanResult{MaxCVSS: 4.5, Licenses: []string{"MIT"}},
		[]evidence.Reference{evidenceOfType(t, evidence.TypeSBOM), evidenceOfType(t, evidence.TypeScan)},
	)
	if report.Decision() != DecisionAdmit {
		t.Fatalf("Decision() = %q, want %q (reasons %v)", report.Decision(), DecisionAdmit, report.Reasons())
	}
	if len(report.Reasons()) != 0 {
		t.Fatalf("Reasons() = %v, want none", report.Reasons())
	}
}

func TestEvaluateQuarantinesOnMissingEvidence(t *testing.T) {
	policy := validPolicy(t)
	report := policy.Evaluate(ScanResult{}, []evidence.Reference{evidenceOfType(t, evidence.TypeSBOM)})
	if report.Decision() != DecisionQuarantine {
		t.Fatalf("Decision() = %q, want %q", report.Decision(), DecisionQuarantine)
	}
	reasons := report.Reasons()
	if len(reasons) != 1 || reasons[0] != `missing required evidence "scan"` {
		t.Fatalf("Reasons() = %v, want missing scan evidence", reasons)
	}
	reasons[0] = "mutated"
	if report.Reasons()[0] == "mutated" {
		t.Fatal("Reasons() does not return a defensive copy")
	}
}

func TestEvaluateQuarantinesOnCVSSAndLicense(t *testing.T) {
	policy := validPolicy(t)
	report := policy.Evaluate(
		ScanResult{MaxCVSS: 9.8, Licenses: []string{"MIT", "GPL-3.0"}},
		[]evidence.Reference{evidenceOfType(t, evidence.TypeSBOM), evidenceOfType(t, evidence.TypeScan)},
	)
	if report.Decision() != DecisionQuarantine {
		t.Fatalf("Decision() = %q, want %q", report.Decision(), DecisionQuarantine)
	}
	if len(report.Reasons()) != 2 {
		t.Fatalf("Reasons() = %v, want CVSS and license violations", report.Reasons())
	}
}

func TestEvaluateWithoutCVSSEnforcement(t *testing.T) {
	policy, err := NewPolicy(candidate.EcosystemGo, []evidence.Type{evidence.TypeSBOM}, 0, false, nil)
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}
	if _, enforced := policy.MaxCVSS(); enforced {
		t.Fatal("MaxCVSS() enforced = true, want false")
	}
	report := policy.Evaluate(ScanResult{MaxCVSS: 10.0}, []evidence.Reference{evidenceOfType(t, evidence.TypeSBOM)})
	if report.Decision() != DecisionAdmit {
		t.Fatalf("Decision() = %q, want %q", report.Decision(), DecisionAdmit)
	}
}
