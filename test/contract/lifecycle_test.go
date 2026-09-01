// Package contract exercises the dependency authority domain model through
// its exported API only, complementing the same-package whitebox tests.
package contract

import (
	"testing"
	"time"

	"github.com/t33n-software/dependency-authority/internal/dependency/domain/admission"
	"github.com/t33n-software/dependency-authority/internal/dependency/domain/approval"
	"github.com/t33n-software/dependency-authority/internal/dependency/domain/candidate"
	"github.com/t33n-software/dependency-authority/internal/dependency/domain/evidence"
	"github.com/t33n-software/dependency-authority/internal/dependency/domain/revocation"
)

const digest = "sha256:3b8f49c12b24cbbd6a4a0e6e2b2a4a4e8f0e1d2c3b4a59687766554433221100"

var issuedAt = time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)

func referenceOf(t *testing.T, evidenceType evidence.Type, locator string) evidence.Reference {
	t.Helper()
	reference, err := evidence.NewReference(evidenceType, locator, digest, "issuer", issuedAt, nil)
	if err != nil {
		t.Fatalf("NewReference(%q) error = %v", evidenceType, err)
	}
	return reference
}

func TestCandidateLifecycleThroughPublicAPI(t *testing.T) {
	c, err := candidate.New(candidate.EcosystemGo, "example.com/mod", "v1.0.0", digest)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if c.State() != candidate.StatePending {
		t.Fatalf("State() = %q, want %q", c.State(), candidate.StatePending)
	}

	if err := c.RecordEvidence(referenceOf(t, evidence.TypeSBOM, "sboms/1")); err != nil {
		t.Fatalf("RecordEvidence() error = %v", err)
	}
	if len(c.Evidence()) != 1 {
		t.Fatalf("Evidence() = %d entries, want 1", len(c.Evidence()))
	}

	if err := c.Quarantine("missing scan evidence"); err != nil {
		t.Fatalf("Quarantine() error = %v", err)
	}
	if c.State() != candidate.StateQuarantined {
		t.Fatalf("State() = %q, want %q", c.State(), candidate.StateQuarantined)
	}

	if err := c.Release("scan evidence completed"); err != nil {
		t.Fatalf("Release() error = %v", err)
	}
	if c.State() != candidate.StatePending {
		t.Fatalf("State() = %q, want %q", c.State(), candidate.StatePending)
	}

	if err := c.Approve(referenceOf(t, evidence.TypeApproval, "approvals/1")); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	if c.State() != candidate.StateApproved {
		t.Fatalf("State() = %q, want %q", c.State(), candidate.StateApproved)
	}

	if err := c.Revoke("supply chain incident"); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	if c.State() != candidate.StateRevoked {
		t.Fatalf("State() = %q, want %q", c.State(), candidate.StateRevoked)
	}
	if err := c.RecordEvidence(referenceOf(t, evidence.TypeScan, "scans/2")); err == nil {
		t.Fatal("RecordEvidence() error = nil on a terminal candidate, want error")
	}
}

func TestAdmissionPolicyEvaluationThroughPublicAPI(t *testing.T) {
	policy, err := admission.NewPolicy(
		candidate.EcosystemGo,
		[]evidence.Type{evidence.TypeSBOM, evidence.TypeScan},
		7.0,
		true,
		[]string{"GPL-3.0"},
	)
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}

	compliant := policy.Evaluate(
		admission.ScanResult{MaxCVSS: 2.0, Licenses: []string{"MIT"}},
		[]evidence.Reference{referenceOf(t, evidence.TypeSBOM, "sboms/1"), referenceOf(t, evidence.TypeScan, "scans/1")},
	)
	if compliant.Decision() != admission.DecisionAdmit {
		t.Fatalf("Decision() = %q, want %q", compliant.Decision(), admission.DecisionAdmit)
	}

	failing := policy.Evaluate(
		admission.ScanResult{MaxCVSS: 9.8, Licenses: []string{"GPL-3.0"}},
		nil,
	)
	if failing.Decision() != admission.DecisionQuarantine {
		t.Fatalf("Decision() = %q, want %q", failing.Decision(), admission.DecisionQuarantine)
	}
	if len(failing.Reasons()) != 4 {
		t.Fatalf("Reasons() = %v, want two missing evidence types, CVSS, and license", failing.Reasons())
	}
}

func TestApprovalAndRevocationThroughPublicAPI(t *testing.T) {
	approver, err := approval.New("approver", referenceOf(t, evidence.TypeApproval, "approvals/1"), issuedAt.Add(time.Hour))
	if err != nil {
		t.Fatalf("approval.New() error = %v", err)
	}
	if !approver.Valid(issuedAt) {
		t.Fatal("Valid() = false before expiry, want true")
	}
	if approver.Valid(issuedAt.Add(2 * time.Hour)) {
		t.Fatal("Valid() = true after expiry, want false")
	}

	revoked, err := revocation.New("confirmed incident", referenceOf(t, evidence.TypeRevocation, "revocations/1"), true, issuedAt)
	if err != nil {
		t.Fatalf("revocation.New() error = %v", err)
	}
	if !revoked.DownloadBlock() {
		t.Fatal("DownloadBlock() = false, want true")
	}
	if _, err := revocation.New("no block", referenceOf(t, evidence.TypeRevocation, "revocations/2"), false, issuedAt); err == nil {
		t.Fatal("revocation.New() error = nil without download block, want error")
	}
}
