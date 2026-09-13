package verification

import (
	"errors"
	"strings"
	"testing"
)

func TestProofValidity(t *testing.T) {
	for _, proof := range []Proof{
		ProofPositiveResolution, ProofNegativeResolution, ProofGraphStability, ProofIntegrity, ProofBuildEvidenceCorrespondence,
	} {
		if !proof.Valid() {
			t.Errorf("Proof(%q).Valid() = false, want true", proof)
		}
	}
	if Proof("bogus").Valid() {
		t.Error("Proof(bogus).Valid() = true, want false")
	}
}

func TestProofsBindsTheCanonicalOrder(t *testing.T) {
	proofs := Proofs()
	want := []Proof{
		ProofPositiveResolution,
		ProofNegativeResolution,
		ProofGraphStability,
		ProofIntegrity,
		ProofBuildEvidenceCorrespondence,
	}
	if len(proofs) != len(want) {
		t.Fatalf("Proofs() = %d entries, want %d", len(proofs), len(want))
	}
	for i, proof := range want {
		if proofs[i] != proof {
			t.Fatalf("Proofs()[%d] = %q, want %q", i, proofs[i], proof)
		}
	}
}

func TestNewResultValidatesTheProofAndDetail(t *testing.T) {
	if _, err := NewResult(Proof("bogus"), "detail"); err == nil {
		t.Fatal("NewResult( unknown proof ) error = nil, want error")
	}
	for _, detail := range []string{"", "  "} {
		if _, err := NewResult(ProofIntegrity, detail); err == nil {
			t.Fatalf("NewResult( detail %q ) error = nil, want error", detail)
		}
	}
	result, err := NewResult(ProofIntegrity, "all modules verified")
	if err != nil {
		t.Fatalf("NewResult() error = %v", err)
	}
	if result.Proof() != ProofIntegrity || result.Detail() != "all modules verified" {
		t.Fatalf("NewResult() = %q %q, want the bound proof and detail", result.Proof(), result.Detail())
	}
}

func reportResults(t *testing.T) []Result {
	t.Helper()
	details := []string{
		"resolved example.com/mod@v1.0.0",
		"probe failed closed",
		"no graph mutation",
		"all modules verified",
		"artifact carries example.com/mod v1.0.0 h1:abc",
	}
	results := make([]Result, 0, len(Proofs()))
	for i, proof := range Proofs() {
		result, err := NewResult(proof, details[i])
		if err != nil {
			t.Fatalf("NewResult() error = %v", err)
		}
		results = append(results, result)
	}
	return results
}

func TestNewReportEnforcesTheCompleteCanonicalOrder(t *testing.T) {
	results := reportResults(t)
	if _, err := NewReport(results[:4]); err == nil {
		t.Fatal("NewReport( four proofs ) error = nil, want the completeness error")
	}
	reordered := reportResults(t)
	reordered[0], reordered[1] = reordered[1], reordered[0]
	if _, err := NewReport(reordered); err == nil {
		t.Fatal("NewReport( reordered ) error = nil, want the order error")
	}
	report, err := NewReport(results)
	if err != nil {
		t.Fatalf("NewReport() error = %v", err)
	}
	if len(report.Results()) != len(Proofs()) {
		t.Fatalf("Results() = %d entries, want %d", len(report.Results()), len(Proofs()))
	}
}

func TestNewReportRejectsAnUnknownProof(t *testing.T) {
	results := reportResults(t)
	results[2] = Result{}
	if _, err := NewReport(results); err == nil {
		t.Fatal("NewReport( unknown proof ) error = nil, want the order error")
	}
}

func TestReportResultsAreDefensiveCopies(t *testing.T) {
	results := reportResults(t)
	report, err := NewReport(results)
	if err != nil {
		t.Fatalf("NewReport() error = %v", err)
	}
	results[0] = Result{}
	if report.Results()[0].Proof() != ProofPositiveResolution {
		t.Fatal("the report shares the caller slice, want a defensive copy")
	}
	returned := report.Results()
	returned[0] = Result{}
	if report.Results()[0].Proof() != ProofPositiveResolution {
		t.Fatal("the report shares its result slice, want a defensive copy")
	}
}

func TestReportDetail(t *testing.T) {
	report, err := NewReport(reportResults(t))
	if err != nil {
		t.Fatalf("NewReport() error = %v", err)
	}
	detail, found := report.Detail(ProofIntegrity)
	if !found || detail != "all modules verified" {
		t.Fatalf("Detail(integrity) = %q, %t, want the recorded detail", detail, found)
	}
	if _, found := report.Detail(Proof("bogus")); found {
		t.Fatal("Detail(bogus) = true, want not found")
	}
}

func TestProofError(t *testing.T) {
	cause := errors.New("endpoint unreachable")
	err := NewProofError(ProofPositiveResolution, "example.com/mod@v1.0.0", cause)
	if err.Proof() != ProofPositiveResolution || err.Detail() != "example.com/mod@v1.0.0" {
		t.Fatalf("ProofError = %q %q, want the bound proof and detail", err.Proof(), err.Detail())
	}
	if !errors.Is(err, cause) {
		t.Fatal("ProofError does not unwrap to the cause")
	}
	if !strings.Contains(err.Error(), "positive_resolution") || !strings.Contains(err.Error(), "example.com/mod@v1.0.0") || !strings.Contains(err.Error(), "endpoint unreachable") {
		t.Fatalf("Error() = %q, want proof, detail, and cause", err.Error())
	}

	bare := NewProofError(ProofIntegrity, "", cause)
	if strings.Contains(bare.Error(), "()") {
		t.Fatalf("Error() = %q, want the bare form without an empty detail", bare.Error())
	}

	substituted := NewProofError(ProofIntegrity, "", nil)
	if substituted.Unwrap() == nil {
		t.Fatal("NewProofError( nil cause ) substitutes no cause, want a non-empty error chain")
	}
}
