// Package verification models the consumer verification report: the five
// consumer-contract proofs in their canonical order, proven against the live
// approved endpoint by the ecosystem's real pinned toolchain. A constructed
// Report is the proof of passage — a failed proof never reaches the report,
// it fails the lane closed through a ProofError.
package verification

import (
	"errors"
	"fmt"
	"strings"
)

// Proof identifies one consumer-contract proof of the verification lane.
type Proof string

const (
	// ProofPositiveResolution proves the admitted version resolves through
	// the approved endpoint.
	ProofPositiveResolution Proof = "positive_resolution"
	// ProofNegativeResolution proves a never-admitted reference fails closed
	// at the approved endpoint.
	ProofNegativeResolution Proof = "negative_resolution"
	// ProofGraphStability proves the admitted graph is stable under the
	// ecosystem's graph-mutation check.
	ProofGraphStability Proof = "graph_stability"
	// ProofIntegrity proves the ecosystem's integrity proof passes for the
	// resolved content.
	ProofIntegrity Proof = "integrity"
	// ProofBuildEvidenceCorrespondence proves a consumer artifact built from
	// the admitted graph carries the evidence-bound module identities.
	ProofBuildEvidenceCorrespondence Proof = "build_evidence_correspondence"
)

// Valid reports whether the proof belongs to the canonical consumer contract.
func (p Proof) Valid() bool {
	switch p {
	case ProofPositiveResolution, ProofNegativeResolution, ProofGraphStability, ProofIntegrity, ProofBuildEvidenceCorrespondence:
		return true
	default:
		return false
	}
}

// Proofs returns the canonical proof order of the consumer contract.
func Proofs() []Proof {
	return []Proof{
		ProofPositiveResolution,
		ProofNegativeResolution,
		ProofGraphStability,
		ProofIntegrity,
		ProofBuildEvidenceCorrespondence,
	}
}

// Result carries the outcome detail of one proven consumer-contract proof.
type Result struct {
	proof  Proof
	detail string
}

// NewResult constructs a validated proof result.
func NewResult(proof Proof, detail string) (Result, error) {
	if !proof.Valid() {
		return Result{}, fmt.Errorf("unknown consumer-contract proof %q", proof)
	}
	if strings.TrimSpace(detail) == "" {
		return Result{}, errors.New("proof detail must not be empty")
	}
	return Result{proof: proof, detail: detail}, nil
}

// Proof returns the proven consumer-contract proof.
func (r Result) Proof() Proof {
	return r.proof
}

// Detail returns the proof outcome detail.
func (r Result) Detail() string {
	return r.detail
}

// Report is the completed consumer verification: exactly the five canonical
// proofs in their canonical order.
type Report struct {
	results []Result
}

// NewReport constructs the verification report and fails closed on any
// missing or misordered proof.
func NewReport(results []Result) (Report, error) {
	canonical := Proofs()
	if len(results) != len(canonical) {
		return Report{}, fmt.Errorf("consumer verification report must carry exactly %d proofs, got %d", len(canonical), len(results))
	}
	for i, result := range results {
		if result.Proof() != canonical[i] {
			return Report{}, fmt.Errorf("consumer verification proof %d must be %q, got %q", i+1, canonical[i], result.Proof())
		}
	}
	recorded := make([]Result, len(results))
	copy(recorded, results)
	return Report{results: recorded}, nil
}

// Results returns a defensive copy of the proof results in canonical order.
func (r Report) Results() []Result {
	results := make([]Result, len(r.results))
	copy(results, r.results)
	return results
}

// Detail returns the recorded detail of one canonical proof.
func (r Report) Detail(proof Proof) (string, bool) {
	for _, result := range r.results {
		if result.Proof() == proof {
			return result.Detail(), true
		}
	}
	return "", false
}

// ProofError fails the lane closed at one consumer-contract proof.
type ProofError struct {
	proof  Proof
	detail string
	err    error
}

// NewProofError binds the failed proof and its cause. A nil cause is
// substituted so the error chain is never empty.
func NewProofError(proof Proof, detail string, err error) *ProofError {
	if err == nil {
		err = errors.New("proof failed without a cause")
	}
	return &ProofError{proof: proof, detail: detail, err: err}
}

// Error reports the failed proof and its cause.
func (e *ProofError) Error() string {
	if e.detail == "" {
		return fmt.Sprintf("consumer-contract proof %q failed: %v", e.proof, e.err)
	}
	return fmt.Sprintf("consumer-contract proof %q failed (%s): %v", e.proof, e.detail, e.err)
}

// Unwrap returns the proof failure cause.
func (e *ProofError) Unwrap() error {
	return e.err
}

// Proof returns the failed consumer-contract proof.
func (e *ProofError) Proof() Proof {
	return e.proof
}

// Detail returns the failure detail.
func (e *ProofError) Detail() string {
	return e.detail
}
