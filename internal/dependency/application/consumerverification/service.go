// Package consumerverification implements the consumer verification use case:
// the governed, repeatable execution of the consumer contract against the
// live approved endpoint of an ecosystem. The admission chain proves what may
// enter the approved boundary and the promotion proves what was published;
// this lane proves what the approved endpoint actually serves to a consumer.
// The five canonical proofs run in order through the ecosystem's real pinned
// toolchain; every proof failure closes the lane through a domain ProofError.
package consumerverification

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/t33n-software/dependency-authority/internal/dependency/domain/candidate"
	"github.com/t33n-software/dependency-authority/internal/dependency/domain/evidence"
	"github.com/t33n-software/dependency-authority/internal/dependency/domain/verification"
)

// Candidates loads the candidate record of the admitted version.
type Candidates interface {
	Find(ctx context.Context, ecosystem candidate.Ecosystem, name string, version string) (candidate.Candidate, bool, error)
}

// EvidenceStore loads the evidence recorded for a candidate.
type EvidenceStore interface {
	Evidence(ctx context.Context, ecosystem candidate.Ecosystem, name string, version string) ([]evidence.Reference, error)
}

// Contract executes the consumer contract through the ecosystem's real
// pinned toolchain against the live approved endpoint.
type Contract interface {
	// Prepare materializes the consumer module workspace for the admitted
	// module version and returns its directory.
	Prepare(module string, version string) (string, error)
	// Release removes the consumer workspace.
	Release(dir string) error
	// Download proves the positive resolution and returns the
	// endpoint-attested module sum.
	Download(ctx context.Context, dir string, module string, version string) (string, error)
	// ProbeFailsClosed proves the never-admitted reference fails closed.
	ProbeFailsClosed(ctx context.Context, dir string, reference string) error
	// GraphStable proves the admitted graph is stable under the ecosystem's
	// graph-mutation check.
	GraphStable(ctx context.Context, dir string) error
	// VerifyIntegrity proves the ecosystem's integrity proof passes.
	VerifyIntegrity(ctx context.Context, dir string) error
	// BuildEvidence builds a consumer artifact from the admitted graph and
	// returns the artifact-carried version and module sum.
	BuildEvidence(ctx context.Context, dir string, module string) (version string, sum string, err error)
}

// Service runs the consumer verification lane.
type Service struct {
	candidates    Candidates
	evidenceStore EvidenceStore
	contract      Contract
}

// NewService constructs the consumer verification service and fails closed on
// unbound ports.
func NewService(candidates Candidates, evidenceStore EvidenceStore, contract Contract) (Service, error) {
	if candidates == nil {
		return Service{}, errors.New("candidates port must not be nil")
	}
	if evidenceStore == nil {
		return Service{}, errors.New("evidence store port must not be nil")
	}
	if contract == nil {
		return Service{}, errors.New("consumer contract port must not be nil")
	}
	return Service{candidates: candidates, evidenceStore: evidenceStore, contract: contract}, nil
}

// Verify proves the consumer contract for an admitted module version against
// the live approved endpoint. The lane verifies admitted versions only, and
// every failed proof closes the lane through a *verification.ProofError
// naming the failed proof.
func (s Service) Verify(ctx context.Context, ecosystem candidate.Ecosystem, name string, version string, negativeProbe string) (verification.Report, error) {
	if strings.TrimSpace(negativeProbe) == "" {
		return verification.Report{}, errors.New("negative probe reference must not be empty")
	}
	current, found, err := s.candidates.Find(ctx, ecosystem, name, version)
	if err != nil {
		return verification.Report{}, fmt.Errorf("load candidate: %w", err)
	}
	if !found {
		return verification.Report{}, fmt.Errorf("candidate %s %s not found", name, version)
	}
	if current.State() != candidate.StateApproved {
		return verification.Report{}, fmt.Errorf("candidate in state %q is not admitted: the consumer verification proves admitted versions only", current.State())
	}
	trail, err := s.evidenceStore.Evidence(ctx, ecosystem, name, version)
	if err != nil {
		return verification.Report{}, fmt.Errorf("load evidence: %w", err)
	}
	if !hasApprovalEvidence(trail) {
		return verification.Report{}, errors.New("no approval evidence recorded: the candidate is not admission-proven")
	}

	dir, err := s.contract.Prepare(name, version)
	if err != nil {
		return verification.Report{}, fmt.Errorf("prepare the consumer workspace: %w", err)
	}
	// The workspace is ephemeral per execution; a release failure cannot
	// invalidate the completed proofs.
	defer func() { _ = s.contract.Release(dir) }()

	sum, err := s.contract.Download(ctx, dir, name, version)
	if err != nil {
		return verification.Report{}, verification.NewProofError(verification.ProofPositiveResolution, name+"@"+version, err)
	}
	if err := s.contract.ProbeFailsClosed(ctx, dir, negativeProbe); err != nil {
		return verification.Report{}, verification.NewProofError(verification.ProofNegativeResolution, negativeProbe, err)
	}
	if err := s.contract.GraphStable(ctx, dir); err != nil {
		return verification.Report{}, verification.NewProofError(verification.ProofGraphStability, name+"@"+version, err)
	}
	if err := s.contract.VerifyIntegrity(ctx, dir); err != nil {
		return verification.Report{}, verification.NewProofError(verification.ProofIntegrity, name+"@"+version, err)
	}
	artifactVersion, artifactSum, err := s.contract.BuildEvidence(ctx, dir, name)
	if err != nil {
		return verification.Report{}, verification.NewProofError(verification.ProofBuildEvidenceCorrespondence, name+"@"+version, err)
	}
	if artifactVersion != version || artifactSum != sum {
		return verification.Report{}, verification.NewProofError(verification.ProofBuildEvidenceCorrespondence, name+"@"+version,
			fmt.Errorf("the consumer artifact carries %s %s, want the evidence-bound %s %s", artifactVersion, artifactSum, version, sum))
	}

	// The canonical proof set and the non-empty details make every result
	// construction total.
	positive, _ := verification.NewResult(verification.ProofPositiveResolution, "resolved "+name+"@"+version+" sum="+sum)
	negative, _ := verification.NewResult(verification.ProofNegativeResolution, "probe "+negativeProbe+" failed closed")
	stable, _ := verification.NewResult(verification.ProofGraphStability, "go mod tidy -diff reports no change")
	integrity, _ := verification.NewResult(verification.ProofIntegrity, "all modules verified")
	correspondence, _ := verification.NewResult(verification.ProofBuildEvidenceCorrespondence, "the consumer artifact carries "+name+" "+artifactVersion+" "+artifactSum)
	// The canonical proof set in canonical order makes the report
	// construction total.
	report, _ := verification.NewReport([]verification.Result{positive, negative, stable, integrity, correspondence})
	return report, nil
}

// hasApprovalEvidence reports whether the candidate trail carries the
// admission approval.
func hasApprovalEvidence(trail []evidence.Reference) bool {
	for _, reference := range trail {
		if reference.Type() == evidence.TypeApproval {
			return true
		}
	}
	return false
}
