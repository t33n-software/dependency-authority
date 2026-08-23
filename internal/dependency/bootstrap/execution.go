package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/t33n-software/dependency-authority/internal/dependency/adapters/inbound/config"
	"github.com/t33n-software/dependency-authority/internal/dependency/adapters/outbound/policy"
	"github.com/t33n-software/dependency-authority/internal/dependency/application/admission"
	"github.com/t33n-software/dependency-authority/internal/dependency/application/intake"
	"github.com/t33n-software/dependency-authority/internal/dependency/application/promotion"
	"github.com/t33n-software/dependency-authority/internal/dependency/application/revalidation"
	"github.com/t33n-software/dependency-authority/internal/dependency/application/revocation"
	domainadmission "github.com/t33n-software/dependency-authority/internal/dependency/domain/admission"
	"github.com/t33n-software/dependency-authority/internal/dependency/domain/approval"
	"github.com/t33n-software/dependency-authority/internal/dependency/domain/candidate"
	"github.com/t33n-software/dependency-authority/internal/dependency/domain/evidence"
)

// Evidence schema versions of the lane-produced evidence documents.
const (
	scanEvidenceSchema       = "dependency-authority/scan-evidence/v1"
	decisionEvidenceSchema   = "dependency-authority/admission-decision/v1"
	approvalEvidenceSchema   = "dependency-authority/approval/v1"
	revocationEvidenceSchema = "dependency-authority/revocation/v1"
)

// EvidenceJournal is the evidence-zone write capability the lane execution
// orchestrates: content-addressed payload publication plus reference indexing.
type EvidenceJournal interface {
	Put(ctx context.Context, subject candidate.Candidate, evidenceType evidence.Type, issuer string, payload []byte, issuedAt time.Time, expiresAt *time.Time) (evidence.Reference, error)
	Record(ctx context.Context, subject candidate.Candidate, reference evidence.Reference) error
}

// readBundle loads the policy bundle content; os.ReadFile in production.
var readBundle = os.ReadFile

// operationFields binds the required operation inputs of each lane.
func operationFields(operation Operation) []config.Field {
	switch operation {
	case OperationIntake, OperationPromotion:
		return []config.Field{config.FieldModule, config.FieldVersion}
	case OperationAdmission:
		return []config.Field{config.FieldModule, config.FieldVersion, config.FieldLaneIdentity, config.FieldScannerIdentity, config.FieldScannerDatabaseIdentity, config.FieldApprovalTTL}
	case OperationRevalidation:
		return []config.Field{config.FieldModule, config.FieldVersion, config.FieldScannerIdentity, config.FieldScannerDatabaseIdentity}
	case OperationRevocation:
		return []config.Field{config.FieldModule, config.FieldVersion, config.FieldLaneIdentity, config.FieldRevocationReason}
	default:
		return nil
	}
}

// execute runs the lane use case with the bound operation inputs.
func execute(ctx context.Context, operation Operation, service any, ports Ports, controllerConfig config.Config, operationInput config.Operation, lookup func(string) string, stdout io.Writer) error {
	switch operation {
	case OperationIntake:
		return executeIntake(ctx, service.(intake.Service), controllerConfig, operationInput, stdout)
	case OperationAdmission:
		return executeAdmission(ctx, service.(admission.Service), ports, controllerConfig, operationInput, lookup, stdout)
	case OperationPromotion:
		return executePromotion(ctx, service.(promotion.Service), ports, controllerConfig, operationInput, stdout)
	case OperationRevalidation:
		return executeRevalidation(ctx, service.(revalidation.Service), ports, controllerConfig, operationInput, lookup, stdout)
	case OperationRevocation:
		return executeRevocation(ctx, service.(revocation.Service), ports, controllerConfig, operationInput, stdout)
	default:
		return fmt.Errorf("unknown operation %q", operation)
	}
}

// executeIntake registers the pending candidate from the controlled upstream
// digest.
func executeIntake(ctx context.Context, service intake.Service, controllerConfig config.Config, operationInput config.Operation, stdout io.Writer) error {
	registered, err := service.Intake(ctx, controllerConfig.Ecosystem(), operationInput.Module(), operationInput.Version())
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "dependency-intake-controller: candidate %s %s %s state=%s digest=%s\n",
		registered.Ecosystem(), registered.Name(), registered.Version(), registered.State(), registered.Digest())
	return nil
}

// executeAdmission scans the candidate, records the scan and decision
// evidence with the pinned tool and policy identities, and records the
// automatic time-bounded approval on a policy pass (ADR-0002).
func executeAdmission(ctx context.Context, service admission.Service, ports Ports, controllerConfig config.Config, operationInput config.Operation, lookup func(string) string, stdout io.Writer) error {
	ecosystem := controllerConfig.Ecosystem()
	name := operationInput.Module()
	version := operationInput.Version()

	identity, err := policyIdentity(lookup)
	if err != nil {
		return err
	}
	journal, err := journalOf(ports)
	if err != nil {
		return err
	}

	current, found, err := ports.Candidates.Find(ctx, ecosystem, name, version)
	if err != nil {
		return fmt.Errorf("load candidate: %w", err)
	}
	if !found {
		return fmt.Errorf("candidate %s %s not found: run the intake lane first", name, version)
	}

	// The lane scans the candidate for the evidence record; the use case
	// re-evaluates the same deterministic offline scan against the policy.
	scan, err := ports.Scanner.Scan(ctx, current)
	if err != nil {
		return fmt.Errorf("scan candidate: %w", err)
	}
	now := ports.Now()
	if _, err := produceEvidence(ctx, journal, current, evidence.TypeScan, operationInput.ScannerIdentity(), scanEvidence(ecosystem, name, version, operationInput, scan, now), now, nil); err != nil {
		return err
	}

	report, err := service.Admit(ctx, ecosystem, name, version)
	if err != nil {
		return err
	}

	now = ports.Now()
	if _, err := produceEvidence(ctx, journal, current, evidence.TypePolicy, identity, decisionEvidence(ecosystem, name, version, identity, report, now), now, nil); err != nil {
		return err
	}

	approvalNote := "approval=none"
	if report.Decision() == domainadmission.DecisionAdmit {
		now = ports.Now()
		expiresAt := now.Add(operationInput.ApprovalTTL())
		if _, err := produceEvidence(ctx, journal, current, evidence.TypeApproval, operationInput.LaneIdentity(), approvalEvidence(ecosystem, name, version, operationInput.LaneIdentity(), now, expiresAt), now, &expiresAt); err != nil {
			return err
		}
		approvalNote = "approval=recorded expires_at=" + expiresAt.UTC().Format(time.RFC3339)
	}

	fmt.Fprintf(stdout, "dependency-admission-controller: candidate %s %s %s decision=%s %s\n",
		ecosystem, name, version, report.Decision(), approvalNote)
	return nil
}

// executePromotion promotes a pending candidate under the newest recorded,
// still valid approval.
func executePromotion(ctx context.Context, service promotion.Service, ports Ports, controllerConfig config.Config, operationInput config.Operation, stdout io.Writer) error {
	ecosystem := controllerConfig.Ecosystem()
	name := operationInput.Module()
	version := operationInput.Version()

	trail, err := ports.EvidenceStore.Evidence(ctx, ecosystem, name, version)
	if err != nil {
		return fmt.Errorf("load evidence trail: %w", err)
	}
	approvalReference, err := latestApproval(trail, ports.Now())
	if err != nil {
		return err
	}
	// The newest-approval selection binds the approval type, a non-empty
	// issuer, and a present expiry, so this construction is total.
	expiresAt, _ := approvalReference.ExpiresAt()
	approver, _ := approval.New(approvalReference.Issuer(), approvalReference, expiresAt)
	if err := service.Promote(ctx, ecosystem, name, version, approver); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "dependency-promotion-controller: candidate %s %s %s state=approved\n",
		ecosystem, name, version)
	return nil
}

// executeRevalidation re-evaluates an approved candidate and records the
// fresh scan and decision evidence.
func executeRevalidation(ctx context.Context, service revalidation.Service, ports Ports, controllerConfig config.Config, operationInput config.Operation, lookup func(string) string, stdout io.Writer) error {
	ecosystem := controllerConfig.Ecosystem()
	name := operationInput.Module()
	version := operationInput.Version()

	journal, err := journalOf(ports)
	if err != nil {
		return err
	}
	identity, err := policyIdentity(lookup)
	if err != nil {
		return err
	}

	current, found, err := ports.Candidates.Find(ctx, ecosystem, name, version)
	if err != nil {
		return fmt.Errorf("load candidate: %w", err)
	}
	if !found {
		return fmt.Errorf("candidate %s %s not found", name, version)
	}

	scan, err := ports.Scanner.Scan(ctx, current)
	if err != nil {
		return fmt.Errorf("scan candidate: %w", err)
	}
	now := ports.Now()
	if _, err := produceEvidence(ctx, journal, current, evidence.TypeScan, operationInput.ScannerIdentity(), scanEvidence(ecosystem, name, version, operationInput, scan, now), now, nil); err != nil {
		return err
	}

	report, err := service.Revalidate(ctx, ecosystem, name, version)
	if err != nil {
		return err
	}

	now = ports.Now()
	if _, err := produceEvidence(ctx, journal, current, evidence.TypePolicy, identity, decisionEvidence(ecosystem, name, version, identity, report, now), now, nil); err != nil {
		return err
	}

	fmt.Fprintf(stdout, "dependency-revalidation-controller: candidate %s %s %s decision=%s\n",
		ecosystem, name, version, report.Decision())
	return nil
}

// executeRevocation publishes the revocation evidence and revokes the
// candidate with an active download block.
func executeRevocation(ctx context.Context, service revocation.Service, ports Ports, controllerConfig config.Config, operationInput config.Operation, stdout io.Writer) error {
	ecosystem := controllerConfig.Ecosystem()
	name := operationInput.Module()
	version := operationInput.Version()

	journal, err := journalOf(ports)
	if err != nil {
		return err
	}

	current, found, err := ports.Candidates.Find(ctx, ecosystem, name, version)
	if err != nil {
		return fmt.Errorf("load candidate: %w", err)
	}
	if !found {
		return fmt.Errorf("candidate %s %s not found", name, version)
	}

	now := ports.Now()
	reference, err := journal.Put(ctx, current, evidence.TypeRevocation, operationInput.LaneIdentity(), revocationEvidence(ecosystem, name, version, operationInput.LaneIdentity(), operationInput.RevocationReason(), now), now, nil)
	if err != nil {
		return fmt.Errorf("publish revocation evidence: %w", err)
	}

	decision, err := service.Revoke(ctx, ecosystem, name, version, operationInput.RevocationReason(), reference)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "dependency-revocation-controller: candidate %s %s %s state=revoked download_block=%t\n",
		ecosystem, name, version, decision.DownloadBlock())
	return nil
}

// journalOf binds the evidence journal or fails closed.
func journalOf(ports Ports) (EvidenceJournal, error) {
	if ports.Journal == nil {
		return nil, errors.New("evidence journal is not bound")
	}
	return ports.Journal, nil
}

// produceEvidence publishes the evidence payload content-addressed and
// indexes its reference in the candidate evidence trail.
func produceEvidence(ctx context.Context, journal EvidenceJournal, subject candidate.Candidate, evidenceType evidence.Type, issuer string, payload []byte, now time.Time, expiresAt *time.Time) (evidence.Reference, error) {
	reference, err := journal.Put(ctx, subject, evidenceType, issuer, payload, now, expiresAt)
	if err != nil {
		return evidence.Reference{}, fmt.Errorf("publish %s evidence: %w", evidenceType, err)
	}
	if err := journal.Record(ctx, subject, reference); err != nil {
		return evidence.Reference{}, fmt.Errorf("index %s evidence: %w", evidenceType, err)
	}
	return reference, nil
}

// latestApproval returns the newest recorded approval reference and fails
// closed when none exists, when it carries no expiry, or when it is expired.
func latestApproval(trail []evidence.Reference, now time.Time) (evidence.Reference, error) {
	var newest *evidence.Reference
	for i := range trail {
		if trail[i].Type() != evidence.TypeApproval {
			continue
		}
		if newest == nil || trail[i].IssuedAt().After(newest.IssuedAt()) {
			newest = &trail[i]
		}
	}
	if newest == nil {
		return evidence.Reference{}, errors.New("no approval evidence recorded: run the admission lane first")
	}
	if _, ok := newest.ExpiresAt(); !ok {
		return evidence.Reference{}, errors.New("the recorded approval evidence carries no expiry")
	}
	if newest.Expired(now) {
		return evidence.Reference{}, errors.New("the recorded approval is expired: re-run the admission lane")
	}
	return *newest, nil
}

// policyIdentity computes the content-pinned identity of the bound policy
// bundle: the exact schema version pin plus the bundle content digest.
func policyIdentity(lookup func(string) string) (string, error) {
	bindings, err := config.BindingsFromEnv(lookup)
	if err != nil {
		return "", err
	}
	content, err := readBundle(bindings.PolicyBundle())
	if err != nil {
		return "", fmt.Errorf("read policy bundle: %w", err)
	}
	sum := sha256.Sum256(content)
	return policy.SchemaID + "@sha256:" + hex.EncodeToString(sum[:]), nil
}

// scanEvidenceDocument is the canonical scan evidence document.
type scanEvidenceDocument struct {
	Schema    string   `json:"schema"`
	Ecosystem string   `json:"ecosystem"`
	Name      string   `json:"name"`
	Version   string   `json:"version"`
	Tool      string   `json:"tool"`
	Database  string   `json:"database"`
	MaxCVSS   float64  `json:"max_cvss"`
	Licenses  []string `json:"licenses"`
	IssuedAt  string   `json:"issued_at"`
}

// scanEvidence builds the canonical scan evidence document of one lane scan.
func scanEvidence(ecosystem candidate.Ecosystem, name string, version string, operationInput config.Operation, scan domainadmission.ScanResult, now time.Time) []byte {
	licenses := scan.Licenses
	if licenses == nil {
		licenses = []string{}
	}
	// The document carries only strings, a number, and a string slice, so
	// marshaling cannot fail.
	content, _ := json.Marshal(scanEvidenceDocument{
		Schema:    scanEvidenceSchema,
		Ecosystem: string(ecosystem),
		Name:      name,
		Version:   version,
		Tool:      operationInput.ScannerIdentity(),
		Database:  operationInput.ScannerDatabaseIdentity(),
		MaxCVSS:   scan.MaxCVSS,
		Licenses:  licenses,
		IssuedAt:  now.UTC().Format(time.RFC3339Nano),
	})
	return content
}

// decisionEvidenceDocument is the canonical admission decision evidence
// document.
type decisionEvidenceDocument struct {
	Schema    string   `json:"schema"`
	Ecosystem string   `json:"ecosystem"`
	Name      string   `json:"name"`
	Version   string   `json:"version"`
	Policy    string   `json:"policy"`
	Decision  string   `json:"decision"`
	Reasons   []string `json:"reasons"`
	IssuedAt  string   `json:"issued_at"`
}

// decisionEvidence builds the canonical decision evidence document of one
// admission or revalidation evaluation.
func decisionEvidence(ecosystem candidate.Ecosystem, name string, version string, identity string, report domainadmission.Report, now time.Time) []byte {
	// The document carries only strings and string slices, so marshaling
	// cannot fail; the report reasons are always a non-nil defensive copy.
	content, _ := json.Marshal(decisionEvidenceDocument{
		Schema:    decisionEvidenceSchema,
		Ecosystem: string(ecosystem),
		Name:      name,
		Version:   version,
		Policy:    identity,
		Decision:  string(report.Decision()),
		Reasons:   report.Reasons(),
		IssuedAt:  now.UTC().Format(time.RFC3339Nano),
	})
	return content
}

// approvalEvidenceDocument is the canonical automatic approval evidence
// document.
type approvalEvidenceDocument struct {
	Schema    string `json:"schema"`
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Issuer    string `json:"issuer"`
	Decision  string `json:"decision"`
	IssuedAt  string `json:"issued_at"`
	ExpiresAt string `json:"expires_at"`
}

// approvalEvidence builds the canonical approval evidence document of the
// automatic policy-pass approval.
func approvalEvidence(ecosystem candidate.Ecosystem, name string, version string, laneIdentity string, now time.Time, expiresAt time.Time) []byte {
	// The document carries only strings, so marshaling cannot fail.
	content, _ := json.Marshal(approvalEvidenceDocument{
		Schema:    approvalEvidenceSchema,
		Ecosystem: string(ecosystem),
		Name:      name,
		Version:   version,
		Issuer:    laneIdentity,
		Decision:  string(domainadmission.DecisionAdmit),
		IssuedAt:  now.UTC().Format(time.RFC3339Nano),
		ExpiresAt: expiresAt.UTC().Format(time.RFC3339Nano),
	})
	return content
}

// revocationEvidenceDocument is the canonical revocation evidence document.
type revocationEvidenceDocument struct {
	Schema    string `json:"schema"`
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Reason    string `json:"reason"`
	Issuer    string `json:"issuer"`
	RevokedAt string `json:"revoked_at"`
}

// revocationEvidence builds the canonical revocation evidence document of one
// revocation decision.
func revocationEvidence(ecosystem candidate.Ecosystem, name string, version string, laneIdentity string, reason string, now time.Time) []byte {
	// The document carries only strings, so marshaling cannot fail.
	content, _ := json.Marshal(revocationEvidenceDocument{
		Schema:    revocationEvidenceSchema,
		Ecosystem: string(ecosystem),
		Name:      name,
		Version:   version,
		Reason:    reason,
		Issuer:    laneIdentity,
		RevokedAt: now.UTC().Format(time.RFC3339Nano),
	})
	return content
}
