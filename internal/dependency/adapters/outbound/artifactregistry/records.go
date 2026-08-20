package artifactregistry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/t33n-software/dependency-authority/internal/dependency/domain/candidate"
	"github.com/t33n-software/dependency-authority/internal/dependency/domain/evidence"
)

// recordSchema binds the candidate record document shape.
const recordSchema = "dependency-authority/candidate-record/v1"

// recordVersion is the immutable generic-artifact version grouping the
// candidate records of one package.
const recordVersion = "v1"

// Records is the append-only candidate records store. Each save uploads one
// content-addressed record document into the bound generic repository; the
// effective candidate state is the newest stored snapshot.
type Records struct {
	client     Client
	repository string
	now        func() time.Time
}

// NewRecords constructs the records store and fails closed on an invalid
// repository resource name or a nil clock.
func NewRecords(client Client, repository string, now func() time.Time) (Records, error) {
	if _, _, _, err := parseRepository(repository); err != nil {
		return Records{}, err
	}
	if now == nil {
		return Records{}, errors.New("records clock must not be nil")
	}
	return Records{client: client, repository: repository, now: now}, nil
}

// Save appends the current candidate snapshot as a new content-addressed
// record. Re-recording identical content is an idempotent success.
func (r Records) Save(ctx context.Context, subject candidate.Candidate) error {
	document := snapshot(r.now, subject)
	// The record document carries only strings and string slices, so
	// marshaling cannot fail.
	content, _ := json.Marshal(document)
	filename := hex.EncodeToString(sha256Sum(content)) + ".json"
	return r.client.upload(ctx, r.repository, recordPackage(subject), recordVersion, filename, content)
}

// Find loads the newest candidate snapshot and rebuilds the aggregate through
// the domain transitions. A candidate without any record is reported as not
// found.
func (r Records) Find(ctx context.Context, ecosystem candidate.Ecosystem, name string, version string) (candidate.Candidate, bool, error) {
	files, err := r.client.list(ctx, r.repository, recordPackageIdentity(ecosystem, name, version), recordVersion)
	if err != nil {
		return candidate.Candidate{}, false, err
	}
	if len(files) == 0 {
		return candidate.Candidate{}, false, nil
	}
	sort.Slice(files, func(i, j int) bool {
		if files[i].CreateTime != files[j].CreateTime {
			return files[i].CreateTime < files[j].CreateTime
		}
		return files[i].Name < files[j].Name
	})

	latest := files[len(files)-1]
	content, err := r.client.download(ctx, latest.Name)
	if err != nil {
		return candidate.Candidate{}, false, err
	}
	document, err := decodeRecord(content)
	if err != nil {
		return candidate.Candidate{}, false, fmt.Errorf("decode candidate record %q: %w", latest.Name, err)
	}
	rebuilt, err := document.rebuild()
	if err != nil {
		return candidate.Candidate{}, false, fmt.Errorf("rebuild candidate from %q: %w", latest.Name, err)
	}
	return rebuilt, true, nil
}

// recordPackage binds the candidate to its generic-artifact package.
func recordPackage(subject candidate.Candidate) string {
	return recordPackageIdentity(subject.Ecosystem(), subject.Name(), subject.Version())
}

// recordPackageIdentity derives the deterministic, alphabet-safe package ID
// of one candidate version.
func recordPackageIdentity(ecosystem candidate.Ecosystem, name string, version string) string {
	sum := sha256.Sum256([]byte(string(ecosystem) + "\n" + name + "\n" + version))
	return "candidates-" + hex.EncodeToString(sum[:])[:24]
}

// referenceDocument mirrors one evidence reference in the record document.
type referenceDocument struct {
	Type      string  `json:"type"`
	Reference string  `json:"reference"`
	Digest    string  `json:"digest"`
	Issuer    string  `json:"issuer"`
	IssuedAt  string  `json:"issued_at"`
	ExpiresAt *string `json:"expires_at"`
}

// recordDocument is the candidate state snapshot persisted per save.
type recordDocument struct {
	Schema     string              `json:"schema"`
	Ecosystem  string              `json:"ecosystem"`
	Name       string              `json:"name"`
	Version    string              `json:"version"`
	Digest     string              `json:"digest"`
	State      string              `json:"state"`
	Evidence   []referenceDocument `json:"evidence"`
	Approval   *referenceDocument  `json:"approval"`
	RecordedAt string              `json:"recorded_at"`
}

// snapshot freezes the aggregate into its record document. Transition reasons
// are governance narrative bound in the referenced evidence documents; the
// state store binds identity, digest, state, and the evidence trail.
func snapshot(now func() time.Time, subject candidate.Candidate) recordDocument {
	trail := subject.Evidence()
	refs := make([]referenceDocument, 0, len(trail))
	for _, reference := range trail {
		refs = append(refs, referenceToDocument(reference))
	}

	document := recordDocument{
		Schema:     recordSchema,
		Ecosystem:  string(subject.Ecosystem()),
		Name:       subject.Name(),
		Version:    subject.Version(),
		Digest:     subject.Digest(),
		State:      string(subject.State()),
		Evidence:   refs,
		RecordedAt: now().UTC().Format(time.RFC3339Nano),
	}
	if subject.State() == candidate.StateApproved {
		// The domain binds the approval evidence into the trail of every
		// approved candidate; the newest approval-typed entry is the
		// promotion proof.
		for i := len(trail) - 1; i >= 0; i-- {
			if trail[i].Type() == evidence.TypeApproval {
				approvalRef := referenceToDocument(trail[i])
				document.Approval = &approvalRef
				break
			}
		}
	}
	return document
}

// rebuild restores the aggregate from its record document through the domain
// constructor and transition methods. Transition reasons are not part of the
// state store; the state-binding transitions use the recorded-state marker.
func (d recordDocument) rebuild() (candidate.Candidate, error) {
	if d.Schema != recordSchema {
		return candidate.Candidate{}, fmt.Errorf("record schema %q does not match %q", d.Schema, recordSchema)
	}
	rebuilt, err := candidate.New(candidate.Ecosystem(d.Ecosystem), d.Name, d.Version, d.Digest)
	if err != nil {
		return candidate.Candidate{}, err
	}
	for _, ref := range d.Evidence {
		if d.Approval != nil && sameReference(ref, *d.Approval) {
			continue
		}
		reference, err := ref.toDomain()
		if err != nil {
			return candidate.Candidate{}, err
		}
		// The rebuild records evidence before any terminal transition, so the
		// append is total on every lifecycle state reached here.
		_ = rebuilt.RecordEvidence(reference)
	}

	switch candidate.State(d.State) {
	case candidate.StatePending:
		return rebuilt, nil
	case candidate.StateQuarantined:
		// The recorded state and the constant non-empty reason make this
		// transition total.
		_ = rebuilt.Quarantine("recorded quarantined state")
		return rebuilt, nil
	case candidate.StateApproved:
		if d.Approval == nil {
			return candidate.Candidate{}, errors.New("approved record carries no approval reference")
		}
		reference, err := d.Approval.toDomain()
		if err != nil {
			return candidate.Candidate{}, err
		}
		if err := rebuilt.Approve(reference); err != nil {
			return candidate.Candidate{}, err
		}
		return rebuilt, nil
	case candidate.StateRevoked:
		// The recorded state and the constant non-empty reason make this
		// transition total.
		_ = rebuilt.Revoke("recorded revoked state")
		return rebuilt, nil
	default:
		return candidate.Candidate{}, fmt.Errorf("record state %q is not a candidate lifecycle state", d.State)
	}
}

// sameReference reports whether two reference documents bind the same
// evidence object.
func sameReference(a referenceDocument, b referenceDocument) bool {
	return a.Reference == b.Reference && a.Digest == b.Digest
}

// referenceToDocument maps the domain reference onto its document form.
func referenceToDocument(reference evidence.Reference) referenceDocument {
	var expiresAt *string
	if expiry, ok := reference.ExpiresAt(); ok {
		encoded := expiry.UTC().Format(time.RFC3339Nano)
		expiresAt = &encoded
	}
	return referenceDocument{
		Type:      string(reference.Type()),
		Reference: reference.Reference(),
		Digest:    reference.Digest(),
		Issuer:    reference.Issuer(),
		IssuedAt:  reference.IssuedAt().UTC().Format(time.RFC3339Nano),
		ExpiresAt: expiresAt,
	}
}

// toDomain rebuilds the domain reference from its document form and fails
// closed on any contract violation.
func (d referenceDocument) toDomain() (evidence.Reference, error) {
	issuedAt, err := time.Parse(time.RFC3339Nano, d.IssuedAt)
	if err != nil {
		return evidence.Reference{}, fmt.Errorf("parse evidence issued-at: %w", err)
	}
	var expiresAt *time.Time
	if d.ExpiresAt != nil {
		parsed, err := time.Parse(time.RFC3339Nano, *d.ExpiresAt)
		if err != nil {
			return evidence.Reference{}, fmt.Errorf("parse evidence expires-at: %w", err)
		}
		expiresAt = &parsed
	}
	reference, err := evidence.NewReference(evidence.Type(d.Type), d.Reference, d.Digest, d.Issuer, issuedAt, expiresAt)
	if err != nil {
		return evidence.Reference{}, err
	}
	return reference, nil
}

// decodeRecord parses a record document.
func decodeRecord(content []byte) (recordDocument, error) {
	var document recordDocument
	if err := json.Unmarshal(content, &document); err != nil {
		return recordDocument{}, err
	}
	return document, nil
}

// sha256Sum computes the raw sha256 digest of the content.
func sha256Sum(content []byte) []byte {
	sum := sha256.Sum256(content)
	return sum[:]
}
