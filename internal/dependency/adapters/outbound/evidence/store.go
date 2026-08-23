package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/t33n-software/dependency-authority/internal/dependency/application/admission"
	"github.com/t33n-software/dependency-authority/internal/dependency/application/revocation"
	"github.com/t33n-software/dependency-authority/internal/dependency/domain/candidate"
	"github.com/t33n-software/dependency-authority/internal/dependency/domain/evidence"
)

// recordSchema binds the evidence record document shape.
const recordSchema = "dependency-authority/evidence-record/v1"

// recordVersion is the immutable generic-artifact version grouping the
// evidence index of one candidate.
const recordVersion = "v1"

// Store is the append-only evidence reference index. Each record uploads one
// content-addressed evidence document into the bound generic repository of
// the evidence zone.
type Store struct {
	transport  transport
	repository string
}

// NewStore constructs the evidence store and fails closed on an invalid
// endpoint, transport, or repository binding.
func NewStore(apiEndpoint string, repository string, token TokenSource, doer Doer) (Store, error) {
	bound, err := newTransport(apiEndpoint, token, doer)
	if err != nil {
		return Store{}, err
	}
	if err := parseRepository(repository); err != nil {
		return Store{}, err
	}
	return Store{transport: bound, repository: repository}, nil
}

// Record appends the evidence reference to the candidate index. Recording an
// identical reference twice is an idempotent success.
func (s Store) Record(ctx context.Context, subject candidate.Candidate, reference evidence.Reference) error {
	document := recordDocument{
		Schema:    recordSchema,
		Ecosystem: string(subject.Ecosystem()),
		Name:      subject.Name(),
		Version:   subject.Version(),
		Reference: referenceToDocument(reference),
	}
	// The record document carries only strings, so marshaling cannot fail.
	content, _ := json.Marshal(document)
	filename := hex.EncodeToString(sha256Sum(content)) + ".json"
	return s.transport.upload(ctx, s.repository, indexPackage(subject), recordVersion, filename, content)
}

// Put publishes the evidence payload content-addressed into the bound
// repository and returns its digest-bound reference. Payloads live in the
// candidate's payload package, separate from the reference index, so the
// index listing never decodes payload documents. Re-publishing identical
// content is an idempotent success.
func (s Store) Put(ctx context.Context, subject candidate.Candidate, evidenceType evidence.Type, issuer string, payload []byte, issuedAt time.Time, expiresAt *time.Time) (evidence.Reference, error) {
	if len(payload) == 0 {
		return evidence.Reference{}, errors.New("evidence payload must not be empty")
	}
	sum := sha256.Sum256(payload)
	filename := hex.EncodeToString(sum[:]) + ".json"
	packageID := payloadPackageIdentity(subject.Ecosystem(), subject.Name(), subject.Version())
	if err := s.transport.upload(ctx, s.repository, packageID, recordVersion, filename, payload); err != nil {
		return evidence.Reference{}, err
	}
	locator := "evidence://" + s.repository + "/" + packageID + "/" + recordVersion + "/" + filename
	reference, err := evidence.NewReference(evidenceType, locator, "sha256:"+hex.EncodeToString(sum[:]), issuer, issuedAt, expiresAt)
	if err != nil {
		return evidence.Reference{}, err
	}
	return reference, nil
}

// payloadPackageIdentity derives the deterministic, alphabet-safe package ID
// of one candidate's evidence payloads.
func payloadPackageIdentity(ecosystem candidate.Ecosystem, name string, version string) string {
	sum := sha256.Sum256([]byte(string(ecosystem) + "\n" + name + "\n" + version))
	return "evidence-payloads-" + hex.EncodeToString(sum[:])[:24]
}

// Evidence loads the recorded evidence references of the candidate in
// deterministic order. A candidate without records has an empty trail.
func (s Store) Evidence(ctx context.Context, ecosystem candidate.Ecosystem, name string, version string) ([]evidence.Reference, error) {
	files, err := s.transport.list(ctx, s.repository, indexPackageIdentity(ecosystem, name, version), recordVersion)
	if err != nil {
		return nil, err
	}

	references := make([]evidence.Reference, 0, len(files))
	for _, file := range files {
		content, err := s.transport.download(ctx, file.Name)
		if err != nil {
			return nil, err
		}
		document, err := decodeRecord(content)
		if err != nil {
			return nil, fmt.Errorf("decode evidence record %q: %w", file.Name, err)
		}
		if document.Ecosystem != string(ecosystem) || document.Name != name || document.Version != version {
			return nil, fmt.Errorf("evidence record %q belongs to %q %q %q, not %q %q %q", file.Name, document.Ecosystem, document.Name, document.Version, ecosystem, name, version)
		}
		reference, err := document.Reference.toDomain()
		if err != nil {
			return nil, fmt.Errorf("rebuild evidence reference from %q: %w", file.Name, err)
		}
		references = append(references, reference)
	}

	sort.Slice(references, func(i, j int) bool {
		if !references[i].IssuedAt().Equal(references[j].IssuedAt()) {
			return references[i].IssuedAt().Before(references[j].IssuedAt())
		}
		if references[i].Reference() != references[j].Reference() {
			return references[i].Reference() < references[j].Reference()
		}
		return references[i].Digest() < references[j].Digest()
	})
	return references, nil
}

// indexPackage binds the candidate to its evidence index package.
func indexPackage(subject candidate.Candidate) string {
	return indexPackageIdentity(subject.Ecosystem(), subject.Name(), subject.Version())
}

// indexPackageIdentity derives the deterministic, alphabet-safe package ID of
// one candidate's evidence index.
func indexPackageIdentity(ecosystem candidate.Ecosystem, name string, version string) string {
	sum := sha256.Sum256([]byte(string(ecosystem) + "\n" + name + "\n" + version))
	return "evidence-" + hex.EncodeToString(sum[:])[:24]
}

// recordDocument is the evidence index document persisted per record.
type recordDocument struct {
	Schema    string            `json:"schema"`
	Ecosystem string            `json:"ecosystem"`
	Name      string            `json:"name"`
	Version   string            `json:"version"`
	Reference referenceDocument `json:"reference"`
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

// decodeRecord parses an evidence record document.
func decodeRecord(content []byte) (recordDocument, error) {
	var document recordDocument
	if err := json.Unmarshal(content, &document); err != nil {
		return recordDocument{}, err
	}
	if document.Schema != recordSchema {
		return recordDocument{}, fmt.Errorf("record schema %q does not match %q", document.Schema, recordSchema)
	}
	return document, nil
}

// sha256Sum computes the raw sha256 digest of the content.
func sha256Sum(content []byte) []byte {
	sum := sha256.Sum256(content)
	return sum[:]
}

var (
	_ admission.EvidenceStore     = Store{}
	_ revocation.EvidenceRecorder = Store{}
)
