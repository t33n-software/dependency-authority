// Package policy implements the admission.Policies port: loading the pinned
// dependency-policy/v1 bundle published by the supply-chain-governance core
// and building the domain admission policy from it. A lane without a bound,
// schema-conformant bundle fails closed.
package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/t33n-software/dependency-authority/internal/dependency/domain/admission"
	"github.com/t33n-software/dependency-authority/internal/dependency/domain/candidate"
	"github.com/t33n-software/dependency-authority/internal/dependency/domain/evidence"
)

// SchemaID is the exact schema version pin this adapter consumes.
const SchemaID = "dependency-policy/v1"

// Reader loads the bundle content. os.ReadFile satisfies it in production.
type Reader func(path string) ([]byte, error)

// Bundle is the pinned dependency-policy/v1 bundle source.
type Bundle struct {
	path string
	read Reader
}

// NewBundle constructs the bundle source and fails closed on an empty path
// or a nil reader.
func NewBundle(path string, read Reader) (Bundle, error) {
	if strings.TrimSpace(path) == "" {
		return Bundle{}, errors.New("policy bundle path must not be empty")
	}
	if read == nil {
		return Bundle{}, errors.New("policy bundle reader must not be nil")
	}
	return Bundle{path: path, read: read}, nil
}

// document mirrors the dependency-policy/v1 schema exactly; strict decoding
// rejects any unknown field.
type document struct {
	Schema    string `json:"schema"`
	Ecosystem string `json:"ecosystem"`
	Admission struct {
		RequiredEvidence []string `json:"required_evidence"`
		MaxCVSS          *float64 `json:"max_cvss"`
		BlockedLicenses  []string `json:"blocked_licenses"`
	} `json:"admission"`
	Exceptions []struct {
		Reference string `json:"reference"`
		ExpiresAt string `json:"expires_at"`
	} `json:"exceptions"`
	Revocation struct {
		DownloadBlock bool `json:"download_block"`
	} `json:"revocation"`
}

// Policy loads the pinned bundle and builds the domain admission policy for
// the requested ecosystem. Every schema, identity, or content deviation
// fails closed.
func (b Bundle) Policy(_ context.Context, ecosystem candidate.Ecosystem) (admission.Policy, error) {
	if !ecosystem.Valid() {
		return admission.Policy{}, fmt.Errorf("unknown ecosystem %q", ecosystem)
	}
	content, err := b.read(b.path)
	if err != nil {
		return admission.Policy{}, fmt.Errorf("read policy bundle: %w", err)
	}

	document, err := decode(content)
	if err != nil {
		return admission.Policy{}, fmt.Errorf("decode policy bundle: %w", err)
	}
	if document.Schema != SchemaID {
		return admission.Policy{}, fmt.Errorf("policy bundle schema %q does not match the pinned %q", document.Schema, SchemaID)
	}
	if document.Ecosystem != string(ecosystem) {
		return admission.Policy{}, fmt.Errorf("policy bundle ecosystem %q does not match the requested %q", document.Ecosystem, ecosystem)
	}
	if !document.Revocation.DownloadBlock {
		return admission.Policy{}, errors.New("policy bundle revocation.download_block must be true")
	}
	for _, exception := range document.Exceptions {
		if strings.TrimSpace(exception.Reference) == "" {
			return admission.Policy{}, errors.New("policy bundle exception reference must not be empty")
		}
		if _, err := time.Parse(time.RFC3339, exception.ExpiresAt); err != nil {
			return admission.Policy{}, fmt.Errorf("policy bundle exception %q expiry: %w", exception.Reference, err)
		}
	}

	required := make([]evidence.Type, 0, len(document.Admission.RequiredEvidence))
	for _, evidenceType := range document.Admission.RequiredEvidence {
		required = append(required, evidence.Type(evidenceType))
	}
	var maxCVSS float64
	enforced := false
	if document.Admission.MaxCVSS != nil {
		maxCVSS = *document.Admission.MaxCVSS
		enforced = true
	}

	policy, err := admission.NewPolicy(ecosystem, required, maxCVSS, enforced, document.Admission.BlockedLicenses)
	if err != nil {
		return admission.Policy{}, fmt.Errorf("build admission policy: %w", err)
	}
	return policy, nil
}

// decode strictly decodes the bundle document, rejecting unknown fields.
func decode(content []byte) (document, error) {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var decoded document
	if err := decoder.Decode(&decoded); err != nil {
		return document{}, err
	}
	if decoder.More() {
		return document{}, errors.New("unexpected trailing content")
	}
	return decoded, nil
}
