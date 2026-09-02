package config

import (
	"errors"
	"strings"
)

const (
	// EnvUpstreamEndpoint names the Go proxy endpoint of the intake zone.
	EnvUpstreamEndpoint = "DEPENDENCY_AUTHORITY_UPSTREAM_ENDPOINT"
	// EnvApprovedEndpoint names the Go proxy endpoint of the approved zone.
	EnvApprovedEndpoint = "DEPENDENCY_AUTHORITY_APPROVED_ENDPOINT"
	// EnvArtifactAPI names the Artifact Registry API endpoint.
	EnvArtifactAPI = "DEPENDENCY_AUTHORITY_ARTIFACT_API"
	// EnvEvidenceRepository names the evidence-zone generic repository resource.
	EnvEvidenceRepository = "DEPENDENCY_AUTHORITY_EVIDENCE_REPOSITORY"
	// EnvApprovedRepository names the approved-zone repository resource.
	EnvApprovedRepository = "DEPENDENCY_AUTHORITY_APPROVED_REPOSITORY"
	// EnvPolicyBundle names the pinned dependency-policy/v1 bundle path.
	EnvPolicyBundle = "DEPENDENCY_AUTHORITY_POLICY_BUNDLE"
	// EnvScannerTool names the pinned scanner tool path.
	EnvScannerTool = "DEPENDENCY_AUTHORITY_SCANNER_TOOL"
	// EnvScannerDatabase names the local scanner database snapshot directory.
	EnvScannerDatabase = "DEPENDENCY_AUTHORITY_SCANNER_DATABASE"
	// EnvScanContentRoot names the candidate materialization root.
	EnvScanContentRoot = "DEPENDENCY_AUTHORITY_SCAN_CONTENT_ROOT"
)

// Bindings carries the outbound adapter bindings of the lane environment.
// Absent values leave the corresponding adapter unbound. Validation of a
// present value belongs to the adapter constructors, which fail closed on any
// contract violation.
type Bindings struct {
	upstreamEndpoint   string
	approvedEndpoint   string
	artifactAPI        string
	evidenceRepository string
	approvedRepository string
	policyBundle       string
	scannerTool        string
	scannerDatabase    string
	scanContentRoot    string
}

// BindingsFromEnv loads the adapter bindings from the process environment.
func BindingsFromEnv(lookup func(string) string) (Bindings, error) {
	if lookup == nil {
		return Bindings{}, errors.New("environment lookup must not be nil")
	}
	return Bindings{
		upstreamEndpoint:   strings.TrimSpace(lookup(EnvUpstreamEndpoint)),
		approvedEndpoint:   strings.TrimSpace(lookup(EnvApprovedEndpoint)),
		artifactAPI:        strings.TrimSpace(lookup(EnvArtifactAPI)),
		evidenceRepository: strings.TrimSpace(lookup(EnvEvidenceRepository)),
		approvedRepository: strings.TrimSpace(lookup(EnvApprovedRepository)),
		policyBundle:       strings.TrimSpace(lookup(EnvPolicyBundle)),
		scannerTool:        strings.TrimSpace(lookup(EnvScannerTool)),
		scannerDatabase:    strings.TrimSpace(lookup(EnvScannerDatabase)),
		scanContentRoot:    strings.TrimSpace(lookup(EnvScanContentRoot)),
	}, nil
}

// UpstreamEndpoint returns the intake Go proxy endpoint.
func (b Bindings) UpstreamEndpoint() string {
	return b.upstreamEndpoint
}

// ApprovedEndpoint returns the approved Go proxy endpoint.
func (b Bindings) ApprovedEndpoint() string {
	return b.approvedEndpoint
}

// ArtifactAPI returns the Artifact Registry API endpoint.
func (b Bindings) ArtifactAPI() string {
	return b.artifactAPI
}

// EvidenceRepository returns the evidence-zone generic repository resource.
func (b Bindings) EvidenceRepository() string {
	return b.evidenceRepository
}

// ApprovedRepository returns the approved-zone repository resource.
func (b Bindings) ApprovedRepository() string {
	return b.approvedRepository
}

// PolicyBundle returns the pinned policy bundle path.
func (b Bindings) PolicyBundle() string {
	return b.policyBundle
}

// ScannerTool returns the pinned scanner tool path.
func (b Bindings) ScannerTool() string {
	return b.scannerTool
}

// ScannerDatabase returns the scanner database snapshot directory.
func (b Bindings) ScannerDatabase() string {
	return b.scannerDatabase
}

// ScanContentRoot returns the candidate materialization root.
func (b Bindings) ScanContentRoot() string {
	return b.scanContentRoot
}
