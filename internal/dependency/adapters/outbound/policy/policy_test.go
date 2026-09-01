package policy

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/t33n-software/dependency-authority/internal/dependency/domain/candidate"
	"github.com/t33n-software/dependency-authority/internal/dependency/domain/evidence"
)

const fullBundle = `{
  "schema": "dependency-policy/v1",
  "ecosystem": "go",
  "admission": {
    "required_evidence": ["sbom", "scan"],
    "max_cvss": 7.5,
    "blocked_licenses": ["GPL-3.0"]
  },
  "exceptions": [
    {"reference": "policy-overlays/exceptions/ex-1", "expires_at": "2027-01-01T00:00:00Z"}
  ],
  "revocation": {"download_block": true}
}`

const minimalBundle = `{
  "schema": "dependency-policy/v1",
  "ecosystem": "go",
  "admission": {
    "required_evidence": ["sbom"]
  },
  "exceptions": [],
  "revocation": {"download_block": true}
}`

func readerReturning(content string) Reader {
	return func(string) ([]byte, error) {
		return []byte(content), nil
	}
}

func newBundle(t *testing.T, read Reader) Bundle {
	t.Helper()
	bundle, err := NewBundle("policies/go.json", read)
	if err != nil {
		t.Fatalf("NewBundle() error = %v", err)
	}
	return bundle
}

func TestNewBundleValidatesConfiguration(t *testing.T) {
	if _, err := NewBundle(" ", readerReturning(fullBundle)); err == nil {
		t.Fatal("NewBundle( blank path ) error = nil, want error")
	}
	if _, err := NewBundle("policies/go.json", nil); err == nil {
		t.Fatal("NewBundle( nil reader ) error = nil, want error")
	}
	if _, err := NewBundle("policies/go.json", readerReturning(fullBundle)); err != nil {
		t.Fatalf("NewBundle() error = %v, want success", err)
	}
}

func TestPolicyRejectsUnknownEcosystem(t *testing.T) {
	bundle := newBundle(t, readerReturning(fullBundle))
	if _, err := bundle.Policy(context.Background(), candidate.Ecosystem("ruby")); err == nil {
		t.Fatal("Policy() error = nil, want ecosystem error")
	}
}

func TestPolicyPropagatesReadError(t *testing.T) {
	bundle := newBundle(t, func(string) ([]byte, error) {
		return nil, errors.New("bundle missing")
	})
	if _, err := bundle.Policy(context.Background(), candidate.EcosystemGo); err == nil {
		t.Fatal("Policy() error = nil, want read error")
	}
}

func TestPolicyRejectsMalformedDocuments(t *testing.T) {
	for name, content := range map[string]string{
		"invalid json":     `{`,
		"unknown field":    `{"schema": "dependency-policy/v1", "unexpected": true}`,
		"trailing content": "{}\n{}\n",
		"wrong field type": `{"schema": 42}`,
	} {
		t.Run(name, func(t *testing.T) {
			bundle := newBundle(t, readerReturning(content))
			if _, err := bundle.Policy(context.Background(), candidate.EcosystemGo); err == nil {
				t.Fatal("Policy() error = nil, want decode error")
			}
		})
	}
}

func TestPolicyRejectsSchemaMismatch(t *testing.T) {
	bundle := newBundle(t, readerReturning(strings.Replace(fullBundle, "dependency-policy/v1", "dependency-policy/v2", 1)))
	if _, err := bundle.Policy(context.Background(), candidate.EcosystemGo); err == nil {
		t.Fatal("Policy() error = nil, want schema error")
	}
}

func TestPolicyRejectsEcosystemMismatch(t *testing.T) {
	bundle := newBundle(t, readerReturning(strings.Replace(fullBundle, `"ecosystem": "go"`, `"ecosystem": "npm"`, 1)))
	if _, err := bundle.Policy(context.Background(), candidate.EcosystemGo); err == nil {
		t.Fatal("Policy() error = nil, want ecosystem mismatch error")
	}
}

func TestPolicyRejectsDisabledDownloadBlock(t *testing.T) {
	bundle := newBundle(t, readerReturning(strings.Replace(fullBundle, `"download_block": true`, `"download_block": false`, 1)))
	if _, err := bundle.Policy(context.Background(), candidate.EcosystemGo); err == nil {
		t.Fatal("Policy() error = nil, want revocation invariant error")
	}
}

func TestPolicyRejectsMalformedExceptions(t *testing.T) {
	for name, exception := range map[string]string{
		"empty reference": `{"reference": " ", "expires_at": "2027-01-01T00:00:00Z"}`,
		"bad expiry":      `{"reference": "ex-1", "expires_at": "not-a-time"}`,
	} {
		t.Run(name, func(t *testing.T) {
			content := strings.Replace(fullBundle, `{"reference": "policy-overlays/exceptions/ex-1", "expires_at": "2027-01-01T00:00:00Z"}`, exception, 1)
			bundle := newBundle(t, readerReturning(content))
			if _, err := bundle.Policy(context.Background(), candidate.EcosystemGo); err == nil {
				t.Fatal("Policy() error = nil, want exception error")
			}
		})
	}
}

func TestPolicyRejectsDomainViolations(t *testing.T) {
	for name, admission := range map[string]string{
		"empty required evidence": `"required_evidence": []`,
		"unknown evidence type":   `"required_evidence": ["bogus"]`,
		"max cvss out of range":   `"required_evidence": ["sbom"], "max_cvss": 11`,
		"blank blocked license":   `"required_evidence": ["sbom"], "blocked_licenses": [" "]`,
	} {
		t.Run(name, func(t *testing.T) {
			content := strings.Replace(fullBundle, `"required_evidence": ["sbom", "scan"],
    "max_cvss": 7.5,
    "blocked_licenses": ["GPL-3.0"]`, admission, 1)
			bundle := newBundle(t, readerReturning(content))
			if _, err := bundle.Policy(context.Background(), candidate.EcosystemGo); err == nil {
				t.Fatal("Policy() error = nil, want domain violation error")
			}
		})
	}
}

func TestPolicyBuildsTheFullDomainPolicy(t *testing.T) {
	bundle := newBundle(t, readerReturning(fullBundle))
	policy, err := bundle.Policy(context.Background(), candidate.EcosystemGo)
	if err != nil {
		t.Fatalf("Policy() error = %v", err)
	}
	if policy.Ecosystem() != candidate.EcosystemGo {
		t.Fatalf("Ecosystem() = %q, want go", policy.Ecosystem())
	}
	required := policy.RequiredEvidence()
	if len(required) != 2 || required[0] != evidence.TypeSBOM || required[1] != evidence.TypeScan {
		t.Fatalf("RequiredEvidence() = %v, want [sbom scan]", required)
	}
	maxCVSS, enforced := policy.MaxCVSS()
	if !enforced || maxCVSS != 7.5 {
		t.Fatalf("MaxCVSS() = %v, %v, want 7.5, true", maxCVSS, enforced)
	}
	blocked := policy.BlockedLicenses()
	if len(blocked) != 1 || blocked[0] != "GPL-3.0" {
		t.Fatalf("BlockedLicenses() = %v, want [GPL-3.0]", blocked)
	}
}

func TestPolicyBuildsTheMinimalDomainPolicy(t *testing.T) {
	bundle := newBundle(t, readerReturning(minimalBundle))
	policy, err := bundle.Policy(context.Background(), candidate.EcosystemGo)
	if err != nil {
		t.Fatalf("Policy() error = %v", err)
	}
	maxCVSS, enforced := policy.MaxCVSS()
	if enforced || maxCVSS != 0 {
		t.Fatalf("MaxCVSS() = %v, %v, want 0, false", maxCVSS, enforced)
	}
	if len(policy.BlockedLicenses()) != 0 {
		t.Fatalf("BlockedLicenses() = %v, want empty", policy.BlockedLicenses())
	}
}
