// Package admission evaluates dependency candidates against the admission
// policy of their ecosystem.
package admission

import (
	"errors"
	"fmt"
	"strings"

	"github.com/t33n-software/dependency-authority/internal/dependency/domain/candidate"
	"github.com/t33n-software/dependency-authority/internal/dependency/domain/evidence"
)

// Policy is the admission contract for one ecosystem.
type Policy struct {
	ecosystem        candidate.Ecosystem
	requiredEvidence []evidence.Type
	maxCVSS          float64
	maxCVSSEnforced  bool
	blockedLicenses  []string
}

// NewPolicy constructs a validated admission policy.
func NewPolicy(ecosystem candidate.Ecosystem, requiredEvidence []evidence.Type, maxCVSS float64, maxCVSSEnforced bool, blockedLicenses []string) (Policy, error) {
	if !ecosystem.Valid() {
		return Policy{}, fmt.Errorf("unknown ecosystem %q", ecosystem)
	}
	if len(requiredEvidence) == 0 {
		return Policy{}, errors.New("required evidence must not be empty")
	}
	for _, evidenceType := range requiredEvidence {
		if !evidenceType.Valid() {
			return Policy{}, fmt.Errorf("unknown required evidence type %q", evidenceType)
		}
	}
	if maxCVSSEnforced && (maxCVSS < 0 || maxCVSS > 10) {
		return Policy{}, fmt.Errorf("max CVSS %.1f out of range [0, 10]", maxCVSS)
	}
	for _, license := range blockedLicenses {
		if strings.TrimSpace(license) == "" {
			return Policy{}, errors.New("blocked license must not be empty")
		}
	}
	required := make([]evidence.Type, len(requiredEvidence))
	copy(required, requiredEvidence)
	blocked := make([]string, len(blockedLicenses))
	copy(blocked, blockedLicenses)
	return Policy{
		ecosystem:        ecosystem,
		requiredEvidence: required,
		maxCVSS:          maxCVSS,
		maxCVSSEnforced:  maxCVSSEnforced,
		blockedLicenses:  blocked,
	}, nil
}

// Ecosystem returns the ecosystem the policy applies to.
func (p Policy) Ecosystem() candidate.Ecosystem {
	return p.ecosystem
}

// RequiredEvidence returns a defensive copy of the required evidence types.
func (p Policy) RequiredEvidence() []evidence.Type {
	required := make([]evidence.Type, len(p.requiredEvidence))
	copy(required, p.requiredEvidence)
	return required
}

// MaxCVSS returns the CVSS ceiling and whether it is enforced.
func (p Policy) MaxCVSS() (float64, bool) {
	return p.maxCVSS, p.maxCVSSEnforced
}

// BlockedLicenses returns a defensive copy of the blocked licenses.
func (p Policy) BlockedLicenses() []string {
	blocked := make([]string, len(p.blockedLicenses))
	copy(blocked, p.blockedLicenses)
	return blocked
}

// ScanResult carries scanner output into policy evaluation.
type ScanResult struct {
	MaxCVSS  float64
	Licenses []string
}

// Decision is the admission outcome.
type Decision string

const (
	DecisionAdmit      Decision = "admit"
	DecisionQuarantine Decision = "quarantine"
)

// Report is the admission decision with its reasons.
type Report struct {
	decision Decision
	reasons  []string
}

// Decision returns the admission decision.
func (r Report) Decision() Decision {
	return r.decision
}

// Reasons returns a defensive copy of the decision reasons.
func (r Report) Reasons() []string {
	reasons := make([]string, len(r.reasons))
	copy(reasons, r.reasons)
	return reasons
}

// Evaluate applies the policy to a scan result and the recorded evidence.
func (p Policy) Evaluate(scan ScanResult, evidenceRefs []evidence.Reference) Report {
	reasons := make([]string, 0)
	for _, required := range p.requiredEvidence {
		if !hasEvidenceType(evidenceRefs, required) {
			reasons = append(reasons, fmt.Sprintf("missing required evidence %q", required))
		}
	}
	if p.maxCVSSEnforced && scan.MaxCVSS > p.maxCVSS {
		reasons = append(reasons, fmt.Sprintf("cvss %.1f exceeds policy maximum %.1f", scan.MaxCVSS, p.maxCVSS))
	}
	for _, license := range scan.Licenses {
		if p.blocksLicense(license) {
			reasons = append(reasons, fmt.Sprintf("blocked license %q", license))
		}
	}
	if len(reasons) > 0 {
		return Report{decision: DecisionQuarantine, reasons: reasons}
	}
	return Report{decision: DecisionAdmit}
}

func hasEvidenceType(evidenceRefs []evidence.Reference, evidenceType evidence.Type) bool {
	for _, reference := range evidenceRefs {
		if reference.Type() == evidenceType {
			return true
		}
	}
	return false
}

func (p Policy) blocksLicense(license string) bool {
	for _, blocked := range p.blockedLicenses {
		if blocked == license {
			return true
		}
	}
	return false
}
