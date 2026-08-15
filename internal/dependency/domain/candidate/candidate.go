// Package candidate models the dependency candidate aggregate and its
// lifecycle across the intake, admission, promotion, and revocation lanes.
package candidate

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/t33n-software/dependency-authority/internal/dependency/domain/evidence"
)

// Ecosystem identifies a dependency ecosystem.
type Ecosystem string

const (
	EcosystemGo     Ecosystem = "go"
	EcosystemNPM    Ecosystem = "npm"
	EcosystemPython Ecosystem = "python"
)

// Valid reports whether the ecosystem is supported by the authority.
func (e Ecosystem) Valid() bool {
	switch e {
	case EcosystemGo, EcosystemNPM, EcosystemPython:
		return true
	default:
		return false
	}
}

// State is the candidate lifecycle state.
type State string

const (
	StatePending     State = "pending"
	StateQuarantined State = "quarantined"
	StateApproved    State = "approved"
	StateRevoked     State = "revoked"
)

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// Candidate is the aggregate root for one dependency package version.
type Candidate struct {
	ecosystem Ecosystem
	name      string
	version   string
	digest    string
	state     State
	evidence  []evidence.Reference
}

// New constructs a pending candidate with a validated identity.
func New(ecosystem Ecosystem, name string, version string, digest string) (Candidate, error) {
	if !ecosystem.Valid() {
		return Candidate{}, fmt.Errorf("unknown ecosystem %q", ecosystem)
	}
	if strings.TrimSpace(name) == "" {
		return Candidate{}, errors.New("name must not be empty")
	}
	if strings.TrimSpace(version) == "" {
		return Candidate{}, errors.New("version must not be empty")
	}
	if !digestPattern.MatchString(digest) {
		return Candidate{}, fmt.Errorf("digest %q must match sha256:<64 lowercase hex>", digest)
	}
	return Candidate{
		ecosystem: ecosystem,
		name:      name,
		version:   version,
		digest:    digest,
		state:     StatePending,
	}, nil
}

// Ecosystem returns the candidate ecosystem.
func (c Candidate) Ecosystem() Ecosystem {
	return c.ecosystem
}

// Name returns the package name.
func (c Candidate) Name() string {
	return c.name
}

// Version returns the package version.
func (c Candidate) Version() string {
	return c.version
}

// Digest returns the immutable package content digest.
func (c Candidate) Digest() string {
	return c.digest
}

// State returns the current lifecycle state.
func (c Candidate) State() State {
	return c.state
}

// Evidence returns a defensive copy of the recorded evidence trail.
func (c Candidate) Evidence() []evidence.Reference {
	trail := make([]evidence.Reference, len(c.evidence))
	copy(trail, c.evidence)
	return trail
}

// RecordEvidence appends immutable evidence to the candidate audit trail.
func (c *Candidate) RecordEvidence(reference evidence.Reference) error {
	if c.state == StateRevoked {
		return errors.New("revoked candidate is terminal and accepts no further evidence")
	}
	c.evidence = append(c.evidence, reference)
	return nil
}

// Quarantine moves a pending or approved candidate into quarantine.
func (c *Candidate) Quarantine(reason string) error {
	if strings.TrimSpace(reason) == "" {
		return errors.New("quarantine reason must not be empty")
	}
	if c.state != StatePending && c.state != StateApproved {
		return fmt.Errorf("cannot quarantine candidate in state %q", c.state)
	}
	c.state = StateQuarantined
	return nil
}

// Release returns a quarantined candidate to pending after re-admission.
func (c *Candidate) Release(reason string) error {
	if strings.TrimSpace(reason) == "" {
		return errors.New("release reason must not be empty")
	}
	if c.state != StateQuarantined {
		return fmt.Errorf("cannot release candidate in state %q", c.state)
	}
	c.state = StatePending
	return nil
}

// Approve promotes a pending candidate to approved with approval evidence.
func (c *Candidate) Approve(approvalEvidence evidence.Reference) error {
	if c.state != StatePending {
		return fmt.Errorf("cannot approve candidate in state %q", c.state)
	}
	if approvalEvidence.Type() != evidence.TypeApproval {
		return fmt.Errorf("approval requires evidence of type %q", evidence.TypeApproval)
	}
	c.evidence = append(c.evidence, approvalEvidence)
	c.state = StateApproved
	return nil
}

// Revoke moves any non-terminal candidate to the terminal revoked state.
func (c *Candidate) Revoke(reason string) error {
	if strings.TrimSpace(reason) == "" {
		return errors.New("revocation reason must not be empty")
	}
	if c.state == StateRevoked {
		return errors.New("candidate is already revoked")
	}
	c.state = StateRevoked
	return nil
}
