package artifactregistry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/t33n-software/dependency-authority/internal/dependency/application/revocation"
	"github.com/t33n-software/dependency-authority/internal/dependency/domain/candidate"
)

// Gate is the revocation download gate: it enforces an active download block
// at the approved boundary through a package-scoped DENY download rule.
type Gate struct {
	client     Client
	repository string
}

// NewGate constructs the download gate and fails closed on an invalid
// approved repository binding.
func NewGate(client Client, approvedRepository string) (Gate, error) {
	if _, _, _, err := parseRepository(approvedRepository); err != nil {
		return Gate{}, err
	}
	return Gate{client: client, repository: approvedRepository}, nil
}

// ruleBody is the download-rule creation document. The operation is fixed to
// DOWNLOAD by the rules surface.
type ruleBody struct {
	Action    string `json:"action"`
	PackageID string `json:"packageId"`
	Condition struct {
		Expression string `json:"expression"`
	} `json:"condition"`
}

// Block creates the package-scoped deny rule for the revoked candidate at the
// approved boundary. Creating an existing identical rule is an idempotent
// success: the block is already in place.
func (g Gate) Block(ctx context.Context, subject candidate.Candidate) error {
	if strings.ContainsAny(subject.Name(), "'\"") || strings.ContainsAny(subject.Version(), "'\"") {
		return fmt.Errorf("candidate identity %q %q must not carry quotes", subject.Name(), subject.Version())
	}

	body := ruleBody{Action: "DENY", PackageID: subject.Name()}
	body.Condition.Expression = "pkg.version.id == '" + subject.Version() + "'"
	// The rule body carries only strings, so marshaling cannot fail.
	content, _ := json.Marshal(body)

	requestURL := g.client.api + "/v1/" + g.repository + "/rules?ruleId=" + ruleID(subject)
	_, status, err := g.client.do(ctx, http.MethodPost, requestURL, content, "application/json")
	if err != nil {
		return err
	}
	if status == http.StatusConflict {
		return nil
	}
	if status != http.StatusOK && status != http.StatusCreated {
		return fmt.Errorf("create download rule on %q: unexpected status %d", g.repository, status)
	}
	return nil
}

// ruleID derives the deterministic, alphabet-safe rule name of the revoked
// candidate version.
func ruleID(subject candidate.Candidate) string {
	sum := sha256.Sum256([]byte(string(subject.Ecosystem()) + "\n" + subject.Name() + "\n" + subject.Version()))
	return "revoke-" + hex.EncodeToString(sum[:])[:24]
}

var _ revocation.DownloadGate = Gate{}
