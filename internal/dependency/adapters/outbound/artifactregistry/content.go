package artifactregistry

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/t33n-software/dependency-authority/internal/dependency/domain/candidate"
)

// CandidateContent materializes candidate module content from the controlled
// intake boundary into the scan content root. The fetched archive is proven
// against the digest the candidate record binds before any content lands, and
// the placement is atomic and idempotent: a target already carrying the proven
// content is a skip, unproven or drifted content fails closed, and a failure
// never leaves a partial target behind.
type CandidateContent struct {
	client Client
	intake *url.URL
	root   string
}

// NewCandidateContent constructs the candidate content materializer and fails
// closed on an invalid intake endpoint or an empty content root.
func NewCandidateContent(client Client, upstreamEndpoint string, contentRoot string) (CandidateContent, error) {
	intake, err := parseGoEndpoint(upstreamEndpoint, "intake")
	if err != nil {
		return CandidateContent{}, err
	}
	if strings.TrimSpace(contentRoot) == "" {
		return CandidateContent{}, errors.New("candidate content root must not be empty")
	}
	return CandidateContent{client: client, intake: intake, root: contentRoot}, nil
}

// The filesystem seams of the candidate content placement; tests bind
// fault-injecting fakes.
var (
	statPath    = os.Stat
	readMarker  = os.ReadFile
	writeMarker = os.WriteFile
	renameTree  = os.Rename
	removeTree  = os.RemoveAll
)

// Materialize fetches the candidate's module archive from the controlled
// intake boundary, proves it against the recorded digest, and places the
// content at the canonical content path. A target already carrying content
// proven against the same digest is an idempotent skip; a target whose content
// cannot be proven is drift and fails closed.
func (c CandidateContent) Materialize(ctx context.Context, subject candidate.Candidate) (string, error) {
	target, err := subject.ContentPath(c.root)
	if err != nil {
		return "", err
	}
	marker := target + ".sha256"
	if _, err := statPath(target); err == nil {
		proven, readErr := readMarker(marker)
		if readErr == nil && strings.TrimSpace(string(proven)) == subject.Digest() {
			return target, nil
		}
		return "", fmt.Errorf("candidate content target %q carries unproven or drifted content", target)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("inspect the candidate content target: %w", err)
	}

	archive, err := fetchModuleArchive(ctx, c.client, c.intake, subject.Name(), subject.Version())
	if err != nil {
		return "", err
	}
	if digest := archiveDigest(archive); digest != subject.Digest() {
		return "", fmt.Errorf("intake content digest %q drifted from the candidate digest %q before materialization", digest, subject.Digest())
	}
	if err := placeCandidateContent(subject, target, marker, archive); err != nil {
		return "", err
	}
	return target, nil
}

// placeCandidateContent extracts the proven archive into a staging sibling of
// the target and renames it into place, so a failure never leaves a partial
// target. The digest marker is written after the placement; a marker failure
// removes the placed target to keep target and marker paired.
func placeCandidateContent(subject candidate.Candidate, target string, marker string, archive []byte) (err error) {
	parent := filepath.Dir(target)
	if err = createModuleDir(parent, 0o755); err != nil {
		return fmt.Errorf("create the candidate content parent: %w", err)
	}
	staging := filepath.Join(parent, ".staging-"+filepath.Base(target))
	// A leftover staging tree from an interrupted run is cleared before the
	// extraction so no stale content can leak into the placement.
	if err = removeTree(staging); err != nil {
		return fmt.Errorf("clear the candidate content staging: %w", err)
	}
	defer func() {
		if err != nil {
			_ = removeTree(staging)
		}
	}()
	moduleRoot, err := extractModule(staging, subject, archive)
	if err != nil {
		return err
	}
	if err = renameTree(moduleRoot, target); err != nil {
		return fmt.Errorf("place the candidate content: %w", err)
	}
	if err = writeMarker(marker, []byte(subject.Digest()), 0o644); err != nil {
		_ = removeTree(target)
		return fmt.Errorf("mark the candidate content: %w", err)
	}
	// The staging shell now holds only the empty module parent chain.
	if err = removeTree(staging); err != nil {
		return fmt.Errorf("clear the candidate content staging: %w", err)
	}
	return nil
}
