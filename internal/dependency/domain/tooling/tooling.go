// Package tooling models the pinned identities of the workload tooling
// channel artifacts: the scanner tool, the scanner database snapshot, and the
// admission policy bundle that the scanning lanes materialize from the
// governed channel before they run. Every identity binds its artifact to the
// artifact content digest; the reference form keeps the canonical
// <algorithm>:<hex> notation while the stored channel object carries the
// platform-safe <algorithm>-<hex> form.
package tooling

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/t33n-software/dependency-authority/internal/dependency/domain/candidate"
)

// Kind classifies a workload tooling channel artifact.
type Kind int

const (
	// KindTool is the pinned scanner tool artifact.
	KindTool Kind = iota + 1
	// KindDatabase is the pinned scanner database snapshot artifact.
	KindDatabase
	// KindBundle is the pinned admission policy bundle artifact.
	KindBundle
)

const (
	// toolName is the pinned scanner engine name of the tool identities.
	toolName = "osv-scanner"
	// databaseName is the pinned snapshot name of the database identities.
	databaseName = "osv-db"
	// bundlePath is the schema-pinned channel path of the admission policy
	// bundle.
	bundlePath = "dependency-policy/v1"
)

var (
	// digestPattern binds the canonical sha256 reference digest form.
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	// versionPattern binds the exact semver pin form of the tool version
	// segment.
	versionPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)
	// assetPattern binds the <tool>_<os>_<arch> form of the tool asset
	// segment.
	assetPattern = regexp.MustCompile(`^osv-scanner_[a-z0-9]+_[a-z0-9]+$`)
)

// Identity is the digest-bound identity of one workload tooling channel
// artifact. Construct through ParseTool, ParseDatabase, or ParseBundle.
type Identity struct {
	kind   Kind
	path   string
	digest string
}

// ParseTool binds the pinned scanner tool identity
// osv-scanner/<version>/<asset>@sha256:<digest> and fails closed on any
// deviation.
func ParseTool(value string) (Identity, error) {
	path, digest, err := split(value)
	if err != nil {
		return Identity{}, err
	}
	parts := strings.Split(path, "/")
	if len(parts) != 3 || parts[0] != toolName {
		return Identity{}, fmt.Errorf("scanner tool identity %q must match osv-scanner/<version>/<asset>@sha256:<digest>", value)
	}
	if !versionPattern.MatchString(parts[1]) {
		return Identity{}, fmt.Errorf("scanner tool identity %q must pin the exact v<major>.<minor>.<patch> version", value)
	}
	if !assetPattern.MatchString(parts[2]) {
		return Identity{}, fmt.Errorf("scanner tool identity %q must carry the osv-scanner_<os>_<arch> asset", value)
	}
	return Identity{kind: KindTool, path: path, digest: digest}, nil
}

// ParseDatabase binds the pinned scanner database snapshot identity
// osv-db/<ecosystem>@sha256:<digest> and fails closed on any deviation.
func ParseDatabase(value string) (Identity, error) {
	path, digest, err := split(value)
	if err != nil {
		return Identity{}, err
	}
	parts := strings.Split(path, "/")
	if len(parts) != 2 || parts[0] != databaseName {
		return Identity{}, fmt.Errorf("scanner database identity %q must match osv-db/<ecosystem>@sha256:<digest>", value)
	}
	if !candidate.Ecosystem(parts[1]).Valid() {
		return Identity{}, fmt.Errorf("scanner database identity %q must carry a supported ecosystem", value)
	}
	return Identity{kind: KindDatabase, path: path, digest: digest}, nil
}

// ParseBundle binds the pinned admission policy bundle identity
// dependency-policy/v1@sha256:<digest> and fails closed on any deviation.
func ParseBundle(value string) (Identity, error) {
	path, digest, err := split(value)
	if err != nil {
		return Identity{}, err
	}
	if path != bundlePath {
		return Identity{}, fmt.Errorf("policy bundle identity %q must match dependency-policy/v1@sha256:<digest>", value)
	}
	return Identity{kind: KindBundle, path: path, digest: digest}, nil
}

// split divides the reference form into its channel path and content digest.
func split(value string) (string, string, error) {
	path, digest, found := strings.Cut(value, "@")
	if !found || strings.TrimSpace(path) == "" {
		return "", "", fmt.Errorf("tooling channel identity %q must match <path>@sha256:<digest>", value)
	}
	if !digestPattern.MatchString(digest) {
		return "", "", fmt.Errorf("tooling channel identity %q must carry the digest sha256:<64 lowercase hex>", value)
	}
	return path, digest, nil
}

// Kind returns the channel artifact class.
func (i Identity) Kind() Kind {
	return i.kind
}

// Path returns the semantic channel path of the artifact.
func (i Identity) Path() string {
	return i.path
}

// Digest returns the content digest in the canonical sha256:<hex> reference
// form.
func (i Identity) Digest() string {
	return i.digest
}

// DigestHex returns the raw lowercase hex digest without the algorithm
// prefix.
func (i Identity) DigestHex() string {
	return strings.TrimPrefix(i.digest, "sha256:")
}

// String returns the reference form of the identity.
func (i Identity) String() string {
	return i.path + "@" + i.digest
}

// Valid reports whether the identity binds a channel artifact.
func (i Identity) Valid() bool {
	switch i.kind {
	case KindTool, KindDatabase, KindBundle:
		return true
	default:
		return false
	}
}
