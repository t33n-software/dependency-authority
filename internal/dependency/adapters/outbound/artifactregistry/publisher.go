package artifactregistry

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/t33n-software/dependency-authority/internal/dependency/application/promotion"
	"github.com/t33n-software/dependency-authority/internal/dependency/domain/candidate"
	"github.com/t33n-software/dependency-authority/internal/dependency/domain/evidence"
)

// maxModuleArchiveBytes bounds the decompressed module content the publisher
// materializes; anything larger fails closed as a decompression risk. It is a
// package variable so whitebox tests can bind a smaller bound.
var maxModuleArchiveBytes int64 = 512 << 20

// createModuleDir is the directory seam of the extractor; tests bind it to a
// fault-injecting fake.
var createModuleDir = os.MkdirAll

// Runner executes the pinned gcloud upload tool.
type Runner func(ctx context.Context, dir string, name string, args ...string) (Result, error)

// Result carries the process outcome of the upload tool.
type Result struct {
	Stdout   []byte
	ExitCode int
}

// Publisher promotes a verified candidate into the approved zone and proves
// the Go content identity before and after the publication.
type Publisher struct {
	client     Client
	intake     *url.URL
	approved   *url.URL
	project    string
	location   string
	repository string
	run        Runner
	tempDir    func() (string, func(), error)
}

// NewPublisher constructs the approved-zone publisher and fails closed on
// invalid endpoints, an invalid approved repository binding, or nil seams.
func NewPublisher(client Client, intakeEndpoint string, approvedEndpoint string, approvedRepository string, run Runner, tempDir func() (string, func(), error)) (Publisher, error) {
	intake, err := parseGoEndpoint(intakeEndpoint, "intake")
	if err != nil {
		return Publisher{}, err
	}
	approved, err := parseGoEndpoint(approvedEndpoint, "approved")
	if err != nil {
		return Publisher{}, err
	}
	project, location, repository, err := parseRepository(approvedRepository)
	if err != nil {
		return Publisher{}, err
	}
	if run == nil {
		return Publisher{}, errors.New("publisher runner must not be nil")
	}
	if tempDir == nil {
		return Publisher{}, errors.New("publisher temp-dir factory must not be nil")
	}
	return Publisher{
		client:     client,
		intake:     intake,
		approved:   approved,
		project:    project,
		location:   location,
		repository: repository,
		run:        run,
		tempDir:    tempDir,
	}, nil
}

// Publish moves the candidate's verified module content from the intake
// boundary into the approved repository. The evidence trail parameter is the
// audit context of the promotion; the publication proof binds the content
// itself. The method never rebuilds the module and never resolves a new
// graph.
func (p Publisher) Publish(ctx context.Context, subject candidate.Candidate, _ []evidence.Reference) error {
	intakeArchive, err := p.fetchArchive(ctx, p.intake, subject)
	if err != nil {
		return err
	}
	if digest := "sha256:" + hex.EncodeToString(sha256Sum(intakeArchive)); digest != subject.Digest() {
		return fmt.Errorf("intake content digest %q drifted from the candidate digest %q before publication", digest, subject.Digest())
	}

	source, cleanupSource, err := p.materialize(subject, intakeArchive)
	if err != nil {
		return err
	}
	defer cleanupSource()
	preHash, err := dirhash(source)
	if err != nil {
		return fmt.Errorf("hash materialized module before publication: %w", err)
	}

	if err := p.upload(ctx, source, subject); err != nil {
		return err
	}

	approvedArchive, err := p.fetchArchive(ctx, p.approved, subject)
	if err != nil {
		return err
	}
	published, cleanupPublished, err := p.materialize(subject, approvedArchive)
	if err != nil {
		return err
	}
	defer cleanupPublished()
	postHash, err := dirhash(published)
	if err != nil {
		return fmt.Errorf("hash materialized module after publication: %w", err)
	}
	if preHash != postHash {
		return fmt.Errorf("content identity mismatch after publication: %q != %q", postHash, preHash)
	}
	return nil
}

// fetchArchive downloads the module archive through the bound Go proxy
// endpoint of the given zone.
func (p Publisher) fetchArchive(ctx context.Context, endpoint *url.URL, subject candidate.Candidate) ([]byte, error) {
	requestURL := strings.TrimRight(endpoint.String(), "/") + "/" + escapeModulePath(subject.Name()) + "/@v/" + escapeModulePath(subject.Version()) + ".zip"
	content, status, err := p.client.do(ctx, http.MethodGet, requestURL, nil, "")
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound || status == http.StatusGone {
		return nil, fmt.Errorf("module archive %s %s not found at %q", subject.Name(), subject.Version(), endpoint.Host)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("fetch module archive from %q: unexpected status %d", endpoint.Host, status)
	}
	return content, nil
}

// materialize extracts the module archive into a fresh temporary directory
// and returns the module root with its cleanup.
func (p Publisher) materialize(subject candidate.Candidate, archive []byte) (string, func(), error) {
	dir, cleanup, err := p.tempDir()
	if err != nil {
		return "", nil, fmt.Errorf("create module workspace: %w", err)
	}
	root, err := extractModule(dir, subject, archive)
	if err != nil {
		cleanup()
		return "", nil, err
	}
	return root, cleanup, nil
}

// upload publishes the materialized module through the pinned gcloud upload
// tool, which authenticates through the lane's application default
// credentials.
func (p Publisher) upload(ctx context.Context, source string, subject candidate.Candidate) error {
	result, err := p.run(ctx, source, "gcloud", "artifacts", "go", "upload",
		"--project="+p.project,
		"--location="+p.location,
		"--repository="+p.repository,
		"--module-path="+subject.Name(),
		"--version="+subject.Version(),
		"--source="+source,
	)
	if err != nil {
		return fmt.Errorf("execute module upload: %w", err)
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("module upload exited with code %d", result.ExitCode)
	}
	return nil
}

// extractModule unpacks the module archive under dir with traversal guards
// and returns the module root directory.
func extractModule(dir string, subject candidate.Candidate, archive []byte) (string, error) {
	reader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return "", fmt.Errorf("open module archive: %w", err)
	}
	prefix := subject.Name() + "@" + subject.Version() + "/"
	if len(reader.File) == 0 {
		return "", errors.New("module archive carries no files")
	}

	var written int64
	for _, entry := range reader.File {
		target, err := moduleEntryTarget(dir, prefix, entry.Name)
		if err != nil {
			return "", err
		}
		if entry.FileInfo().IsDir() {
			if err := createModuleDir(target, 0o755); err != nil {
				return "", fmt.Errorf("create module directory: %w", err)
			}
			continue
		}
		written, err = extractEntry(target, entry, written)
		if err != nil {
			return "", err
		}
	}
	return filepath.Join(dir, filepath.FromSlash(strings.TrimSuffix(prefix, "/"))), nil
}

// moduleEntryTarget binds one archive entry to its extraction path and
// rejects anything outside the module prefix or the module root.
func moduleEntryTarget(dir string, prefix string, name string) (string, error) {
	if !strings.HasPrefix(name, prefix) {
		return "", fmt.Errorf("module archive entry %q escapes the module prefix %q", name, prefix)
	}
	moduleRoot := filepath.Join(dir, filepath.FromSlash(strings.TrimSuffix(prefix, "/")))
	target := filepath.Join(dir, filepath.FromSlash(name))
	cleaned := filepath.Clean(target)
	if cleaned != moduleRoot && !strings.HasPrefix(cleaned, moduleRoot+string(os.PathSeparator)) {
		return "", fmt.Errorf("module archive entry %q escapes the module root", name)
	}
	return target, nil
}

// extractEntry writes one regular file entry and enforces the decompression
// bound.
func extractEntry(target string, entry *zip.File, written int64) (int64, error) {
	source, err := entry.Open()
	if err != nil {
		return written, fmt.Errorf("open module archive entry %q: %w", entry.Name, err)
	}
	defer func() {
		_ = source.Close()
	}()
	if err := createModuleDir(filepath.Dir(target), 0o755); err != nil {
		return written, fmt.Errorf("create module directory: %w", err)
	}
	out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return written, fmt.Errorf("create module file: %w", err)
	}
	// The close is best-effort cleanup: a truncated write surfaces downstream
	// as a content-identity mismatch in the publisher's dirhash comparison.
	defer func() {
		_ = out.Close()
	}()
	count, err := io.Copy(out, io.LimitReader(source, maxModuleArchiveBytes+1-written))
	if err != nil {
		return written, fmt.Errorf("write module file: %w", err)
	}
	written += count
	if written > maxModuleArchiveBytes {
		return written, errors.New("module archive exceeds the decompression bound")
	}
	return written, nil
}

// parseGoEndpoint validates a Go proxy endpoint of a trust zone.
func parseGoEndpoint(endpoint string, zone string) (*url.URL, error) {
	if strings.TrimSpace(endpoint) == "" {
		return nil, fmt.Errorf("%s endpoint must not be empty", zone)
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse %s endpoint: %w", zone, err)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("%s endpoint %q must carry a host", zone, endpoint)
	}
	if parsed.Scheme != "https" && !isLoopbackHTTP(parsed) {
		return nil, fmt.Errorf("%s endpoint %q must use https", zone, endpoint)
	}
	return parsed, nil
}

// escapeModulePath encodes upper-case letters as '!' followed by the
// lower-case letter, as the Go module proxy protocol requires.
func escapeModulePath(path string) string {
	var escaped strings.Builder
	for _, r := range path {
		if r >= 'A' && r <= 'Z' {
			escaped.WriteByte('!')
			escaped.WriteRune(r + ('a' - 'A'))
			continue
		}
		escaped.WriteRune(r)
	}
	return escaped.String()
}

var _ promotion.ApprovedRegistry = Publisher{}
