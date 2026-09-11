// Package tooling implements the workload tooling channel consumer of the
// dependency authority lane controllers: at startup the scanning lanes
// materialize the pinned scanner tool, scanner database snapshot, and
// admission policy bundle from the governed evidence-zone generic repository,
// every object proven fail-closed against the content digest its bound
// identity carries. The channel is append-only and digest-addressed; the
// materializer never overwrites differing content and never leaves a partial
// placement behind. The adapter binds no organization value; the trust-zone
// endpoint and repository arrive through the lane environment.
package tooling

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	domaintooling "github.com/t33n-software/dependency-authority/internal/dependency/domain/tooling"
)

// Doer executes HTTP requests. *http.Client satisfies it; tests inject fakes.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// TokenSource supplies a short-lived bearer token per request. The token
// never persists beyond the request it authorizes.
type TokenSource func(ctx context.Context) (string, error)

// transport is the authenticated, read-only Artifact Registry surface of the
// channel materializer.
type transport struct {
	api   string
	doer  Doer
	token TokenSource
}

// newTransport constructs the transport and fails closed on an empty
// endpoint, a non-TLS transport outside loopback test servers, a nil token
// source, or a nil HTTP client.
func newTransport(apiEndpoint string, token TokenSource, doer Doer) (transport, error) {
	if strings.TrimSpace(apiEndpoint) == "" {
		return transport{}, errors.New("artifact registry API endpoint must not be empty")
	}
	parsed, err := url.Parse(apiEndpoint)
	if err != nil {
		return transport{}, fmt.Errorf("parse artifact registry API endpoint: %w", err)
	}
	if parsed.Host == "" {
		return transport{}, fmt.Errorf("artifact registry API endpoint %q must carry a host", apiEndpoint)
	}
	if parsed.Scheme != "https" && !isLoopbackHTTP(parsed) {
		return transport{}, fmt.Errorf("artifact registry API endpoint %q must use https", apiEndpoint)
	}
	if token == nil {
		return transport{}, errors.New("token source must not be nil")
	}
	if doer == nil {
		return transport{}, errors.New("http client must not be nil")
	}
	return transport{api: strings.TrimRight(apiEndpoint, "/"), doer: doer, token: token}, nil
}

// do issues one authenticated request and returns the response body and
// status code. Transport and read failures are errors; status handling
// belongs to the caller.
func (t transport) do(ctx context.Context, method string, requestURL string) ([]byte, int, error) {
	request, err := http.NewRequestWithContext(ctx, method, requestURL, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("build artifact registry request: %w", err)
	}
	token, err := t.token(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("resolve artifact registry credential: %w", err)
	}
	if token == "" {
		return nil, 0, errors.New("artifact registry credential must not be empty")
	}
	request.Header.Set("Authorization", "Bearer "+token)

	response, err := t.doer.Do(request)
	if err != nil {
		return nil, 0, fmt.Errorf("execute artifact registry request: %w", err)
	}
	defer func() {
		_ = response.Body.Close()
	}()
	content, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("read artifact registry response: %w", err)
	}
	return content, response.StatusCode, nil
}

// fileEntry is the listed shape of one stored generic file.
type fileEntry struct {
	Name string `json:"name"`
}

// filePage is one page of the files.list response.
type filePage struct {
	Files         []fileEntry `json:"files"`
	NextPageToken string      `json:"nextPageToken"`
}

// list returns every file in the repository, following the list pagination
// contract.
func (t transport) list(ctx context.Context, repository string) ([]fileEntry, error) {
	files := make([]fileEntry, 0)
	pageToken := ""
	for {
		requestURL := t.api + "/v1/" + repository + "/files?pageSize=1000"
		if pageToken != "" {
			requestURL += "&pageToken=" + url.QueryEscape(pageToken)
		}
		content, status, err := t.do(ctx, http.MethodGet, requestURL)
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK {
			return nil, fmt.Errorf("list files of %q: unexpected status %d", repository, status)
		}
		page, err := decodeFilePage(content)
		if err != nil {
			return nil, fmt.Errorf("decode file list of %q: %w", repository, err)
		}
		files = append(files, page.Files...)
		if page.NextPageToken == "" {
			return files, nil
		}
		pageToken = page.NextPageToken
	}
}

// download fetches one stored file by its server-issued resource name.
func (t transport) download(ctx context.Context, name string) ([]byte, error) {
	content, status, err := t.do(ctx, http.MethodGet, t.api+"/v1/"+name+":download")
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("download %q: unexpected status %d", name, status)
	}
	return content, nil
}

func decodeFilePage(content []byte) (filePage, error) {
	var page filePage
	if err := json.Unmarshal(content, &page); err != nil {
		return filePage{}, err
	}
	return page, nil
}

// parseRepository binds and validates the repository resource name
// projects/<project>/locations/<location>/repositories/<repository>.
func parseRepository(resource string) error {
	parts := strings.Split(resource, "/")
	if len(parts) != 6 || parts[0] != "projects" || parts[2] != "locations" || parts[4] != "repositories" {
		return fmt.Errorf("repository resource %q must match projects/<project>/locations/<location>/repositories/<repository>", resource)
	}
	if parts[1] == "" || parts[3] == "" || parts[5] == "" {
		return fmt.Errorf("repository resource %q must not carry empty segments", resource)
	}
	return nil
}

// isLoopbackHTTP permits plain HTTP only for loopback test servers.
func isLoopbackHTTP(base *url.URL) bool {
	if base.Scheme != "http" {
		return false
	}
	host := base.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Request binds one channel artifact identity to its materialization target.
type Request struct {
	identity domaintooling.Identity
	target   string
	mode     os.FileMode
}

// NewRequest constructs a materialization request and fails closed on an
// unbound identity, an empty target, or a mode outside the channel forms.
func NewRequest(identity domaintooling.Identity, target string, mode os.FileMode) (Request, error) {
	if !identity.Valid() {
		return Request{}, errors.New("tooling channel identity must be bound")
	}
	if strings.TrimSpace(target) == "" {
		return Request{}, errors.New("tooling channel target path must not be empty")
	}
	if mode != 0o644 && mode != 0o755 {
		return Request{}, fmt.Errorf("tooling channel target mode %o must be 0644 or 0755", mode)
	}
	return Request{identity: identity, target: target, mode: mode}, nil
}

// Identity returns the bound channel artifact identity.
func (r Request) Identity() domaintooling.Identity {
	return r.identity
}

// Target returns the materialization target path.
func (r Request) Target() string {
	return r.target
}

// Mode returns the target file mode.
func (r Request) Mode() os.FileMode {
	return r.mode
}

// Materializer materializes workload tooling channel artifacts from the bound
// evidence-zone generic repository.
type Materializer struct {
	transport  transport
	repository string
}

// NewMaterializer constructs the channel materializer and fails closed on an
// invalid endpoint, transport, or repository binding.
func NewMaterializer(apiEndpoint string, repository string, token TokenSource, doer Doer) (Materializer, error) {
	bound, err := newTransport(apiEndpoint, token, doer)
	if err != nil {
		return Materializer{}, err
	}
	if err := parseRepository(repository); err != nil {
		return Materializer{}, err
	}
	return Materializer{transport: bound, repository: repository}, nil
}

// Materialize fetches every requested artifact, proves its content against
// the digest its identity binds, and places it at its target path. The first
// deviation fails the lane closed.
func (m Materializer) Materialize(ctx context.Context, requests ...Request) error {
	for _, request := range requests {
		if err := m.materialize(ctx, request); err != nil {
			return err
		}
	}
	return nil
}

// materialize proves and places one channel artifact.
func (m Materializer) materialize(ctx context.Context, request Request) error {
	object, err := objectPath(request.identity)
	if err != nil {
		return err
	}
	content, err := m.fetch(ctx, object)
	if err != nil {
		return err
	}
	if digest := digestOf(content); digest != request.identity.Digest() {
		return fmt.Errorf("tooling channel object %q digest %q does not match the bound identity %q", object, digest, request.identity.Digest())
	}
	if err := place(request, content); err != nil {
		return err
	}
	return nil
}

// fetch downloads the channel object by the resource name the repository
// inventory proves for it.
func (m Materializer) fetch(ctx context.Context, object string) ([]byte, error) {
	name, err := m.resolve(ctx, object)
	if err != nil {
		return nil, err
	}
	return m.transport.download(ctx, name)
}

// resolve binds the channel object to its server-issued resource name through
// the repository file inventory. The platform carries the file path
// URL-encoded in the inventory resource name (the path slashes as %2F), so
// the comparison runs on the canonical decoded form while the download keeps
// the server-issued name. A malformed escape fails closed.
func (m Materializer) resolve(ctx context.Context, object string) (string, error) {
	want := m.repository + "/files/" + object
	files, err := m.transport.list(ctx, m.repository)
	if err != nil {
		return "", err
	}
	for _, file := range files {
		decoded, err := url.PathUnescape(file.Name)
		if err != nil {
			return "", fmt.Errorf("decode the inventory resource name %q: %w", file.Name, err)
		}
		if decoded == want {
			return file.Name, nil
		}
	}
	return "", fmt.Errorf("tooling channel object %q not found in %q", object, m.repository)
}

// objectPath derives the registry object address of the channel artifact from
// its identity: the platform addresses a generic file as
// <package>:<version>:<filename>, and the stored filename carries the
// platform-safe <algorithm>-<hex> digest notation. The fail-closed domain
// parse guarantees the segment forms, so the mapping is total for every bound
// identity.
func objectPath(identity domaintooling.Identity) (string, error) {
	switch identity.Kind() {
	case domaintooling.KindTool:
		// osv-scanner/<version>/<asset>
		parts := strings.Split(identity.Path(), "/")
		return parts[0] + ":" + parts[1] + ":" + parts[2] + "@sha256-" + identity.DigestHex(), nil
	case domaintooling.KindDatabase:
		// osv-db/<ecosystem>
		parts := strings.Split(identity.Path(), "/")
		return parts[0] + ":" + parts[1] + ":all-" + identity.DigestHex() + ".zip", nil
	case domaintooling.KindBundle:
		// dependency-policy/v1
		parts := strings.Split(identity.Path(), "/")
		return parts[0] + ":" + parts[1] + ":" + identity.DigestHex() + ".json", nil
	default:
		return "", fmt.Errorf("unknown tooling channel artifact kind %d", identity.Kind())
	}
}

// digestOf computes the canonical sha256 reference digest of the content.
func digestOf(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// The filesystem seams of the placement; tests bind fault-injecting fakes.
var (
	makeDirectory = os.MkdirAll
	readTarget    = os.ReadFile
	writeStaged   = os.WriteFile
	chmodStaged   = os.Chmod
	renameFile    = os.Rename
	removeFile    = os.Remove
)

// place materializes the proven content at the request target atomically: the
// content is staged beside the target and renamed into place, so a failure
// never leaves a partial target. A target already carrying the proven content
// is an idempotent skip; differing content is drift and fails closed.
func place(request Request, content []byte) (err error) {
	directory := filepath.Dir(request.target)
	if err = makeDirectory(directory, 0o755); err != nil {
		return fmt.Errorf("create the tooling channel target directory: %w", err)
	}
	existing, readErr := readTarget(request.target)
	switch {
	case readErr == nil:
		if digestOf(existing) == request.identity.Digest() {
			return nil
		}
		return fmt.Errorf("tooling channel target %q carries content drift", request.target)
	case !errors.Is(readErr, os.ErrNotExist):
		return fmt.Errorf("read the tooling channel target: %w", readErr)
	}

	staged := filepath.Join(directory, ".tooling-"+request.identity.DigestHex()+".tmp")
	if err = writeStaged(staged, content, request.mode); err != nil {
		return fmt.Errorf("stage the tooling channel object: %w", err)
	}
	defer func() {
		if err != nil {
			_ = removeFile(staged)
		}
	}()
	if err = chmodStaged(staged, request.mode); err != nil {
		return fmt.Errorf("mark the tooling channel object: %w", err)
	}
	if err = renameFile(staged, request.target); err != nil {
		return fmt.Errorf("place the tooling channel object: %w", err)
	}
	return nil
}
