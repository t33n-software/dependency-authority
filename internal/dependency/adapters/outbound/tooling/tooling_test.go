package tooling

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	domaintooling "github.com/t33n-software/dependency-authority/internal/dependency/domain/tooling"
)

type doerFunc func(*http.Request) (*http.Response, error)

func (f doerFunc) Do(req *http.Request) (*http.Response, error) {
	return f(req)
}

func staticToken(token string) TokenSource {
	return func(context.Context) (string, error) {
		return token, nil
	}
}

func okResponse(body string) *http.Response {
	return &http.Response{Status: "200 OK", StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}
}

func newTestMaterializer(t *testing.T, doer Doer) Materializer {
	t.Helper()
	materializer, err := NewMaterializer("https://artifactregistry.googleapis.com", "projects/p/locations/l/repositories/r", staticToken("token"), doer)
	if err != nil {
		t.Fatalf("NewMaterializer() error = %v", err)
	}
	return materializer
}

func toolIdentityFor(t *testing.T, content []byte) domaintooling.Identity {
	t.Helper()
	sum := sha256.Sum256(content)
	identity, err := domaintooling.ParseTool("osv-scanner/v2.5.1/osv-scanner_linux_amd64@sha256:" + hex.EncodeToString(sum[:]))
	if err != nil {
		t.Fatalf("ParseTool() error = %v", err)
	}
	return identity
}

func databaseIdentityFor(t *testing.T, content []byte) domaintooling.Identity {
	t.Helper()
	sum := sha256.Sum256(content)
	identity, err := domaintooling.ParseDatabase("osv-db/go@sha256:" + hex.EncodeToString(sum[:]))
	if err != nil {
		t.Fatalf("ParseDatabase() error = %v", err)
	}
	return identity
}

func bundleIdentityFor(t *testing.T, content []byte) domaintooling.Identity {
	t.Helper()
	sum := sha256.Sum256(content)
	identity, err := domaintooling.ParseBundle("dependency-policy/v1@sha256:" + hex.EncodeToString(sum[:]))
	if err != nil {
		t.Fatalf("ParseBundle() error = %v", err)
	}
	return identity
}

// channelServer fakes the read surface of the evidence-zone generic
// repository: the file inventory and the content downloads.
type channelServer struct {
	documents      map[string][]byte
	names          []string
	listStatus     int
	downloadStatus int
}

func newChannelServer() *channelServer {
	return &channelServer{documents: make(map[string][]byte)}
}

// serve stores the content under the channel object path. The inventory lists
// the platform wire form of the resource name — the file path URL-encoded
// with the path slashes as %2F, as the Artifact Registry files.list response
// carries it — while the download request path decodes back to the logical
// form the documents are keyed by.
func (s *channelServer) serve(object string, content []byte) {
	name := "projects/p/locations/l/repositories/r/files/" + object
	s.documents[name] = content
	s.names = append(s.names, "projects/p/locations/l/repositories/r/files/"+strings.ReplaceAll(object, "/", "%2F"))
}

func (s *channelServer) do(req *http.Request) (*http.Response, error) {
	if strings.HasSuffix(req.URL.Path, ":download") {
		name := strings.TrimPrefix(strings.TrimSuffix(req.URL.Path, ":download"), "/v1/")
		content, found := s.documents[name]
		if s.downloadStatus != 0 || !found {
			status := s.downloadStatus
			if status == 0 {
				status = 404
			}
			return &http.Response{Status: fmt.Sprintf("%d", status), StatusCode: status, Body: io.NopCloser(strings.NewReader(""))}, nil
		}
		return &http.Response{Status: "200 OK", StatusCode: 200, Body: io.NopCloser(bytes.NewReader(content))}, nil
	}
	if s.listStatus != 0 {
		return &http.Response{Status: fmt.Sprintf("%d", s.listStatus), StatusCode: s.listStatus, Body: io.NopCloser(strings.NewReader(""))}, nil
	}
	entries := make([]string, 0, len(s.names))
	for _, name := range s.names {
		entries = append(entries, fmt.Sprintf(`{"name": %q}`, name))
	}
	return okResponse(`{"files": [` + strings.Join(entries, ",") + `]}`), nil
}

func TestNewMaterializerValidatesConfiguration(t *testing.T) {
	if _, err := NewMaterializer(" ", "projects/p/locations/l/repositories/r", staticToken("token"), http.DefaultClient); err == nil {
		t.Fatal("NewMaterializer( blank endpoint ) error = nil, want error")
	}
	if _, err := NewMaterializer("ht tp://invalid", "projects/p/locations/l/repositories/r", staticToken("token"), http.DefaultClient); err == nil {
		t.Fatal("NewMaterializer( unparseable endpoint ) error = nil, want error")
	}
	if _, err := NewMaterializer("https://", "projects/p/locations/l/repositories/r", staticToken("token"), http.DefaultClient); err == nil {
		t.Fatal("NewMaterializer( hostless endpoint ) error = nil, want error")
	}
	if _, err := NewMaterializer("http://example.com", "projects/p/locations/l/repositories/r", staticToken("token"), http.DefaultClient); err == nil {
		t.Fatal("NewMaterializer( plaintext endpoint ) error = nil, want error")
	}
	if _, err := NewMaterializer("ftp://example.com", "projects/p/locations/l/repositories/r", staticToken("token"), http.DefaultClient); err == nil {
		t.Fatal("NewMaterializer( non-http endpoint ) error = nil, want error")
	}
	if _, err := NewMaterializer("http://localhost:8080", "projects/p/locations/l/repositories/r", staticToken("token"), http.DefaultClient); err != nil {
		t.Fatalf("NewMaterializer( loopback ) error = %v, want success", err)
	}
	if _, err := NewMaterializer("https://artifactregistry.googleapis.com", "bogus", staticToken("token"), http.DefaultClient); err == nil {
		t.Fatal("NewMaterializer( invalid repository ) error = nil, want error")
	}
	if _, err := NewMaterializer("https://artifactregistry.googleapis.com", "projects/p/locations//repositories/r", staticToken("token"), http.DefaultClient); err == nil {
		t.Fatal("NewMaterializer( empty segment repository ) error = nil, want error")
	}
	if _, err := NewMaterializer("https://artifactregistry.googleapis.com", "projects/p/locations/l/repositories/r", nil, http.DefaultClient); err == nil {
		t.Fatal("NewMaterializer( nil token ) error = nil, want error")
	}
	if _, err := NewMaterializer("https://artifactregistry.googleapis.com", "projects/p/locations/l/repositories/r", staticToken("token"), nil); err == nil {
		t.Fatal("NewMaterializer( nil doer ) error = nil, want error")
	}
}

func TestNewRequestValidatesTheBinding(t *testing.T) {
	identity := toolIdentityFor(t, []byte("content"))
	if _, err := NewRequest(domaintooling.Identity{}, "target", 0o644); err == nil {
		t.Fatal("NewRequest( zero identity ) error = nil, want error")
	}
	if _, err := NewRequest(identity, "", 0o644); err == nil {
		t.Fatal("NewRequest( empty target ) error = nil, want error")
	}
	if _, err := NewRequest(identity, "  ", 0o644); err == nil {
		t.Fatal("NewRequest( blank target ) error = nil, want error")
	}
	if _, err := NewRequest(identity, "target", 0o600); err == nil {
		t.Fatal("NewRequest( non-channel mode ) error = nil, want error")
	}
	for _, mode := range []os.FileMode{0o644, 0o755} {
		request, err := NewRequest(identity, "target", mode)
		if err != nil {
			t.Fatalf("NewRequest( mode %o ) error = %v", mode, err)
		}
		if request.Identity() != identity || request.Target() != "target" || request.Mode() != mode {
			t.Fatalf("NewRequest() = %q %q %o", request.Identity(), request.Target(), request.Mode())
		}
	}
}

func TestObjectPathDerivesTheStoredCoordinates(t *testing.T) {
	tool := toolIdentityFor(t, []byte("tool"))
	wantTool := "tooling/osv-scanner/v2.5.1/osv-scanner_linux_amd64@sha256-" + tool.DigestHex()
	got, err := objectPath(tool)
	if err != nil || got != wantTool {
		t.Fatalf("objectPath(tool) = %q, %v, want %q", got, err, wantTool)
	}

	database := databaseIdentityFor(t, []byte("db"))
	wantDatabase := "tooling/osv-db/go/all-" + database.DigestHex() + ".zip"
	got, err = objectPath(database)
	if err != nil || got != wantDatabase {
		t.Fatalf("objectPath(database) = %q, %v, want %q", got, err, wantDatabase)
	}

	bundle := bundleIdentityFor(t, []byte("bundle"))
	wantBundle := "policy/dependency-policy/v1/" + bundle.DigestHex() + ".json"
	got, err = objectPath(bundle)
	if err != nil || got != wantBundle {
		t.Fatalf("objectPath(bundle) = %q, %v, want %q", got, err, wantBundle)
	}

	if _, err := objectPath(domaintooling.Identity{}); err == nil {
		t.Fatal("objectPath( zero identity ) error = nil, want error")
	}
}

func TestMaterializeWithoutRequestsIsANoOp(t *testing.T) {
	materializer := newTestMaterializer(t, doerFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("no call expected")
	}))
	if err := materializer.Materialize(context.Background()); err != nil {
		t.Fatalf("Materialize() error = %v", err)
	}
}

func TestMaterializePlacesEveryProvenObject(t *testing.T) {
	toolContent := []byte("the pinned tool content")
	bundleContent := []byte("the pinned bundle content")
	tool := toolIdentityFor(t, toolContent)
	bundle := bundleIdentityFor(t, bundleContent)

	server := newChannelServer()
	toolObject, err := objectPath(tool)
	if err != nil {
		t.Fatalf("objectPath() error = %v", err)
	}
	server.serve(toolObject, toolContent)
	bundleObject, err := objectPath(bundle)
	if err != nil {
		t.Fatalf("objectPath() error = %v", err)
	}
	server.serve(bundleObject, bundleContent)

	directory := t.TempDir()
	toolRequest, err := NewRequest(tool, filepath.Join(directory, "tool", "osv-scanner"), 0o755)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	bundleRequest, err := NewRequest(bundle, filepath.Join(directory, "policy", "go.json"), 0o644)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}

	materializer := newTestMaterializer(t, doerFunc(server.do))
	if err := materializer.Materialize(context.Background(), toolRequest, bundleRequest); err != nil {
		t.Fatalf("Materialize() error = %v", err)
	}

	for target, want := range map[string][]byte{
		toolRequest.Target():   toolContent,
		bundleRequest.Target(): bundleContent,
	} {
		placed, err := os.ReadFile(target)
		if err != nil {
			t.Fatalf("ReadFile(%q) error = %v", target, err)
		}
		if !bytes.Equal(placed, want) {
			t.Fatalf("placed content at %q does not match the proven content", target)
		}
	}
}

func TestMaterializeFailsClosedOnAnUnboundRequest(t *testing.T) {
	materializer := newTestMaterializer(t, doerFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("no call expected")
	}))
	// The raw struct bypasses the NewRequest guard to prove the materialize
	// path still fails closed on the unbound identity.
	request := Request{identity: domaintooling.Identity{}, target: "target", mode: 0o644}
	if err := materializer.Materialize(context.Background(), request); err == nil {
		t.Fatal("Materialize( unbound identity ) error = nil, want error")
	}
}

func TestMaterializePropagatesTheInventoryFailure(t *testing.T) {
	server := newChannelServer()
	server.listStatus = 503
	materializer := newTestMaterializer(t, doerFunc(server.do))
	request, err := NewRequest(toolIdentityFor(t, []byte("content")), filepath.Join(t.TempDir(), "tool"), 0o755)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	if err := materializer.Materialize(context.Background(), request); err == nil || !strings.Contains(err.Error(), "unexpected status 503") {
		t.Fatalf("Materialize() error = %v, want the inventory failure", err)
	}
}

func TestMaterializeFailsClosedOnAnUnknownObject(t *testing.T) {
	server := newChannelServer()
	materializer := newTestMaterializer(t, doerFunc(server.do))
	request, err := NewRequest(toolIdentityFor(t, []byte("content")), filepath.Join(t.TempDir(), "tool"), 0o755)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	if err := materializer.Materialize(context.Background(), request); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("Materialize() error = %v, want the unknown object failure", err)
	}
}

func TestResolveMatchesThePlatformEncodedInventoryName(t *testing.T) {
	content := []byte("the pinned tool content")
	identity := toolIdentityFor(t, content)
	server := newChannelServer()
	object, err := objectPath(identity)
	if err != nil {
		t.Fatalf("objectPath() error = %v", err)
	}
	server.serve(object, content)

	var downloadEscapedPath string
	materializer := newTestMaterializer(t, doerFunc(func(req *http.Request) (*http.Response, error) {
		if strings.HasSuffix(req.URL.Path, ":download") {
			downloadEscapedPath = req.URL.EscapedPath()
		}
		return server.do(req)
	}))
	request, err := NewRequest(identity, filepath.Join(t.TempDir(), "tool", "osv-scanner"), 0o755)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	if err := materializer.Materialize(context.Background(), request); err != nil {
		t.Fatalf("Materialize() error = %v, want the resolution over the platform-encoded inventory name", err)
	}
	wantDownload := "/v1/projects/p/locations/l/repositories/r/files/" + strings.ReplaceAll(object, "/", "%2F") + ":download"
	if downloadEscapedPath != wantDownload {
		t.Fatalf("download escaped path = %q, want the server-issued encoded resource name %q", downloadEscapedPath, wantDownload)
	}
}

func TestResolveFailsClosedOnAMalformedInventoryName(t *testing.T) {
	server := newChannelServer()
	server.names = append(server.names, "projects/p/locations/l/repositories/r/files/tooling%zz")
	materializer := newTestMaterializer(t, doerFunc(server.do))
	request, err := NewRequest(toolIdentityFor(t, []byte("content")), filepath.Join(t.TempDir(), "tool"), 0o755)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	if err := materializer.Materialize(context.Background(), request); err == nil || !strings.Contains(err.Error(), "decode the inventory resource name") {
		t.Fatalf("Materialize() error = %v, want the inventory name decode failure", err)
	}
}

func TestMaterializePropagatesTheDownloadFailure(t *testing.T) {
	content := []byte("content")
	identity := toolIdentityFor(t, content)
	server := newChannelServer()
	object, err := objectPath(identity)
	if err != nil {
		t.Fatalf("objectPath() error = %v", err)
	}
	server.serve(object, content)
	server.downloadStatus = 500
	materializer := newTestMaterializer(t, doerFunc(server.do))
	request, err := NewRequest(identity, filepath.Join(t.TempDir(), "tool"), 0o755)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	if err := materializer.Materialize(context.Background(), request); err == nil || !strings.Contains(err.Error(), "unexpected status 500") {
		t.Fatalf("Materialize() error = %v, want the download failure", err)
	}
}

func TestMaterializeFailsClosedOnDigestDrift(t *testing.T) {
	identity := toolIdentityFor(t, []byte("the bound content"))
	server := newChannelServer()
	object, err := objectPath(identity)
	if err != nil {
		t.Fatalf("objectPath() error = %v", err)
	}
	server.serve(object, []byte("drifted content"))

	target := filepath.Join(t.TempDir(), "tool", "osv-scanner")
	request, err := NewRequest(identity, target, 0o755)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	materializer := newTestMaterializer(t, doerFunc(server.do))
	if err := materializer.Materialize(context.Background(), request); err == nil || !strings.Contains(err.Error(), "does not match the bound identity") {
		t.Fatalf("Materialize() error = %v, want the digest drift failure", err)
	}
	if _, statErr := os.Stat(target); !os.IsNotExist(statErr) {
		t.Fatal("Materialize() left a target behind after the digest drift, want no placement")
	}
}

func TestMaterializeSkipsAnAlreadyMaterializedTarget(t *testing.T) {
	content := []byte("the pinned content")
	identity := toolIdentityFor(t, content)
	server := newChannelServer()
	object, err := objectPath(identity)
	if err != nil {
		t.Fatalf("objectPath() error = %v", err)
	}
	server.serve(object, content)

	target := filepath.Join(t.TempDir(), "tool", "osv-scanner")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(target, content, 0o755); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	request, err := NewRequest(identity, target, 0o755)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	materializer := newTestMaterializer(t, doerFunc(server.do))
	if err := materializer.Materialize(context.Background(), request); err != nil {
		t.Fatalf("Materialize() error = %v, want the idempotent skip", err)
	}
	placed, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !bytes.Equal(placed, content) {
		t.Fatal("the already materialized target changed, want the idempotent skip")
	}
}

func TestMaterializeFailsClosedOnTargetDrift(t *testing.T) {
	content := []byte("the pinned content")
	identity := toolIdentityFor(t, content)
	server := newChannelServer()
	object, err := objectPath(identity)
	if err != nil {
		t.Fatalf("objectPath() error = %v", err)
	}
	server.serve(object, content)

	target := filepath.Join(t.TempDir(), "tool", "osv-scanner")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(target, []byte("foreign content"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	request, err := NewRequest(identity, target, 0o755)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	materializer := newTestMaterializer(t, doerFunc(server.do))
	if err := materializer.Materialize(context.Background(), request); err == nil || !strings.Contains(err.Error(), "content drift") {
		t.Fatalf("Materialize() error = %v, want the target drift failure", err)
	}
}

// lockPlaceSeams restores every placement seam after the test.
func lockPlaceSeams(t *testing.T) {
	t.Helper()
	mk, rd, wr, ch, rn, rm := makeDirectory, readTarget, writeStaged, chmodStaged, renameFile, removeFile
	t.Cleanup(func() {
		makeDirectory, readTarget, writeStaged, chmodStaged, renameFile, removeFile = mk, rd, wr, ch, rn, rm
	})
}

func TestPlaceFailsClosedOnTheDirectoryCreation(t *testing.T) {
	lockPlaceSeams(t)
	makeDirectory = func(string, os.FileMode) error {
		return errors.New("read-only filesystem")
	}
	request, err := NewRequest(toolIdentityFor(t, []byte("content")), filepath.Join(t.TempDir(), "tool"), 0o755)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	if err := place(request, []byte("content")); err == nil || !strings.Contains(err.Error(), "target directory") {
		t.Fatalf("place() error = %v, want the directory failure", err)
	}
}

func TestPlaceFailsClosedOnTheTargetRead(t *testing.T) {
	lockPlaceSeams(t)
	readTarget = func(string) ([]byte, error) {
		return nil, errors.New("permission denied")
	}
	request, err := NewRequest(toolIdentityFor(t, []byte("content")), filepath.Join(t.TempDir(), "tool"), 0o755)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	if err := place(request, []byte("content")); err == nil || !strings.Contains(err.Error(), "read the tooling channel target") {
		t.Fatalf("place() error = %v, want the read failure", err)
	}
}

func TestPlaceFailsClosedOnTheStagingWrite(t *testing.T) {
	lockPlaceSeams(t)
	writeStaged = func(string, []byte, os.FileMode) error {
		return errors.New("disk full")
	}
	request, err := NewRequest(toolIdentityFor(t, []byte("content")), filepath.Join(t.TempDir(), "tool"), 0o755)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	if err := place(request, []byte("content")); err == nil || !strings.Contains(err.Error(), "stage the tooling channel object") {
		t.Fatalf("place() error = %v, want the staging failure", err)
	}
}

func TestPlaceFailsClosedOnTheModeMarking(t *testing.T) {
	lockPlaceSeams(t)
	chmodStaged = func(string, os.FileMode) error {
		return errors.New("mode unsupported")
	}
	request, err := NewRequest(toolIdentityFor(t, []byte("content")), filepath.Join(t.TempDir(), "tool"), 0o755)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	if err := place(request, []byte("content")); err == nil || !strings.Contains(err.Error(), "mark the tooling channel object") {
		t.Fatalf("place() error = %v, want the marking failure", err)
	}
}

func TestPlaceFailsClosedOnThePlacementAndCleansUp(t *testing.T) {
	lockPlaceSeams(t)
	renameFile = func(string, string) error {
		return errors.New("cross-device link")
	}
	directory := t.TempDir()
	identity := toolIdentityFor(t, []byte("content"))
	request, err := NewRequest(identity, filepath.Join(directory, "tool"), 0o755)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	if err := place(request, []byte("content")); err == nil || !strings.Contains(err.Error(), "place the tooling channel object") {
		t.Fatalf("place() error = %v, want the placement failure", err)
	}
	staged := filepath.Join(directory, ".tooling-"+identity.DigestHex()+".tmp")
	if _, statErr := os.Stat(staged); !os.IsNotExist(statErr) {
		t.Fatal("place() left the staging file behind after the failure, want cleanup")
	}
}

func TestPlaceCarriesTheModeThroughTheSeams(t *testing.T) {
	lockPlaceSeams(t)
	var writeMode, chmodMode os.FileMode
	writeStaged = func(name string, content []byte, mode os.FileMode) error {
		writeMode = mode
		return os.WriteFile(name, content, mode)
	}
	chmodStaged = func(name string, mode os.FileMode) error {
		chmodMode = mode
		return os.Chmod(name, mode)
	}
	request, err := NewRequest(toolIdentityFor(t, []byte("content")), filepath.Join(t.TempDir(), "tool"), 0o755)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	if err := place(request, []byte("content")); err != nil {
		t.Fatalf("place() error = %v", err)
	}
	if writeMode != 0o755 || chmodMode != 0o755 {
		t.Fatalf("place() modes = %o, %o, want 0755 through both seams", writeMode, chmodMode)
	}
}

func TestTransportDoFailures(t *testing.T) {
	materializer := newTestMaterializer(t, http.DefaultClient)

	materializer.transport.token = func(context.Context) (string, error) {
		return "", errors.New("token exchange failed")
	}
	if _, _, err := materializer.transport.do(context.Background(), http.MethodGet, "https://artifactregistry.googleapis.com/v1/x"); err == nil {
		t.Fatal("do() error = nil, want credential error")
	}

	materializer.transport.token = staticToken("")
	if _, _, err := materializer.transport.do(context.Background(), http.MethodGet, "https://artifactregistry.googleapis.com/v1/x"); err == nil {
		t.Fatal("do() error = nil, want empty credential error")
	}

	materializer.transport.token = staticToken("token")
	if _, _, err := materializer.transport.do(context.Background(), http.MethodGet, "https://exa\nmple.com"); err == nil {
		t.Fatal("do() error = nil, want request build error")
	}

	materializer.transport.doer = doerFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("reset")
	})
	if _, _, err := materializer.transport.do(context.Background(), http.MethodGet, "https://artifactregistry.googleapis.com/v1/x"); err == nil {
		t.Fatal("do() error = nil, want transport error")
	}

	materializer.transport.doer = doerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{Status: "200 OK", StatusCode: 200, Body: io.NopCloser(&failingReader{})}, nil
	})
	if _, _, err := materializer.transport.do(context.Background(), http.MethodGet, "https://artifactregistry.googleapis.com/v1/x"); err == nil {
		t.Fatal("do() error = nil, want read error")
	}
}

type failingReader struct{}

func (*failingReader) Read([]byte) (int, error) {
	return 0, errors.New("mid-stream failure")
}

func TestTransportDoCarriesTheRequestContract(t *testing.T) {
	var gotAuth string
	materializer := newTestMaterializer(t, doerFunc(func(req *http.Request) (*http.Response, error) {
		gotAuth = req.Header.Get("Authorization")
		return okResponse(`{"ok": true}`), nil
	}))
	body, status, err := materializer.transport.do(context.Background(), http.MethodGet, "https://artifactregistry.googleapis.com/v1/x")
	if err != nil {
		t.Fatalf("do() error = %v", err)
	}
	if status != 200 || string(body) != `{"ok": true}` {
		t.Fatalf("do() = %q, %d", body, status)
	}
	if gotAuth != "Bearer token" {
		t.Fatalf("authorization = %q, want the bearer token", gotAuth)
	}
}

func TestTransportListPaginates(t *testing.T) {
	requests := make([]string, 0)
	materializer := newTestMaterializer(t, doerFunc(func(req *http.Request) (*http.Response, error) {
		requests = append(requests, req.URL.String())
		if strings.Contains(req.URL.RawQuery, "pageToken=two") {
			return okResponse(`{"files": [{"name": "projects/p/locations/l/repositories/r/files/b"}]}`), nil
		}
		return okResponse(`{"files": [{"name": "projects/p/locations/l/repositories/r/files/a"}], "nextPageToken": "two"}`), nil
	}))

	files, err := materializer.transport.list(context.Background(), "projects/p/locations/l/repositories/r")
	if err != nil {
		t.Fatalf("list() error = %v", err)
	}
	if len(files) != 2 || files[0].Name != "projects/p/locations/l/repositories/r/files/a" || files[1].Name != "projects/p/locations/l/repositories/r/files/b" {
		t.Fatalf("list() = %v, want both pages", files)
	}
	if len(requests) != 2 || !strings.Contains(requests[1], "pageToken=two") {
		t.Fatalf("list requests = %v, want the paginated sequence", requests)
	}
}

func TestTransportListFailures(t *testing.T) {
	materializer := newTestMaterializer(t, doerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{Status: "403 Forbidden", StatusCode: 403, Body: io.NopCloser(strings.NewReader(""))}, nil
	}))
	if _, err := materializer.transport.list(context.Background(), "projects/p/locations/l/repositories/r"); err == nil {
		t.Fatal("list() error = nil, want status error")
	}

	materializer = newTestMaterializer(t, doerFunc(func(*http.Request) (*http.Response, error) {
		return okResponse(`{`), nil
	}))
	if _, err := materializer.transport.list(context.Background(), "projects/p/locations/l/repositories/r"); err == nil {
		t.Fatal("list() error = nil, want decode error")
	}

	materializer = newTestMaterializer(t, doerFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("reset")
	}))
	if _, err := materializer.transport.list(context.Background(), "projects/p/locations/l/repositories/r"); err == nil {
		t.Fatal("list() error = nil, want transport error")
	}
}

func TestTransportDownloadFailures(t *testing.T) {
	materializer := newTestMaterializer(t, doerFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("reset")
	}))
	if _, err := materializer.transport.download(context.Background(), "x"); err == nil {
		t.Fatal("download() error = nil, want transport error")
	}

	materializer = newTestMaterializer(t, doerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{Status: "404 Not Found", StatusCode: 404, Body: io.NopCloser(strings.NewReader(""))}, nil
	}))
	if _, err := materializer.transport.download(context.Background(), "x"); err == nil {
		t.Fatal("download() error = nil, want status error")
	}
}
