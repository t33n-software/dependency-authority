package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/t33n-software/dependency-authority/internal/dependency/domain/candidate"
	"github.com/t33n-software/dependency-authority/internal/dependency/domain/evidence"
)

const evidenceDigest = "sha256:3b8f49c12b24cbbd6a4a0e6e2b2a4a4e8f0e1d2c3b4a59687766554433221100"

var evidenceTime = time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)

type doerFunc func(*http.Request) (*http.Response, error)

func (f doerFunc) Do(req *http.Request) (*http.Response, error) {
	return f(req)
}

func staticToken(token string) TokenSource {
	return func(context.Context) (string, error) {
		return token, nil
	}
}

func newTestStore(t *testing.T, doer Doer) Store {
	t.Helper()
	store, err := NewStore("https://artifactregistry.googleapis.com", "projects/p/locations/l/repositories/r", staticToken("token"), doer)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	return store
}

func okResponse(body string) *http.Response {
	return &http.Response{Status: "200 OK", StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}
}

func testCandidate(t *testing.T) candidate.Candidate {
	t.Helper()
	subject, err := candidate.New(candidate.EcosystemGo, "example.com/mod", "v1.0.0", evidenceDigest)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return subject
}

func testReference(t *testing.T, evidenceType evidence.Type, locator string, issuedAt time.Time) evidence.Reference {
	t.Helper()
	expiry := issuedAt.Add(time.Hour)
	reference, err := evidence.NewReference(evidenceType, locator, evidenceDigest, "issuer", issuedAt, &expiry)
	if err != nil {
		t.Fatalf("NewReference() error = %v", err)
	}
	return reference
}

func TestNewStoreValidatesConfiguration(t *testing.T) {
	if _, err := NewStore(" ", "projects/p/locations/l/repositories/r", staticToken("token"), http.DefaultClient); err == nil {
		t.Fatal("NewStore( blank endpoint ) error = nil, want error")
	}
	if _, err := NewStore("ht tp://invalid", "projects/p/locations/l/repositories/r", staticToken("token"), http.DefaultClient); err == nil {
		t.Fatal("NewStore( unparseable endpoint ) error = nil, want error")
	}
	if _, err := NewStore("https://", "projects/p/locations/l/repositories/r", staticToken("token"), http.DefaultClient); err == nil {
		t.Fatal("NewStore( hostless endpoint ) error = nil, want error")
	}
	if _, err := NewStore("http://example.com", "projects/p/locations/l/repositories/r", staticToken("token"), http.DefaultClient); err == nil {
		t.Fatal("NewStore( plaintext endpoint ) error = nil, want error")
	}
	if _, err := NewStore("ftp://example.com", "projects/p/locations/l/repositories/r", staticToken("token"), http.DefaultClient); err == nil {
		t.Fatal("NewStore( non-http endpoint ) error = nil, want error")
	}
	if _, err := NewStore("http://localhost:8080", "projects/p/locations/l/repositories/r", staticToken("token"), http.DefaultClient); err != nil {
		t.Fatalf("NewStore( loopback ) error = %v, want success", err)
	}
	if _, err := NewStore("http://127.0.0.1:8080", "bogus", staticToken("token"), http.DefaultClient); err == nil {
		t.Fatal("NewStore( invalid repository ) error = nil, want error")
	}
	if _, err := NewStore("http://127.0.0.1:8080", "projects/p/locations//repositories/r", staticToken("token"), http.DefaultClient); err == nil {
		t.Fatal("NewStore( empty segment repository ) error = nil, want error")
	}
	if _, err := NewStore("https://artifactregistry.googleapis.com", "projects/p/locations/l/repositories/r", nil, http.DefaultClient); err == nil {
		t.Fatal("NewStore( nil token ) error = nil, want error")
	}
	if _, err := NewStore("https://artifactregistry.googleapis.com", "projects/p/locations/l/repositories/r", staticToken("token"), nil); err == nil {
		t.Fatal("NewStore( nil doer ) error = nil, want error")
	}
}

func TestTransportDoFailures(t *testing.T) {
	store := newTestStore(t, http.DefaultClient)

	store.transport.token = func(context.Context) (string, error) {
		return "", errors.New("token exchange failed")
	}
	if _, _, err := store.transport.do(context.Background(), http.MethodGet, "https://artifactregistry.googleapis.com/v1/x", nil, ""); err == nil {
		t.Fatal("do() error = nil, want credential error")
	}

	store.transport.token = staticToken("")
	if _, _, err := store.transport.do(context.Background(), http.MethodGet, "https://artifactregistry.googleapis.com/v1/x", nil, ""); err == nil {
		t.Fatal("do() error = nil, want empty credential error")
	}

	store.transport.token = staticToken("token")
	if _, _, err := store.transport.do(context.Background(), http.MethodGet, "https://exa\nmple.com", nil, ""); err == nil {
		t.Fatal("do() error = nil, want request build error")
	}

	store.transport.doer = doerFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("reset")
	})
	if _, _, err := store.transport.do(context.Background(), http.MethodGet, "https://artifactregistry.googleapis.com/v1/x", nil, ""); err == nil {
		t.Fatal("do() error = nil, want transport error")
	}

	store.transport.doer = doerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{Status: "200 OK", StatusCode: 200, Body: io.NopCloser(&failingReader{})}, nil
	})
	if _, _, err := store.transport.do(context.Background(), http.MethodGet, "https://artifactregistry.googleapis.com/v1/x", nil, ""); err == nil {
		t.Fatal("do() error = nil, want read error")
	}
}

type failingReader struct{}

func (*failingReader) Read([]byte) (int, error) {
	return 0, errors.New("mid-stream failure")
}

func TestTransportDoCarriesTheRequestContract(t *testing.T) {
	var gotAuth, gotContentType, gotBody string
	store := newTestStore(t, doerFunc(func(req *http.Request) (*http.Response, error) {
		gotAuth = req.Header.Get("Authorization")
		gotContentType = req.Header.Get("Content-Type")
		content, _ := io.ReadAll(req.Body)
		gotBody = string(content)
		return okResponse(`{"ok": true}`), nil
	}))
	body, status, err := store.transport.do(context.Background(), http.MethodPost, "https://artifactregistry.googleapis.com/v1/x", []byte("payload"), "application/json")
	if err != nil {
		t.Fatalf("do() error = %v", err)
	}
	if status != 200 || string(body) != `{"ok": true}` {
		t.Fatalf("do() = %q, %d", body, status)
	}
	if gotAuth != "Bearer token" || gotContentType != "application/json" || gotBody != "payload" {
		t.Fatalf("request = %q %q %q", gotAuth, gotContentType, gotBody)
	}
}

func TestRecordAppendsTheEvidenceDocument(t *testing.T) {
	var gotURL, gotBody string
	store := newTestStore(t, doerFunc(func(req *http.Request) (*http.Response, error) {
		gotURL = req.URL.String()
		content, _ := io.ReadAll(req.Body)
		gotBody = string(content)
		return okResponse(`{"operation": {"name": "operations/1"}}`), nil
	}))

	reference := testReference(t, evidence.TypeScan, "scans/1", evidenceTime)
	if err := store.Record(context.Background(), testCandidate(t), reference); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	if !strings.Contains(gotURL, "https://artifactregistry.googleapis.com/upload/v1/projects/p/locations/l/repositories/r/genericArtifacts:create") {
		t.Fatalf("upload URL = %q, want the create surface", gotURL)
	}
	for _, fragment := range []string{
		`"schema":"dependency-authority/evidence-record/v1"`,
		`"ecosystem":"go"`,
		`"name":"example.com/mod"`,
		`"version":"v1.0.0"`,
		`"type":"scan"`,
		`"reference":"scans/1"`,
		`"expires_at":"2026-08-20T13:00:00Z"`,
	} {
		if !strings.Contains(gotBody, fragment) {
			t.Fatalf("evidence document misses %q", fragment)
		}
	}
}

func TestRecordPropagatesUploadFailures(t *testing.T) {
	store := newTestStore(t, doerFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("repository unavailable")
	}))
	if err := store.Record(context.Background(), testCandidate(t), testReference(t, evidence.TypeScan, "scans/1", evidenceTime)); err == nil {
		t.Fatal("Record() error = nil, want upload error")
	}

	store = newTestStore(t, doerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{Status: "500 Internal Server Error", StatusCode: 500, Body: io.NopCloser(strings.NewReader(""))}, nil
	}))
	if err := store.Record(context.Background(), testCandidate(t), testReference(t, evidence.TypeScan, "scans/1", evidenceTime)); err == nil {
		t.Fatal("Record() error = nil, want status error")
	}

	store = newTestStore(t, doerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{Status: "409 Conflict", StatusCode: 409, Body: io.NopCloser(strings.NewReader(""))}, nil
	}))
	if err := store.Record(context.Background(), testCandidate(t), testReference(t, evidence.TypeScan, "scans/1", evidenceTime)); err != nil {
		t.Fatalf("Record() error = %v, want idempotent success", err)
	}
}

// evidenceServer fakes the generic-artifact read surface of the evidence
// index: paginated file lists and content downloads.
type evidenceServer struct {
	t          *testing.T
	documents  map[string]string
	names      []string
	owner      string
	listStatus int
}

func newEvidenceServer(t *testing.T) *evidenceServer {
	t.Helper()
	return &evidenceServer{t: t, documents: make(map[string]string)}
}

func (s *evidenceServer) do(req *http.Request) (*http.Response, error) {
	if idx := strings.Index(req.URL.Path, ":download"); idx >= 0 {
		name := strings.TrimPrefix(strings.TrimSuffix(req.URL.Path, ":download"), "/v1/")
		content, found := s.documents[name]
		if !found {
			return &http.Response{Status: "404", StatusCode: 404, Body: io.NopCloser(strings.NewReader(""))}, nil
		}
		return okResponse(content), nil
	}
	if s.listStatus != 0 {
		return &http.Response{Status: "500", StatusCode: s.listStatus, Body: io.NopCloser(strings.NewReader(""))}, nil
	}
	entries := make([]string, 0, len(s.names))
	for _, name := range s.names {
		entries = append(entries, fmt.Sprintf(`{"name": %q, "owner": %q, "createTime": "2026-08-20T10:00:00Z"}`, name, s.owner))
	}
	return okResponse(`{"files": [` + strings.Join(entries, ",") + `]}`), nil
}

// serve stores the evidence document of the given reference as a listed file.
func (s *evidenceServer) serve(t *testing.T, subject candidate.Candidate, reference evidence.Reference) {
	t.Helper()
	document := recordDocument{
		Schema:    recordSchema,
		Ecosystem: string(subject.Ecosystem()),
		Name:      subject.Name(),
		Version:   subject.Version(),
		Reference: referenceToDocument(reference),
	}
	content, _ := json.Marshal(document)
	pkg := indexPackage(subject)
	name := "projects/p/locations/l/repositories/r/files/" + pkg + ":v1:doc-" + fmt.Sprint(len(s.names)) + ".json"
	s.documents[name] = string(content)
	s.names = append(s.names, name)
	s.owner = "projects/p/locations/l/repositories/r/packages/" + pkg + "/versions/v1"
}

// serveRaw stores a raw document payload as a listed file.
func (s *evidenceServer) serveRaw(subject candidate.Candidate, content string) {
	pkg := indexPackage(subject)
	name := "projects/p/locations/l/repositories/r/files/" + pkg + ":v1:raw-" + fmt.Sprint(len(s.names)) + ".json"
	s.documents[name] = content
	s.names = append(s.names, name)
	s.owner = "projects/p/locations/l/repositories/r/packages/" + pkg + "/versions/v1"
}

func TestEvidenceReturnsAnEmptyTrailForUnknownCandidates(t *testing.T) {
	server := newEvidenceServer(t)
	store := newTestStore(t, doerFunc(server.do))
	references, err := store.Evidence(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("Evidence() error = %v", err)
	}
	if len(references) != 0 {
		t.Fatalf("Evidence() = %v, want an empty trail", references)
	}
}

func TestEvidencePropagatesListAndDownloadFailures(t *testing.T) {
	server := newEvidenceServer(t)
	server.listStatus = 500
	store := newTestStore(t, doerFunc(server.do))
	if _, err := store.Evidence(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0"); err == nil {
		t.Fatal("Evidence() error = nil, want list error")
	}

	server = newEvidenceServer(t)
	server.listStatus = 0
	server.names = []string{"projects/p/locations/l/repositories/r/files/pkg:v1:missing.json"}
	server.owner = "projects/p/locations/l/repositories/r/packages/" + indexPackageIdentity(candidate.EcosystemGo, "example.com/mod", "v1.0.0") + "/versions/v1"
	store = newTestStore(t, doerFunc(server.do))
	if _, err := store.Evidence(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0"); err == nil {
		t.Fatal("Evidence() error = nil, want download error")
	}
}

func TestEvidenceRejectsCorruptRecords(t *testing.T) {
	subject := testCandidate(t)
	for name, content := range map[string]string{
		"malformed json": `{`,
		"unknown schema": `{"schema":"other/v9","ecosystem":"go","name":"example.com/mod","version":"v1.0.0","reference":{"type":"scan","reference":"scans/1","digest":"` + evidenceDigest + `","issuer":"issuer","issued_at":"2026-08-20T12:00:00Z","expires_at":null}}`,
		"foreign record": `{"schema":"dependency-authority/evidence-record/v1","ecosystem":"go","name":"example.com/other","version":"v1.0.0","reference":{"type":"scan","reference":"scans/1","digest":"` + evidenceDigest + `","issuer":"issuer","issued_at":"2026-08-20T12:00:00Z","expires_at":null}}`,
		"invalid digest": `{"schema":"dependency-authority/evidence-record/v1","ecosystem":"go","name":"example.com/mod","version":"v1.0.0","reference":{"type":"scan","reference":"scans/1","digest":"sha256:zz","issuer":"issuer","issued_at":"2026-08-20T12:00:00Z","expires_at":null}}`,
		"invalid issued": `{"schema":"dependency-authority/evidence-record/v1","ecosystem":"go","name":"example.com/mod","version":"v1.0.0","reference":{"type":"scan","reference":"scans/1","digest":"` + evidenceDigest + `","issuer":"issuer","issued_at":"not-a-time","expires_at":null}}`,
		"invalid expiry": `{"schema":"dependency-authority/evidence-record/v1","ecosystem":"go","name":"example.com/mod","version":"v1.0.0","reference":{"type":"scan","reference":"scans/1","digest":"` + evidenceDigest + `","issuer":"issuer","issued_at":"2026-08-20T12:00:00Z","expires_at":"not-a-time"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			server := newEvidenceServer(t)
			server.serveRaw(subject, content)
			store := newTestStore(t, doerFunc(server.do))
			if _, err := store.Evidence(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0"); err == nil {
				t.Fatal("Evidence() error = nil, want corrupt record error")
			}
		})
	}
}

func TestEvidenceLoadsTheSortedTrail(t *testing.T) {
	server := newEvidenceServer(t)
	store := newTestStore(t, doerFunc(server.do))
	subject := testCandidate(t)

	latest := testReference(t, evidence.TypeScan, "scans/2", evidenceTime.Add(time.Hour))
	middle := testReference(t, evidence.TypeSBOM, "sboms/1", evidenceTime)
	earliestTieA := testReference(t, evidence.TypeScan, "scans/1", evidenceTime)
	earliestTieB, err := evidence.NewReference(evidence.TypeQuality, "scans/1", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "issuer", evidenceTime, nil)
	if err != nil {
		t.Fatalf("NewReference() error = %v", err)
	}

	server.serve(t, subject, latest)
	server.serve(t, subject, earliestTieB)
	server.serve(t, subject, middle)
	server.serve(t, subject, earliestTieA)

	references, err := store.Evidence(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("Evidence() error = %v", err)
	}
	if len(references) != 4 {
		t.Fatalf("Evidence() = %d entries, want 4", len(references))
	}
	order := []string{
		string(references[0].Type()) + "/" + references[0].Reference(),
		string(references[1].Type()) + "/" + references[1].Reference(),
		string(references[2].Type()) + "/" + references[2].Reference(),
		string(references[3].Type()) + "/" + references[3].Reference(),
	}
	want := []string{"sbom/sboms/1", "scan/scans/1", "quality/scans/1", "scan/scans/2"}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("Evidence() order = %v, want %v", order, want)
		}
	}
}

func TestTransportListPaginatesAndFilters(t *testing.T) {
	requests := make([]string, 0)
	store := newTestStore(t, doerFunc(func(req *http.Request) (*http.Response, error) {
		requests = append(requests, req.URL.String())
		if strings.Contains(req.URL.RawQuery, "pageToken=two") {
			return okResponse(`{"files": [
				{"name": "projects/p/locations/l/repositories/r/files/pkg:v1:b.json", "owner": "projects/p/locations/l/repositories/r/packages/pkg/versions/v1"},
				{"name": "projects/p/locations/l/repositories/r/files/other:v1:c.json", "owner": "projects/p/locations/l/repositories/r/packages/other/versions/v1"}
			]}`), nil
		}
		return okResponse(`{"files": [
			{"name": "projects/p/locations/l/repositories/r/files/pkg:v1:a.json", "owner": "projects/p/locations/l/repositories/r/packages/pkg/versions/v1"}
		], "nextPageToken": "two"}`), nil
	}))

	files, err := store.transport.list(context.Background(), "projects/p/locations/l/repositories/r", "pkg", "v1")
	if err != nil {
		t.Fatalf("list() error = %v", err)
	}
	if len(files) != 2 || files[0].Name != "projects/p/locations/l/repositories/r/files/pkg:v1:a.json" || files[1].Name != "projects/p/locations/l/repositories/r/files/pkg:v1:b.json" {
		t.Fatalf("list() = %v, want the two owned files", files)
	}
	if len(requests) != 2 || !strings.Contains(requests[1], "pageToken=two") {
		t.Fatalf("list requests = %v, want the paginated sequence", requests)
	}
}

func TestTransportDownloadFailures(t *testing.T) {
	store := newTestStore(t, doerFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("reset")
	}))
	if _, err := store.transport.download(context.Background(), "x"); err == nil {
		t.Fatal("download() error = nil, want transport error")
	}

	store = newTestStore(t, doerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{Status: "404 Not Found", StatusCode: 404, Body: io.NopCloser(strings.NewReader(""))}, nil
	}))
	if _, err := store.transport.download(context.Background(), "x"); err == nil {
		t.Fatal("download() error = nil, want status error")
	}
}

func TestTransportListFailures(t *testing.T) {
	store := newTestStore(t, doerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{Status: "403 Forbidden", StatusCode: 403, Body: io.NopCloser(strings.NewReader(""))}, nil
	}))
	if _, err := store.transport.list(context.Background(), "projects/p/locations/l/repositories/r", "pkg", "v1"); err == nil {
		t.Fatal("list() error = nil, want status error")
	}

	store = newTestStore(t, doerFunc(func(*http.Request) (*http.Response, error) {
		return okResponse(`{`), nil
	}))
	if _, err := store.transport.list(context.Background(), "projects/p/locations/l/repositories/r", "pkg", "v1"); err == nil {
		t.Fatal("list() error = nil, want decode error")
	}

	store = newTestStore(t, doerFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("reset")
	}))
	if _, err := store.transport.list(context.Background(), "projects/p/locations/l/repositories/r", "pkg", "v1"); err == nil {
		t.Fatal("list() error = nil, want transport error")
	}
}

func TestPutRejectsAnEmptyPayload(t *testing.T) {
	store := newTestStore(t, doerFunc(func(*http.Request) (*http.Response, error) {
		return okResponse(`{}`), nil
	}))
	if _, err := store.Put(context.Background(), testCandidate(t), evidence.TypeScan, "issuer", nil, evidenceTime, nil); err == nil {
		t.Fatal("Put() error = nil, want empty payload error")
	}
}

func TestPutPublishesThePayloadAndBindsTheReference(t *testing.T) {
	var gotURL, gotBody string
	store := newTestStore(t, doerFunc(func(req *http.Request) (*http.Response, error) {
		gotURL = req.URL.String()
		content, _ := io.ReadAll(req.Body)
		gotBody = string(content)
		return okResponse(`{"operation": {"name": "operations/1"}}`), nil
	}))

	payload := []byte(`{"schema":"dependency-authority/scan-evidence/v1"}`)
	expiry := evidenceTime.Add(time.Hour)
	reference, err := store.Put(context.Background(), testCandidate(t), evidence.TypeScan, "osv-scanner 2.2.3", payload, evidenceTime, &expiry)
	if err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	sum := sha256.Sum256(payload)
	wantDigest := "sha256:" + hex.EncodeToString(sum[:])
	if reference.Digest() != wantDigest {
		t.Fatalf("Put() digest = %q, want %q", reference.Digest(), wantDigest)
	}
	identitySum := sha256.Sum256([]byte("go\nexample.com/mod\nv1.0.0"))
	wantPackage := "evidence-payloads-" + hex.EncodeToString(identitySum[:])[:24]
	wantLocator := "evidence://projects/p/locations/l/repositories/r/" + wantPackage + "/v1/" + hex.EncodeToString(sum[:]) + ".json"
	if reference.Reference() != wantLocator {
		t.Fatalf("Put() locator = %q, want %q", reference.Reference(), wantLocator)
	}
	if reference.Type() != evidence.TypeScan || reference.Issuer() != "osv-scanner 2.2.3" {
		t.Fatalf("Put() reference = %q %q", reference.Type(), reference.Issuer())
	}
	if !reference.IssuedAt().Equal(evidenceTime) {
		t.Fatalf("Put() issued-at = %v", reference.IssuedAt())
	}
	if expiresAt, ok := reference.ExpiresAt(); !ok || !expiresAt.Equal(expiry) {
		t.Fatalf("Put() expires-at = %v, %v", expiresAt, ok)
	}
	if !strings.Contains(gotURL, "/upload/v1/projects/p/locations/l/repositories/r/genericArtifacts:create") {
		t.Fatalf("Put() upload URL = %q", gotURL)
	}
	if !strings.Contains(gotBody, "evidence-payloads-") || !strings.Contains(gotBody, string(payload)) {
		t.Fatalf("Put() upload body misses the payload package or content: %q", gotBody)
	}
}

func TestPutWithoutExpiryLeavesTheReferenceOpen(t *testing.T) {
	store := newTestStore(t, doerFunc(func(*http.Request) (*http.Response, error) {
		return okResponse(`{}`), nil
	}))
	reference, err := store.Put(context.Background(), testCandidate(t), evidence.TypePolicy, "issuer", []byte(`{"ok":true}`), evidenceTime, nil)
	if err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	if _, ok := reference.ExpiresAt(); ok {
		t.Fatal("Put() expires-at present, want an open reference")
	}
}

func TestPutPropagatesUploadFailures(t *testing.T) {
	store := newTestStore(t, doerFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("repository unavailable")
	}))
	if _, err := store.Put(context.Background(), testCandidate(t), evidence.TypeScan, "issuer", []byte(`{"ok":true}`), evidenceTime, nil); err == nil {
		t.Fatal("Put() error = nil, want upload error")
	}

	store = newTestStore(t, doerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{Status: "500 Internal Server Error", StatusCode: 500, Body: io.NopCloser(strings.NewReader(""))}, nil
	}))
	if _, err := store.Put(context.Background(), testCandidate(t), evidence.TypeScan, "issuer", []byte(`{"ok":true}`), evidenceTime, nil); err == nil {
		t.Fatal("Put() error = nil, want status error")
	}

	store = newTestStore(t, doerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{Status: "409 Conflict", StatusCode: 409, Body: io.NopCloser(strings.NewReader(""))}, nil
	}))
	if _, err := store.Put(context.Background(), testCandidate(t), evidence.TypeScan, "issuer", []byte(`{"ok":true}`), evidenceTime, nil); err != nil {
		t.Fatalf("Put() error = %v, want idempotent success", err)
	}
}

func TestPutPropagatesReferenceValidation(t *testing.T) {
	store := newTestStore(t, doerFunc(func(*http.Request) (*http.Response, error) {
		return okResponse(`{}`), nil
	}))
	if _, err := store.Put(context.Background(), testCandidate(t), evidence.Type("bogus"), "issuer", []byte(`{"ok":true}`), evidenceTime, nil); err == nil {
		t.Fatal("Put() error = nil, want unknown evidence type error")
	}

	expired := evidenceTime.Add(-time.Hour)
	if _, err := store.Put(context.Background(), testCandidate(t), evidence.TypeScan, "issuer", []byte(`{"ok":true}`), evidenceTime, &expired); err == nil {
		t.Fatal("Put() error = nil, want expiry ordering error")
	}
}
