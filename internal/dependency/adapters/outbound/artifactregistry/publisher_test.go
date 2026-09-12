package artifactregistry

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/t33n-software/dependency-authority/internal/dependency/domain/candidate"
	"github.com/t33n-software/dependency-authority/internal/dependency/domain/evidence"
)

const publisherDigestPrefix = "sha256:"

var archiveContent = map[string]string{
	"go.mod": "module example.com/mod\n\ngo 1.26\n",
	"mod.go": "package mod\n",
}

// moduleZip builds a deterministic in-memory Go module archive.
func moduleZip(t *testing.T, prefix string, files map[string]string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	for i := 0; i < len(names); i++ {
		for j := i + 1; j < len(names); j++ {
			if names[j] < names[i] {
				names[i], names[j] = names[j], names[i]
			}
		}
	}
	for _, name := range names {
		entry, err := writer.Create(prefix + name)
		if err != nil {
			t.Fatalf("create zip entry: %v", err)
		}
		if _, err := entry.Write([]byte(files[name])); err != nil {
			t.Fatalf("write zip entry: %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buffer.Bytes()
}

func digestOf(content []byte) string {
	sum := sha256.Sum256(content)
	return publisherDigestPrefix + hex.EncodeToString(sum[:])
}

// publisherFixture binds a fake transport that serves the intake and approved
// archives by host and the module upload and upload-operation reads of the
// Artifact Registry API surface. The approved host reports the module as
// absent until an upload landed, unless approvedPresent binds the already
// published form.
type publisherFixture struct {
	intakeArchive   []byte
	approvedArchive []byte
	approvedPresent bool
	intakeStatus    int
	approvedStatus  int
	transportErr    error
	uploadErr       error
	uploadStatus    int
	uploadBody      string
	operationErr    error
	operationStatus int
	operationBody   string
	pendingPolls    int

	uploads           int
	uploadURL         string
	uploadContentType string
	uploadContent     []byte
	polls             int
	pollURLs          []string
}

func (f *publisherFixture) do(req *http.Request) (*http.Response, error) {
	if f.transportErr != nil {
		return nil, f.transportErr
	}
	switch req.URL.Host {
	case "intake.example.com":
		if f.intakeStatus != 0 {
			return &http.Response{Status: "intake failure", StatusCode: f.intakeStatus, Body: io.NopCloser(strings.NewReader(""))}, nil
		}
		return okResponse(string(f.intakeArchive)), nil
	case "approved.example.com":
		if !f.approvedPresent && f.uploads == 0 {
			return &http.Response{Status: "404 Not Found", StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader(""))}, nil
		}
		if f.approvedStatus != 0 {
			return &http.Response{Status: "approved failure", StatusCode: f.approvedStatus, Body: io.NopCloser(strings.NewReader(""))}, nil
		}
		return okResponse(string(f.approvedArchive)), nil
	case "artifactregistry.googleapis.com":
		if req.Method == http.MethodPost {
			f.uploads++
			f.uploadURL = req.URL.String()
			f.uploadContentType = req.Header.Get("Content-Type")
			content, _ := io.ReadAll(req.Body)
			f.uploadContent = content
			if f.uploadErr != nil {
				return nil, f.uploadErr
			}
			if f.uploadStatus != 0 {
				return &http.Response{Status: "upload failure", StatusCode: f.uploadStatus, Body: io.NopCloser(strings.NewReader(""))}, nil
			}
			body := f.uploadBody
			if body == "" {
				body = `{"operation":{"name":"projects/p/locations/l/operations/op-1"}}`
			}
			return okResponse(body), nil
		}
		f.polls++
		f.pollURLs = append(f.pollURLs, req.URL.String())
		if f.operationErr != nil {
			return nil, f.operationErr
		}
		if f.operationStatus != 0 {
			return &http.Response{Status: "operation failure", StatusCode: f.operationStatus, Body: io.NopCloser(strings.NewReader(""))}, nil
		}
		if f.polls <= f.pendingPolls {
			return okResponse(`{"name":"projects/p/locations/l/operations/op-1","done":false}`), nil
		}
		body := f.operationBody
		if body == "" {
			body = `{"name":"projects/p/locations/l/operations/op-1","done":true,"response":{}}`
		}
		return okResponse(body), nil
	default:
		return nil, errors.New("unexpected host " + req.URL.Host)
	}
}

func tempFactory(t *testing.T) func() (string, func(), error) {
	t.Helper()
	return func() (string, func(), error) {
		return t.TempDir(), func() {}, nil
	}
}

func failingTempFactory() (string, func(), error) {
	return "", nil, errors.New("no workspace")
}

func newPublisher(t *testing.T, doer Doer) Publisher {
	t.Helper()
	publisher, err := NewPublisher(
		newTestClient(t, doer),
		"https://intake.example.com/p/r",
		"https://approved.example.com/p/r",
		"projects/p/locations/l/repositories/r",
		tempFactory(t),
	)
	if err != nil {
		t.Fatalf("NewPublisher() error = %v", err)
	}
	return publisher
}

func publishableCandidate(t *testing.T, archive []byte) candidate.Candidate {
	t.Helper()
	subject, err := candidate.New(candidate.EcosystemGo, "example.com/mod", "v1.0.0", digestOf(archive))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return subject
}

func TestNewPublisherValidatesConfiguration(t *testing.T) {
	client := newTestClient(t, http.DefaultClient)
	for _, tc := range []struct {
		name     string
		intake   string
		approved string
		repo     string
	}{
		{"empty intake", " ", "https://approved.example.com", "projects/p/locations/l/repositories/r"},
		{"unparseable intake", "ht tp://x", "https://approved.example.com", "projects/p/locations/l/repositories/r"},
		{"hostless intake", "https://", "https://approved.example.com", "projects/p/locations/l/repositories/r"},
		{"plaintext intake", "http://intake.example.com", "https://approved.example.com", "projects/p/locations/l/repositories/r"},
		{"empty approved", "https://intake.example.com", "", "projects/p/locations/l/repositories/r"},
		{"plaintext approved", "https://intake.example.com", "http://approved.example.com", "projects/p/locations/l/repositories/r"},
		{"invalid repository", "https://intake.example.com", "https://approved.example.com", "bogus"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewPublisher(client, tc.intake, tc.approved, tc.repo, tempFactory(t)); err == nil {
				t.Fatal("NewPublisher() error = nil, want error")
			}
		})
	}
	if _, err := NewPublisher(client, "https://intake.example.com", "https://approved.example.com", "projects/p/locations/l/repositories/r", nil); err == nil {
		t.Fatal("NewPublisher( nil temp dir ) error = nil, want error")
	}
}

func TestPublishProvesContentIdentityEndToEnd(t *testing.T) {
	archive := moduleZip(t, "example.com/mod@v1.0.0/", archiveContent)
	fixture := &publisherFixture{intakeArchive: archive, approvedArchive: archive}
	publisher := newPublisher(t, doerFunc(fixture.do))

	subject := publishableCandidate(t, archive)
	if err := publisher.Publish(context.Background(), subject, []evidence.Reference{}); err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	if fixture.uploads != 1 {
		t.Fatalf("uploads = %d, want 1", fixture.uploads)
	}
	wantURL := "https://artifactregistry.googleapis.com/upload/v1/projects/p/locations/l/repositories/r/goModules:create?uploadType=multipart"
	if fixture.uploadURL != wantURL {
		t.Fatalf("upload URL = %q, want %q", fixture.uploadURL, wantURL)
	}
	if !strings.HasPrefix(fixture.uploadContentType, "multipart/related; boundary=") {
		t.Fatalf("upload content type = %q, want the multipart/related form", fixture.uploadContentType)
	}
	if !bytes.Contains(fixture.uploadContent, []byte("application/json")) || !bytes.Contains(fixture.uploadContent, []byte(`{}`)) {
		t.Fatal("the upload body misses the empty JSON metadata part")
	}
	if !bytes.Contains(fixture.uploadContent, archive) {
		t.Fatal("the upload body does not carry the proven module archive")
	}
	if fixture.polls != 1 {
		t.Fatalf("polls = %d, want 1", fixture.polls)
	}
	wantPoll := "https://artifactregistry.googleapis.com/v1/projects/p/locations/l/operations/op-1"
	if fixture.pollURLs[0] != wantPoll {
		t.Fatalf("poll URL = %q, want %q", fixture.pollURLs[0], wantPoll)
	}
}

func TestPublishRejectsIntakeDigestDrift(t *testing.T) {
	archive := moduleZip(t, "example.com/mod@v1.0.0/", archiveContent)
	drifted := moduleZip(t, "example.com/mod@v1.0.0/", map[string]string{"go.mod": "module example.com/mod\n"})
	publisher := newPublisher(t, doerFunc((&publisherFixture{intakeArchive: archive}).do))

	subject := publishableCandidate(t, drifted)
	if err := publisher.Publish(context.Background(), subject, nil); err == nil {
		t.Fatal("Publish() error = nil, want digest drift error")
	}
}

func TestPublishIntakeFetchFailures(t *testing.T) {
	archive := moduleZip(t, "example.com/mod@v1.0.0/", archiveContent)
	subject := publishableCandidate(t, archive)

	publisher := newPublisher(t, doerFunc((&publisherFixture{intakeStatus: http.StatusNotFound}).do))
	if err := publisher.Publish(context.Background(), subject, nil); err == nil {
		t.Fatal("Publish() error = nil, want intake not-found error")
	}

	publisher = newPublisher(t, doerFunc((&publisherFixture{intakeStatus: http.StatusInternalServerError}).do))
	if err := publisher.Publish(context.Background(), subject, nil); err == nil {
		t.Fatal("Publish() error = nil, want intake status error")
	}

	publisher = newPublisher(t, doerFunc((&publisherFixture{transportErr: errors.New("reset")}).do))
	if err := publisher.Publish(context.Background(), subject, nil); err == nil {
		t.Fatal("Publish() error = nil, want intake transport error")
	}
}

func TestPublishRejectsCorruptModuleArchive(t *testing.T) {
	corrupt := []byte("not a zip")
	publisher := newPublisher(t, doerFunc((&publisherFixture{intakeArchive: corrupt}).do))
	subject := publishableCandidate(t, corrupt)
	if err := publisher.Publish(context.Background(), subject, nil); err == nil {
		t.Fatal("Publish() error = nil, want archive error")
	}
}

func TestPublishPropagatesWorkspaceFailure(t *testing.T) {
	archive := moduleZip(t, "example.com/mod@v1.0.0/", archiveContent)
	publisher, err := NewPublisher(
		newTestClient(t, doerFunc((&publisherFixture{intakeArchive: archive}).do)),
		"https://intake.example.com/p/r",
		"https://approved.example.com/p/r",
		"projects/p/locations/l/repositories/r",
		failingTempFactory,
	)
	if err != nil {
		t.Fatalf("NewPublisher() error = %v", err)
	}
	subject := publishableCandidate(t, archive)
	if err := publisher.Publish(context.Background(), subject, nil); err == nil {
		t.Fatal("Publish() error = nil, want workspace error")
	}
}

func TestPublishUploadFailures(t *testing.T) {
	archive := moduleZip(t, "example.com/mod@v1.0.0/", archiveContent)
	subject := publishableCandidate(t, archive)

	t.Run("transport error", func(t *testing.T) {
		fixture := &publisherFixture{intakeArchive: archive, uploadErr: errors.New("reset")}
		publisher := newPublisher(t, doerFunc(fixture.do))
		if err := publisher.Publish(context.Background(), subject, nil); err == nil {
			t.Fatal("Publish() error = nil, want upload transport error")
		}
	})

	t.Run("status error", func(t *testing.T) {
		fixture := &publisherFixture{intakeArchive: archive, uploadStatus: http.StatusInternalServerError}
		publisher := newPublisher(t, doerFunc(fixture.do))
		if err := publisher.Publish(context.Background(), subject, nil); err == nil {
			t.Fatal("Publish() error = nil, want upload status error")
		}
	})

	t.Run("malformed operation response", func(t *testing.T) {
		fixture := &publisherFixture{intakeArchive: archive, uploadBody: `{`}
		publisher := newPublisher(t, doerFunc(fixture.do))
		if err := publisher.Publish(context.Background(), subject, nil); err == nil {
			t.Fatal("Publish() error = nil, want operation decode error")
		}
	})

	t.Run("missing operation name", func(t *testing.T) {
		fixture := &publisherFixture{intakeArchive: archive, uploadBody: `{"operation":{}}`}
		publisher := newPublisher(t, doerFunc(fixture.do))
		if err := publisher.Publish(context.Background(), subject, nil); err == nil {
			t.Fatal("Publish() error = nil, want operation name error")
		}
	})
}

func TestPublishAwaitsTheUploadOperation(t *testing.T) {
	archive := moduleZip(t, "example.com/mod@v1.0.0/", archiveContent)
	fixture := &publisherFixture{intakeArchive: archive, approvedArchive: archive, pendingPolls: 2}
	publisher := newPublisher(t, doerFunc(fixture.do))
	subject := publishableCandidate(t, archive)

	original := awaitPoll
	awaitPoll = func(context.Context) error { return nil }
	t.Cleanup(func() { awaitPoll = original })

	if err := publisher.Publish(context.Background(), subject, nil); err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	if fixture.polls != 3 {
		t.Fatalf("polls = %d, want 3 (two pending reads and the completed read)", fixture.polls)
	}
}

func TestPublishUploadOperationFailures(t *testing.T) {
	archive := moduleZip(t, "example.com/mod@v1.0.0/", archiveContent)
	subject := publishableCandidate(t, archive)

	original := awaitPoll
	awaitPoll = func(context.Context) error { return nil }
	t.Cleanup(func() { awaitPoll = original })

	t.Run("poll transport error", func(t *testing.T) {
		fixture := &publisherFixture{intakeArchive: archive, operationErr: errors.New("reset")}
		publisher := newPublisher(t, doerFunc(fixture.do))
		if err := publisher.Publish(context.Background(), subject, nil); err == nil {
			t.Fatal("Publish() error = nil, want operation read error")
		}
	})

	t.Run("poll status error", func(t *testing.T) {
		fixture := &publisherFixture{intakeArchive: archive, operationStatus: http.StatusInternalServerError}
		publisher := newPublisher(t, doerFunc(fixture.do))
		if err := publisher.Publish(context.Background(), subject, nil); err == nil {
			t.Fatal("Publish() error = nil, want operation status error")
		}
	})

	t.Run("poll malformed operation", func(t *testing.T) {
		fixture := &publisherFixture{intakeArchive: archive, operationBody: `{`}
		publisher := newPublisher(t, doerFunc(fixture.do))
		if err := publisher.Publish(context.Background(), subject, nil); err == nil {
			t.Fatal("Publish() error = nil, want operation decode error")
		}
	})

	t.Run("operation error state", func(t *testing.T) {
		fixture := &publisherFixture{intakeArchive: archive, operationBody: `{"name":"projects/p/locations/l/operations/op-1","done":true,"error":{"code":13,"message":"broken"}}`}
		publisher := newPublisher(t, doerFunc(fixture.do))
		err := publisher.Publish(context.Background(), subject, nil)
		if err == nil {
			t.Fatal("Publish() error = nil, want operation error")
		}
		if errors.Is(err, errModuleAlreadyExists) {
			t.Fatalf("Publish() error = %v, want the non-ALREADY_EXISTS operation error to stay fail-closed", err)
		}
	})

	t.Run("poll budget exhausted", func(t *testing.T) {
		fixture := &publisherFixture{intakeArchive: archive, pendingPolls: maxUploadPolls + 1}
		publisher := newPublisher(t, doerFunc(fixture.do))
		if err := publisher.Publish(context.Background(), subject, nil); err == nil {
			t.Fatal("Publish() error = nil, want poll budget error")
		}
		if fixture.polls != maxUploadPolls {
			t.Fatalf("polls = %d, want the bounded %d", fixture.polls, maxUploadPolls)
		}
	})

	t.Run("wait seam failure", func(t *testing.T) {
		fixture := &publisherFixture{intakeArchive: archive, pendingPolls: 1}
		publisher := newPublisher(t, doerFunc(fixture.do))
		original := awaitPoll
		awaitPoll = func(context.Context) error { return errors.New("wait failed") }
		t.Cleanup(func() { awaitPoll = original })
		if err := publisher.Publish(context.Background(), subject, nil); err == nil {
			t.Fatal("Publish() error = nil, want wait error")
		}
	})
}

func TestAwaitPoll(t *testing.T) {
	t.Run("waits for the interval", func(t *testing.T) {
		original := pollInterval
		pollInterval = time.Nanosecond
		t.Cleanup(func() { pollInterval = original })
		if err := awaitPoll(context.Background()); err != nil {
			t.Fatalf("awaitPoll() error = %v", err)
		}
	})

	t.Run("honors cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := awaitPoll(ctx); err == nil {
			t.Fatal("awaitPoll() error = nil, want context error")
		}
	})
}

func TestPublishApprovedFetchFailure(t *testing.T) {
	archive := moduleZip(t, "example.com/mod@v1.0.0/", archiveContent)
	publisher := newPublisher(t, doerFunc((&publisherFixture{intakeArchive: archive, approvedStatus: http.StatusInternalServerError}).do))
	subject := publishableCandidate(t, archive)
	if err := publisher.Publish(context.Background(), subject, nil); err == nil {
		t.Fatal("Publish() error = nil, want approved fetch error")
	}
}

func TestPublishSkipsTheProvenExistingModule(t *testing.T) {
	archive := moduleZip(t, "example.com/mod@v1.0.0/", archiveContent)
	fixture := &publisherFixture{intakeArchive: archive, approvedArchive: archive, approvedPresent: true}
	publisher := newPublisher(t, doerFunc(fixture.do))

	subject := publishableCandidate(t, archive)
	if err := publisher.Publish(context.Background(), subject, []evidence.Reference{}); err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	if fixture.uploads != 0 {
		t.Fatalf("uploads = %d, want 0 (the proven existing content is a skip, never an overwrite)", fixture.uploads)
	}
	if fixture.polls != 0 {
		t.Fatalf("polls = %d, want 0 (no upload operation was started)", fixture.polls)
	}
}

func TestPublishRejectsTheDriftedExistingModule(t *testing.T) {
	archive := moduleZip(t, "example.com/mod@v1.0.0/", archiveContent)
	drifted := moduleZip(t, "example.com/mod@v1.0.0/", map[string]string{
		"go.mod":  "module example.com/mod\n\ngo 1.26\n",
		"mod.go":  "package mod\n",
		"evil.go": "package mod\n",
	})
	fixture := &publisherFixture{intakeArchive: archive, approvedArchive: drifted, approvedPresent: true}
	publisher := newPublisher(t, doerFunc(fixture.do))

	subject := publishableCandidate(t, archive)
	err := publisher.Publish(context.Background(), subject, nil)
	if err == nil {
		t.Fatal("Publish() error = nil, want the approved content digest anomaly")
	}
	if !strings.Contains(err.Error(), "does not match the candidate digest") {
		t.Fatalf("Publish() error = %v, want the approved content digest anomaly", err)
	}
	if fixture.uploads != 0 {
		t.Fatalf("uploads = %d, want 0 (the drifted existing content is never overwritten)", fixture.uploads)
	}
}

func TestPublishVerifyFirstReadFailure(t *testing.T) {
	archive := moduleZip(t, "example.com/mod@v1.0.0/", archiveContent)
	fixture := &publisherFixture{intakeArchive: archive, approvedPresent: true, approvedStatus: http.StatusInternalServerError}
	publisher := newPublisher(t, doerFunc(fixture.do))

	subject := publishableCandidate(t, archive)
	if err := publisher.Publish(context.Background(), subject, nil); err == nil {
		t.Fatal("Publish() error = nil, want the verify-first read failure")
	}
	if fixture.uploads != 0 {
		t.Fatalf("uploads = %d, want 0 (a publication never happens against an unread target state)", fixture.uploads)
	}
}

func TestPublishAlreadyExistsRace(t *testing.T) {
	archive := moduleZip(t, "example.com/mod@v1.0.0/", archiveContent)
	subject := publishableCandidate(t, archive)
	operationError := `{"name":"projects/p/locations/l/operations/op-1","done":true,"error":{"code":6,"message":"Requested entity already exists"}}`

	t.Run("matching raced content completes the proof", func(t *testing.T) {
		fixture := &publisherFixture{intakeArchive: archive, approvedArchive: archive, operationBody: operationError}
		publisher := newPublisher(t, doerFunc(fixture.do))
		if err := publisher.Publish(context.Background(), subject, nil); err != nil {
			t.Fatalf("Publish() error = %v, want the race guard to complete the content proof", err)
		}
		if fixture.uploads != 1 {
			t.Fatalf("uploads = %d, want 1", fixture.uploads)
		}
	})

	t.Run("drifted raced content fails closed", func(t *testing.T) {
		drifted := moduleZip(t, "example.com/mod@v1.0.0/", map[string]string{"go.mod": "module example.com/mod\n"})
		fixture := &publisherFixture{intakeArchive: archive, approvedArchive: drifted, operationBody: operationError}
		publisher := newPublisher(t, doerFunc(fixture.do))
		err := publisher.Publish(context.Background(), subject, nil)
		if err == nil {
			t.Fatal("Publish() error = nil, want the raced content digest anomaly")
		}
		if !strings.Contains(err.Error(), "does not match the candidate digest") {
			t.Fatalf("Publish() error = %v, want the raced content digest anomaly", err)
		}
	})

	t.Run("the raced re-read failure fails closed", func(t *testing.T) {
		fixture := &publisherFixture{intakeArchive: archive, approvedStatus: http.StatusInternalServerError, operationBody: operationError}
		publisher := newPublisher(t, doerFunc(fixture.do))
		if err := publisher.Publish(context.Background(), subject, nil); err == nil {
			t.Fatal("Publish() error = nil, want the raced re-read failure")
		}
	})
}

func TestPublishPropagatesTheApprovedWorkspaceFailure(t *testing.T) {
	archive := moduleZip(t, "example.com/mod@v1.0.0/", archiveContent)
	calls := 0
	publisher, err := NewPublisher(
		newTestClient(t, doerFunc((&publisherFixture{intakeArchive: archive, approvedArchive: archive}).do)),
		"https://intake.example.com/p/r",
		"https://approved.example.com/p/r",
		"projects/p/locations/l/repositories/r",
		func() (string, func(), error) {
			calls++
			if calls > 1 {
				return "", nil, errors.New("no workspace")
			}
			return t.TempDir(), func() {}, nil
		},
	)
	if err != nil {
		t.Fatalf("NewPublisher() error = %v", err)
	}
	subject := publishableCandidate(t, archive)
	if err := publisher.Publish(context.Background(), subject, nil); err == nil {
		t.Fatal("Publish() error = nil, want the approved workspace failure")
	}
}

func TestPublishRejectsTheApprovedTreeMismatch(t *testing.T) {
	archive := moduleZip(t, "example.com/mod@v1.0.0/", archiveContent)
	fixture := &publisherFixture{intakeArchive: archive, approvedArchive: archive}
	publisher := newPublisher(t, doerFunc(fixture.do))
	subject := publishableCandidate(t, archive)

	original := readModuleFile
	t.Cleanup(func() { readModuleFile = original })
	reads := 0
	readModuleFile = func(name string) ([]byte, error) {
		reads++
		if reads >= 3 {
			return []byte("drifted"), nil
		}
		return os.ReadFile(name)
	}
	if err := publisher.Publish(context.Background(), subject, nil); err == nil {
		t.Fatal("Publish() error = nil, want the approved content identity mismatch")
	}
}

func TestModuleNotFoundError(t *testing.T) {
	err := &moduleNotFoundError{name: "example.com/mod", version: "v1.0.0", host: "approved.example.com"}
	if got := err.Error(); got != `module archive example.com/mod v1.0.0 not found at "approved.example.com"` {
		t.Fatalf("moduleNotFoundError.Error() = %q, want the proven absence form", got)
	}
}

func TestPublishRejectsPostPublicationMismatch(t *testing.T) {
	archive := moduleZip(t, "example.com/mod@v1.0.0/", archiveContent)
	mutated := moduleZip(t, "example.com/mod@v1.0.0/", map[string]string{
		"go.mod":  "module example.com/mod\n\ngo 1.26\n",
		"mod.go":  "package mod\n",
		"evil.go": "package mod\n",
	})
	publisher := newPublisher(t, doerFunc((&publisherFixture{intakeArchive: archive, approvedArchive: mutated}).do))
	subject := publishableCandidate(t, archive)
	if err := publisher.Publish(context.Background(), subject, nil); err == nil {
		t.Fatal("Publish() error = nil, want content identity mismatch error")
	}
}

func TestPublishApprovedArchiveCorrupt(t *testing.T) {
	archive := moduleZip(t, "example.com/mod@v1.0.0/", archiveContent)
	corrupt := []byte("not a zip")
	publisher := newPublisher(t, doerFunc((&publisherFixture{intakeArchive: archive, approvedArchive: corrupt}).do))
	subject := publishableCandidate(t, archive)
	if err := publisher.Publish(context.Background(), subject, nil); err == nil {
		t.Fatal("Publish() error = nil, want approved archive error")
	}
}

func TestPublishRejectsHashFailures(t *testing.T) {
	archive := moduleZip(t, "example.com/mod@v1.0.0/", archiveContent)
	subject := publishableCandidate(t, archive)

	t.Run("before publication", func(t *testing.T) {
		original := readModuleFile
		t.Cleanup(func() { readModuleFile = original })
		readModuleFile = func(string) ([]byte, error) {
			return nil, errors.New("read failure")
		}
		publisher := newPublisher(t, doerFunc((&publisherFixture{intakeArchive: archive}).do))
		if err := publisher.Publish(context.Background(), subject, nil); err == nil {
			t.Fatal("Publish() error = nil, want pre-publication hash error")
		}
	})

	t.Run("after publication", func(t *testing.T) {
		original := readModuleFile
		t.Cleanup(func() { readModuleFile = original })
		reads := 0
		readModuleFile = func(name string) ([]byte, error) {
			reads++
			if reads >= 3 {
				return nil, errors.New("read failure")
			}
			return os.ReadFile(name)
		}
		publisher := newPublisher(t, doerFunc((&publisherFixture{intakeArchive: archive, approvedArchive: archive}).do))
		if err := publisher.Publish(context.Background(), subject, nil); err == nil {
			t.Fatal("Publish() error = nil, want post-publication hash error")
		}
	})
}

// moduleZipWithDirectory builds an archive carrying an explicit directory
// entry before its files.
func moduleZipWithDirectory(t *testing.T, prefix string, dir string, files map[string]string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	if _, err := writer.Create(prefix + dir + "/"); err != nil {
		t.Fatalf("create directory entry: %v", err)
	}
	for name, content := range files {
		entry, err := writer.Create(prefix + name)
		if err != nil {
			t.Fatalf("create zip entry: %v", err)
		}
		if _, err := entry.Write([]byte(content)); err != nil {
			t.Fatalf("write zip entry: %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buffer.Bytes()
}

func TestExtractModuleDirectoryEntries(t *testing.T) {
	subject := publishableCandidate(t, moduleZip(t, "example.com/mod@v1.0.0/", archiveContent))
	archive := moduleZipWithDirectory(t, "example.com/mod@v1.0.0/", "sub", map[string]string{"sub/mod.go": "package mod\n"})
	root, err := extractModule(t.TempDir(), subject, archive)
	if err != nil {
		t.Fatalf("extractModule() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "sub", "mod.go")); err != nil {
		t.Fatalf("extracted file missing: %v", err)
	}
}

func TestExtractModuleDirectoryCreationFailures(t *testing.T) {
	subject := publishableCandidate(t, moduleZip(t, "example.com/mod@v1.0.0/", archiveContent))

	t.Run("directory entry", func(t *testing.T) {
		original := createModuleDir
		t.Cleanup(func() { createModuleDir = original })
		createModuleDir = func(string, os.FileMode) error {
			return errors.New("mkdir failure")
		}
		archive := moduleZipWithDirectory(t, "example.com/mod@v1.0.0/", "sub", map[string]string{"sub/mod.go": "package mod\n"})
		if _, err := extractModule(t.TempDir(), subject, archive); err == nil {
			t.Fatal("extractModule() error = nil, want directory creation error")
		}
	})

	t.Run("file parent", func(t *testing.T) {
		original := createModuleDir
		t.Cleanup(func() { createModuleDir = original })
		createModuleDir = func(string, os.FileMode) error {
			return errors.New("mkdir failure")
		}
		archive := moduleZip(t, "example.com/mod@v1.0.0/", map[string]string{"sub/mod.go": "package mod\n"})
		if _, err := extractModule(t.TempDir(), subject, archive); err == nil {
			t.Fatal("extractModule() error = nil, want directory creation error")
		}
	})
}

// orderedModuleZip builds an archive with the exact entry order given.
func orderedModuleZip(t *testing.T, entries ...string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for _, name := range entries {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatalf("create zip entry: %v", err)
		}
		if !strings.HasSuffix(name, "/") {
			if _, err := entry.Write([]byte("content")); err != nil {
				t.Fatalf("write zip entry: %v", err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buffer.Bytes()
}

func TestExtractModuleRejectsFileOverDirectory(t *testing.T) {
	subject := publishableCandidate(t, moduleZip(t, "example.com/mod@v1.0.0/", archiveContent))
	archive := orderedModuleZip(t, "example.com/mod@v1.0.0/x/", "example.com/mod@v1.0.0/x")
	if _, err := extractModule(t.TempDir(), subject, archive); err == nil {
		t.Fatal("extractModule() error = nil, want file-over-directory error")
	}
}

// corruptEntryMethod patches the central directory compression method of the
// first entry to an unsupported algorithm.
func corruptEntryMethod(t *testing.T, archive []byte) []byte {
	t.Helper()
	content := bytes.Clone(archive)
	index := bytes.Index(content, []byte("PK\x01\x02"))
	if index < 0 {
		t.Fatal("archive carries no central directory")
	}
	content[index+10] = 99
	content[index+11] = 0
	return content
}

func TestExtractModuleRejectsUnsupportedEntryMethod(t *testing.T) {
	archive := moduleZip(t, "example.com/mod@v1.0.0/", archiveContent)
	subject := publishableCandidate(t, archive)
	if _, err := extractModule(t.TempDir(), subject, corruptEntryMethod(t, archive)); err == nil {
		t.Fatal("extractModule() error = nil, want unsupported method error")
	}
}

// corruptEntryData flips one byte of the first entry's compressed data so the
// reader fails mid-stream.
func corruptEntryData(t *testing.T, archive []byte) []byte {
	t.Helper()
	content := bytes.Clone(archive)
	index := bytes.Index(content, []byte("PK\x03\x04"))
	if index < 0 {
		t.Fatal("archive carries no local header")
	}
	nameLength := int(binary.LittleEndian.Uint16(content[index+26:]))
	extraLength := int(binary.LittleEndian.Uint16(content[index+28:]))
	dataStart := index + 30 + nameLength + extraLength
	content[dataStart] ^= 0xff
	return content
}

func TestExtractModuleRejectsCorruptEntryData(t *testing.T) {
	archive := moduleZip(t, "example.com/mod@v1.0.0/", archiveContent)
	corrupt := corruptEntryData(t, archive)
	subject := publishableCandidate(t, corrupt)
	if _, err := extractModule(t.TempDir(), subject, corrupt); err == nil {
		t.Fatal("extractModule() error = nil, want corrupt entry error")
	}
}

func TestExtractModuleGuards(t *testing.T) {
	subject := publishableCandidate(t, moduleZip(t, "example.com/mod@v1.0.0/", archiveContent))

	for name, files := range map[string]map[string]string{
		"prefix escape":  {"go.mod": "x", "../escape.txt": "x"},
		"module escape":  {"go.mod": "x", "sub/../../escape.txt": "x"},
		"foreign prefix": {"go.mod": "x"},
	} {
		t.Run(name, func(t *testing.T) {
			prefix := "example.com/mod@v1.0.0/"
			if name == "foreign prefix" {
				prefix = "other/mod@v9.9.9/"
			}
			archive := moduleZip(t, prefix, files)
			if _, err := extractModule(t.TempDir(), subject, archive); err == nil {
				t.Fatal("extractModule() error = nil, want guard error")
			}
		})
	}
}

func TestExtractModuleRejectsEmptyArchive(t *testing.T) {
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	if err := writer.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	subject := publishableCandidate(t, moduleZip(t, "example.com/mod@v1.0.0/", archiveContent))
	if _, err := extractModule(t.TempDir(), subject, buffer.Bytes()); err == nil {
		t.Fatal("extractModule() error = nil, want empty archive error")
	}
}

func TestExtractModuleCreatesDirectories(t *testing.T) {
	files := map[string]string{
		"go.mod":     "module example.com/mod\n",
		"sub/mod.go": "package mod\n",
	}
	archive := moduleZip(t, "example.com/mod@v1.0.0/", files)
	subject := publishableCandidate(t, archive)
	root, err := extractModule(t.TempDir(), subject, archive)
	if err != nil {
		t.Fatalf("extractModule() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "sub", "mod.go")); err != nil {
		t.Fatalf("extracted file missing: %v", err)
	}
}

func TestExtractModuleEnforcesTheDecompressionBound(t *testing.T) {
	original := maxModuleArchiveBytes
	maxModuleArchiveBytes = 8
	t.Cleanup(func() { maxModuleArchiveBytes = original })

	files := map[string]string{"mod.go": "package mod // larger than eight bytes"}
	archive := moduleZip(t, "example.com/mod@v1.0.0/", files)
	subject := publishableCandidate(t, archive)
	if _, err := extractModule(t.TempDir(), subject, archive); err == nil {
		t.Fatal("extractModule() error = nil, want decompression bound error")
	}
}

func TestDirhash(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/mod\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sub", "mod.go"), []byte("package mod\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	first, err := dirhash(root)
	if err != nil {
		t.Fatalf("dirhash() error = %v", err)
	}
	if !strings.HasPrefix(first, "h1:") {
		t.Fatalf("dirhash() = %q, want the h1: form", first)
	}

	second, err := dirhash(root)
	if err != nil {
		t.Fatalf("dirhash() error = %v", err)
	}
	if first != second {
		t.Fatalf("dirhash() not deterministic: %q != %q", first, second)
	}

	if err := os.WriteFile(filepath.Join(root, "sub", "mod.go"), []byte("package changed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	changed, err := dirhash(root)
	if err != nil {
		t.Fatalf("dirhash() error = %v", err)
	}
	if first == changed {
		t.Fatal("dirhash() unchanged after a content change, want a different identity")
	}
}

func TestDirhashRejectsMissingRoot(t *testing.T) {
	if _, err := dirhash(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("dirhash() error = nil, want walk error")
	}
}

func TestDirhashRejectsEmptyTree(t *testing.T) {
	if _, err := dirhash(t.TempDir()); err == nil {
		t.Fatal("dirhash() error = nil, want empty tree error")
	}
}

type fakeDirEntry struct {
	name string
	mode os.FileMode
}

func (e fakeDirEntry) Name() string               { return e.name }
func (e fakeDirEntry) IsDir() bool                { return false }
func (e fakeDirEntry) Type() os.FileMode          { return e.mode }
func (e fakeDirEntry) Info() (os.FileInfo, error) { return nil, nil }

func TestDirhashRejectsNonRegularEntries(t *testing.T) {
	originalWalk := walkModuleTree
	t.Cleanup(func() { walkModuleTree = originalWalk })
	walkModuleTree = func(_ string, fn fs.WalkDirFunc) error {
		return fn("root/link", fakeDirEntry{name: "link", mode: os.ModeSymlink}, nil)
	}
	if _, err := dirhash("root"); err == nil {
		t.Fatal("dirhash() error = nil, want non-regular entry error")
	}
}

func TestDirhashPropagatesReadFailures(t *testing.T) {
	originalWalk, originalRead := walkModuleTree, readModuleFile
	t.Cleanup(func() { walkModuleTree, readModuleFile = originalWalk, originalRead })
	walkModuleTree = func(_ string, fn fs.WalkDirFunc) error {
		return fn("root/mod.go", fakeDirEntry{name: "mod.go", mode: 0}, nil)
	}
	readModuleFile = func(string) ([]byte, error) {
		return nil, errors.New("read failure")
	}
	if _, err := dirhash("root"); err == nil {
		t.Fatal("dirhash() error = nil, want read error")
	}
}

func TestEscapeModulePath(t *testing.T) {
	if got := escapeModulePath("Example.com/Mod"); got != "!example.com/!mod" {
		t.Fatalf("escapeModulePath() = %q, want !example.com/!mod", got)
	}
	if got := escapeModulePath("example.com/mod"); got != "example.com/mod" {
		t.Fatalf("escapeModulePath() = %q, want the unchanged path", got)
	}
}
