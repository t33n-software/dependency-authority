package artifactregistry

import (
	"context"
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

const recordDigest = "sha256:3b8f49c12b24cbbd6a4a0e6e2b2a4a4e8f0e1d2c3b4a59687766554433221100"

const otherRecordDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

var recordTime = time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)

func fixedClock() time.Time {
	return recordTime
}

func testRecords(t *testing.T, doer Doer) Records {
	t.Helper()
	records, err := NewRecords(newTestClient(t, doer), "projects/p/locations/l/repositories/r", fixedClock)
	if err != nil {
		t.Fatalf("NewRecords() error = %v", err)
	}
	return records
}

func newCandidate(t *testing.T) candidate.Candidate {
	t.Helper()
	subject, err := candidateWithIdentity("example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return subject
}

func candidateWithIdentity(name string, version string) (candidate.Candidate, error) {
	return candidate.New(candidate.EcosystemGo, name, version, recordDigest)
}

func stringPointer(value string) *string {
	return &value
}

func testReference(t *testing.T, evidenceType evidence.Type, locator string) evidence.Reference {
	t.Helper()
	expiry := recordTime.Add(time.Hour)
	reference, err := evidence.NewReference(evidenceType, locator, recordDigest, "issuer", recordTime, &expiry)
	if err != nil {
		t.Fatalf("NewReference() error = %v", err)
	}
	return reference
}

func approvalReference(t *testing.T) evidence.Reference {
	t.Helper()
	reference, err := evidence.NewReference(evidence.TypeApproval, "approvals/1", otherRecordDigest, "approver", recordTime, nil)
	if err != nil {
		t.Fatalf("NewReference() error = %v", err)
	}
	return reference
}

// recordServer fakes the generic-artifact surface for the records store:
// uploads, paginated file lists, and content downloads.
type recordServer struct {
	t          *testing.T
	uploaded   map[string]string
	documents  map[string]string
	listPages  []string
	listCalls  int
	uploadErr  error
	listStatus int
	downloaded []string
}

func newRecordServer(t *testing.T) *recordServer {
	t.Helper()
	return &recordServer{
		t:         t,
		uploaded:  make(map[string]string),
		documents: make(map[string]string),
	}
}

func (s *recordServer) do(req *http.Request) (*http.Response, error) {
	switch {
	case strings.Contains(req.URL.Path, "genericArtifacts:create"):
		if s.uploadErr != nil {
			return nil, s.uploadErr
		}
		body, err := io.ReadAll(req.Body)
		if err != nil {
			s.t.Fatalf("read upload body: %v", err)
		}
		content := string(body)
		start := strings.Index(content, "{\"schema\":")
		if start < 0 {
			s.t.Fatalf("upload body carries no record document: %q", content)
		}
		s.uploaded[req.URL.String()] = content[start:]
		return okResponse(`{"operation": {"name": "operations/1"}}`), nil
	case strings.Contains(req.URL.RawQuery, "pageSize") || strings.Contains(req.URL.Path, "/files"):
		if s.listStatus != 0 {
			return &http.Response{Status: "500", StatusCode: s.listStatus, Body: io.NopCloser(strings.NewReader(""))}, nil
		}
		if s.listCalls < len(s.listPages) {
			page := s.listPages[s.listCalls]
			s.listCalls++
			return okResponse(page), nil
		}
		return okResponse(`{"files": []}`), nil
	default:
		s.t.Fatalf("unexpected request %q", req.URL.String())
		return nil, nil
	}
}

func (s *recordServer) downloadOf(name string) (string, bool) {
	content, found := s.documents[name]
	return content, found
}

func (s *recordServer) doWithDownloads(req *http.Request) (*http.Response, error) {
	if idx := strings.Index(req.URL.Path, ":download"); idx >= 0 {
		name := strings.TrimPrefix(strings.TrimSuffix(req.URL.Path, ":download"), "/v1/")
		content, found := s.downloadOf(name)
		if !found {
			return &http.Response{Status: "404", StatusCode: 404, Body: io.NopCloser(strings.NewReader(""))}, nil
		}
		s.downloaded = append(s.downloaded, name)
		return okResponse(content), nil
	}
	return s.do(req)
}

func TestNewRecordsValidatesConfiguration(t *testing.T) {
	client := newTestClient(t, http.DefaultClient)
	if _, err := NewRecords(client, "bogus", fixedClock); err == nil {
		t.Fatal("NewRecords( invalid repository ) error = nil, want error")
	}
	if _, err := NewRecords(client, "projects/p/locations/l/repositories/r", nil); err == nil {
		t.Fatal("NewRecords( nil clock ) error = nil, want error")
	}
	if _, err := NewRecords(client, "projects/p/locations/l/repositories/r", fixedClock); err != nil {
		t.Fatalf("NewRecords() error = %v, want success", err)
	}
}

func TestRecordsSaveUploadsTheSnapshot(t *testing.T) {
	server := newRecordServer(t)
	records := testRecords(t, doerFunc(server.do))

	subject := newCandidate(t)
	if err := subject.RecordEvidence(testReference(t, evidence.TypeSBOM, "sboms/1")); err != nil {
		t.Fatalf("RecordEvidence() error = %v", err)
	}
	if err := records.Save(context.Background(), subject); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	if len(server.uploaded) != 1 {
		t.Fatalf("uploaded = %d, want 1", len(server.uploaded))
	}
	for url, content := range server.uploaded {
		if !strings.Contains(url, "/packages/") && !strings.Contains(url, "genericArtifacts:create") {
			t.Fatalf("upload URL = %q, want the create surface", url)
		}
		for _, fragment := range []string{
			`"schema":"dependency-authority/candidate-record/v1"`,
			`"ecosystem":"go"`,
			`"name":"example.com/mod"`,
			`"version":"v1.0.0"`,
			`"state":"pending"`,
			`"type":"sbom"`,
			`"reference":"sboms/1"`,
			`"recorded_at":"2026-08-20T12:00:00Z"`,
		} {
			if !strings.Contains(content, fragment) {
				t.Fatalf("record document misses %q: %q", fragment, content)
			}
		}
	}
}

func TestRecordsSavePropagatesUploadFailure(t *testing.T) {
	server := newRecordServer(t)
	server.uploadErr = errors.New("repository unavailable")
	records := testRecords(t, doerFunc(server.do))
	if err := records.Save(context.Background(), newCandidate(t)); err == nil {
		t.Fatal("Save() error = nil, want upload error")
	}
}

func TestRecordsFindReportsUnknownCandidate(t *testing.T) {
	server := newRecordServer(t)
	server.listPages = []string{`{"files": []}`}
	records := testRecords(t, doerFunc(server.doWithDownloads))
	_, found, err := records.Find(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("Find() error = %v", err)
	}
	if found {
		t.Fatal("Find() found = true, want false for an empty record set")
	}
}

func TestRecordsFindPropagatesListFailure(t *testing.T) {
	server := newRecordServer(t)
	server.listStatus = http.StatusInternalServerError
	records := testRecords(t, doerFunc(server.doWithDownloads))
	if _, _, err := records.Find(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0"); err == nil {
		t.Fatal("Find() error = nil, want list error")
	}
}

func TestRecordsFindPropagatesDownloadFailure(t *testing.T) {
	server := newRecordServer(t)
	owner := "projects/p/locations/l/repositories/r/packages/" + recordPackageIdentity(candidate.EcosystemGo, "example.com/mod", "v1.0.0") + "/versions/v1"
	server.listPages = []string{`{"files": [{"name": "projects/p/locations/l/repositories/r/files/pkg:v1:x.json", "owner": "` + owner + `", "createTime": "2026-08-20T10:00:00Z"}]}`}
	records := testRecords(t, doerFunc(server.doWithDownloads))
	if _, _, err := records.Find(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0"); err == nil {
		t.Fatal("Find() error = nil, want download error")
	}
}

// serveRoundTrip stores the snapshot document of the subject so Find can
// download it back.
func serveRoundTrip(t *testing.T, server *recordServer, subject candidate.Candidate, createTime string) {
	t.Helper()
	document := snapshot(fixedClock, subject)
	content, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}
	pkg := recordPackage(subject)
	name := "projects/p/locations/l/repositories/r/files/" + pkg + ":v1:" + fmt.Sprintf("%d", len(server.documents)) + ".json"
	owner := "projects/p/locations/l/repositories/r/packages/" + pkg + "/versions/v1"
	server.documents[name] = string(content)
	server.listPages = []string{fmt.Sprintf(`{"files": [{"name": %q, "owner": %q, "createTime": %q}]}`, name, owner, createTime)}
}

func TestRecordsFindRoundTripsEveryLifecycleState(t *testing.T) {
	for _, state := range []string{"pending", "quarantined", "approved", "revoked"} {
		t.Run(state, func(t *testing.T) {
			server := newRecordServer(t)
			records := testRecords(t, doerFunc(server.doWithDownloads))

			subject := newCandidate(t)
			if err := subject.RecordEvidence(testReference(t, evidence.TypeSBOM, "sboms/1")); err != nil {
				t.Fatalf("RecordEvidence() error = %v", err)
			}
			switch state {
			case "quarantined":
				if err := subject.Quarantine("policy failure"); err != nil {
					t.Fatalf("Quarantine() error = %v", err)
				}
			case "approved":
				if err := subject.RecordEvidence(testReference(t, evidence.TypeScan, "scans/1")); err != nil {
					t.Fatalf("RecordEvidence() error = %v", err)
				}
				if err := subject.Approve(approvalReference(t)); err != nil {
					t.Fatalf("Approve() error = %v", err)
				}
			case "revoked":
				if err := subject.Revoke("confirmed incident"); err != nil {
					t.Fatalf("Revoke() error = %v", err)
				}
			}
			serveRoundTrip(t, server, subject, "2026-08-20T10:00:00Z")

			got, found, err := records.Find(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0")
			if err != nil {
				t.Fatalf("Find() error = %v", err)
			}
			if !found {
				t.Fatal("Find() found = false, want true")
			}
			if string(got.State()) != state {
				t.Fatalf("State() = %q, want %q", got.State(), state)
			}
			if got.Digest() != recordDigest || got.Name() != "example.com/mod" || got.Version() != "v1.0.0" {
				t.Fatalf("Find() identity = %q %q %q", got.Name(), got.Version(), got.Digest())
			}
			if len(got.Evidence()) != len(subject.Evidence()) {
				t.Fatalf("Evidence() = %d entries, want %d", len(got.Evidence()), len(subject.Evidence()))
			}
		})
	}
}

func TestRecordsFindSelectsTheNewestSnapshot(t *testing.T) {
	server := newRecordServer(t)
	records := testRecords(t, doerFunc(server.doWithDownloads))

	pending := newCandidate(t)
	quarantined := newCandidate(t)
	if err := quarantined.Quarantine("policy failure"); err != nil {
		t.Fatalf("Quarantine() error = %v", err)
	}

	pkg := recordPackageIdentity(candidate.EcosystemGo, "example.com/mod", "v1.0.0")
	owner := "projects/p/locations/l/repositories/r/packages/" + pkg + "/versions/v1"
	olderName := "projects/p/locations/l/repositories/r/files/pkg:v1:a-older.json"
	newerName := "projects/p/locations/l/repositories/r/files/pkg:v1:z-newer.json"

	olderContent, _ := json.Marshal(snapshot(fixedClock, pending))
	newerContent, _ := json.Marshal(snapshot(fixedClock, quarantined))
	server.documents[olderName] = string(olderContent)
	server.documents[newerName] = string(newerContent)
	server.listPages = []string{fmt.Sprintf(`{"files": [
		{"name": %q, "owner": %q, "createTime": "2026-08-20T10:00:00Z"},
		{"name": %q, "owner": %q, "createTime": "2026-08-20T10:00:01Z"}
	]}`, olderName, owner, newerName, owner)}

	got, found, err := records.Find(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("Find() error = %v", err)
	}
	if !found || got.State() != candidate.StateQuarantined {
		t.Fatalf("Find() = %q, %v, want the quarantined newest snapshot", got.State(), found)
	}
	if len(server.downloaded) != 1 || server.downloaded[0] != newerName {
		t.Fatalf("downloaded = %v, want only the newest record", server.downloaded)
	}
}

func TestRecordsFindBreaksCreateTimeTiesByName(t *testing.T) {
	server := newRecordServer(t)
	records := testRecords(t, doerFunc(server.doWithDownloads))

	pending := newCandidate(t)
	quarantined := newCandidate(t)
	if err := quarantined.Quarantine("policy failure"); err != nil {
		t.Fatalf("Quarantine() error = %v", err)
	}

	pkg := recordPackageIdentity(candidate.EcosystemGo, "example.com/mod", "v1.0.0")
	owner := "projects/p/locations/l/repositories/r/packages/" + pkg + "/versions/v1"
	aName := "projects/p/locations/l/repositories/r/files/pkg:v1:a.json"
	bName := "projects/p/locations/l/repositories/r/files/pkg:v1:b.json"

	aContent, _ := json.Marshal(snapshot(fixedClock, pending))
	bContent, _ := json.Marshal(snapshot(fixedClock, quarantined))
	server.documents[aName] = string(aContent)
	server.documents[bName] = string(bContent)
	server.listPages = []string{fmt.Sprintf(`{"files": [
		{"name": %q, "owner": %q, "createTime": "2026-08-20T10:00:00Z"},
		{"name": %q, "owner": %q, "createTime": "2026-08-20T10:00:00Z"}
	]}`, aName, owner, bName, owner)}

	got, _, err := records.Find(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("Find() error = %v", err)
	}
	if got.State() != candidate.StateQuarantined {
		t.Fatalf("State() = %q, want the tie-broken newest name (quarantined)", got.State())
	}
}

func TestRecordsFindRejectsCorruptDocuments(t *testing.T) {
	for name, mutate := range map[string]func(*recordDocument){
		"unknown schema": func(d *recordDocument) { d.Schema = "other/v9" },
		"invalid digest": func(d *recordDocument) { d.Digest = "sha256:zz" },
		"invalid evidence issued-at": func(d *recordDocument) {
			d.Evidence[0].IssuedAt = "not-a-time"
		},
		"invalid evidence expiry": func(d *recordDocument) {
			d.Evidence[0].ExpiresAt = stringPointer("not-a-time")
		},
		"unknown state": func(d *recordDocument) { d.State = "retired" },
	} {
		t.Run(name, func(t *testing.T) {
			server := newRecordServer(t)
			records := testRecords(t, doerFunc(server.doWithDownloads))
			subject := newCandidate(t)
			if err := subject.RecordEvidence(testReference(t, evidence.TypeSBOM, "sboms/1")); err != nil {
				t.Fatalf("RecordEvidence() error = %v", err)
			}
			document := snapshot(fixedClock, subject)
			mutate(&document)
			content, _ := json.Marshal(document)

			pkg := recordPackage(subject)
			fileName := "projects/p/locations/l/repositories/r/files/pkg:v1:x.json"
			owner := "projects/p/locations/l/repositories/r/packages/" + pkg + "/versions/v1"
			server.documents[fileName] = string(content)
			server.listPages = []string{fmt.Sprintf(`{"files": [{"name": %q, "owner": %q, "createTime": "2026-08-20T10:00:00Z"}]}`, fileName, owner)}

			if _, _, err := records.Find(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0"); err == nil {
				t.Fatal("Find() error = nil, want corrupt record error")
			}
		})
	}
}

func TestRecordsFindRejectsInconsistentApprovedRecords(t *testing.T) {
	for name, mutate := range map[string]func(*recordDocument){
		"missing approval": func(d *recordDocument) { d.Approval = nil },
		"non-approval reference": func(d *recordDocument) {
			d.Approval = &referenceDocument{
				Type:      "scan",
				Reference: "scans/1",
				Digest:    recordDigest,
				Issuer:    "scanner",
				IssuedAt:  recordTime.Format(time.RFC3339Nano),
			}
		},
		"invalid approval digest": func(d *recordDocument) {
			d.Approval = &referenceDocument{
				Type:      "approval",
				Reference: "approvals/1",
				Digest:    "sha256:zz",
				Issuer:    "approver",
				IssuedAt:  recordTime.Format(time.RFC3339Nano),
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			server := newRecordServer(t)
			records := testRecords(t, doerFunc(server.doWithDownloads))
			subject := newCandidate(t)
			if err := subject.Approve(approvalReference(t)); err != nil {
				t.Fatalf("Approve() error = %v", err)
			}
			document := snapshot(fixedClock, subject)
			mutate(&document)
			content, _ := json.Marshal(document)

			pkg := recordPackage(subject)
			fileName := "projects/p/locations/l/repositories/r/files/pkg:v1:x.json"
			owner := "projects/p/locations/l/repositories/r/packages/" + pkg + "/versions/v1"
			server.documents[fileName] = string(content)
			server.listPages = []string{fmt.Sprintf(`{"files": [{"name": %q, "owner": %q, "createTime": "2026-08-20T10:00:00Z"}]}`, fileName, owner)}

			if _, _, err := records.Find(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0"); err == nil {
				t.Fatal("Find() error = nil, want inconsistent approved record error")
			}
		})
	}
}

func TestRecordsFindRejectsMalformedJSON(t *testing.T) {
	server := newRecordServer(t)
	records := testRecords(t, doerFunc(server.doWithDownloads))
	pkg := recordPackageIdentity(candidate.EcosystemGo, "example.com/mod", "v1.0.0")
	owner := "projects/p/locations/l/repositories/r/packages/" + pkg + "/versions/v1"
	fileName := "projects/p/locations/l/repositories/r/files/pkg:v1:x.json"
	server.documents[fileName] = "{"
	server.listPages = []string{fmt.Sprintf(`{"files": [{"name": %q, "owner": %q, "createTime": "2026-08-20T10:00:00Z"}]}`, fileName, owner)}

	if _, _, err := records.Find(context.Background(), candidate.EcosystemGo, "example.com/mod", "v1.0.0"); err == nil {
		t.Fatal("Find() error = nil, want decode error")
	}
}

func TestReferenceDocumentRoundTrip(t *testing.T) {
	reference := testReference(t, evidence.TypeScan, "scans/1")
	document := referenceToDocument(reference)
	if document.ExpiresAt == nil {
		t.Fatal("referenceToDocument() expiresAt = nil, want encoded expiry")
	}
	rebuilt, err := document.toDomain()
	if err != nil {
		t.Fatalf("toDomain() error = %v", err)
	}
	if rebuilt.Type() != reference.Type() || rebuilt.Reference() != reference.Reference() || rebuilt.Digest() != reference.Digest() || rebuilt.Issuer() != reference.Issuer() {
		t.Fatal("toDomain() changed the reference identity")
	}
	expiry, ok := rebuilt.ExpiresAt()
	if !ok || !expiry.Equal(recordTime.Add(time.Hour)) {
		t.Fatalf("ExpiresAt() = %v, %v, want the encoded expiry", expiry, ok)
	}
}

func TestSameReference(t *testing.T) {
	a := referenceToDocument(testReference(t, evidence.TypeScan, "scans/1"))
	b := referenceToDocument(testReference(t, evidence.TypeScan, "scans/2"))
	if !sameReference(a, a) {
		t.Fatal("sameReference(a, a) = false, want true")
	}
	if sameReference(a, b) {
		t.Fatal("sameReference(a, b) = true, want false")
	}
}
