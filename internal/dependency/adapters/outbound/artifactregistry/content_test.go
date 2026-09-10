package artifactregistry

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/t33n-software/dependency-authority/internal/dependency/domain/candidate"
)

// newCandidateContent binds the materializer against the fake intake
// transport.
func newCandidateContent(t *testing.T, doer Doer, root string) CandidateContent {
	t.Helper()
	content, err := NewCandidateContent(newTestClient(t, doer), "https://intake.example.com/p/r", root)
	if err != nil {
		t.Fatalf("NewCandidateContent() error = %v", err)
	}
	return content
}

func TestNewCandidateContentValidatesConfiguration(t *testing.T) {
	client := newTestClient(t, http.DefaultClient)
	for _, tc := range []struct {
		name     string
		endpoint string
		root     string
	}{
		{"empty endpoint", " ", "root"},
		{"unparseable endpoint", "ht tp://x", "root"},
		{"hostless endpoint", "https://", "root"},
		{"plaintext endpoint", "http://intake.example.com", "root"},
		{"empty root", "https://intake.example.com", " "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewCandidateContent(client, tc.endpoint, tc.root); err == nil {
				t.Fatal("NewCandidateContent() error = nil, want error")
			}
		})
	}
	if _, err := NewCandidateContent(client, "https://intake.example.com", "root"); err != nil {
		t.Fatalf("NewCandidateContent() error = %v, want success", err)
	}
}

func TestMaterializeFetchesProvesAndPlaces(t *testing.T) {
	archive := moduleZip(t, "example.com/mod@v1.0.0/", archiveContent)
	root := t.TempDir()
	content := newCandidateContent(t, doerFunc((&publisherFixture{intakeArchive: archive}).do), root)
	subject := publishableCandidate(t, archive)

	target, err := content.Materialize(context.Background(), subject)
	if err != nil {
		t.Fatalf("Materialize() error = %v", err)
	}
	want := filepath.Join(root, "go", filepath.FromSlash("example.com/mod")+"@v1.0.0")
	if target != want {
		t.Fatalf("Materialize() target = %q, want %q", target, want)
	}
	if _, err := os.Stat(filepath.Join(target, "go.mod")); err != nil {
		t.Fatalf("the materialized go.mod is missing: %v", err)
	}
	marker, err := os.ReadFile(target + ".sha256")
	if err != nil {
		t.Fatalf("the digest marker is missing: %v", err)
	}
	if strings.TrimSpace(string(marker)) != subject.Digest() {
		t.Fatalf("marker = %q, want %q", marker, subject.Digest())
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(target), ".staging-"+filepath.Base(target))); !os.IsNotExist(err) {
		t.Fatalf("the staging shell remains after the placement: %v", err)
	}
}

func TestMaterializeSkipsTheProvenTarget(t *testing.T) {
	archive := moduleZip(t, "example.com/mod@v1.0.0/", archiveContent)
	root := t.TempDir()
	subject := publishableCandidate(t, archive)
	target := filepath.Join(root, "go", filepath.FromSlash("example.com/mod")+"@v1.0.0")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target+".sha256", []byte(subject.Digest()), 0o644); err != nil {
		t.Fatal(err)
	}
	// The transport fails on any call: a skip must not fetch.
	content := newCandidateContent(t, doerFunc((&publisherFixture{transportErr: errors.New("unexpected fetch")}).do), root)
	got, err := content.Materialize(context.Background(), subject)
	if err != nil {
		t.Fatalf("Materialize() error = %v", err)
	}
	if got != target {
		t.Fatalf("Materialize() = %q, want the existing target %q", got, target)
	}
}

func TestMaterializeRejectsTheUnprovenTarget(t *testing.T) {
	archive := moduleZip(t, "example.com/mod@v1.0.0/", archiveContent)
	subject := publishableCandidate(t, archive)

	t.Run("missing marker", func(t *testing.T) {
		root := t.TempDir()
		target := filepath.Join(root, "go", filepath.FromSlash("example.com/mod")+"@v1.0.0")
		if err := os.MkdirAll(target, 0o755); err != nil {
			t.Fatal(err)
		}
		content := newCandidateContent(t, doerFunc((&publisherFixture{intakeArchive: archive}).do), root)
		if _, err := content.Materialize(context.Background(), subject); err == nil {
			t.Fatal("Materialize() error = nil, want the unproven target failure")
		}
	})

	t.Run("drifted marker", func(t *testing.T) {
		root := t.TempDir()
		target := filepath.Join(root, "go", filepath.FromSlash("example.com/mod")+"@v1.0.0")
		if err := os.MkdirAll(target, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target+".sha256", []byte("sha256:"+strings.Repeat("0", 64)), 0o644); err != nil {
			t.Fatal(err)
		}
		content := newCandidateContent(t, doerFunc((&publisherFixture{intakeArchive: archive}).do), root)
		if _, err := content.Materialize(context.Background(), subject); err == nil {
			t.Fatal("Materialize() error = nil, want the drifted target failure")
		}
	})

	t.Run("unreadable marker", func(t *testing.T) {
		root := t.TempDir()
		target := filepath.Join(root, "go", filepath.FromSlash("example.com/mod")+"@v1.0.0")
		if err := os.MkdirAll(target, 0o755); err != nil {
			t.Fatal(err)
		}
		original := readMarker
		t.Cleanup(func() { readMarker = original })
		readMarker = func(string) ([]byte, error) {
			return nil, errors.New("marker unreadable")
		}
		content := newCandidateContent(t, doerFunc((&publisherFixture{intakeArchive: archive}).do), root)
		if _, err := content.Materialize(context.Background(), subject); err == nil {
			t.Fatal("Materialize() error = nil, want the marker read failure")
		}
	})
}

func TestMaterializePropagatesTheTargetInspectionFailure(t *testing.T) {
	original := statPath
	t.Cleanup(func() { statPath = original })
	statPath = func(string) (os.FileInfo, error) {
		return nil, errors.New("inspection failed")
	}
	content := newCandidateContent(t, http.DefaultClient, t.TempDir())
	subject := publishableCandidate(t, moduleZip(t, "example.com/mod@v1.0.0/", archiveContent))
	if _, err := content.Materialize(context.Background(), subject); err == nil {
		t.Fatal("Materialize() error = nil, want the inspection failure")
	}
}

func TestMaterializeRejectsAnEscapingContentPath(t *testing.T) {
	subject, err := candidate.New(candidate.EcosystemGo, "../../escape", "v1.0.0", digestOf(moduleZip(t, "example.com/mod@v1.0.0/", archiveContent)))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	content := newCandidateContent(t, http.DefaultClient, t.TempDir())
	if _, err := content.Materialize(context.Background(), subject); err == nil {
		t.Fatal("Materialize() error = nil, want the content path guard")
	}
}

func TestMaterializeRejectsDigestDrift(t *testing.T) {
	archive := moduleZip(t, "example.com/mod@v1.0.0/", archiveContent)
	drifted := moduleZip(t, "example.com/mod@v1.0.0/", map[string]string{"go.mod": "module example.com/mod\n"})
	root := t.TempDir()
	content := newCandidateContent(t, doerFunc((&publisherFixture{intakeArchive: archive}).do), root)
	subject := publishableCandidate(t, drifted)
	if _, err := content.Materialize(context.Background(), subject); err == nil {
		t.Fatal("Materialize() error = nil, want the digest drift failure")
	}
	target, err := subject.ContentPath(root)
	if err != nil {
		t.Fatalf("ContentPath() error = %v", err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("the drifted content left a target behind: %v", err)
	}
}

func TestMaterializeFetchFailures(t *testing.T) {
	archive := moduleZip(t, "example.com/mod@v1.0.0/", archiveContent)
	subject := publishableCandidate(t, archive)

	content := newCandidateContent(t, doerFunc((&publisherFixture{intakeStatus: http.StatusNotFound}).do), t.TempDir())
	if _, err := content.Materialize(context.Background(), subject); err == nil {
		t.Fatal("Materialize() error = nil, want the not-found failure")
	}

	content = newCandidateContent(t, doerFunc((&publisherFixture{intakeStatus: http.StatusInternalServerError}).do), t.TempDir())
	if _, err := content.Materialize(context.Background(), subject); err == nil {
		t.Fatal("Materialize() error = nil, want the status failure")
	}

	content = newCandidateContent(t, doerFunc((&publisherFixture{transportErr: errors.New("reset")}).do), t.TempDir())
	if _, err := content.Materialize(context.Background(), subject); err == nil {
		t.Fatal("Materialize() error = nil, want the transport failure")
	}
}

func TestMaterializeRejectsCorruptArchive(t *testing.T) {
	corrupt := []byte("not a zip")
	content := newCandidateContent(t, doerFunc((&publisherFixture{intakeArchive: corrupt}).do), t.TempDir())
	subject := publishableCandidate(t, corrupt)
	if _, err := content.Materialize(context.Background(), subject); err == nil {
		t.Fatal("Materialize() error = nil, want the archive failure")
	}
}

func TestPlaceCandidateContentFailures(t *testing.T) {
	archive := moduleZip(t, "example.com/mod@v1.0.0/", archiveContent)
	subject := publishableCandidate(t, archive)

	t.Run("parent directory", func(t *testing.T) {
		original := createModuleDir
		t.Cleanup(func() { createModuleDir = original })
		createModuleDir = func(string, os.FileMode) error {
			return errors.New("mkdir failure")
		}
		content := newCandidateContent(t, doerFunc((&publisherFixture{intakeArchive: archive}).do), t.TempDir())
		if _, err := content.Materialize(context.Background(), subject); err == nil {
			t.Fatal("Materialize() error = nil, want the parent directory failure")
		}
	})

	t.Run("staging clear", func(t *testing.T) {
		original := removeTree
		t.Cleanup(func() { removeTree = original })
		removeTree = func(string) error {
			return errors.New("remove failure")
		}
		content := newCandidateContent(t, doerFunc((&publisherFixture{intakeArchive: archive}).do), t.TempDir())
		if _, err := content.Materialize(context.Background(), subject); err == nil {
			t.Fatal("Materialize() error = nil, want the staging clear failure")
		}
	})

	t.Run("rename", func(t *testing.T) {
		original := renameTree
		t.Cleanup(func() { renameTree = original })
		renameTree = func(string, string) error {
			return errors.New("rename failure")
		}
		content := newCandidateContent(t, doerFunc((&publisherFixture{intakeArchive: archive}).do), t.TempDir())
		if _, err := content.Materialize(context.Background(), subject); err == nil {
			t.Fatal("Materialize() error = nil, want the rename failure")
		}
	})

	t.Run("marker write removes the placed target", func(t *testing.T) {
		root := t.TempDir()
		original := writeMarker
		t.Cleanup(func() { writeMarker = original })
		writeMarker = func(string, []byte, os.FileMode) error {
			return errors.New("marker failure")
		}
		content := newCandidateContent(t, doerFunc((&publisherFixture{intakeArchive: archive}).do), root)
		if _, err := content.Materialize(context.Background(), subject); err == nil {
			t.Fatal("Materialize() error = nil, want the marker failure")
		}
		target, err := subject.ContentPath(root)
		if err != nil {
			t.Fatalf("ContentPath() error = %v", err)
		}
		if _, err := os.Stat(target); !os.IsNotExist(err) {
			t.Fatalf("the placed target remains after the marker failure: %v", err)
		}
	})

	t.Run("final staging clear", func(t *testing.T) {
		original := removeTree
		t.Cleanup(func() { removeTree = original })
		removals := 0
		removeTree = func(string) error {
			removals++
			if removals > 1 {
				return errors.New("remove failure")
			}
			return nil
		}
		content := newCandidateContent(t, doerFunc((&publisherFixture{intakeArchive: archive}).do), t.TempDir())
		if _, err := content.Materialize(context.Background(), subject); err == nil {
			t.Fatal("Materialize() error = nil, want the final staging clear failure")
		}
	})
}
