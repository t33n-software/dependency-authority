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
	"reflect"
	"strings"
	"testing"

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
// archives by host.
type publisherFixture struct {
	intakeArchive   []byte
	approvedArchive []byte
	intakeStatus    int
	approvedStatus  int
	transportErr    error
}

func (f publisherFixture) do(req *http.Request) (*http.Response, error) {
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
		if f.approvedStatus != 0 {
			return &http.Response{Status: "approved failure", StatusCode: f.approvedStatus, Body: io.NopCloser(strings.NewReader(""))}, nil
		}
		return okResponse(string(f.approvedArchive)), nil
	default:
		return nil, errors.New("unexpected host " + req.URL.Host)
	}
}

type fakeUploadRunner struct {
	result Result
	err    error
	calls  int
	dir    string
	args   []string
}

func (f *fakeUploadRunner) run(_ context.Context, dir string, _ string, args ...string) (Result, error) {
	f.calls++
	f.dir = dir
	f.args = args
	return f.result, f.err
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

func newPublisher(t *testing.T, doer Doer, run Runner) Publisher {
	t.Helper()
	publisher, err := NewPublisher(
		newTestClient(t, doer),
		"https://intake.example.com/p/r",
		"https://approved.example.com/p/r",
		"projects/p/locations/l/repositories/r",
		run,
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
			if _, err := NewPublisher(client, tc.intake, tc.approved, tc.repo, func(context.Context, string, string, ...string) (Result, error) {
				return Result{}, nil
			}, tempFactory(t)); err == nil {
				t.Fatal("NewPublisher() error = nil, want error")
			}
		})
	}
	if _, err := NewPublisher(client, "https://intake.example.com", "https://approved.example.com", "projects/p/locations/l/repositories/r", nil, tempFactory(t)); err == nil {
		t.Fatal("NewPublisher( nil runner ) error = nil, want error")
	}
	if _, err := NewPublisher(client, "https://intake.example.com", "https://approved.example.com", "projects/p/locations/l/repositories/r", func(context.Context, string, string, ...string) (Result, error) {
		return Result{}, nil
	}, nil); err == nil {
		t.Fatal("NewPublisher( nil temp dir ) error = nil, want error")
	}
}

func TestPublishProvesContentIdentityEndToEnd(t *testing.T) {
	archive := moduleZip(t, "example.com/mod@v1.0.0/", archiveContent)
	runner := &fakeUploadRunner{result: Result{ExitCode: 0}}
	publisher := newPublisher(t, doerFunc(publisherFixture{intakeArchive: archive, approvedArchive: archive}.do), runner.run)

	subject := publishableCandidate(t, archive)
	if err := publisher.Publish(context.Background(), subject, []evidence.Reference{}); err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	if runner.calls != 1 {
		t.Fatalf("upload calls = %d, want 1", runner.calls)
	}
	wantArgs := []string{"artifacts", "go", "upload", "--project=p", "--location=l", "--repository=r", "--module-path=example.com/mod", "--version=v1.0.0"}
	if !reflect.DeepEqual(runner.args[:len(wantArgs)], wantArgs) {
		t.Fatalf("upload args = %v, want prefix %v", runner.args, wantArgs)
	}
	if !strings.HasPrefix(runner.args[len(wantArgs)], "--source=") {
		t.Fatalf("upload args = %v, want a --source binding", runner.args)
	}
	if _, err := os.Stat(runner.dir); err != nil {
		t.Fatalf("module root %q not materialized: %v", runner.dir, err)
	}
	if !strings.HasSuffix(runner.dir, filepath.FromSlash("example.com/mod@v1.0.0")) {
		t.Fatalf("module root = %q, want the module@version directory", runner.dir)
	}
}

func TestPublishRejectsIntakeDigestDrift(t *testing.T) {
	archive := moduleZip(t, "example.com/mod@v1.0.0/", archiveContent)
	drifted := moduleZip(t, "example.com/mod@v1.0.0/", map[string]string{"go.mod": "module example.com/mod\n"})
	publisher := newPublisher(t, doerFunc(publisherFixture{intakeArchive: archive}.do), (&fakeUploadRunner{}).run)

	subject := publishableCandidate(t, drifted)
	if err := publisher.Publish(context.Background(), subject, nil); err == nil {
		t.Fatal("Publish() error = nil, want digest drift error")
	}
}

func TestPublishIntakeFetchFailures(t *testing.T) {
	archive := moduleZip(t, "example.com/mod@v1.0.0/", archiveContent)
	subject := publishableCandidate(t, archive)

	publisher := newPublisher(t, doerFunc(publisherFixture{intakeStatus: http.StatusNotFound}.do), (&fakeUploadRunner{}).run)
	if err := publisher.Publish(context.Background(), subject, nil); err == nil {
		t.Fatal("Publish() error = nil, want intake not-found error")
	}

	publisher = newPublisher(t, doerFunc(publisherFixture{intakeStatus: http.StatusInternalServerError}.do), (&fakeUploadRunner{}).run)
	if err := publisher.Publish(context.Background(), subject, nil); err == nil {
		t.Fatal("Publish() error = nil, want intake status error")
	}

	publisher = newPublisher(t, doerFunc(publisherFixture{transportErr: errors.New("reset")}.do), (&fakeUploadRunner{}).run)
	if err := publisher.Publish(context.Background(), subject, nil); err == nil {
		t.Fatal("Publish() error = nil, want intake transport error")
	}
}

func TestPublishRejectsCorruptModuleArchive(t *testing.T) {
	corrupt := []byte("not a zip")
	publisher := newPublisher(t, doerFunc(publisherFixture{intakeArchive: corrupt}.do), (&fakeUploadRunner{}).run)
	subject := publishableCandidate(t, corrupt)
	if err := publisher.Publish(context.Background(), subject, nil); err == nil {
		t.Fatal("Publish() error = nil, want archive error")
	}
}

func TestPublishPropagatesWorkspaceFailure(t *testing.T) {
	archive := moduleZip(t, "example.com/mod@v1.0.0/", archiveContent)
	publisher, err := NewPublisher(
		newTestClient(t, doerFunc(publisherFixture{intakeArchive: archive}.do)),
		"https://intake.example.com/p/r",
		"https://approved.example.com/p/r",
		"projects/p/locations/l/repositories/r",
		(&fakeUploadRunner{}).run,
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

	runner := &fakeUploadRunner{err: errors.New("gcloud missing")}
	publisher := newPublisher(t, doerFunc(publisherFixture{intakeArchive: archive}.do), runner.run)
	if err := publisher.Publish(context.Background(), subject, nil); err == nil {
		t.Fatal("Publish() error = nil, want runner error")
	}

	runner = &fakeUploadRunner{result: Result{ExitCode: 2}}
	publisher = newPublisher(t, doerFunc(publisherFixture{intakeArchive: archive}.do), runner.run)
	if err := publisher.Publish(context.Background(), subject, nil); err == nil {
		t.Fatal("Publish() error = nil, want exit code error")
	}
}

func TestPublishApprovedFetchFailure(t *testing.T) {
	archive := moduleZip(t, "example.com/mod@v1.0.0/", archiveContent)
	publisher := newPublisher(t, doerFunc(publisherFixture{intakeArchive: archive, approvedStatus: http.StatusInternalServerError}.do), (&fakeUploadRunner{}).run)
	subject := publishableCandidate(t, archive)
	if err := publisher.Publish(context.Background(), subject, nil); err == nil {
		t.Fatal("Publish() error = nil, want approved fetch error")
	}
}

func TestPublishRejectsPostPublicationMismatch(t *testing.T) {
	archive := moduleZip(t, "example.com/mod@v1.0.0/", archiveContent)
	mutated := moduleZip(t, "example.com/mod@v1.0.0/", map[string]string{
		"go.mod":  "module example.com/mod\n\ngo 1.26\n",
		"mod.go":  "package mod\n",
		"evil.go": "package mod\n",
	})
	publisher := newPublisher(t, doerFunc(publisherFixture{intakeArchive: archive, approvedArchive: mutated}.do), (&fakeUploadRunner{result: Result{ExitCode: 0}}).run)
	subject := publishableCandidate(t, archive)
	if err := publisher.Publish(context.Background(), subject, nil); err == nil {
		t.Fatal("Publish() error = nil, want content identity mismatch error")
	}
}

func TestPublishApprovedArchiveCorrupt(t *testing.T) {
	archive := moduleZip(t, "example.com/mod@v1.0.0/", archiveContent)
	corrupt := []byte("not a zip")
	publisher := newPublisher(t, doerFunc(publisherFixture{intakeArchive: archive, approvedArchive: corrupt}.do), (&fakeUploadRunner{result: Result{ExitCode: 0}}).run)
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
		publisher := newPublisher(t, doerFunc(publisherFixture{intakeArchive: archive}.do), (&fakeUploadRunner{result: Result{ExitCode: 0}}).run)
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
		publisher := newPublisher(t, doerFunc(publisherFixture{intakeArchive: archive, approvedArchive: archive}.do), (&fakeUploadRunner{result: Result{ExitCode: 0}}).run)
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
