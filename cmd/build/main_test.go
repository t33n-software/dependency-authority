package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func restoreSeams(t *testing.T) {
	t.Helper()
	originalExit := exitProcess
	originalArgs := commandArgs
	originalRun := runExternalCommand
	originalFind := findGoFiles
	originalRead := readSource
	originalFormat := formatSource
	originalCreate := createDirectory
	t.Cleanup(func() {
		exitProcess = originalExit
		commandArgs = originalArgs
		runExternalCommand = originalRun
		findGoFiles = originalFind
		readSource = originalRead
		formatSource = originalFormat
		createDirectory = originalCreate
	})
}

func fakeRunnerOK(output string) commandRunner {
	return func(context.Context, []string, string, ...string) ([]byte, error) {
		return []byte(output), nil
	}
}

func fakeFinderOK(files []string) goFileFinder {
	return func(string) ([]string, error) {
		return files, nil
	}
}

func fakeReaderOK() sourceReader {
	return func(string) ([]byte, error) {
		return []byte("package main\n"), nil
	}
}

func fakeFormatterIdentity() sourceFormatter {
	return func(source []byte) ([]byte, error) {
		return source, nil
	}
}

func fakeCreatorOK() directoryCreator {
	return func(string, os.FileMode) error {
		return nil
	}
}

func TestMainExitsWithRunResult(t *testing.T) {
	restoreSeams(t)
	exitCode := -1
	exitProcess = func(code int) { exitCode = code }
	commandArgs = []string{"build"}
	runExternalCommand = fakeRunnerOK("")
	findGoFiles = fakeFinderOK(nil)
	readSource = fakeReaderOK()
	formatSource = fakeFormatterIdentity()
	createDirectory = fakeCreatorOK()

	main()

	if exitCode != 0 {
		t.Fatalf("main() exit code = %d, want 0", exitCode)
	}
}

func TestRunRejectsArguments(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"unexpected"}, &stdout, &stderr,
		fakeRunnerOK(""), fakeFinderOK(nil), fakeReaderOK(), fakeFormatterIdentity(), fakeCreatorOK())
	if code != 2 {
		t.Fatalf("run() = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "usage: build") {
		t.Fatalf("stderr = %q, want usage", stderr.String())
	}
}

func TestRunWithNilContextUsesBackground(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(testNilContext(), nil, &stdout, &stderr,
		fakeRunnerOK(""), fakeFinderOK(nil), fakeReaderOK(), fakeFormatterIdentity(), fakeCreatorOK())
	if code != 0 {
		t.Fatalf("run() = %d, want 0; stderr = %q", code, stderr.String())
	}
}

func testNilContext() context.Context {
	return nil
}

func TestRunStopsWhenFormattingFails(t *testing.T) {
	var stdout, stderr bytes.Buffer
	failingFinder := func(string) ([]string, error) {
		return nil, errors.New("walk failure")
	}
	code := run(context.Background(), nil, &stdout, &stderr,
		fakeRunnerOK(""), failingFinder, fakeReaderOK(), fakeFormatterIdentity(), fakeCreatorOK())
	if code != 1 {
		t.Fatalf("run() = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "list Go files") {
		t.Fatalf("stderr = %q, want list error", stderr.String())
	}
}

func TestRunStopsWhenSourceQualityFails(t *testing.T) {
	var stdout, stderr bytes.Buffer
	failingRunner := func(context.Context, []string, string, ...string) ([]byte, error) {
		return nil, errors.New("step failure")
	}
	code := run(context.Background(), nil, &stdout, &stderr,
		failingRunner, fakeFinderOK(nil), fakeReaderOK(), fakeFormatterIdentity(), fakeCreatorOK())
	if code != 1 {
		t.Fatalf("run() = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "verify module checksums") {
		t.Fatalf("stderr = %q, want first step failure", stderr.String())
	}
}

func TestRunStopsWhenDirectoryCreationFails(t *testing.T) {
	var stdout, stderr bytes.Buffer
	failingCreator := func(string, os.FileMode) error {
		return errors.New("mkdir failure")
	}
	code := run(context.Background(), nil, &stdout, &stderr,
		fakeRunnerOK(""), fakeFinderOK(nil), fakeReaderOK(), fakeFormatterIdentity(), failingCreator)
	if code != 1 {
		t.Fatalf("run() = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "create build directory") {
		t.Fatalf("stderr = %q, want mkdir error", stderr.String())
	}
}

func TestRunStopsWhenLinuxBuildFails(t *testing.T) {
	var stdout, stderr bytes.Buffer
	failingLinuxRunner := func(_ context.Context, environment []string, _ string, _ ...string) ([]byte, error) {
		if len(environment) > 0 {
			return nil, errors.New("linux build failure")
		}
		return nil, nil
	}
	code := run(context.Background(), nil, &stdout, &stderr,
		failingLinuxRunner, fakeFinderOK(nil), fakeReaderOK(), fakeFormatterIdentity(), fakeCreatorOK())
	if code != 1 {
		t.Fatalf("run() = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "linux build failure") {
		t.Fatalf("stderr = %q, want linux build failure", stderr.String())
	}
}

func TestRunSuccessExecutesEveryGate(t *testing.T) {
	var stdout, stderr bytes.Buffer
	executed := make([]string, 0)
	recorder := func(_ context.Context, _ []string, executable string, arguments ...string) ([]byte, error) {
		executed = append(executed, executable+" "+strings.Join(arguments, " "))
		return nil, nil
	}
	code := run(context.Background(), nil, &stdout, &stderr,
		recorder, fakeFinderOK(nil), fakeReaderOK(), fakeFormatterIdentity(), fakeCreatorOK())
	if code != 0 {
		t.Fatalf("run() = %d, want 0; stderr = %q", code, stderr.String())
	}
	joined := strings.Join(executed, "\n")
	for _, required := range []string{
		"go mod verify",
		"go mod tidy -diff",
		"go -C tools mod download",
		"go -C tools mod verify",
		"go -C tools mod tidy -diff",
		"go tool -modfile tools/go.mod staticcheck ./...",
		"go test -mod=readonly ./...",
		"go run -mod=readonly ./cmd/check-coverage",
		"go test -mod=readonly -race ./...",
		"go vet ./...",
		"go tool -modfile tools/go.mod govulncheck ./...",
		"go test -mod=readonly ./internal/dependency/adapters/inbound/config -run=^$ -fuzz=FuzzFromEnv -fuzztime=50000x -parallel=1",
		"go test -mod=readonly ./internal/dependency/adapters/inbound/config -run=^$ -fuzz=FuzzBindingsFromEnv -fuzztime=50000x -parallel=1",
		"go tool -modfile tools/go.mod lefthook validate",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("executed steps do not contain %q:\n%s", required, joined)
		}
	}
	for _, controller := range controllerPackages {
		build := "go build -mod=readonly -trimpath -o " + linuxBuildDirectory + "/" + controller + " ./cmd/" + controller
		if !strings.Contains(joined, build) {
			t.Fatalf("executed steps do not contain %q:\n%s", build, joined)
		}
		provenance := "go version -m " + linuxBuildDirectory + "/" + controller
		if !strings.Contains(joined, provenance) {
			t.Fatalf("executed steps do not contain %q:\n%s", provenance, joined)
		}
	}
	if !strings.Contains(stdout.String(), "completed successfully") {
		t.Fatalf("stdout = %q, want success message", stdout.String())
	}
}

func TestRunSuccessOrdersSecurityAndFuzzGates(t *testing.T) {
	var stdout, stderr bytes.Buffer
	executed := make([]string, 0)
	recorder := func(_ context.Context, _ []string, executable string, arguments ...string) ([]byte, error) {
		executed = append(executed, executable+" "+strings.Join(arguments, " "))
		return nil, nil
	}
	code := run(context.Background(), nil, &stdout, &stderr,
		recorder, fakeFinderOK(nil), fakeReaderOK(), fakeFormatterIdentity(), fakeCreatorOK())
	if code != 0 {
		t.Fatalf("run() = %d, want 0; stderr = %q", code, stderr.String())
	}

	orderedSteps := []string{
		"go mod verify",
		"go mod tidy -diff",
		"go -C tools mod download",
		"go -C tools mod verify",
		"go -C tools mod tidy -diff",
		"go tool -modfile tools/go.mod staticcheck ./...",
		"go test -mod=readonly ./...",
		"go run -mod=readonly ./cmd/check-coverage",
		"go test -mod=readonly -race ./...",
		"go vet ./...",
		"go tool -modfile tools/go.mod govulncheck ./...",
		"go test -mod=readonly ./internal/dependency/adapters/inbound/config -run=^$ -fuzz=FuzzFromEnv -fuzztime=50000x -parallel=1",
		"go test -mod=readonly ./internal/dependency/adapters/inbound/config -run=^$ -fuzz=FuzzBindingsFromEnv -fuzztime=50000x -parallel=1",
		"go tool -modfile tools/go.mod lefthook validate",
		"go build -mod=readonly -trimpath -o " + linuxBuildDirectory + "/dependency-intake-controller ./cmd/dependency-intake-controller",
	}
	previous := -1
	for _, expected := range orderedSteps {
		index := slices.Index(executed, expected)
		if index < 0 {
			t.Fatalf("executed steps do not contain %q:\n%s", expected, strings.Join(executed, "\n"))
		}
		if index < previous {
			t.Fatalf("step %q executed at position %d, after position %d; want increasing order", expected, index, previous)
		}
		previous = index
	}
}

func TestCheckFormatting(t *testing.T) {
	t.Run("list error", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		failingFinder := func(string) ([]string, error) {
			return nil, errors.New("walk failure")
		}
		if checkFormatting(&stdout, &stderr, failingFinder, fakeReaderOK(), fakeFormatterIdentity()) {
			t.Fatal("checkFormatting() = true, want false")
		}
	})

	t.Run("read error", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		failingReader := func(string) ([]byte, error) {
			return nil, errors.New("read failure")
		}
		if checkFormatting(&stdout, &stderr, fakeFinderOK([]string{"main.go"}), failingReader, fakeFormatterIdentity()) {
			t.Fatal("checkFormatting() = true, want false")
		}
	})

	t.Run("format error", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		failingFormatter := func([]byte) ([]byte, error) {
			return nil, errors.New("format failure")
		}
		if checkFormatting(&stdout, &stderr, fakeFinderOK([]string{"main.go"}), fakeReaderOK(), failingFormatter) {
			t.Fatal("checkFormatting() = true, want false")
		}
	})

	t.Run("unformatted file", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		reformatter := func([]byte) ([]byte, error) {
			return []byte("package main\n\n// changed\n"), nil
		}
		if checkFormatting(&stdout, &stderr, fakeFinderOK([]string{"main.go"}), fakeReaderOK(), reformatter) {
			t.Fatal("checkFormatting() = true, want false")
		}
		if !strings.Contains(stderr.String(), "main.go") {
			t.Fatalf("stderr = %q, want file name", stderr.String())
		}
	})

	t.Run("crlf normalized equal", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		crlfReader := func(string) ([]byte, error) {
			return []byte("package main\r\n"), nil
		}
		lfFormatter := func([]byte) ([]byte, error) {
			return []byte("package main\n"), nil
		}
		if !checkFormatting(&stdout, &stderr, fakeFinderOK([]string{"main.go"}), crlfReader, lfFormatter) {
			t.Fatalf("checkFormatting() = false, want true; stderr = %q", stderr.String())
		}
	})

	t.Run("formatted", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		if !checkFormatting(&stdout, &stderr, fakeFinderOK([]string{"main.go"}), fakeReaderOK(), fakeFormatterIdentity()) {
			t.Fatal("checkFormatting() = false, want true")
		}
	})
}

func TestRunStepWritesOutputAndReportsError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	okStep := step{name: "ok", executable: "go", arguments: []string{"version"}}
	if !runStep(context.Background(), okStep, &stdout, &stderr, fakeRunnerOK("some-output")) {
		t.Fatal("runStep() = false, want true")
	}
	if !strings.Contains(stdout.String(), "some-output") {
		t.Fatalf("stdout = %q, want step output", stdout.String())
	}

	failingRunner := func(context.Context, []string, string, ...string) ([]byte, error) {
		return nil, errors.New("boom")
	}
	if runStep(context.Background(), okStep, &stdout, &stderr, failingRunner) {
		t.Fatal("runStep() = true, want false")
	}
	if !strings.Contains(stderr.String(), "boom") {
		t.Fatalf("stderr = %q, want error", stderr.String())
	}
}

func TestRunStepsStopsOnFirstFailure(t *testing.T) {
	var stdout, stderr bytes.Buffer
	calls := 0
	recorder := func(context.Context, []string, string, ...string) ([]byte, error) {
		calls++
		return nil, errors.New("boom")
	}
	steps := []step{
		{name: "first", executable: "go"},
		{name: "second", executable: "go"},
	}
	if runSteps(context.Background(), steps, &stdout, &stderr, recorder) {
		t.Fatal("runSteps() = true, want false")
	}
	if calls != 1 {
		t.Fatalf("runSteps() executed %d steps, want 1", calls)
	}
}

func TestGoFilesFindsGoSources(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a.go", "b.txt", filepath.Join("sub", "c.go")} {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("package main\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, directory := range []string{".build", "vendor"} {
		path := filepath.Join(root, directory, "skip.go")
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("package main\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	files, err := goFiles(root)
	if err != nil {
		t.Fatalf("goFiles() error = %v", err)
	}
	want := []string{
		filepath.Join(root, "a.go"),
		filepath.Join(root, "sub", "c.go"),
	}
	if strings.Join(files, "|") != strings.Join(want, "|") {
		t.Fatalf("goFiles() = %v, want %v", files, want)
	}
}

func TestGoFilesPropagatesWalkError(t *testing.T) {
	if _, err := goFiles(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("goFiles() error = nil, want error")
	}
}

func TestIgnoredDirectory(t *testing.T) {
	for _, name := range []string{".build", ".git", ".cache", "coverage", "dist", "vendor"} {
		if !ignoredDirectory(name) {
			t.Errorf("ignoredDirectory(%q) = false, want true", name)
		}
	}
	if ignoredDirectory("cmd") {
		t.Error("ignoredDirectory(cmd) = true, want false")
	}
}

func TestNormalizeLineEndings(t *testing.T) {
	if got := normalizeLineEndings([]byte("a\r\nb\r\n")); string(got) != "a\nb\n" {
		t.Fatalf("normalizeLineEndings() = %q, want %q", got, "a\nb\n")
	}
}

func TestRunCommand(t *testing.T) {
	output, err := runCommand(context.Background(), nil, "go", "version")
	if err != nil {
		t.Fatalf("runCommand(go version) error = %v", err)
	}
	if !strings.Contains(string(output), "go version") {
		t.Fatalf("runCommand(go version) = %q, want version output", string(output))
	}

	if _, err := runCommand(context.Background(), nil, "definitely-not-a-real-command-xyz"); err == nil {
		t.Fatal("runCommand(unknown) error = nil, want error")
	}
}
