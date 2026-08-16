package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

func restoreSeams(t *testing.T) {
	t.Helper()
	originalExit := exitProcess
	originalArgs := commandArgs
	originalRun := runCommand
	t.Cleanup(func() {
		exitProcess = originalExit
		commandArgs = originalArgs
		runCommand = originalRun
	})
}

func TestMainExitsWithRunResult(t *testing.T) {
	restoreSeams(t)
	exitCode := -1
	exitProcess = func(code int) { exitCode = code }
	commandArgs = []string{"check-coverage"}
	runCommand = func(context.Context, string, ...string) ([]byte, error) {
		return []byte("ok  \texample/pkg\tcoverage: 100.0% of statements\n"), nil
	}

	main()

	if exitCode != 0 {
		t.Fatalf("main() exit code = %d, want 0", exitCode)
	}
}

func TestRunRejectsArguments(t *testing.T) {
	var stdout, stderr bytes.Buffer
	runner := func(context.Context, string, ...string) ([]byte, error) {
		return nil, nil
	}
	code := run(context.Background(), []string{"unexpected"}, &stdout, &stderr, runner)
	if code != 2 {
		t.Fatalf("run() = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "usage: check-coverage") {
		t.Fatalf("stderr = %q, want usage", stderr.String())
	}
}

func TestRunWithNilContextUsesBackground(t *testing.T) {
	var stdout, stderr bytes.Buffer
	runner := func(context.Context, string, ...string) ([]byte, error) {
		return []byte("ok  \texample/pkg\tcoverage: 100.0% of statements\n"), nil
	}
	if code := run(testNilContext(), nil, &stdout, &stderr, runner); code != 0 {
		t.Fatalf("run() = %d, want 0", code)
	}
}

func testNilContext() context.Context {
	return nil
}

func TestRunReportsCommandError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	runner := func(context.Context, string, ...string) ([]byte, error) {
		return []byte("partial output"), errors.New("go test failure")
	}
	code := run(context.Background(), nil, &stdout, &stderr, runner)
	if code != 1 {
		t.Fatalf("run() = %d, want 1", code)
	}
	if !strings.Contains(stdout.String(), "partial output") {
		t.Fatalf("stdout = %q, want command output", stdout.String())
	}
	if !strings.Contains(stderr.String(), "run Go coverage") {
		t.Fatalf("stderr = %q, want coverage error", stderr.String())
	}
}

func TestRunReportsPackagesWithoutTests(t *testing.T) {
	var stdout, stderr bytes.Buffer
	runner := func(context.Context, string, ...string) ([]byte, error) {
		return []byte("?   \texample/pkg\t[no test files]\n"), nil
	}
	code := run(context.Background(), nil, &stdout, &stderr, runner)
	if code != 1 {
		t.Fatalf("run() = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "must contain at least one _test.go file") {
		t.Fatalf("stderr = %q, want missing tests message", stderr.String())
	}
}

func TestRunReportsIncompleteCoverage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	runner := func(context.Context, string, ...string) ([]byte, error) {
		return []byte("ok  \texample/pkg\tcoverage: 99.0% of statements\n"), nil
	}
	code := run(context.Background(), nil, &stdout, &stderr, runner)
	if code != 1 {
		t.Fatalf("run() = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "100.0% statement coverage") {
		t.Fatalf("stderr = %q, want coverage message", stderr.String())
	}
}

func TestRunSuccess(t *testing.T) {
	var stdout, stderr bytes.Buffer
	runner := func(context.Context, string, ...string) ([]byte, error) {
		return []byte("ok  \texample/pkg\tcoverage: 100.0% of statements\n"), nil
	}
	code := run(context.Background(), nil, &stdout, &stderr, runner)
	if code != 0 {
		t.Fatalf("run() = %d, want 0", code)
	}
	if !strings.Contains(stdout.String(), "100.0% statement coverage") {
		t.Fatalf("stdout = %q, want success message", stdout.String())
	}
}

func TestPackagesWithoutTests(t *testing.T) {
	output := "?   \texample/a\t[no test files]\r\nok  \texample/b\tcoverage: 100.0% of statements\n"
	missing := packagesWithoutTests(output)
	if len(missing) != 1 || !strings.Contains(missing[0], "example/a") {
		t.Fatalf("packagesWithoutTests() = %v, want example/a", missing)
	}
	if len(packagesWithoutTests("ok  \texample/b\tcoverage: 100.0% of statements\n")) != 0 {
		t.Fatal("packagesWithoutTests() found unexpected package")
	}
}

func TestIncompletePackages(t *testing.T) {
	cases := map[string]int{
		"ok  \texample/a\tcoverage: 100.0% of statements\n":  0,
		"?   \texample/a\tcoverage: [no test files]\n":       0,
		"ok  \texample/a\tcoverage: 99.9% of statements\n":   1,
		"ok  \texample/a\tcoverage:\n":                       0,
		"ok  \texample/a\twithout coverage field\n":          0,
		"ok  \texample/a\tcoverage: 99.9% of statements\r\n": 1,
	}
	for output, want := range cases {
		if got := len(incompletePackages(output)); got != want {
			t.Errorf("incompletePackages(%q) = %d entries, want %d", output, got, want)
		}
	}
}
