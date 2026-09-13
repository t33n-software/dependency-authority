package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/t33n-software/dependency-authority/internal/dependency/adapters/inbound/config"
	"github.com/t33n-software/dependency-authority/internal/dependency/bootstrap"
)

const testEndpoint = "https://europe-west3-go.pkg.dev/example-approved/go-dependencies-approved"

func TestMainRunsConsumerVerificationController(t *testing.T) {
	originalExit, originalRun, originalLookup, originalBuild := exitProcess, run, lookupEnv, buildPorts
	t.Cleanup(func() {
		exitProcess = originalExit
		run = originalRun
		lookupEnv = originalLookup
		buildPorts = originalBuild
	})

	exitCode := -1
	exitProcess = func(code int) { exitCode = code }
	run = func(ctx context.Context, lookup func(string) string, build bootstrap.PortsBuilder, _ io.Writer, _ io.Writer) int {
		if ctx == nil || lookup == nil || build == nil {
			t.Error("run() received nil context, lookup, or ports builder")
		}
		return 23
	}

	main()

	if exitCode != 23 {
		t.Fatalf("main() exit code = %d, want 23", exitCode)
	}
}

func TestRunMainServesTheVersionSurface(t *testing.T) {
	var stdout bytes.Buffer
	code := runMain(context.Background(), []string{"--version"}, lookupEnv, buildPorts, &stdout, io.Discard)
	if code != 0 {
		t.Fatalf("runMain(--version) = %d, want 0", code)
	}
	if stdout.String() != "dependency-consumer-verification-controller devel\n" {
		t.Fatalf("runMain(--version) output = %q, want the version surface", stdout.String())
	}
}

func TestRunMainDelegatesToTheLaneRuntime(t *testing.T) {
	originalRun := run
	t.Cleanup(func() { run = originalRun })
	run = func(context.Context, func(string) string, bootstrap.PortsBuilder, io.Writer, io.Writer) int {
		return 23
	}

	code := runMain(context.Background(), nil, lookupEnv, buildPorts, io.Discard, io.Discard)
	if code != 23 {
		t.Fatalf("runMain() = %d, want the lane runtime code 23", code)
	}
}

// failingWriter fails every write.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}

// goAuthEnv binds the approved endpoint the credential set applies to.
func goAuthEnv(key string) string {
	if key == config.EnvApprovedEndpoint {
		return testEndpoint
	}
	return ""
}

func TestRunMainServesTheGoAuthSurface(t *testing.T) {
	original := tokenSource
	t.Cleanup(func() { tokenSource = original })
	tokenSource = func(context.Context) (string, error) { return "token-123", nil }

	var stdout bytes.Buffer
	for _, arguments := range [][]string{{"goauth"}, {"goauth", testEndpoint + "/example.com/mod/@v/list"}} {
		stdout.Reset()
		code := runMain(context.Background(), arguments, goAuthEnv, buildPorts, &stdout, io.Discard)
		if code != 0 {
			t.Fatalf("runMain(%v) = %d, want 0", arguments, code)
		}
		want := testEndpoint + "/\n\nAuthorization: Bearer token-123\n\n"
		if stdout.String() != want {
			t.Fatalf("runMain(%v) output = %q, want the GOAUTH credential set %q", arguments, stdout.String(), want)
		}
	}
}

func TestRunMainGoAuthFailsWithoutTheBindings(t *testing.T) {
	code := runMain(context.Background(), []string{"goauth"}, nil, buildPorts, io.Discard, io.Discard)
	if code != 2 {
		t.Fatalf("runMain(goauth, nil lookup) = %d, want 2", code)
	}
}

func TestRunMainGoAuthFailsWithoutTheEndpoint(t *testing.T) {
	original := tokenSource
	t.Cleanup(func() { tokenSource = original })
	tokenSource = func(context.Context) (string, error) { return "token-123", nil }

	code := runMain(context.Background(), []string{"goauth"}, func(string) string { return "" }, buildPorts, io.Discard, io.Discard)
	if code != 2 {
		t.Fatalf("runMain(goauth, no endpoint) = %d, want 2", code)
	}
}

func TestRunMainGoAuthFailsOnTheTokenSource(t *testing.T) {
	original := tokenSource
	t.Cleanup(func() { tokenSource = original })
	tokenSource = func(context.Context) (string, error) { return "", errors.New("outside the provider runtime") }

	var stderr bytes.Buffer
	code := runMain(context.Background(), []string{"goauth"}, goAuthEnv, buildPorts, io.Discard, &stderr)
	if code != 1 {
		t.Fatalf("runMain(goauth, token failure) = %d, want 1", code)
	}
	if !bytes.Contains(stderr.Bytes(), []byte("resolve the workload token")) {
		t.Fatalf("stderr = %q, want the token failure", stderr.String())
	}
}

func TestRunMainGoAuthFailsOnTheWrite(t *testing.T) {
	original := tokenSource
	t.Cleanup(func() { tokenSource = original })
	tokenSource = func(context.Context) (string, error) { return "token-123", nil }

	code := runMain(context.Background(), []string{"goauth"}, goAuthEnv, buildPorts, failingWriter{}, io.Discard)
	if code != 1 {
		t.Fatalf("runMain(goauth, write failure) = %d, want 1", code)
	}
}
