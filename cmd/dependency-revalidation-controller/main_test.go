package main

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/t33n-software/dependency-authority/internal/dependency/bootstrap"
)

func TestMainRunsRevalidationController(t *testing.T) {
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
	if stdout.String() != "dependency-revalidation-controller devel\n" {
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
