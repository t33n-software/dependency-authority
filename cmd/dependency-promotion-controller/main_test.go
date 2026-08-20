package main

import (
	"context"
	"io"
	"testing"

	"github.com/t33n-software/dependency-authority/internal/dependency/bootstrap"
)

func TestMainRunsPromotionController(t *testing.T) {
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
