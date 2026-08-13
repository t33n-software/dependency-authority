package main

import (
	"context"
	"io"
	"testing"

	"github.com/CyberT33N/dependency-authority/internal/dependency/bootstrap"
)

func TestMainRunsAdmissionController(t *testing.T) {
	originalExit, originalRun, originalLookup := exitProcess, run, lookupEnv
	t.Cleanup(func() {
		exitProcess = originalExit
		run = originalRun
		lookupEnv = originalLookup
	})

	exitCode := -1
	exitProcess = func(code int) { exitCode = code }
	run = func(ctx context.Context, lookup func(string) string, _ bootstrap.Ports, _ io.Writer, _ io.Writer) int {
		if ctx == nil || lookup == nil {
			t.Error("run() received nil context or lookup")
		}
		return 23
	}

	main()

	if exitCode != 23 {
		t.Fatalf("main() exit code = %d, want 23", exitCode)
	}
}
