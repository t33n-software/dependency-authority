package artifactregistry

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestExecRunner(t *testing.T) {
	result, err := ExecRunner(context.Background(), ".", "go", "version")
	if err != nil {
		t.Fatalf("ExecRunner(go version) error = %v", err)
	}
	if result.ExitCode != 0 || !strings.Contains(string(result.Stdout), "go version") {
		t.Fatalf("ExecRunner(go version) = %+v, want exit 0 with version output", result)
	}

	failing, err := ExecRunner(context.Background(), ".", "go", "nosuchcommand")
	if err != nil {
		t.Fatalf("ExecRunner(go nosuchcommand) error = %v, want a result with a non-zero exit code", err)
	}
	if failing.ExitCode == 0 {
		t.Fatal("ExecRunner(go nosuchcommand) exit code = 0, want non-zero")
	}

	if _, err := ExecRunner(context.Background(), ".", "definitely-not-a-real-tool-xyz"); err == nil {
		t.Fatal("ExecRunner( unknown tool ) error = nil, want start error")
	}
}

func TestModuleWorkspace(t *testing.T) {
	dir, cleanup, err := ModuleWorkspace()
	if err != nil {
		t.Fatalf("ModuleWorkspace() error = %v", err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("workspace %q not created: %v", dir, err)
	}
	cleanup()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("workspace %q still present after cleanup: %v", dir, err)
	}
}

func TestModuleWorkspacePropagatesCreationFailure(t *testing.T) {
	original := createModuleWorkspace
	t.Cleanup(func() { createModuleWorkspace = original })
	createModuleWorkspace = func(string, string) (string, error) {
		return "", errors.New("no temp space")
	}
	if _, _, err := ModuleWorkspace(); err == nil {
		t.Fatal("ModuleWorkspace() error = nil, want creation error")
	}
}
