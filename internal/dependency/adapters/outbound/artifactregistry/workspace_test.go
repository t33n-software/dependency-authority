package artifactregistry

import (
	"errors"
	"os"
	"testing"
)

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
