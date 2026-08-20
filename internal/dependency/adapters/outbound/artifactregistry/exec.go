package artifactregistry

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
)

// ExecRunner executes the pinned gcloud upload tool as a child process. A
// non-zero exit code is a result, not an error; only a failed start is an
// error.
func ExecRunner(ctx context.Context, dir string, name string, args ...string) (Result, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Dir = dir
	var stdout bytes.Buffer
	command.Stdout = &stdout
	err := command.Run()
	if err == nil {
		return Result{Stdout: stdout.Bytes(), ExitCode: 0}, nil
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return Result{Stdout: stdout.Bytes(), ExitCode: exitError.ExitCode()}, nil
	}
	return Result{}, err
}

// createModuleWorkspace is the workspace creation seam; tests bind it to a
// fault-injecting fake.
var createModuleWorkspace = os.MkdirTemp

// ModuleWorkspace creates the publisher's temporary module workspace and its
// best-effort cleanup.
func ModuleWorkspace() (string, func(), error) {
	dir, err := createModuleWorkspace("", "dependency-authority-module-")
	if err != nil {
		return "", nil, err
	}
	return dir, func() {
		_ = os.RemoveAll(dir)
	}, nil
}
