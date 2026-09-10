package artifactregistry

import "os"

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
