package artifactregistry

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// walkModuleTree and readModuleFile are the filesystem seams of the identity
// hash; tests bind them to fault-injecting fakes.
var (
	walkModuleTree = filepath.WalkDir
	readModuleFile = os.ReadFile
)

// dirhash computes the Go module dirhash (the h1: integrity value recorded in
// go.sum) over the materialized module tree. It is the content-identity anchor
// that survives a registry-side rezip of the module archive.
func dirhash(root string) (string, error) {
	lines := make([]string, 0)
	err := walkModuleTree(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("module tree entry %q is not a regular file", path)
		}
		rel := strings.TrimLeft(strings.TrimPrefix(path, root), `/\`)
		content, err := readModuleFile(path)
		if err != nil {
			return err
		}
		fileSum := sha256.Sum256(content)
		lines = append(lines, fmt.Sprintf("%x  %s\n", fileSum, filepath.ToSlash(rel)))
		return nil
	})
	if err != nil {
		return "", err
	}
	if len(lines) == 0 {
		return "", fmt.Errorf("module tree %q carries no files", root)
	}

	sort.Strings(lines)
	tree := sha256.New()
	for _, line := range lines {
		tree.Write([]byte(line))
	}
	return "h1:" + base64.StdEncoding.EncodeToString(tree.Sum(nil)), nil
}
