// Command build runs the Dependency Authority source-level quality gates.
package main

import (
	"bytes"
	"context"
	"fmt"
	"go/format"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

const linuxBuildDirectory = ".build/bin"

// controllerPackages lists the lane controllers the Linux/AMD64 gate builds.
var controllerPackages = []string{
	"dependency-intake-controller",
	"dependency-admission-controller",
	"dependency-promotion-controller",
	"dependency-revalidation-controller",
	"dependency-revocation-controller",
}

type commandRunner func(context.Context, []string, string, ...string) ([]byte, error)

type goFileFinder func(string) ([]string, error)

type sourceReader func(string) ([]byte, error)

type sourceFormatter func([]byte) ([]byte, error)

type directoryCreator func(string, os.FileMode) error

type step struct {
	name        string
	environment []string
	executable  string
	arguments   []string
}

var (
	exitProcess        = os.Exit
	commandArgs        = os.Args
	runExternalCommand = runCommand
	findGoFiles        = goFiles
	readSource         = os.ReadFile
	formatSource       = format.Source
	createDirectory    = os.MkdirAll
)

func main() {
	exitProcess(run(
		context.Background(),
		commandArgs[1:],
		os.Stdout,
		os.Stderr,
		runExternalCommand,
		findGoFiles,
		readSource,
		formatSource,
		createDirectory,
	))
}

func run(
	ctx context.Context,
	arguments []string,
	stdout io.Writer,
	stderr io.Writer,
	execute commandRunner,
	locateGoFiles goFileFinder,
	read sourceReader,
	format sourceFormatter,
	makeDirectory directoryCreator,
) int {
	if len(arguments) != 0 {
		fmt.Fprintln(stderr, "usage: build")
		return 2
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if !checkFormatting(stdout, stderr, locateGoFiles, read, format) {
		return 1
	}
	if !runSteps(ctx, sourceQualitySteps(), stdout, stderr, execute) {
		return 1
	}
	if err := makeDirectory(linuxBuildDirectory, 0o755); err != nil {
		fmt.Fprintln(stderr, "create build directory:", err)
		return 1
	}
	if !runSteps(ctx, linuxBuildSteps(), stdout, stderr, execute) {
		return 1
	}

	fmt.Fprintln(stdout, "Dependency Authority source-level build completed successfully.")
	return 0
}

func sourceQualitySteps() []step {
	return []step{
		{
			name:       "verify module checksums",
			executable: "go",
			arguments:  []string{"mod", "verify"},
		},
		{
			name:       "verify module metadata",
			executable: "go",
			arguments:  []string{"mod", "tidy", "-diff"},
		},
		{
			name:       "download build tool dependencies",
			executable: "go",
			arguments:  []string{"-C", "tools", "mod", "download"},
		},
		{
			name:       "verify build tool dependencies",
			executable: "go",
			arguments:  []string{"-C", "tools", "mod", "verify"},
		},
		{
			name:       "verify build tool metadata",
			executable: "go",
			arguments:  []string{"-C", "tools", "mod", "tidy", "-diff"},
		},
		{
			name:       "run lint",
			executable: "go",
			arguments:  []string{"tool", "-modfile", "tools/go.mod", "staticcheck", "./..."},
		},
		{
			name:       "run unit tests",
			executable: "go",
			arguments:  []string{"test", "-mod=readonly", "./..."},
		},
		{
			name:       "enforce complete statement coverage",
			executable: "go",
			arguments:  []string{"run", "-mod=readonly", "./cmd/check-coverage"},
		},
		{
			name:       "run race detector",
			executable: "go",
			arguments:  []string{"test", "-mod=readonly", "-race", "./..."},
		},
		{
			name:       "run static analysis",
			executable: "go",
			arguments:  []string{"vet", "./..."},
		},
		{
			name:       "run vulnerability analysis",
			executable: "go",
			arguments:  []string{"tool", "-modfile", "tools/go.mod", "govulncheck", "./..."},
		},
		{
			name:       "fuzz inbound config boundary",
			executable: "go",
			arguments:  []string{"test", "-mod=readonly", "./internal/dependency/adapters/inbound/config", "-run=^$", "-fuzz=FuzzFromEnv", "-fuzztime=50000x", "-parallel=1"},
		},
		{
			name:       "validate Lefthook configuration",
			executable: "go",
			arguments:  []string{"tool", "-modfile", "tools/go.mod", "lefthook", "validate"},
		},
	}
}

func linuxBuildSteps() []step {
	steps := make([]step, 0, len(controllerPackages)*2)
	for _, controller := range controllerPackages {
		binaryPath := linuxBuildDirectory + "/" + controller
		steps = append(steps, step{
			name:        "build Linux AMD64 " + controller,
			environment: []string{"CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64"},
			executable:  "go",
			arguments:   []string{"build", "-mod=readonly", "-trimpath", "-o", binaryPath, "./cmd/" + controller},
		}, step{
			name:       "record Linux module provenance for " + controller,
			executable: "go",
			arguments:  []string{"version", "-m", binaryPath},
		})
	}
	return steps
}

func runSteps(ctx context.Context, steps []step, stdout io.Writer, stderr io.Writer, execute commandRunner) bool {
	for _, step := range steps {
		if !runStep(ctx, step, stdout, stderr, execute) {
			return false
		}
	}
	return true
}

func runStep(ctx context.Context, step step, stdout io.Writer, stderr io.Writer, execute commandRunner) bool {
	fmt.Fprintln(stdout, "==>", step.name)
	output, err := execute(ctx, step.environment, step.executable, step.arguments...)
	if len(output) > 0 {
		_, _ = stdout.Write(output)
	}
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", step.name, err)
		return false
	}
	return true
}

func checkFormatting(stdout io.Writer, stderr io.Writer, locateGoFiles goFileFinder, read sourceReader, format sourceFormatter) bool {
	files, err := locateGoFiles(".")
	if err != nil {
		fmt.Fprintln(stderr, "list Go files:", err)
		return false
	}

	fmt.Fprintln(stdout, "==> check Go formatting")
	unformatted := make([]string, 0)
	for _, file := range files {
		source, err := read(file)
		if err != nil {
			fmt.Fprintln(stderr, "read Go source:", err)
			return false
		}
		formatted, err := format(source)
		if err != nil {
			fmt.Fprintln(stderr, "format Go source:", err)
			return false
		}
		if !bytes.Equal(normalizeLineEndings(source), normalizeLineEndings(formatted)) {
			unformatted = append(unformatted, file)
		}
	}
	if len(unformatted) > 0 {
		fmt.Fprintln(stderr, "the following files require gofmt:")
		fmt.Fprintln(stderr, strings.Join(unformatted, "\n"))
		return false
	}
	return true
}

func normalizeLineEndings(source []byte) []byte {
	return bytes.ReplaceAll(source, []byte("\r\n"), []byte("\n"))
}

func goFiles(root string) ([]string, error) {
	files := make([]string, 0)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if ignoredDirectory(entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) == ".go" {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}

func ignoredDirectory(name string) bool {
	switch name {
	case ".build", ".git", ".cache", "coverage", "dist", "vendor":
		return true
	default:
		return false
	}
}

func runCommand(ctx context.Context, environment []string, executable string, arguments ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, executable, arguments...)
	command.Env = append(os.Environ(), environment...)
	return command.CombinedOutput()
}
