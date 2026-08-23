// Command check-coverage enforces test-source presence and complete statement coverage.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

type commandRunner func(context.Context, string, ...string) ([]byte, error)

var (
	exitProcess = os.Exit
	commandArgs = os.Args
	runCommand  = runGoCommand
	version     = "devel"
)

func main() {
	exitProcess(run(context.Background(), commandArgs[1:], os.Stdout, os.Stderr, runCommand))
}

func run(ctx context.Context, arguments []string, stdout io.Writer, stderr io.Writer, execute commandRunner) int {
	if len(arguments) == 1 && arguments[0] == "--version" {
		fmt.Fprintf(stdout, "check-coverage %s\n", version)
		return 0
	}
	if len(arguments) != 0 {
		fmt.Fprintln(stderr, "usage: check-coverage")
		return 2
	}
	if ctx == nil {
		ctx = context.Background()
	}

	output, err := execute(ctx, "go", "test", "-count=1", "-cover", "./...")
	if len(output) > 0 {
		_, _ = stdout.Write(output)
	}
	if err != nil {
		fmt.Fprintln(stderr, "run Go coverage:", err)
		return 1
	}

	missingTests := packagesWithoutTests(string(output))
	incomplete := incompletePackages(string(output))
	if len(missingTests) > 0 {
		fmt.Fprintln(stderr, "every Go package must contain at least one _test.go file:")
		for _, line := range missingTests {
			fmt.Fprintln(stderr, line)
		}
	}
	if len(incomplete) > 0 {
		fmt.Fprintln(stderr, "every executable Go package must reach 100.0% statement coverage:")
		for _, line := range incomplete {
			fmt.Fprintln(stderr, line)
		}
	}
	if len(missingTests) > 0 || len(incomplete) > 0 {
		return 1
	}

	fmt.Fprintln(stdout, "All Go packages contain test files and all executable Go packages reached 100.0% statement coverage.")
	return 0
}

func runGoCommand(ctx context.Context, executable string, arguments ...string) ([]byte, error) {
	return exec.CommandContext(ctx, executable, arguments...).CombinedOutput()
}

func packagesWithoutTests(output string) []string {
	lines := strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n")
	packages := make([]string, 0)
	for _, line := range lines {
		if strings.Contains(line, "[no test files]") {
			packages = append(packages, line)
		}
	}
	return packages
}

func incompletePackages(output string) []string {
	lines := strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n")
	incomplete := make([]string, 0)
	for _, line := range lines {
		fields := strings.Fields(line)
		for index, field := range fields {
			if field != "coverage:" || index+1 >= len(fields) {
				continue
			}
			if fields[index+1] != "100.0%" && fields[index+1] != "[no" {
				incomplete = append(incomplete, line)
			}
		}
	}
	return incomplete
}
