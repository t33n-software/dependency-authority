// Command dependency-admission-controller runs the admission lane controller.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/t33n-software/dependency-authority/internal/dependency/bootstrap"
)

var (
	exitProcess = os.Exit
	run         = bootstrap.RunAdmission
	lookupEnv   = os.Getenv
	buildPorts  = bootstrap.PortsFromEnv
	commandArgs = os.Args
	version     = "devel"
)

func main() {
	runtimeContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	exitProcess(runMain(runtimeContext, commandArgs[1:], lookupEnv, buildPorts, os.Stdout, os.Stderr))
}

// runMain serves the conventional version surface before delegating to the
// lane runtime.
func runMain(ctx context.Context, arguments []string, lookup func(string) string, build bootstrap.PortsBuilder, stdout io.Writer, stderr io.Writer) int {
	if len(arguments) == 1 && arguments[0] == "--version" {
		fmt.Fprintf(stdout, "dependency-admission-controller %s\n", version)
		return 0
	}
	return run(ctx, lookup, build, stdout, stderr)
}
