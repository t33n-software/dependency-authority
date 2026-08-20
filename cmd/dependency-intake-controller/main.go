// Command dependency-intake-controller runs the intake lane controller.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/t33n-software/dependency-authority/internal/dependency/bootstrap"
)

var (
	exitProcess = os.Exit
	run         = bootstrap.RunIntake
	lookupEnv   = os.Getenv
	buildPorts  = bootstrap.PortsFromEnv
)

func main() {
	runtimeContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	exitProcess(run(runtimeContext, lookupEnv, buildPorts, os.Stdout, os.Stderr))
}
