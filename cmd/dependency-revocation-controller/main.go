// Command dependency-revocation-controller runs the revocation lane
// controller.
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
	run         = bootstrap.RunRevocation
	lookupEnv   = os.Getenv
)

func main() {
	runtimeContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	exitProcess(run(runtimeContext, lookupEnv, bootstrap.Ports{}, os.Stdout, os.Stderr))
}
