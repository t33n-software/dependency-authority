// Command dependency-consumer-verification-controller runs the consumer
// verification lane controller and serves the GOAUTH credential surface the
// consumer contract executions authenticate through: the toolchain child
// processes invoke this binary with the goauth argument and receive the
// bearer header of the workload's own short-lived token from the provider
// instance metadata mechanism — the token never leaves the process and is
// never written to a file, the environment, or a mounted surface.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/t33n-software/dependency-authority/internal/dependency/adapters/inbound/config"
	"github.com/t33n-software/dependency-authority/internal/dependency/adapters/outbound/consumercontract"
	"github.com/t33n-software/dependency-authority/internal/dependency/adapters/outbound/workloadidentity"
	"github.com/t33n-software/dependency-authority/internal/dependency/bootstrap"
)

var (
	exitProcess = os.Exit
	run         = bootstrap.RunConsumerVerification
	lookupEnv   = os.Getenv
	buildPorts  = bootstrap.PortsFromEnv
	commandArgs = os.Args
	version     = "devel"
	// The construction of the metadata token source is total: the pinned
	// endpoint and scope constants satisfy the source contract.
	tokenSource = consumercontract.TokenSource(workloadidentity.NewGCPSource().Token)
)

func main() {
	runtimeContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	exitProcess(runMain(runtimeContext, commandArgs[1:], lookupEnv, buildPorts, os.Stdout, os.Stderr))
}

// runMain serves the conventional version surface and the GOAUTH credential
// surface before delegating to the lane runtime.
func runMain(ctx context.Context, arguments []string, lookup func(string) string, build bootstrap.PortsBuilder, stdout io.Writer, stderr io.Writer) int {
	if len(arguments) == 1 && arguments[0] == "--version" {
		fmt.Fprintf(stdout, "dependency-consumer-verification-controller %s\n", version)
		return 0
	}
	if len(arguments) >= 1 && arguments[0] == "goauth" {
		return runGoAuth(ctx, lookup, stdout, stderr)
	}
	return run(ctx, lookup, build, stdout, stderr)
}

// runGoAuth renders the GOAUTH credential set of the workload's own identity:
// the approved endpoint URL line and the bearer header of the short-lived
// token. A 4xx re-invocation of the GOAUTH contract carries the rejected URL
// as an additional argument and the response on standard input; the credential
// set is re-rendered identically, and a second rejection fails the fetch
// closed.
func runGoAuth(ctx context.Context, lookup func(string) string, stdout io.Writer, stderr io.Writer) int {
	bindings, err := config.BindingsFromEnv(lookup)
	if err != nil {
		fmt.Fprintln(stderr, "load the lane bindings:", err)
		return 2
	}
	token, err := tokenSource(ctx)
	if err != nil {
		fmt.Fprintln(stderr, "resolve the workload token:", err)
		return 1
	}
	content, err := consumercontract.CredentialSet(bindings.ApprovedEndpoint(), token)
	if err != nil {
		fmt.Fprintln(stderr, "render the credential set:", err)
		return 2
	}
	if _, err := stdout.Write(content); err != nil {
		fmt.Fprintln(stderr, "write the credential set:", err)
		return 1
	}
	return 0
}
