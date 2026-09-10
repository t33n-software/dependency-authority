package bootstrap

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/t33n-software/dependency-authority/internal/dependency/adapters/inbound/config"
	"github.com/t33n-software/dependency-authority/internal/dependency/adapters/outbound/scanner"
	"github.com/t33n-software/dependency-authority/internal/dependency/adapters/outbound/tooling"
	"github.com/t33n-software/dependency-authority/internal/dependency/adapters/outbound/workloadidentity"
	domaintooling "github.com/t33n-software/dependency-authority/internal/dependency/domain/tooling"
)

// runChannelMaterialization is the startup seam of the workload tooling
// channel materialization; the lane runtime tests bind a fake.
var runChannelMaterialization = materializeToolingChannel

// channelMaterializer is the materialization capability the bootstrap binds
// for the workload tooling channel.
type channelMaterializer interface {
	Materialize(ctx context.Context, requests ...tooling.Request) error
}

// newChannelMaterializer binds the production materializer over the
// workload-internal token source; the tests bind a fake.
var newChannelMaterializer = func(apiEndpoint string, repository string) (channelMaterializer, error) {
	return tooling.NewMaterializer(apiEndpoint, repository, workloadidentity.NewGCPSource().Token, &http.Client{Timeout: 30 * time.Second})
}

// materializeToolingChannel materializes the workload tooling channel objects
// the operation consumes, each proven fail-closed against the digest its
// bound identity carries. A lane without channel bindings materializes
// nothing; a lane whose channel bindings cannot be proven fails closed before
// its use case executes.
func materializeToolingChannel(ctx context.Context, operation Operation, lookup func(string) string) error {
	bindings, err := config.BindingsFromEnv(lookup)
	if err != nil {
		return err
	}
	requests, err := toolingChannelRequests(operation, bindings, lookup)
	if err != nil {
		return err
	}
	if len(requests) == 0 {
		return nil
	}
	materializer, err := newChannelMaterializer(bindings.ArtifactAPI(), bindings.EvidenceRepository())
	if err != nil {
		return fmt.Errorf("bind the tooling channel materializer: %w", err)
	}
	if err := materializer.Materialize(ctx, requests...); err != nil {
		return fmt.Errorf("materialize the tooling channel: %w", err)
	}
	return nil
}

// toolingChannelRequests binds the channel materialization scope of the
// operation from the lane environment: the admission and revalidation lanes
// materialize the scanner tool, the scanner database snapshot, and the policy
// bundle; the promotion lane materializes the policy bundle; every other lane
// carries no channel scope.
func toolingChannelRequests(operation Operation, bindings config.Bindings, lookup func(string) string) ([]tooling.Request, error) {
	var requests []tooling.Request
	switch operation {
	case OperationAdmission, OperationRevalidation:
		scannerRequests, err := scannerChannelRequests(bindings, lookup)
		if err != nil {
			return nil, err
		}
		requests = append(requests, scannerRequests...)
		bundleRequests, err := bundleChannelRequest(bindings, lookup)
		if err != nil {
			return nil, err
		}
		requests = append(requests, bundleRequests...)
	case OperationPromotion:
		bundleRequests, err := bundleChannelRequest(bindings, lookup)
		if err != nil {
			return nil, err
		}
		requests = append(requests, bundleRequests...)
	}
	return requests, nil
}

// scannerChannelRequests binds the scanner tool and database snapshot
// materialization of the scanning lanes. An incomplete scanner contract
// leaves the scanner unbound; the lane fails closed at bind time.
func scannerChannelRequests(bindings config.Bindings, lookup func(string) string) ([]tooling.Request, error) {
	if bindings.ScannerTool() == "" || bindings.ScannerDatabase() == "" || bindings.ScanContentRoot() == "" {
		return nil, nil
	}
	toolIdentity, err := domaintooling.ParseTool(lookup(config.EnvScannerIdentity))
	if err != nil {
		return nil, fmt.Errorf("bind %s: %w", config.EnvScannerIdentity, err)
	}
	databaseIdentity, err := domaintooling.ParseDatabase(lookup(config.EnvScannerDatabaseIdentity))
	if err != nil {
		return nil, fmt.Errorf("bind %s: %w", config.EnvScannerDatabaseIdentity, err)
	}
	// The parsed identity, the non-empty contract path, and the fixed mode make
	// these constructions total.
	tool, _ := tooling.NewRequest(toolIdentity, bindings.ScannerTool(), 0o755)
	database, _ := tooling.NewRequest(databaseIdentity, scanner.DatabaseSnapshotPath(bindings.ScannerDatabase()), 0o644)
	return []tooling.Request{tool, database}, nil
}

// bundleChannelRequest binds the admission policy bundle materialization of
// the policy-consuming lanes. An absent bundle path leaves the policy source
// unbound; the lane fails closed at bind time.
func bundleChannelRequest(bindings config.Bindings, lookup func(string) string) ([]tooling.Request, error) {
	if bindings.PolicyBundle() == "" {
		return nil, nil
	}
	identity, err := domaintooling.ParseBundle(lookup(config.EnvPolicyBundleIdentity))
	if err != nil {
		return nil, fmt.Errorf("bind %s: %w", config.EnvPolicyBundleIdentity, err)
	}
	// The parsed identity, the non-empty bundle path, and the fixed mode make
	// this construction total.
	request, _ := tooling.NewRequest(identity, bindings.PolicyBundle(), 0o644)
	return []tooling.Request{request}, nil
}
