package bootstrap

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/t33n-software/dependency-authority/internal/dependency/adapters/inbound/config"
	"github.com/t33n-software/dependency-authority/internal/dependency/adapters/outbound/artifactregistry"
	"github.com/t33n-software/dependency-authority/internal/dependency/adapters/outbound/evidence"
	"github.com/t33n-software/dependency-authority/internal/dependency/adapters/outbound/policy"
	"github.com/t33n-software/dependency-authority/internal/dependency/adapters/outbound/scanner"
	"github.com/t33n-software/dependency-authority/internal/dependency/adapters/outbound/upstream"
	"github.com/t33n-software/dependency-authority/internal/dependency/adapters/outbound/workloadidentity"
)

// PortsBuilder constructs the outbound ports from the process environment.
type PortsBuilder func(lookup func(string) string) (Ports, error)

// PortsFromEnv constructs the outbound adapters bound by the lane
// environment. An adapter binds only when its complete environment contract
// is present; a lane requiring an unbound adapter fails closed at bind time,
// and a present-but-invalid binding fails closed here.
func PortsFromEnv(lookup func(string) string) (Ports, error) {
	bindings, err := config.BindingsFromEnv(lookup)
	if err != nil {
		return Ports{}, err
	}

	ports := Ports{Now: time.Now}
	httpClient := &http.Client{Timeout: 30 * time.Second}

	// The workload-internal authentication contract: the adapters authenticate
	// with short-lived tokens from the identity attached to the workload,
	// obtained at runtime through the provider instance metadata mechanism. No
	// credential is injected through the environment.
	token := workloadidentity.NewGCPSource().Token

	if bindings.UpstreamEndpoint() != "" {
		proxy, err := upstream.NewProxy(bindings.UpstreamEndpoint(), token, httpClient)
		if err != nil {
			return Ports{}, fmt.Errorf("bind upstream adapter: %w", err)
		}
		ports.Upstream = proxy
	}

	if bindings.PolicyBundle() != "" {
		// The non-empty guard and the fixed reader make this construction
		// total.
		bundle, _ := policy.NewBundle(bindings.PolicyBundle(), os.ReadFile)
		ports.Policies = bundle
	}

	if bindings.ScannerTool() != "" && bindings.ScannerDatabase() != "" && bindings.ScanContentRoot() != "" {
		// The three-part guard and the fixed runner make this construction
		// total.
		adapter, _ := scanner.NewOSV(bindings.ScannerTool(), bindings.ScannerDatabase(), bindings.ScanContentRoot(), scanner.ExecRunner)
		ports.Scanner = adapter
	}

	if bindings.ArtifactAPI() != "" {
		client, err := artifactregistry.NewClient(bindings.ArtifactAPI(), token, httpClient)
		if err != nil {
			return Ports{}, fmt.Errorf("bind artifact registry transport: %w", err)
		}
		if bindings.EvidenceRepository() != "" {
			records, err := artifactregistry.NewRecords(client, bindings.EvidenceRepository(), time.Now)
			if err != nil {
				return Ports{}, fmt.Errorf("bind candidate records adapter: %w", err)
			}
			ports.Candidates = records

			// The transport and the repository binding were validated by the
			// client and records constructions above; the evidence store over
			// the same values is total.
			store, _ := evidence.NewStore(bindings.ArtifactAPI(), bindings.EvidenceRepository(), token, httpClient)
			ports.EvidenceStore = store
			ports.Recorder = store
			ports.Journal = store
		}
		if bindings.ApprovedRepository() != "" {
			gate, err := artifactregistry.NewGate(client, bindings.ApprovedRepository())
			if err != nil {
				return Ports{}, fmt.Errorf("bind download gate adapter: %w", err)
			}
			ports.Gate = gate

			if bindings.UpstreamEndpoint() != "" && bindings.ApprovedEndpoint() != "" {
				publisher, err := artifactregistry.NewPublisher(client, bindings.UpstreamEndpoint(), bindings.ApprovedEndpoint(), bindings.ApprovedRepository(), artifactregistry.ExecRunner, artifactregistry.ModuleWorkspace)
				if err != nil {
					return Ports{}, fmt.Errorf("bind publisher adapter: %w", err)
				}
				ports.Registry = publisher
			}
		}
	}
	return ports, nil
}
