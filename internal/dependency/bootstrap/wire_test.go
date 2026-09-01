package bootstrap

import (
	"context"
	"testing"

	"github.com/t33n-software/dependency-authority/internal/dependency/adapters/inbound/config"
)

func envBinding(values map[string]string) func(string) string {
	return func(key string) string {
		return values[key]
	}
}

func fullLaneEnv() map[string]string {
	return map[string]string{
		config.EnvUpstreamEndpoint:   "https://europe-west3-go.pkg.dev/example-intake/go-dependencies-intake",
		config.EnvApprovedEndpoint:   "https://europe-west3-go.pkg.dev/example-approved/go-dependencies-approved",
		config.EnvArtifactAPI:        "https://artifactregistry.googleapis.com",
		config.EnvEvidenceRepository: "projects/p/locations/l/repositories/evidence",
		config.EnvApprovedRepository: "projects/p/locations/l/repositories/approved",
		config.EnvPolicyBundle:       "policies/go.json",
		config.EnvScannerTool:        "tools/osv-scanner",
		config.EnvScannerDatabase:    "tools/osv-db",
		config.EnvScanContentRoot:    "work/content",
		config.EnvAccessToken:        "token",
	}
}

func TestPortsFromEnvRejectsInvalidBindings(t *testing.T) {
	if _, err := PortsFromEnv(nil); err == nil {
		t.Fatal("PortsFromEnv( nil lookup ) error = nil, want error")
	}
	if _, err := PortsFromEnv(envBinding(map[string]string{
		config.EnvUpstreamEndpoint: "http://plaintext.example.com",
	})); err == nil {
		t.Fatal("PortsFromEnv( invalid endpoint ) error = nil, want error")
	}
}

func TestPortsFromEnvEmptyEnvironmentBindsNoAdapter(t *testing.T) {
	ports, err := PortsFromEnv(envBinding(map[string]string{}))
	if err != nil {
		t.Fatalf("PortsFromEnv() error = %v", err)
	}
	if ports.Now == nil {
		t.Fatal("PortsFromEnv() Now = nil, want the lane clock")
	}
	if ports.Upstream != nil || ports.Scanner != nil || ports.Policies != nil || ports.Candidates != nil || ports.EvidenceStore != nil || ports.Registry != nil || ports.Gate != nil || ports.Recorder != nil {
		t.Fatalf("PortsFromEnv() = %+v, want every adapter unbound", ports)
	}
}

func TestPortsFromEnvBindsUpstreamAndPolicy(t *testing.T) {
	ports, err := PortsFromEnv(envBinding(map[string]string{
		config.EnvUpstreamEndpoint: "https://europe-west3-go.pkg.dev/p/r",
		config.EnvPolicyBundle:     "policies/go.json",
	}))
	if err != nil {
		t.Fatalf("PortsFromEnv() error = %v", err)
	}
	if ports.Upstream == nil || ports.Policies == nil {
		t.Fatal("PortsFromEnv() left upstream or policy unbound")
	}
	if ports.Scanner != nil || ports.Candidates != nil || ports.Registry != nil || ports.Gate != nil || ports.EvidenceStore != nil || ports.Recorder != nil {
		t.Fatal("PortsFromEnv() bound an adapter without its environment contract")
	}
}

func TestPortsFromEnvBindsTheCompleteScannerContract(t *testing.T) {
	partial, err := PortsFromEnv(envBinding(map[string]string{
		config.EnvScannerTool: "tools/osv-scanner",
	}))
	if err != nil {
		t.Fatalf("PortsFromEnv() error = %v", err)
	}
	if partial.Scanner != nil {
		t.Fatal("PortsFromEnv() bound the scanner on a partial contract")
	}

	full, err := PortsFromEnv(envBinding(map[string]string{
		config.EnvScannerTool:     "tools/osv-scanner",
		config.EnvScannerDatabase: "tools/osv-db",
		config.EnvScanContentRoot: "work/content",
	}))
	if err != nil {
		t.Fatalf("PortsFromEnv() error = %v", err)
	}
	if full.Scanner == nil {
		t.Fatal("PortsFromEnv() left the scanner unbound on a complete contract")
	}
}

func TestPortsFromEnvBindsTheArtifactSurface(t *testing.T) {
	t.Run("api only", func(t *testing.T) {
		ports, err := PortsFromEnv(envBinding(map[string]string{
			config.EnvArtifactAPI: "https://artifactregistry.googleapis.com",
		}))
		if err != nil {
			t.Fatalf("PortsFromEnv() error = %v", err)
		}
		if ports.Candidates != nil || ports.EvidenceStore != nil || ports.Recorder != nil || ports.Gate != nil || ports.Registry != nil {
			t.Fatal("PortsFromEnv() bound a store without its repository contract")
		}
	})

	t.Run("evidence repository", func(t *testing.T) {
		ports, err := PortsFromEnv(envBinding(map[string]string{
			config.EnvArtifactAPI:        "https://artifactregistry.googleapis.com",
			config.EnvEvidenceRepository: "projects/p/locations/l/repositories/evidence",
		}))
		if err != nil {
			t.Fatalf("PortsFromEnv() error = %v", err)
		}
		if ports.Candidates == nil || ports.EvidenceStore == nil || ports.Recorder == nil {
			t.Fatal("PortsFromEnv() left the evidence adapters unbound")
		}
		if ports.Gate != nil || ports.Registry != nil {
			t.Fatal("PortsFromEnv() bound the approved-zone adapters without their contract")
		}
	})

	t.Run("approved repository without endpoints", func(t *testing.T) {
		ports, err := PortsFromEnv(envBinding(map[string]string{
			config.EnvArtifactAPI:        "https://artifactregistry.googleapis.com",
			config.EnvApprovedRepository: "projects/p/locations/l/repositories/approved",
		}))
		if err != nil {
			t.Fatalf("PortsFromEnv() error = %v", err)
		}
		if ports.Gate == nil {
			t.Fatal("PortsFromEnv() left the download gate unbound")
		}
		if ports.Registry != nil {
			t.Fatal("PortsFromEnv() bound the publisher without both Go endpoints")
		}
	})

	t.Run("approved repository with one endpoint", func(t *testing.T) {
		ports, err := PortsFromEnv(envBinding(map[string]string{
			config.EnvArtifactAPI:        "https://artifactregistry.googleapis.com",
			config.EnvApprovedRepository: "projects/p/locations/l/repositories/approved",
			config.EnvUpstreamEndpoint:   "https://europe-west3-go.pkg.dev/p/r",
		}))
		if err != nil {
			t.Fatalf("PortsFromEnv() error = %v", err)
		}
		if ports.Registry != nil {
			t.Fatal("PortsFromEnv() bound the publisher without the approved endpoint")
		}
	})
}

func TestPortsFromEnvBindsTheFullLaneEnvironment(t *testing.T) {
	ports, err := PortsFromEnv(envBinding(fullLaneEnv()))
	if err != nil {
		t.Fatalf("PortsFromEnv() error = %v", err)
	}
	for name, port := range map[string]any{
		"upstream":       ports.Upstream,
		"scanner":        ports.Scanner,
		"policies":       ports.Policies,
		"candidates":     ports.Candidates,
		"evidence store": ports.EvidenceStore,
		"registry":       ports.Registry,
		"gate":           ports.Gate,
		"recorder":       ports.Recorder,
	} {
		if port == nil {
			t.Errorf("PortsFromEnv() left %s unbound on the full contract", name)
		}
	}
}

func TestPortsFromEnvPropagatesAdapterValidation(t *testing.T) {
	for name, values := range map[string]map[string]string{
		"invalid artifact api": {
			config.EnvArtifactAPI: "http://plaintext.example.com",
		},
		"invalid evidence repository": {
			config.EnvArtifactAPI:        "https://artifactregistry.googleapis.com",
			config.EnvEvidenceRepository: "bogus",
		},
		"invalid approved repository": {
			config.EnvArtifactAPI:        "https://artifactregistry.googleapis.com",
			config.EnvApprovedRepository: "bogus",
		},
		"invalid approved endpoint": {
			config.EnvArtifactAPI:        "https://artifactregistry.googleapis.com",
			config.EnvApprovedRepository: "projects/p/locations/l/repositories/approved",
			config.EnvUpstreamEndpoint:   "https://europe-west3-go.pkg.dev/p/r",
			config.EnvApprovedEndpoint:   "http://plaintext.example.com",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := PortsFromEnv(envBinding(values)); err == nil {
				t.Fatal("PortsFromEnv() error = nil, want adapter validation error")
			}
		})
	}
}

func TestStaticTokenSource(t *testing.T) {
	token, err := staticTokenSource("token").token(context.Background())
	if err != nil {
		t.Fatalf("token() error = %v", err)
	}
	if token != "token" {
		t.Fatalf("token() = %q, want token", token)
	}
}
