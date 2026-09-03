package config

import (
	"testing"
)

func bindingsEnv(values map[string]string) func(string) string {
	return func(key string) string {
		return values[key]
	}
}

func TestBindingsFromEnvRejectsNilLookup(t *testing.T) {
	if _, err := BindingsFromEnv(nil); err == nil {
		t.Fatal("BindingsFromEnv() error = nil, want nil lookup error")
	}
}

func TestBindingsFromEnvBindsEveryValue(t *testing.T) {
	bindings, err := BindingsFromEnv(bindingsEnv(map[string]string{
		EnvUpstreamEndpoint:   " https://europe-west3-go.pkg.dev/p/intake ",
		EnvApprovedEndpoint:   "https://europe-west3-go.pkg.dev/p/approved",
		EnvArtifactAPI:        "https://artifactregistry.googleapis.com",
		EnvEvidenceRepository: "projects/p/locations/l/repositories/evidence",
		EnvApprovedRepository: "projects/p/locations/l/repositories/approved",
		EnvPolicyBundle:       "policies/go.json",
		EnvScannerTool:        "tools/osv-scanner",
		EnvScannerDatabase:    "tools/osv-db",
		EnvScanContentRoot:    "work/content",
	}))
	if err != nil {
		t.Fatalf("BindingsFromEnv() error = %v", err)
	}

	for name, got := range map[string]struct {
		got  string
		want string
	}{
		"upstream endpoint":   {bindings.UpstreamEndpoint(), "https://europe-west3-go.pkg.dev/p/intake"},
		"approved endpoint":   {bindings.ApprovedEndpoint(), "https://europe-west3-go.pkg.dev/p/approved"},
		"artifact api":        {bindings.ArtifactAPI(), "https://artifactregistry.googleapis.com"},
		"evidence repository": {bindings.EvidenceRepository(), "projects/p/locations/l/repositories/evidence"},
		"approved repository": {bindings.ApprovedRepository(), "projects/p/locations/l/repositories/approved"},
		"policy bundle":       {bindings.PolicyBundle(), "policies/go.json"},
		"scanner tool":        {bindings.ScannerTool(), "tools/osv-scanner"},
		"scanner database":    {bindings.ScannerDatabase(), "tools/osv-db"},
		"scan content root":   {bindings.ScanContentRoot(), "work/content"},
	} {
		if got.got != got.want {
			t.Errorf("%s = %q, want %q", name, got.got, got.want)
		}
	}
}

func TestBindingsFromEnvEmptyEnvironment(t *testing.T) {
	bindings, err := BindingsFromEnv(bindingsEnv(map[string]string{}))
	if err != nil {
		t.Fatalf("BindingsFromEnv() error = %v", err)
	}
	for name, got := range map[string]string{
		"upstream endpoint":   bindings.UpstreamEndpoint(),
		"approved endpoint":   bindings.ApprovedEndpoint(),
		"artifact api":        bindings.ArtifactAPI(),
		"evidence repository": bindings.EvidenceRepository(),
		"approved repository": bindings.ApprovedRepository(),
		"policy bundle":       bindings.PolicyBundle(),
		"scanner tool":        bindings.ScannerTool(),
		"scanner database":    bindings.ScannerDatabase(),
		"scan content root":   bindings.ScanContentRoot(),
	} {
		if got != "" {
			t.Errorf("%s = %q, want empty", name, got)
		}
	}
}
