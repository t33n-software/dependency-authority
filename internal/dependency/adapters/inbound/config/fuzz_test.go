package config

import (
	"strings"
	"testing"
	"time"

	"github.com/t33n-software/dependency-authority/internal/dependency/domain/candidate"
)

func FuzzFromEnv(f *testing.F) {
	for _, seed := range [][2]string{
		{"control", "go"},
		{"intake", "npm"},
		{"quarantine", "python"},
		{"approved", ""},
		{"evidence", "go"},
		{"", ""},
		{"CONTROL", "GO"},
		{"\x00", "\x00"},
	} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, zone, ecosystem string) {
		lookup := func(name string) string {
			switch name {
			case EnvZone:
				return zone
			case EnvEcosystem:
				return ecosystem
			default:
				return ""
			}
		}
		cfg, err := FromEnv(lookup)
		valid := Zone(zone).Valid() && candidate.Ecosystem(ecosystem).Valid()
		switch {
		case valid && err != nil:
			t.Fatalf("FromEnv(%q, %q) error = %v, want success", zone, ecosystem, err)
		case !valid && err == nil:
			t.Fatalf("FromEnv(%q, %q) succeeded, want error", zone, ecosystem)
		case err == nil:
			if cfg.Zone() != Zone(zone) || cfg.Ecosystem() != candidate.Ecosystem(ecosystem) {
				t.Fatalf("FromEnv(%q, %q) bound zone %q and ecosystem %q",
					zone, ecosystem, cfg.Zone(), cfg.Ecosystem())
			}
		}
	})
}

func FuzzBindingsFromEnv(f *testing.F) {
	for _, seed := range [][2]string{
		{"https://europe-west3-go.pkg.dev/p/r", "projects/p/locations/l/repositories/r"},
		{"", ""},
		{"not a url", "bogus"},
		{"\x00", "\x00"},
	} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, endpoint, repository string) {
		lookup := func(name string) string {
			switch name {
			case EnvUpstreamEndpoint, EnvApprovedEndpoint, EnvArtifactAPI:
				return endpoint
			case EnvEvidenceRepository, EnvApprovedRepository:
				return repository
			default:
				return ""
			}
		}
		bindings, err := BindingsFromEnv(lookup)
		if err != nil {
			t.Fatalf("BindingsFromEnv(%q, %q) error = %v, want the pure loader to succeed", endpoint, repository, err)
		}
		if bindings.UpstreamEndpoint() != strings.TrimSpace(endpoint) {
			t.Fatalf("UpstreamEndpoint() = %q, want the trimmed input", bindings.UpstreamEndpoint())
		}
		if bindings.EvidenceRepository() != strings.TrimSpace(repository) {
			t.Fatalf("EvidenceRepository() = %q, want the trimmed input", bindings.EvidenceRepository())
		}
	})
}

func FuzzOperationFromEnv(f *testing.F) {
	for _, seed := range [][3]string{
		{"github.com/google/go-cmp", "v0.7.0", "72h"},
		{"", "", ""},
		{"  ", "  ", "  "},
		{"mod", "v1", "soon"},
		{"mod", "v1", "-1h"},
		{"mod", "v1", "0s"},
		{"\x00", "\x00", "\x00"},
	} {
		f.Add(seed[0], seed[1], seed[2])
	}
	f.Fuzz(func(t *testing.T, module, version, ttl string) {
		lookup := func(name string) string {
			switch name {
			case EnvModule:
				return module
			case EnvVersion:
				return version
			case EnvApprovalTTL:
				return ttl
			default:
				return ""
			}
		}
		operation, err := OperationFromEnv(lookup, FieldModule, FieldVersion, FieldApprovalTTL)
		trimmedTTL := strings.TrimSpace(ttl)
		parsed, parseErr := time.ParseDuration(trimmedTTL)
		valid := strings.TrimSpace(module) != "" && strings.TrimSpace(version) != "" && trimmedTTL != "" && parseErr == nil && parsed > 0
		if valid && err != nil {
			t.Fatalf("OperationFromEnv(%q, %q, %q) error = %v, want success", module, version, ttl, err)
		}
		if !valid && err == nil {
			t.Fatalf("OperationFromEnv(%q, %q, %q) succeeded, want error", module, version, ttl)
		}
		if err == nil {
			if operation.Module() != strings.TrimSpace(module) || operation.Version() != strings.TrimSpace(version) {
				t.Fatalf("OperationFromEnv() bound %q %q, want the trimmed inputs", operation.Module(), operation.Version())
			}
			if operation.ApprovalTTL() != parsed {
				t.Fatalf("ApprovalTTL() = %v, want %v", operation.ApprovalTTL(), parsed)
			}
		}
	})
}
