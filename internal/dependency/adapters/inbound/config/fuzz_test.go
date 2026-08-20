package config

import (
	"strings"
	"testing"

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
	for _, seed := range [][3]string{
		{"https://europe-west3-go.pkg.dev/p/r", "projects/p/locations/l/repositories/r", "token"},
		{"", "", ""},
		{"not a url", "bogus", " "},
		{"\x00", "\x00", "\x00"},
	} {
		f.Add(seed[0], seed[1], seed[2])
	}
	f.Fuzz(func(t *testing.T, endpoint, repository, token string) {
		lookup := func(name string) string {
			switch name {
			case EnvUpstreamEndpoint, EnvApprovedEndpoint, EnvArtifactAPI:
				return endpoint
			case EnvEvidenceRepository, EnvApprovedRepository:
				return repository
			case EnvAccessToken:
				return token
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
		if bindings.AccessToken() != token {
			t.Fatalf("AccessToken() = %q, want the untrimmed input", bindings.AccessToken())
		}
	})
}
