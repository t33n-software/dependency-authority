package config

import (
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
