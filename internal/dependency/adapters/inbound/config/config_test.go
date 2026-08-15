package config

import (
	"testing"

	"github.com/t33n-software/dependency-authority/internal/dependency/domain/candidate"
)

func envWith(zone string, ecosystem string) func(string) string {
	return func(key string) string {
		switch key {
		case EnvZone:
			return zone
		case EnvEcosystem:
			return ecosystem
		default:
			return ""
		}
	}
}

func TestZoneValidity(t *testing.T) {
	for _, zone := range []Zone{ZoneControl, ZoneIntake, ZoneQuarantine, ZoneApproved, ZoneEvidence} {
		if !zone.Valid() {
			t.Errorf("Zone(%q).Valid() = false, want true", zone)
		}
	}
	if Zone("bogus").Valid() {
		t.Error("Zone(bogus).Valid() = true, want false")
	}
}

func TestFromEnvRejectsNilLookup(t *testing.T) {
	if _, err := FromEnv(nil); err == nil {
		t.Fatal("FromEnv() error = nil, want nil lookup error")
	}
}

func TestFromEnvRejectsUnknownZone(t *testing.T) {
	if _, err := FromEnv(envWith("", "go")); err == nil {
		t.Fatal("FromEnv() error = nil, want zone error")
	}
	if _, err := FromEnv(envWith("bogus", "go")); err == nil {
		t.Fatal("FromEnv() error = nil, want zone error")
	}
}

func TestFromEnvRejectsUnknownEcosystem(t *testing.T) {
	if _, err := FromEnv(envWith("intake", "")); err == nil {
		t.Fatal("FromEnv() error = nil, want ecosystem error")
	}
	if _, err := FromEnv(envWith("intake", "ruby")); err == nil {
		t.Fatal("FromEnv() error = nil, want ecosystem error")
	}
}

func TestFromEnvBindsZoneAndEcosystem(t *testing.T) {
	config, err := FromEnv(envWith("intake", "go"))
	if err != nil {
		t.Fatalf("FromEnv() error = %v", err)
	}
	if config.Zone() != ZoneIntake {
		t.Errorf("Zone() = %q, want %q", config.Zone(), ZoneIntake)
	}
	if config.Ecosystem() != candidate.EcosystemGo {
		t.Errorf("Ecosystem() = %q, want %q", config.Ecosystem(), candidate.EcosystemGo)
	}
}
