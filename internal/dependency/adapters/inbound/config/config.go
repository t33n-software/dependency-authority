// Package config binds dependency authority controller configuration from
// the process environment.
package config

import (
	"errors"
	"fmt"

	"github.com/t33n-software/dependency-authority/internal/dependency/domain/candidate"
)

const (
	// EnvZone names the trust zone the controller runs in.
	EnvZone = "DEPENDENCY_AUTHORITY_ZONE"
	// EnvEcosystem names the ecosystem the controller serves.
	EnvEcosystem = "DEPENDENCY_AUTHORITY_ECOSYSTEM"
)

// Zone is a physical dependency authority trust zone.
type Zone string

const (
	ZoneControl    Zone = "control"
	ZoneIntake     Zone = "intake"
	ZoneQuarantine Zone = "quarantine"
	ZoneApproved   Zone = "approved"
	ZoneEvidence   Zone = "evidence"
)

// Valid reports whether the zone is a known trust zone.
func (z Zone) Valid() bool {
	switch z {
	case ZoneControl, ZoneIntake, ZoneQuarantine, ZoneApproved, ZoneEvidence:
		return true
	default:
		return false
	}
}

// Config is the validated controller configuration.
type Config struct {
	zone      Zone
	ecosystem candidate.Ecosystem
}

// FromEnv loads and validates the controller configuration from the process
// environment.
func FromEnv(lookup func(string) string) (Config, error) {
	if lookup == nil {
		return Config{}, errors.New("environment lookup must not be nil")
	}
	zone := Zone(lookup(EnvZone))
	if !zone.Valid() {
		return Config{}, fmt.Errorf("%s must be one of control, intake, quarantine, approved, evidence", EnvZone)
	}
	ecosystem := candidate.Ecosystem(lookup(EnvEcosystem))
	if !ecosystem.Valid() {
		return Config{}, fmt.Errorf("%s must be one of go, npm, python", EnvEcosystem)
	}
	return Config{zone: zone, ecosystem: ecosystem}, nil
}

// Zone returns the configured trust zone.
func (c Config) Zone() Zone {
	return c.zone
}

// Ecosystem returns the configured ecosystem.
func (c Config) Ecosystem() candidate.Ecosystem {
	return c.ecosystem
}
