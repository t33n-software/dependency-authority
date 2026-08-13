// Package bootstrap wires the dependency authority lane controllers.
//
// The controllers bind their outbound ports only when the trust-zone
// infrastructure provides real adapters. Until then, binding fails closed:
// a controller with unbound ports never executes its lane.
package bootstrap

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/CyberT33N/dependency-authority/internal/dependency/adapters/inbound/config"
	"github.com/CyberT33N/dependency-authority/internal/dependency/application/admission"
	"github.com/CyberT33N/dependency-authority/internal/dependency/application/intake"
	"github.com/CyberT33N/dependency-authority/internal/dependency/application/promotion"
	"github.com/CyberT33N/dependency-authority/internal/dependency/application/revalidation"
	"github.com/CyberT33N/dependency-authority/internal/dependency/application/revocation"
)

// Operation identifies a dependency authority lane.
type Operation string

const (
	OperationIntake       Operation = "intake"
	OperationAdmission    Operation = "admission"
	OperationPromotion    Operation = "promotion"
	OperationRevalidation Operation = "revalidation"
	OperationRevocation   Operation = "revocation"
)

// Ports carries every outbound port a lane controller may bind. A single
// adapter implementation may satisfy several of these consumer-defined
// interfaces at once.
type Ports struct {
	Upstream      intake.Upstream
	Scanner       admission.Scanner
	Policies      admission.Policies
	Candidates    intake.Candidates
	EvidenceStore admission.EvidenceStore
	Registry      promotion.ApprovedRegistry
	Gate          revocation.DownloadGate
	Recorder      revocation.EvidenceRecorder
	Now           func() time.Time
}

// RunIntake runs the intake lane controller.
func RunIntake(ctx context.Context, lookup func(string) string, ports Ports, stdout io.Writer, stderr io.Writer) int {
	return run(ctx, OperationIntake, lookup, ports, stdout, stderr)
}

// RunAdmission runs the admission lane controller.
func RunAdmission(ctx context.Context, lookup func(string) string, ports Ports, stdout io.Writer, stderr io.Writer) int {
	return run(ctx, OperationAdmission, lookup, ports, stdout, stderr)
}

// RunPromotion runs the promotion lane controller.
func RunPromotion(ctx context.Context, lookup func(string) string, ports Ports, stdout io.Writer, stderr io.Writer) int {
	return run(ctx, OperationPromotion, lookup, ports, stdout, stderr)
}

// RunRevalidation runs the revalidation lane controller.
func RunRevalidation(ctx context.Context, lookup func(string) string, ports Ports, stdout io.Writer, stderr io.Writer) int {
	return run(ctx, OperationRevalidation, lookup, ports, stdout, stderr)
}

// RunRevocation runs the revocation lane controller.
func RunRevocation(ctx context.Context, lookup func(string) string, ports Ports, stdout io.Writer, stderr io.Writer) int {
	return run(ctx, OperationRevocation, lookup, ports, stdout, stderr)
}

func run(_ context.Context, operation Operation, lookup func(string) string, ports Ports, stdout io.Writer, stderr io.Writer) int {
	controllerConfig, err := config.FromEnv(lookup)
	if err != nil {
		fmt.Fprintln(stderr, "load controller configuration:", err)
		return 2
	}
	if err := checkZone(operation, controllerConfig.Zone()); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if err := bind(operation, ports); err != nil {
		fmt.Fprintf(stderr, "bind dependency-%s-controller: %v\n", operation, err)
		return 1
	}
	fmt.Fprintf(stdout, "dependency-%s-controller configured for zone %s and ecosystem %s\n",
		operation, controllerConfig.Zone(), controllerConfig.Ecosystem())
	return 0
}

// checkZone binds each operation to its trust zone: intake runs in the
// intake zone; admission, promotion, revalidation, and revocation run in the
// control zone.
func checkZone(operation Operation, zone config.Zone) error {
	expected, err := zoneFor(operation)
	if err != nil {
		return err
	}
	if zone != expected {
		return fmt.Errorf("dependency-%s-controller must run in the %s zone, got %q", operation, expected, zone)
	}
	return nil
}

func zoneFor(operation Operation) (config.Zone, error) {
	switch operation {
	case OperationIntake:
		return config.ZoneIntake, nil
	case OperationAdmission, OperationPromotion, OperationRevalidation, OperationRevocation:
		return config.ZoneControl, nil
	default:
		return "", fmt.Errorf("unknown operation %q", operation)
	}
}

// bind constructs the lane service and fails closed when a required port is
// unbound.
func bind(operation Operation, ports Ports) error {
	switch operation {
	case OperationIntake:
		_, err := intake.NewService(ports.Upstream, ports.Candidates)
		return err
	case OperationAdmission:
		_, err := admission.NewService(ports.Policies, ports.Candidates, ports.Scanner, ports.EvidenceStore)
		return err
	case OperationPromotion:
		_, err := promotion.NewService(ports.Candidates, ports.Policies, ports.EvidenceStore, ports.Registry, ports.Now)
		return err
	case OperationRevalidation:
		_, err := revalidation.NewService(ports.Candidates, ports.Policies, ports.Scanner, ports.EvidenceStore)
		return err
	case OperationRevocation:
		_, err := revocation.NewService(ports.Candidates, ports.Gate, ports.Recorder, ports.Now)
		return err
	default:
		return fmt.Errorf("unknown operation %q", operation)
	}
}
