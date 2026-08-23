// Package bootstrap wires the dependency authority lane controllers and runs
// their execution contract: each controller binds its outbound ports from the
// lane environment, loads its validated operation inputs, and executes its
// lane use case with the bound adapters. A controller with unbound ports or
// invalid inputs fails closed and never executes its lane partially.
package bootstrap

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/t33n-software/dependency-authority/internal/dependency/adapters/inbound/config"
	"github.com/t33n-software/dependency-authority/internal/dependency/application/admission"
	"github.com/t33n-software/dependency-authority/internal/dependency/application/intake"
	"github.com/t33n-software/dependency-authority/internal/dependency/application/promotion"
	"github.com/t33n-software/dependency-authority/internal/dependency/application/revalidation"
	"github.com/t33n-software/dependency-authority/internal/dependency/application/revocation"
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
	Journal       EvidenceJournal
	Now           func() time.Time
}

// RunIntake runs the intake lane controller.
func RunIntake(ctx context.Context, lookup func(string) string, buildPorts PortsBuilder, stdout io.Writer, stderr io.Writer) int {
	return run(ctx, OperationIntake, lookup, buildPorts, stdout, stderr)
}

// RunAdmission runs the admission lane controller.
func RunAdmission(ctx context.Context, lookup func(string) string, buildPorts PortsBuilder, stdout io.Writer, stderr io.Writer) int {
	return run(ctx, OperationAdmission, lookup, buildPorts, stdout, stderr)
}

// RunPromotion runs the promotion lane controller.
func RunPromotion(ctx context.Context, lookup func(string) string, buildPorts PortsBuilder, stdout io.Writer, stderr io.Writer) int {
	return run(ctx, OperationPromotion, lookup, buildPorts, stdout, stderr)
}

// RunRevalidation runs the revalidation lane controller.
func RunRevalidation(ctx context.Context, lookup func(string) string, buildPorts PortsBuilder, stdout io.Writer, stderr io.Writer) int {
	return run(ctx, OperationRevalidation, lookup, buildPorts, stdout, stderr)
}

// RunRevocation runs the revocation lane controller.
func RunRevocation(ctx context.Context, lookup func(string) string, buildPorts PortsBuilder, stdout io.Writer, stderr io.Writer) int {
	return run(ctx, OperationRevocation, lookup, buildPorts, stdout, stderr)
}

func run(ctx context.Context, operation Operation, lookup func(string) string, buildPorts PortsBuilder, stdout io.Writer, stderr io.Writer) int {
	controllerConfig, err := config.FromEnv(lookup)
	if err != nil {
		fmt.Fprintln(stderr, "load controller configuration:", err)
		return 2
	}
	if err := checkZone(operation, controllerConfig.Zone()); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	ports, err := buildPorts(lookup)
	if err != nil {
		fmt.Fprintf(stderr, "wire dependency-%s-controller: %v\n", operation, err)
		return 2
	}
	service, err := bind(operation, ports)
	if err != nil {
		fmt.Fprintf(stderr, "bind dependency-%s-controller: %v\n", operation, err)
		return 1
	}
	operationInput, err := config.OperationFromEnv(lookup, operationFields(operation)...)
	if err != nil {
		fmt.Fprintln(stderr, "load operation inputs:", err)
		return 2
	}
	if err := execute(ctx, operation, service, ports, controllerConfig, operationInput, lookup, stdout); err != nil {
		fmt.Fprintf(stderr, "execute dependency-%s-controller: %v\n", operation, err)
		return 1
	}
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
func bind(operation Operation, ports Ports) (any, error) {
	switch operation {
	case OperationIntake:
		return intake.NewService(ports.Upstream, ports.Candidates)
	case OperationAdmission:
		return admission.NewService(ports.Policies, ports.Candidates, ports.Scanner, ports.EvidenceStore)
	case OperationPromotion:
		return promotion.NewService(ports.Candidates, ports.Policies, ports.EvidenceStore, ports.Registry, ports.Now)
	case OperationRevalidation:
		return revalidation.NewService(ports.Candidates, ports.Policies, ports.Scanner, ports.EvidenceStore)
	case OperationRevocation:
		return revocation.NewService(ports.Candidates, ports.Gate, ports.Recorder, ports.Now)
	default:
		return nil, fmt.Errorf("unknown operation %q", operation)
	}
}
