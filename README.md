# Dependency Authority

`dependency-authority` is the organization-agnostic core for the dependency
authority bounded context: the intake, admission, promotion, revalidation,
and revocation lanes that govern how package dependencies enter an
organization, are evaluated, promoted into the approved zone, revalidated,
and revoked.

This repository never contains concrete organization, tenant, project,
identity, network, secret, or registry bindings. Organization instances and
tenant instances consume this core only through versioned releases, immutable
digests, and schema version pins.

## Core boundary

The core owns:

- the candidate lifecycle domain model (`pending`, `quarantined`,
  `approved`, `revoked`);
- the admission policy model and its evaluation;
- the intake, admission, promotion, revalidation, and revocation use cases;
- the consumer-defined outbound ports for upstream, scanner, policy,
  evidence, registry, and download-gate adapters;
- the five lane controllers under `cmd/`.

The core never contains:

- concrete organization or tenant values;
- credentials, tokens, private keys, or authorization headers;
- cloud adapter implementations or runtime bindings.

## Lanes and trust zones

```text
dependency-intake-controller        runs in the intake zone
dependency-admission-controller     runs in the control zone
dependency-promotion-controller     runs in the control zone
dependency-revalidation-controller  runs in the control zone
dependency-revocation-controller    runs in the control zone
```

Each controller binds `DEPENDENCY_AUTHORITY_ZONE` and
`DEPENDENCY_AUTHORITY_ECOSYSTEM` from the process environment, validates the
zone binding, and wires its lane service through the ports in
`internal/dependency/bootstrap`. Binding fails closed: a controller with
unbound ports never executes its lane. The outbound adapter implementations
follow with the trust-zone infrastructure.

## Quality gates

```text
gofmt
go test ./...
go run -mod=readonly ./cmd/check-coverage
go run -mod=readonly ./cmd/build
```

Every executable Go package must reach exactly 100.0% statement coverage.

## Repository layout

- `cmd/` contains the five lane controllers plus the build and coverage
  gates.
- `internal/dependency/domain/` contains the lifecycle, admission, approval,
  quarantine, revocation, and evidence domain models.
- `internal/dependency/application/` contains the five lane use cases.
- `internal/dependency/adapters/inbound/` contains the environment
  configuration adapter.
- `internal/dependency/bootstrap/` wires the controllers.
- `internal/packaging/` contains the same-package workflow contract tests.
- `test/contract/` contains the exported-API contract tests;
  `test/integration/` receives the trust-zone adapter integration tests.
- `docs/` contains architecture, development, and GitHub Ruleset
  documentation.

## Governance

Governed changes land through ticket branches and pull requests into
`develop`. `main` is the production and control-plane truth. See
`docs/hosting-platforms/github/rulesets/` for the importable shared-line
Rulesets and their import timing.
