# ADR-0002: Go Lane Design — Scanner, Policy, Approval, Environments, and Adapter Placement

## Status

Accepted

## Context

ADR-0001 established the organization-agnostic core: the candidate lifecycle,
the five lane use cases, their consumer-defined outbound ports, and
fail-closed controller wiring until adapters are bound. It deliberately left
four lane design decisions unbound: the scanner engine, the policy-engine
consumption, the approval and exception flow, and the concrete lane
federation contract.

The reference organization has since provisioned the five trust zones with
their Workload Identity Federation pools, providers, service accounts, and
the evidence signing key. Each WIF provider binds one repository (this one),
one protected environment, and one target service account through the
canonical claim condition; the lane environments referenced here are the
bound counterparts of those providers.

## Decision

1. **Adapter placement, clarified.** The outbound adapter implementations
   live in this repository under `internal/dependency/adapters/outbound/`
   (`artifact-registry/`, `evidence/`, `policy/`, `scanner/`, `upstream/`),
   exactly where the canonical reference topology places them. The ADR-0001
   statement that cloud adapter implementations are never part of this core
   binds the hexagonal core — the domain and application packages never
   import provider SDKs or adapter code. The sentence "adapters are delivered
   with the trust-zone infrastructure" binds the delivery order, not a
   different repository: adapters land together with the trust-zone lane
   enablement. This clarification changes no existing behavior.

2. **Scanner engine.** The reference implementation of the `scanner`
   outbound port is OSV (`osv-scanner`) with a pinned version and a local,
   snapshot-based vulnerability database. The scanner adapter executes the
   pinned tool, never downloads vulnerability data at scan time in an
   isolated lane, and records tool name, exact version, and database snapshot
   identity in the scan evidence. License and policy findings are produced by
   policy evaluation, not by the scanner. A different scanner engine is added
   only through a documented exception that proves the same fail-closed and
   evidence properties.

3. **Policy consumption.** Admission, promotion, revalidation, and
   revocation evaluate `dependency-policy/v1` bundles published by
   `supply-chain-governance`, consumed through exact schema version pins and
   verified against its conformance vectors. A lane without a bound policy
   bundle fails closed. Policy evaluation is deterministic: the same resolved
   graph, the same scan evidence, and the same bundle always produce the same
   decision.

4. **Approval and exception flow.** A candidate is promoted only under a
   valid, time-bounded approval with complete policy-required evidence (the
   ADR-0001 invariant). The default approval is automatic on a policy pass.
   An exception is a time-bounded policy overlay recorded in the organization
   instance (`policy-overlays/exceptions/`); its human gate is the governed
   instance pull request with code owner review. Exception expiry or
   revocation triggers revalidation of every dependent candidate.

5. **Lane environments and federation.** The lane workflows of this
   repository run under seven protected GitHub environments:
   `dep-intake-fetch`, `dep-admission`, `dep-promotion`, `dep-revalidation`,
   `dep-revocation`, `dep-evidence-write`, and `dep-evidence-audit`. Each
   environment restricts deployment to protected refs and requires review
   where the lane mutates a trust zone. The environments are created and
   protected through the hosting-platform GUI when the lane workflows land;
   the organization WIF providers already federate exactly these
   environments.

6. **Consumer fetch and isolated build contract.** Consumers resolve only
   the approved endpoint of their ecosystem: `GOPROXY` points at the approved
   Go repository, `GOAUTH` uses the artifact-registry credential helper,
   `GOSUMDB` stays enabled through the controlled verifier, `GOTOOLCHAIN` is
   `local`, `GOFLAGS` is `-mod=readonly`, and `GOVCS` is `*:off` (no VCS
   fallback). Isolated builds materialize the admitted module graph
   first and then build with `GOPROXY=off` and no public network egress.

7. **Perimeter intake check.** Whether the intake remote repository fetches
   its upstream through the enforced service perimeter without an egress
   exception is verified empirically when the intake lane first executes; any
   required exception becomes a governed, zone-scoped change and is never
   assumed in advance.

8. **Trigger-form lane execution.** The seven lane workflows are
   authenticated triggers, never executors: each lane authenticates as the
   dedicated invoke-only trigger identity of its operation
   (`dep-<operation>-trigger`), invokes the zone-resident Cloud Run job of
   its operation over the compute control plane (`run.googleapis.com`) with
   the operation inputs as execution parameters, reads the execution status
   back over the same plane, and reports the control-plane audit pointer.
   The lane identity carries no data-plane grant; a direct lane call against
   a restricted service is the intended fail-closed perimeter denial. The
   controller domain logic is unchanged — only the execution environment
   moves inside the perimeter, and the lane input validation of DA-7 runs
   again fail-closed inside the job. The lane environments keep their
   dispatch form, their protection rules, and their reviewer gates; their
   variable surface retargets to the trigger identities
   (`DEP_<OPERATION>_TRIGGER_SERVICE_ACCOUNT`) and adds the workload job
   coordinate (`DEP_<OPERATION>_WORKLOAD_JOB`), while the data-plane
   references move into the job environment bound at provisioning time. The
   empirical perimeter intake check of item 7 is answered by the job
   execution from inside, never by a lane-side probe.

## Consequences

- Adapter implementations arrive with the trust-zone lane tickets as
  same-package whitebox-tested Go under `internal/dependency/adapters/`; the
  domain and application packages stay provider-free.
- Every scan, decision, and promotion writes its evidence through the
  evidence port with the pinned tool and policy identities.
- A lane workflow cannot start without its protected environment, and the
  federation condition rejects any token outside the bound repository and
  environment.
- The acceptance gates of the Go projection — unapproved versions do not
  resolve, revoked versions are denied before download, no public registry or
  VCS fallback, `go mod tidy -diff` does not mutate the admitted graph,
  `go mod verify` passes, and `go version -m` matches the approved graph
  evidence — bind these decisions end to end.
- The lane workflows carry no controller build, no Go toolchain, no raw
  access tokens, and no data-plane references; the workload jobs execute the
  unchanged controllers inside the perimeter, and the lane proves the
  execution status fail-closed over the compute control plane.
