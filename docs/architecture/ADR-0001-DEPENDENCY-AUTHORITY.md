# ADR-0001: Dependency Authority Core

## Status

Accepted

## Context

The federated multi-tenant supply chain architecture requires a dependency
authority: a logical bounded context with five physical trust zones
(`control`, `intake`, `quarantine`, `approved`, `evidence`) that governs how
package dependencies enter an organization, are admitted, promoted into the
approved zone, revalidated, and revoked. Without an executable,
organization-agnostic core, every organization would re-implement the lane
semantics and drift from the canonical lifecycle.

## Decision

This repository is the organization-agnostic dependency authority core.

1. It owns the candidate lifecycle domain model: a candidate is `pending`
   after intake, moves to `quarantined` on a failed admission or
   revalidation, returns to `pending` after re-admission, is promoted to
   `approved` only under a valid time-bounded approval with complete
   policy-required evidence, and reaches the terminal `revoked` state only
   with an active download block.
2. It owns the five lane use cases and their consumer-defined outbound ports.
   The intake controller runs in the `intake` zone; the admission,
   promotion, revalidation, and revocation controllers run in the `control`
   zone. The `quarantine` zone never serves consumers, and `approved` is the
   only dependency consumer endpoint.
3. Outbound ports are interfaces defined by their consumers. Cloud adapter
   implementations are delivered with the trust-zone infrastructure and are
   never part of this core. Until an adapter is bound, controller wiring
   fails closed.
4. This core never contains concrete organization bindings.
   This core never contains tenant bindings.
   It contains no credentials, tokens, private keys, or authorization
   headers.
5. Instances consume this core only through the three-pin consumption
   contract: module version pins for infrastructure, artifact digest pins
   for runtime, and schema version pins for policies and evidence.

## Consequences

- Every lane behavior is a governed, reviewable change with same-package
  whitebox tests for every invariant, branch, state transition, and error
  path.
- A semantically incompatible lifecycle change requires a governed
  architecture review; additive behavior remains valid within the existing
  lanes.
- Organization and tenant instances bind the controllers through their own
  trust-zone adapters and prove the binding in their own evidence.
- The core never references a concrete organization or tenant; instances
  reference only the core.
