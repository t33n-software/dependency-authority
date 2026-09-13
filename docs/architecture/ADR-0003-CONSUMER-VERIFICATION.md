# ADR-0003: Consumer Verification Lane — Contract Execution, GOAUTH Form, Evidence, and Cadence

## Status

Accepted

## Context

The admission chain proves what may enter the approved boundary, and the
promotion proves what was published; neither proves what the approved
endpoint actually serves to a consumer. The consumer-verification convention
of the cloud-agnostic dependency-authority reference binds the missing proof
as a dedicated lane operation of the control zone: the governed, repeatable
execution of the consumer contract against the live approved endpoint through
the ecosystem's real pinned toolchain, with five proofs per admitted module
version (positive resolution, fail-closed negative resolution of a
never-admitted probe, graph stability under `go mod tidy -diff`, integrity
under `go mod verify`, and build-evidence correspondence of the consumer
artifact's `go version -m` module table). The lane is a deterministic
contract evaluation and carries no human approval gate.

The convention binds two execution occasions: a governed dispatch after every
mutation with consumer-contract effect, and a continuous cadence, because a
revocation and platform drift outside the governed channels change the
consumer contract without any governed change.

Two form decisions needed a binding answer: how the toolchain child processes
authenticate against the approved endpoint without credential material
leaving the process, and how the cadence occasion fires without weakening the
dispatch-only trigger form of the lanes.

## Decision

1. **Sixth lane controller.** `cmd/dependency-consumer-verification-controller`
   runs the `consumerverification` use case in the control zone. The five
   proofs are bound as the canonical ordered domain report
   (`internal/dependency/domain/verification`): a constructed report is the
   proof of passage, and every proof failure closes the lane through the
   domain `ProofError` naming the failed proof. The lane verifies admitted
   versions only: an unknown or non-approved candidate and a missing approval
   evidence fail closed before any proof runs.

2. **Real toolchain, controlled environment.** The `consumercontract`
   outbound adapter executes the pinned Go toolchain the image carries
   (`DEPENDENCY_AUTHORITY_GO_TOOL`), with the approved endpoint as the only
   `GOPROXY`, no checksum-database or VCS fallback (`GONOSUMDB=*`,
   `GOVCS=*:off`), the pinned local toolchain (`GOTOOLCHAIN=local`), and every
   writable surface inside the declared scratch home
   (`DEPENDENCY_AUTHORITY_CONSUMER_WORK_ROOT`). A reimplementation of the
   consumer contract is prohibited: only the real toolchain defines the
   consumer-visible semantics.

3. **GOAUTH command form, never a credential file.** The toolchain child
   processes authenticate through the controller's own `goauth` mode
   (`GOAUTH=<controller> goauth`): the controller renders the credential set
   — the approved endpoint URL line and the bearer header of the workload's
   own short-lived token from the provider instance metadata mechanism — in
   process memory only. The provider's documented netrc credential-helper
   form writes tokens to a file and is not permissible for the workload: the
   workload-internal authentication convention binds process memory as the
   only credential surface.

4. **Lane evidence through the lane's own evidence port.** The lane writes
   its dependency evidence (`dependency-authority/consumer-verification/v1`)
   as an atomic part of the execution: the pass record carries the five proof
   results; a failed proof is supply-chain-relevant and is recorded with the
   failed proof and its detail before the lane fails closed. A precondition
   failure (unknown or non-admitted candidate) records nothing, consistent
   with every other lane.

5. **The lane stays dispatch-only; the cadence gets its own dispatcher.** The
   lane workflow `dep-consumer-verification.yml` keeps the dispatch-only
   trigger form of every lane. The cadence occasion is carried by
   `dep-consumer-verification-schedule.yml`: it reads the instance-bound
   cadence target set (`DEP_CONSUMER_VERIFICATION_CADENCE_TARGETS`) and fires
   the lane through the documented first-class dispatch form
   (`gh workflow run`), never federating and never touching the perimeter
   itself. The cron value mirrors the organization-instance binding (planned
   until the provisioning read-back proof); a value change is a governed pull
   request.

6. **Toolchain-bearing image variant.** The parameterized root `Dockerfile`
   gains `ARG TOOLCHAIN=none` and copies `.build/toolchain/${TOOLCHAIN}` to
   `/toolchain/`: the consumer verification image is built with
   `TOOLCHAIN=go` after the pinned Go distribution tree was staged and proven
   against the publisher's checksums; every other controller builds with the
   empty `none` tree. The single-Dockerfile, pure-packaging, digest-pinned
   non-root form is unchanged.

## Consequences

- The consumer verification lane is declared in the infrastructure core like
  every other lane operation; the organization instance binds its image
  digest, its never-admitted probe reference, and its cadence value with
  binding status `planned` until the provisioning read-back proof flips them
  to `bound`.
- The lane's execution identity reads the approved repository as a consumer
  and writes its own dependency evidence — both standing grants declared in
  the canonical identity matrix, never a mutation-window grant.
- The lane runs after every governed mutation with consumer-contract effect
  and on the bound cadence; both occasions use the same trigger seam and the
  same identities and carry no human approval gate.
- The packaging contract guards bind the lane form, the cadence dispatcher
  form, the extended layout, the six binaries, and the toolchain-variant
  packaging fail-closed.
