# Verification

This document binds the local and CI verification contract for the
dependency authority core. It exists so every instance and every tenant
consumer can re-run the same gates.

## Local gates

Run from the repository root with the pinned Go toolchain (`go 1.26`,
`toolchain go1.26.6`):

```text
gofmt
go test ./...
go run -mod=readonly ./cmd/check-coverage
go run -mod=readonly ./cmd/build
```

`cmd/build` is the full source-level gate: formatting, module checksums,
module metadata, build tool download, build tool checksums, build tool
metadata, lint (staticcheck), unit tests, exact 100% statement coverage,
race detector, static analysis, fail-closed vulnerability analysis
(govulncheck), fuzz smoke lanes for the inbound configuration, adapter
bindings, and operation inputs boundaries, Lefthook configuration validation,
Linux/AMD64 build of all five lane controllers, and module provenance.

## Build tooling

Build tools live in the separate `tools/` module and are resolved through
its own verified `go.mod` and committed `go.sum`; they never join the source
module graph. The module pins `govulncheck`, `staticcheck`, and `lefthook`
via the Go tool directive and shares the repository toolchain pin.

## Toolchain and vulnerability re-scans

The Go toolchain is pinned exactly (`toolchain go1.26.6`,
`GOTOOLCHAIN=local`); CI asserts `go env GOVERSION` before any gate runs and
no lane may download a toolchain at build time. `govulncheck` is part of the
full source gate, and CI re-runs the full gate on a daily schedule so newly
disclosed vulnerabilities in the pinned toolchain or dependency graph fail
closed even without source changes.

## Test architecture

Every production package carries same-package whitebox tests for its
invariants, branches, state transitions, errors, and cleanup paths.
`test/contract/` complements them with exported-API contract tests.
Integration tests for the trust-zone adapters land in `test/integration/`
with the tickets that deliver those adapters.

## Lane workflows

The seven dispatch-only lane workflows under `.github/workflows/` run under
the protected `dep-*` environments and are verified by the packaging contract
tests: environment binding, `id-token: write`, full-length SHA-pinned
actions, no organization values, no push/pull_request/schedule triggers, and
the bound operation inputs. The five controller lanes take the candidate
identity as required dispatch inputs (`module`, `version`; the revocation
lane additionally takes `reason`) and execute their use case: the intake lane
registers the pending candidate from the controlled upstream digest; the
admission lane scans the candidate, records the scan and decision evidence
with the pinned tool and policy identities, and records the automatic
time-bounded approval on a policy pass (ADR-0002); the promotion lane
promotes under the newest recorded, still valid approval; the revalidation
lane re-evaluates the approved candidate and records the fresh scan and
decision evidence; the revocation lane blocks downloads at the approved
boundary and records the revocation evidence. A lane without its complete
environment contract fails closed before any mutation; the scanner tool, the
scanner database snapshot, and the policy bundle pins land with their bound
identities, and a lane dispatched without them fails closed at execution. The
intake lane's boundary probe is the empirical perimeter intake check
(ADR-0002).

## CI gates

The shared-line workflows are the byte-identical canonical callers of the
repository-governance home, pinned by full-length commit SHA: `ci.yml` runs
the canonical quality gate of the go-quality-authority territory home (check
context `Quality gates / linux-amd64`), `codeql.yml` runs the canonical
CodeQL lane (check context `CodeQL / CodeQL (go)`, consumed by the
code-scanning rule-set rule), and `dependency-review.yml` runs the dependency
admission review (check context `Dependency review / Dependency admission
review`). The callers trigger on push and pull request to every shared line
(`main`, `develop`, `release/**`, `support/**`) plus a daily schedule and
manual dispatch. The `canonical-conformance.yml` workflow runs the home's
conformance verifier (check context `Canonical conformance`) against
`repo-bindings.json`: caller hashes and pins, canonical file equality,
CODEOWNERS materialization, config-seam conformance, tool-pin admission, and
license-lane wiring. The organization rule-sets bind a check context only
after the lane has proven it on a real pull request to the exact target line;
the binding of this repository is documented in
`docs/conventions/hosting-plattform/github/rule-sets/`.

Lefthook provides the local `commit-msg` hook (`git-governance --interactive
never commit validate --message-file`) and the pre-push validation through
`git-governance --interactive never validate pre-push`.

## Instance and tenant consumption

An organization instance or tenant instance pins this core by module
version, artifact digest, and schema version. An instance never copies the
lane source into its own boundary; it references the pinned version and
proves the binding in its own CI and evidence.
