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
(govulncheck), a fuzz smoke lane for the inbound configuration boundary,
Lefthook configuration validation, Linux/AMD64 build of all five lane
controllers, and module provenance.

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

## CI gates

The `Quality gates (linux-amd64)` check runs the full source-level gate on
every push and pull request to the shared lines and once per day on a
schedule. The `Dependency admission review` check blocks unreviewed
dependency changes. CodeQL code scanning runs with all alerts blocking once
the organization-level shared-line rule-sets are imported and active; the
binding of this repository is documented in
`docs/conventions/hosting-plattform/github/rule-sets/`.

Lefthook provides the local `commit-msg` hook (`git-governance --interactive
never commit validate --message-file`) and the pre-push source-quality gate.

## Instance and tenant consumption

An organization instance or tenant instance pins this core by module
version, artifact digest, and schema version. An instance never copies the
lane source into its own boundary; it references the pinned version and
proves the binding in its own CI and evidence.
