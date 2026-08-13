# Verification

This document binds the local and CI verification contract for the
dependency authority core. It exists so every instance and every tenant
consumer can re-run the same gates.

## Local gates

Run from the repository root with the pinned Go toolchain (`go 1.26`,
`toolchain go1.26.5`):

```text
gofmt
go test ./...
go run -mod=readonly ./cmd/check-coverage
go run -mod=readonly ./cmd/build
```

`cmd/build` is the full source-level gate: formatting, module checksums,
module metadata, unit tests, exact 100% statement coverage, race detector,
static analysis, Linux/AMD64 build of all five lane controllers, and module
provenance.

## Test architecture

Every production package carries same-package whitebox tests for its
invariants, branches, state transitions, errors, and cleanup paths.
`test/contract/` complements them with exported-API contract tests.
Integration tests for the trust-zone adapters land in `test/integration/`
with the tickets that deliver those adapters.

## CI gates

The `Quality gates (linux-amd64)` check runs the full source-level gate. The
`Dependency admission review` check blocks unreviewed dependency changes.
CodeQL code scanning runs with all alerts blocking once the shared-line
Rulesets are imported.

## Instance and tenant consumption

An organization instance or tenant instance pins this core by module
version, artifact digest, and schema version. An instance never copies the
lane source into its own boundary; it references the pinned version and
proves the binding in its own CI and evidence.
