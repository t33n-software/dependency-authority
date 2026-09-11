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
- provider SDK or adapter imports in the domain and application packages.

The outbound adapter implementations live in this repository under
`internal/dependency/adapters/outbound/` (ADR-0002); they bind concrete
trust-zone endpoints through the lane environment and never through source
constants.

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
live in this repository under `internal/dependency/adapters/outbound/`
(ADR-0002); the domain and application core never imports provider SDKs or
adapter code.

## Outbound adapters

The trust-zone adapters under `internal/dependency/adapters/outbound/`
implement the consumer-defined ports:

- `upstream`: the Go module proxy digest client of the intake boundary
  (`intake.Upstream`), with GOPROXY `!`-escaping, TLS-only endpoints, and no
  public-registry or VCS fallback;
- `policy`: the pinned `dependency-policy/v1` bundle loader
  (`admission.Policies`), strictly decoded and fail-closed on any schema,
  ecosystem, or revocation-invariant deviation;
- `scanner`: the offline OSV-Scanner adapter (`admission.Scanner`) with the
  snapshot database, CVSS v3 base scoring, and a conservative maximum score
  for vulnerabilities without a computable vector;
- `artifactregistry`: the append-only candidate records store
  (`Candidates`), the approved-zone publisher that uploads the
  digest-proven module archive through the direct Artifact Registry Go
  module upload and proves the content identity before and after the
  publication (`promotion.ApprovedRegistry`), the package-scoped
  download-rule revocation gate (`revocation.DownloadGate`), and the
  candidate content materialization that fetches the module archive from
  the controlled intake boundary, proves it against the recorded
  candidate digest, and places it at the canonical content path for the scan;
- `evidence`: the append-only evidence reference index
  (`admission.EvidenceStore`, `revocation.EvidenceRecorder`);
- `tooling`: the read-only workload tooling channel consumer — at startup the
  scanning lanes materialize the pinned scanner tool, the scanner database
  snapshot, and the admission policy bundle from the evidence-zone generic
  repository, every object proven fail-closed against the content digest its
  bound identity carries, with atomic, idempotent placement and no overwrite
  of differing content; each bound identity maps to the platform's generic
  file address `<package>:<version>:<filename>` (the stored filename carries
  the platform-safe `<algorithm>-<hex>` digest notation), and the inventory
  resolution decodes the server-issued resource names before the comparison;
  the download requests the media form (`?alt=media`), so the proven content
  is the file bytes, never the JSON envelope.

The adapters bind through the validated lane environment:

| Variable | Binding |
|---|---|
| `DEPENDENCY_AUTHORITY_UPSTREAM_ENDPOINT` | Go proxy endpoint of the intake repository |
| `DEPENDENCY_AUTHORITY_APPROVED_ENDPOINT` | Go proxy endpoint of the approved repository |
| `DEPENDENCY_AUTHORITY_ARTIFACT_API` | Artifact Registry API endpoint |
| `DEPENDENCY_AUTHORITY_EVIDENCE_REPOSITORY` | evidence-zone generic repository resource |
| `DEPENDENCY_AUTHORITY_APPROVED_REPOSITORY` | approved-zone repository resource |
| `DEPENDENCY_AUTHORITY_POLICY_BUNDLE` | pinned policy bundle path |
| `DEPENDENCY_AUTHORITY_POLICY_BUNDLE_IDENTITY` | pinned policy bundle channel identity (`dependency-policy/v1@sha256:<digest>`) |
| `DEPENDENCY_AUTHORITY_SCANNER_TOOL` | pinned scanner tool path |
| `DEPENDENCY_AUTHORITY_SCANNER_DATABASE` | scanner database snapshot directory |
| `DEPENDENCY_AUTHORITY_SCAN_CONTENT_ROOT` | candidate materialization root |

An adapter binds only when its complete environment contract is present; a
lane requiring an unbound adapter fails closed at bind time.

At startup the admission and revalidation controllers materialize the pinned
scanner tool, the scanner database snapshot, and the policy bundle from the
evidence-zone channel, and the promotion controller materializes the policy
bundle; every object is proven against the digest its bound identity carries
before the lane runs, and a missing or unprovable object fails the controller
closed. The scanner tool and database identities arrive through the operation
inputs (`DEPENDENCY_AUTHORITY_SCANNER_IDENTITY`,
`DEPENDENCY_AUTHORITY_SCANNER_DATABASE_IDENTITY`), the policy bundle identity
through `DEPENDENCY_AUTHORITY_POLICY_BUNDLE_IDENTITY`, and the materialized
content lands at the bound `DEPENDENCY_AUTHORITY_SCANNER_TOOL`,
`DEPENDENCY_AUTHORITY_SCANNER_DATABASE`, and `DEPENDENCY_AUTHORITY_POLICY_BUNDLE`
paths. Before the scan, the admission and revalidation lanes materialize the
candidate content from the controlled intake boundary into the scan content
root: the fetched archive is proven against the digest the candidate record
binds, placed atomically, and never overwritten with differing content. The
scan and decision evidence carry only the channel identities proven against
the materialized artifacts — the tool and database identities are re-proven
against the materialized content at evidence time, and the policy identity is
derived from the materialized bundle content — never an asserted input.

The controllers authenticate to the trust-zone APIs through the identity
attached to the workload: each controller obtains short-lived access tokens at
runtime from the provider instance metadata mechanism (process memory only,
cached until the expiry minus a safety skew, refreshed under a single-flight
guard) and fails closed outside the provider runtime. No credential is
injected through the environment, parameters, image content, mounts, or the
control plane.

## Lane workflows

Seven dispatch-only workflows under `.github/workflows/` run the lanes under
the seven protected `dep-*` environments (ADR-0002): `dep-intake-fetch`,
`dep-admission`, `dep-promotion`, `dep-revalidation`, `dep-revocation`,
`dep-evidence-write`, and `dep-evidence-audit`. Each controller lane takes
the candidate identity as required dispatch inputs (`module`, `version`; the
revocation lane additionally takes `reason`), federates its
environment-scoped trigger identity, and invokes the zone-resident workload
job that executes the lane use case with the adapters bound from the job
environment: the
intake lane registers the pending candidate from the controlled upstream
digest, the admission lane materializes the candidate content from the
controlled intake boundary (proven against the recorded digest), scans it,
records the scan and decision evidence with the artifact-proven pinned tool
and policy identities, and records the automatic time-bounded approval on a
policy pass, the promotion lane promotes under the newest recorded, still
valid approval, the revalidation lane materializes the candidate content,
re-evaluates approved candidates, and records the fresh scan and decision
evidence with the artifact-proven identities, and the revocation lane blocks
downloads at the approved boundary and records the revocation evidence. The
admission lane carries the automatic approval TTL `72h`, and the admission
and revalidation lanes carry the pinned scanner tool and scanner database
identities (`DEPENDENCY_AUTHORITY_SCANNER_IDENTITY`,
`DEPENDENCY_AUTHORITY_SCANNER_DATABASE_IDENTITY`) as versioned workflow values
passed as execution parameters — a pin bump is a governed pull request. The
workflows carry no organization value — every concrete zone binding arrives
through environment variables set on the protected environments.

## Quality gates

```text
gofmt
go test ./...
go tool -modfile tools/go.mod check-coverage
go tool -modfile tools/go.mod quality-gate
```

Every executable Go package must reach exactly 100.0% statement coverage.

`quality-gate` runs the canonical gate chain of the go-quality-authority
territory home through the pinned tooling module: formatting, module checksums
and metadata, the pinned build tool module, lint (staticcheck), unit tests,
exact 100% statement coverage, race detector, static analysis, fail-closed
vulnerability analysis (govulncheck), the registered fuzz smoke lanes for the
inbound configuration, adapter bindings, and operation inputs boundaries,
Lefthook configuration validation, and native binary builds of all five lane
controllers with smoke tests.

The Go toolchain is pinned exactly (`toolchain go1.26.6`,
`GOTOOLCHAIN=local`); no lane downloads a toolchain at build time. CI re-runs
the full gate daily so newly disclosed vulnerabilities fail closed even
without source changes.

In CI the repository is a tenant of the canonical repo surface: the three
shared-line workflows (`ci.yml`, `codeql.yml`, `dependency-review.yml`) are
byte-identical callers of the repository-governance home, and the canonical
quality gate of the go-quality-authority territory home runs through the
tooling module. The `repo-bindings.json` manifest binds the adoption (home
pin, fleet classes, caller and file hashes, config-seam and tool-catalog
versions), and the `Canonical conformance` check re-proves it fail-closed on
every shared-line change.

## Repository layout

- `cmd/` contains the five lane controllers; the canonical gate chain is
  referenced through the `tools/` module pin.
- `Dockerfile` is the single parameterized controller workload image form
  (GO-SCF-019): the pure packaging of a locally built controller binary on
  the digest-pinned minimal non-root runtime; the build and delivery
  procedure lives in `docs/operations/controller-image-substrate.md`.
- `internal/dependency/domain/` contains the lifecycle, admission, approval,
  quarantine, revocation, and evidence domain models.
- `internal/dependency/application/` contains the five lane use cases.
- `internal/dependency/adapters/inbound/` contains the environment
  configuration adapter; `internal/dependency/adapters/outbound/` contains
  the trust-zone adapter implementations (ADR-0002).
- `internal/dependency/bootstrap/` wires the controllers.
- `internal/packaging/` contains the same-package workflow contract tests.
- `test/contract/` contains the exported-API contract tests;
  `test/integration/` receives the trust-zone adapter integration tests.
- `repo-bindings.json` binds the canonical repo-surface adoption (home pin,
  fleet classes, caller and file hashes, config-seam and tool-catalog
  versions).
- `docs/` contains architecture, development, and hosting-platform convention
  documentation.

## Governance

Governed changes land through ticket branches and pull requests into
`develop`. `main` is the production and control-plane truth. Branch
governance is bound through the organization-level rule-sets; see
`docs/conventions/hosting-plattform/github/rule-sets/` for the canonical
source and the rule-set family of this repository.
