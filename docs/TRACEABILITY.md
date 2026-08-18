# Traceability

## Tickets

| Ticket | Change | Status |
|---|---|---|
| DA-1 | Establish the dependency authority core: candidate lifecycle domain model, admission policy evaluation, intake/admission/promotion/revalidation/revocation use cases, consumer-defined outbound ports, five lane controllers with fail-closed bootstrap wiring, source-quality gates, CodeQL, dependency admission review, Dependabot, Lefthook, and importable Rulesets. | In progress |
| DA-2 | Migrate the module path and Go import paths to the `t33n-software` organization namespace; add the LF line-ending contract (`.gitattributes`) and the push-protections Ruleset source `00-push-protections.json` in the verified GitHub export format. | In progress |
| DA-3 | Align the Go 1.26.6 toolchain and source gates with the supply chain fortress contract: pinned `tools/` module with govulncheck, staticcheck, and Lefthook; fail-closed vulnerability analysis; fuzz smoke lane for the inbound configuration boundary; Lefthook configuration validation and commit-msg hook; daily CI re-scan. | In progress |
| DA-4 | Bind the Go lane design (ADR-0002): adapter placement in `internal/dependency/adapters/outbound/` with a provider-free domain and application core; OSV as the pinned reference scanner engine with snapshot-based scanning and recorded tool identity; `dependency-policy/v1` consumption through exact schema version pins with fail-closed admission; the automatic policy-pass approval with time-bounded instance-overlay exceptions; the seven protected `dep-*` lane environments matching the organization WIF federation; the consumer fetch and isolated build contract; and the empirical perimeter intake check at first lane execution. | In progress |

## Scope boundaries

- DA-1 delivers the source-level core only. It does not deliver trust-zone
  adapter implementations, a versioned release, an artifact delivery lane,
  or any organization- or tenant-bound content.
- The outbound adapters for upstream, scanner, policy, evidence, registry,
  and download-gate ports land in `internal/dependency/adapters/outbound/`
  with the trust-zone lane enablement (ADR-0002); the domain and application
  core stays provider-free.
- The `release/*` and `support/*` branch families and their Rulesets are
  activated only with a complete governed release lifecycle.
