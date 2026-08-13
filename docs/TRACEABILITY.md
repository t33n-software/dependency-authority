# Traceability

## Tickets

| Ticket | Change | Status |
|---|---|---|
| DA-1 | Establish the dependency authority core: candidate lifecycle domain model, admission policy evaluation, intake/admission/promotion/revalidation/revocation use cases, consumer-defined outbound ports, five lane controllers with fail-closed bootstrap wiring, source-quality gates, CodeQL, dependency admission review, Dependabot, Lefthook, and importable Rulesets. | In progress |

## Scope boundaries

- DA-1 delivers the source-level core only. It does not deliver trust-zone
  adapter implementations, a versioned release, an artifact delivery lane,
  or any organization- or tenant-bound content.
- The outbound adapters for upstream, scanner, policy, evidence, registry,
  and download-gate ports follow with the Google Cloud trust-zone
  infrastructure.
- The `release/*` and `support/*` branch families and their Rulesets are
  activated only with a complete governed release lifecycle.
