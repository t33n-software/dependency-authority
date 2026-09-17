# ADR-0004: Evidence Workloads — the Operations-Evidence Content Contract, the Two Controller Forms, and the Lane Input Forms

## Status

Accepted

## Context

The cloud-agnostic dependency-authority reference separates the evidence
plane into two content classes with two different writer boundaries (its
evidence writer boundaries section): dependency evidence is written by the
lane workload itself as an atomic part of its use case, and operations
evidence — lane-run markers and the operations, revalidation, revocation,
quarantine and retention records — is written only by the evidence-write
workload identity, because the identity an attestation describes never holds
the writer grant for its own attestation. The evidence-audit workload is the
read-only proof surface of the internal evidence index: it reads the index
and proves the content-addressed locators a lane report references, and it
writes nothing.

The same reference binds the gate placement per operation class at the
external trigger seam: the attestation write (the operations-evidence
boundary) carries a human approval gate, and a read-only proof surface
carries none. It also defers the concrete operations-evidence content
contract — the marker schema, the operations record types and their cadence —
to the change that implements the evidence workloads; until that binding
exists the two evidence jobs remain declared but unprovisioned.

Two form decisions needed a binding answer: which execution form writes the
operations evidence, and which read surface proves the referenced locators.

## Decision

1. **The content contract.** The operations-evidence record is a JSON
   document of the schema `dependency-authority/operations-evidence/v1`: the
   record type from the controlled vocabulary (`lane-run`, `operation`,
   `revalidation`, `revocation`, `quarantine`, `retention`), the attested
   subject lane, the execution reference, the outcome (`succeeded` or
   `failed`), the evidence locators the operation produced, an optional
   detail, the issuer, and the issue time. The record type is validated data,
   never a code path: the evidence-write controller is the single generic
   writer, and a new record type is a vocabulary extension, never a new
   workload.

2. **The human-gated attestation-write form.** The evidence-write lane stays
   a dispatch-only trigger and carries the operation event as validated
   dispatch inputs (`record_type`, `subject_lane`, `execution`, `outcome`,
   the optional `evidence_references` and `detail`), passed as execution
   parameters. The attestation write is the human-gated trigger-seam
   operation: the reviewed dispatch is the provenance of the attested values.
   The controller validates the event fail-closed through the domain record
   construction and writes it through the evidence store over the new
   operations write path — the same append-only store, the fixed
   `operations-evidence` package, content-addressed and idempotent. The
   issuer identity is bound in the job environment at provisioning time,
   never passed by the lane.

3. **The read-only audit form.** The evidence-audit lane carries the subject
   (`module`, `version`) as dispatch inputs. The controller reads the
   candidate's evidence trail through the existing evidence-store read
   surface, fetches every referenced payload through the new
   locator-addressed fetch path, and re-proves the content identity against
   the digest-bound reference; a digest drift fails closed as a supply-chain
   anomaly. The audit workload writes nothing.

4. **The store carries the two new paths.** The evidence store gains the
   operations write path (the candidate-free operations record publication)
   and the payload proof path (the locator-addressed payload fetch over the
   decode-compare-resolve inventory form). Both stay inside the bound
   evidence repository; a locator crossing the bound repository fails closed.

## Consequences

- The operations-evidence content contract is bound by this change; the two
  evidence jobs remain declared but unprovisioned until the convergence
  program provisions them through the bound engine execution form.
- The lane forms evolve: the evidence-write lane carries the operation event
  inputs, the evidence-audit lane carries the subject inputs; the packaging
  contract guards bind both forms fail-closed.
- The controller and application layout gains the two controllers
  (`dependency-evidence-write-controller`,
  `dependency-evidence-audit-controller`) and the two use-case packages
  (`evidencewrite`, `evidenceaudit`); the quality seam carries eight lane
  controller binaries.
- The evidence-write identity holds no lane-operation grant, and no lane
  identity writes its own attestation — the separation of duties is
  structural.
