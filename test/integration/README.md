# Integration tests

Integration tests for the dependency authority lanes land here together with
the outbound trust-zone adapters (upstream, scanner, policy store, evidence
store, approved registry, download gate).

The DA-1 foundation ships the domain model, the application services, the
consumer-defined ports, and the five lane controllers. Real adapter
implementations follow with the Google Cloud trust-zone infrastructure; the
integration tests for those adapters belong to the tickets that deliver them.

An integration test proves behavior a fake cannot prove: real registry
promotion, real download revocation, real evidence persistence, and real
upstream intake semantics.
