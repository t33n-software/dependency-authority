# Dependency Authority

`dependency-authority` is the organization-agnostic core for the dependency
authority bounded context: intake, admission, quarantine, approval,
promotion, revalidation, and revocation controllers.

This repository never contains concrete organization, tenant, project,
identity, network, secret, or registry bindings. Instances consume this core
only through versioned releases, immutable digests, and schema version pins.

Governed changes land through ticket branches and pull requests into
`develop`. `main` is the production and control-plane truth.
