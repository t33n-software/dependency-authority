# GitHub Rulesets

These files map the canonical Git governance to the current Dependency
Authority source boundary. They do not define a second release, evidence, or
dependency policy.

## Import timing

The branch Rulesets 01 to 03 bind required status checks; import them through
the GitHub graphical interface only after the repository has produced the
actual required checks for the target line:

```text
Settings
-> Rules
-> Rulesets
-> New ruleset
-> Import a ruleset
```

The push Ruleset 00 binds no required checks and no branch targets, so it does
not wait for check evidence.

Import in this order:

```text
00-push-protections.json
01-ticket-working-branches.json
02-develop.json
03-main.json
```

Do not import a `release/*` or `support/*` Ruleset yet. Those families require
their own governed release workflow, immutable artifact delivery, and release
or maintenance contract.

## Push protections

`00-push-protections.json` is a push Ruleset: it applies to every push to the
repository and its entire fork network and carries no branch targeting. It
blocks secret- and key-shaped artifacts (private-key and key-store extensions,
environment files, credential files, and infrastructure state files) from
entering the commit graph.

Push Rulesets exist only for private and internal repositories with the Team
plan. This repository is public and cannot carry one; the file documents the
boundary and stands ready if the repository is ever reclassified as private.
The public secret-material boundary is secret scanning with push protection
plus the local quality gates.

The file mirrors the official GitHub export envelope because the import
validates against that schema: a `source` field with the repository's own
identity, an explicit `conditions: null` (push Rulesets carry no branch
conditions), and restricted file extensions in glob form (`*.pem`, not `pem`).

## Required GitHub repository settings

```text
Allow merge commits: enabled
Allow rebase merging: enabled
Allow squash merging: enabled
Automatically delete head branches: enabled
Allow auto-merge: disabled
Always suggest updating pull request branches: disabled
Enable release immutability: enabled
```

## Required checks

The shared-line Rulesets require only checks emitted by the current source
workflows:

```text
Quality gates (linux-amd64)
Dependency admission review
CodeQL code scanning with all alerts blocking
```

The Linux quality gate enforces formatting, module integrity, tests, exact
100% statement coverage, race detection, static analysis, the Linux/AMD64
build of all five lane controllers, and module provenance.

## Security boundary

Ruleset files must not contain credentials, signing keys, organization or
tenant bindings, bypass actors, or mutable references. The push Ruleset
carries the `source` field as the repository's own identity because the GitHub
import format requires it.
