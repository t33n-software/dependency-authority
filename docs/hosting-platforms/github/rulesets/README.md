# GitHub Rulesets

These files map the canonical Git governance to the current Dependency
Authority source boundary. They do not define a second release, evidence, or
dependency policy.

## Import timing

Import through the GitHub graphical interface only after the first DA-1 pull
request has produced the actual required checks for this repository:

```text
Settings
-> Rules
-> Rulesets
-> New ruleset
-> Import a ruleset
```

Import in this order:

```text
01-ticket-working-branches.json
02-develop.json
03-main.json
```

Do not import a `release/*` or `support/*` Ruleset yet. Those families require
their own governed release workflow, immutable artifact delivery, and release
or maintenance contract.

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
tenant bindings, bypass actors, or mutable references.
