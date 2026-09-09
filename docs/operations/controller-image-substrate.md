# Controller Image Substrate

This runbook binds the build and delivery procedure of the dependency
authority controller workload images (GO-SCF-019): the single parameterized
root `Dockerfile` packages one locally built lane controller on the
digest-pinned minimal non-root runtime, and the governed producer channel
delivers the image to the staging class and promotes the proven digest to the
release class.

## Bound form

- Exactly one versioned `Dockerfile` at the repository root, parameterized by
  `ARG CONTROLLER` over the five lane controllers:
  - `dependency-intake-controller`
  - `dependency-admission-controller`
  - `dependency-promotion-controller`
  - `dependency-revalidation-controller`
  - `dependency-revocation-controller`
- The base is the minimal non-root runtime
  `gcr.io/distroless/static-debian12:nonroot`, pinned by the full index digest
  `sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab`
  resolved and proven at the upstream (see the base pin proof below). Never a
  tag, never `latest`, and never a floating `# syntax` frontend reference.
- The image carries no build: the controller binary is built locally with the
  controlled toolchain and copied in. The runtime user is the numeric
  non-root identity `65532:65532`.
- Consumption is digest-only from the release class; the staging class is the
  only delivery target of the producer channel and never serves workloads.

## Base pin proof

The base digest is bound at the upstream and re-proven before every build
wave; a digest drift is a governed change, never a silent edit:

```text
docker buildx imagetools inspect gcr.io/distroless/static-debian12:nonroot
```

The `Digest` line of the OCI image index is the bound value. In the bootstrap
era the digest is bound at the upstream directly; the steady-state channel
migrates the reference to the approved docker dependency registry without
changing the binding form.

## Build

Build the controller binary with the controlled toolchain and the bound
flags, from the repository root:

```text
GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
go build -trimpath -ldflags="-s -w" \
  -o .build/controller-images/<controller> ./cmd/<controller>
```

The toolchain is exactly the pinned one (the `toolchain` directive of
`go.mod`); a host whose local installation diverges resolves the pinned
toolchain through the Go toolchain mechanism, and a binary built with a
divergent toolchain is never delivered.

Build the image (the build context is the repository root; only the binary
under `.build/controller-images/` enters the image):

```text
docker build --build-arg CONTROLLER=<controller> \
  --platform linux/amd64 \
  -t <region>-docker.pkg.dev/<organization>-dep-control/staging-controller-images/<controller>:<build-id> .
```

Smoke-proof the image before any delivery:

```text
docker run --rm <image> --version
```

## Delivery

1. Push the image to the staging class only (`staging-controller-images`); a
   direct write to the release class is forbidden in every era.
2. Prove the delivered content fail-closed by reading back the digest of the
   pushed image and comparing it to the local build digest.
3. Promote exactly that digest to the release class
   (`release-controller-images`) as a separate auditable release event.
4. Workloads consume only from the release class and only by full `@sha256:`
   digest.

## Verification

The packaging contract tests bind the substrate fail-closed: the
digest-pinned base, the `ARG CONTROLLER` parametrization, the non-root user,
the absent syntax frontend reference, the five controller names, and the
bindings of this runbook. The governed quality gate runs them on every
shared-line change.
