# The single parameterized controller workload image of the dependency
# authority (GO-SCF-019): pure packaging of the locally built controller
# binary on the digest-pinned minimal non-root runtime. The base digest is
# resolved and proven at the upstream; the build and delivery procedure lives
# in docs/operations/controller-image-substrate.md.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

ARG CONTROLLER
COPY .build/controller-images/${CONTROLLER} /controller

USER 65532:65532

ENTRYPOINT ["/controller"]
