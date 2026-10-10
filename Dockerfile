# syntax=docker/dockerfile:1

# Builds the flint image: a static binary in a FROM scratch image.
#
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     --build-arg VERSION=v1.2.3 -t ghcr.io/terrabyteian/flint:v1.2.3 .
#
# The builder stage runs on the build host's platform and cross-compiles for
# each target platform, so multi-arch builds need no emulation.
#
# Data volume: flint keeps its state in /var/lib/flint, owned by the non-root
# user 65532:65532 that the image runs as. Mount a persistent volume there.
#
# The builder image's Go version must match the toolchain line in go.mod, which
# CI and the release binaries build with; bump the two together.

FROM --platform=$BUILDPLATFORM golang:1.27.2@sha256:5bc7f572bbaa98885a3a1fd9c0aa76b59e3e14e8628bfc316bbfd0c701e4818c AS build

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev

WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
	go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/flint ./cmd/flint

# An empty directory to become the data volume mount point, owned by the
# runtime user so a fresh volume is writable.
RUN mkdir -p /out/var/lib/flint

FROM scratch

ARG VERSION=dev

LABEL org.opencontainers.image.title="flint" \
	org.opencontainers.image.description="Artifact registry for OCI images and Python packages" \
	org.opencontainers.image.source="https://github.com/terrabyteian/flint" \
	org.opencontainers.image.licenses="Apache-2.0" \
	org.opencontainers.image.version="${VERSION}"

# CA certificates for TLS connections to upstream registries.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build --chown=65532:65532 /out/var/lib/flint /var/lib/flint
COPY --from=build /out/flint /flint

USER 65532:65532
ENTRYPOINT ["/flint"]
CMD ["serve"]
