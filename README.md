# flint

flint is a self-hosted artifact registry, built from scratch as a lightweight replacement for JFrog Artifactory.
It serves container images and OCI artifacts, and Python packages, from hosted repositories and caching proxies of upstream registries such as Docker Hub, ghcr.io, and PyPI.

> **Status: pre-alpha.** flint does not serve anything yet.
> The binary only prints its version.
> See the [roadmap](docs/design.md#roadmap) for what comes next.

## Goals

- **One static binary plus a data directory.** No database, cache server, or object store to run beside it.
- **OCI and Docker:** the full OCI Distribution Spec v1.1, the referrers API, multi-arch images, and arbitrary OCI artifacts such as Helm charts.
- **PyPI:** the simple API (PEP 503 and 691), metadata files, yanking, uploads from twine and uv, and a merged index with dependency-confusion protection.
- **Caching proxies** that keep upstream content forever, keep serving when the upstream is down, and never delete anything silently.
- **Durable by construction:** a write is acknowledged only after it is on disk, and all content is stored once by its sha256 digest.

The [design document](docs/design.md) covers the architecture and the reasoning behind it.

## Zero dependencies

flint is written in Go and builds with **only the Go standard library**: no third-party modules, including `golang.org/x`.
An artifact registry sits in the supply chain of everything built with it, so flint keeps its own supply chain to the Go toolchain alone.
CI rejects any change that adds a dependency.

## Building

flint needs the Go version named in [`go.mod`](go.mod).

```sh
CGO_ENABLED=0 go build -ldflags "-X main.version=v0.0.0" -o flint ./cmd/flint
./flint version
```

## Contributing

Contributions are welcome under the Developer Certificate of Origin; see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

flint is licensed under the [Apache License 2.0](LICENSE).
