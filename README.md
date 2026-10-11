# flint

flint is a self-hosted artifact registry, built from scratch.
It serves container images and OCI artifacts, and Python packages, from hosted repositories and caching proxies of upstream registries such as Docker Hub, ghcr.io, and PyPI.

> **Status: pre-alpha.** `flint serve` serves hosted OCI repositories (the OCI Distribution Spec v1.1, checked against the official conformance suite), local users and API tokens, the Docker token service, and an [admin API](docs/auth.md), but the registry API does not require authentication yet: anyone who can reach it can push and delete.
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
echo '{"dataDir": "/tmp/flint-data"}' > /tmp/flint.json
./flint serve -config /tmp/flint.json    # plain HTTP on :5000
```

[docs/configuration.md](docs/configuration.md) describes the configuration file.

Releases publish a multi-arch `FROM scratch` image to `ghcr.io/terrabyteian/flint`, a Helm chart to `oci://ghcr.io/terrabyteian/charts/flint`, and static binaries, signed with cosign; see [installing with Helm](docs/helm.md), and [releasing](docs/releasing.md) for how to cut and verify a release.

## Contributing

Contributions are welcome under the Developer Certificate of Origin; see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

flint is licensed under the [Apache License 2.0](LICENSE).
