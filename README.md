# flint

flint is a self-hosted artifact registry, built from scratch.
It serves container images and OCI artifacts, Python packages, Rust crates, npm packages, Java and other JVM artifacts, Go modules, and arbitrary files, from hosted repositories and caching proxies of upstream registries such as Docker Hub, ghcr.io, PyPI, crates.io, registry.npmjs.org, Maven Central, and proxy.golang.org.

> **Status: pre-alpha.** `flint serve` serves hosted OCI repositories (the OCI Distribution Spec v1.1, checked against the official conformance suite), caching proxies of upstream registries such as Docker Hub and ghcr.io that also work as [containerd mirrors](docs/containerd.md), [classic Helm chart repositories](docs/helm-repository.md) over charts pushed with `helm push`, [PyPI repositories](docs/pypi.md) (hosted, caching proxies of indexes such as pypi.org, and virtual indexes merging them) for pip, uv, and twine, [generic files repositories](docs/generic.md) (hosted, caching proxies of any download site, and virtual repositories merging them) for curl and wget, [Cargo repositories](docs/cargo.md) (hosted, caching proxies of sparse indexes such as crates.io's, and virtual registries merging them), [npm repositories](docs/npm.md) (hosted, caching proxies of registries such as registry.npmjs.org, and virtual registries merging them) for npm, pnpm, Yarn, and Bun, [Maven repositories](docs/maven.md) (hosted, caching proxies of repositories such as Maven Central, and virtual repositories merging them) for Maven and Gradle, [Go module repositories](docs/go.md) (caching proxies of module proxies such as proxy.golang.org, verified against and proxying the Go checksum database, and virtual repositories merging them) for the go command, local users and API tokens, the Docker token service, an [admin API](docs/auth.md), incremental [backups](docs/backup.md) with restore, an [audit log](docs/operations.md#audit-log) of every change, and online [garbage collection](docs/garbage-collection.md).
> See the [roadmap](docs/design.md#roadmap) for what comes next.

## Goals

- **One static binary plus a data directory.** No database, cache server, or object store to run beside it.
- **OCI and Docker:** the full OCI Distribution Spec v1.1, the referrers API, multi-arch images, and arbitrary OCI artifacts such as Helm charts.
- **PyPI:** the simple API (PEP 503 and 691), metadata files, yanking, uploads from twine and uv, and a merged index with dependency-confusion protection.
- **Generic files:** arbitrary files by path for curl, wget, and scripts, immutable by default, with digest-checked uploads and directory listings.
- **Cargo:** the sparse registry protocol, `cargo publish`, yanking, search, and a merged registry with dependency-confusion protection that resolves a crate's whole dependency graph.
- **npm:** the registry API that npm, pnpm, Yarn, and Bun use: publish, dist-tags, deprecate, unpublish, npm login, and a merged registry with dependency-confusion protection that installs and publishes through one URL.
- **Maven:** the Maven 2 repository layout for Maven and Gradle, with deploys, snapshots, generated `maven-metadata.xml`, checksums, and a merged repository with dependency-confusion protection.
- **Go modules:** the GOPROXY protocol and the checksum database, every cached module verified against it, and merged module proxies with filters for internal module paths.
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

[docs/configuration.md](docs/configuration.md) describes the configuration file, and [docs/operations.md](docs/operations.md) running flint, including its audit log.

Releases publish a multi-arch `FROM scratch` image to `ghcr.io/terrabyteian/flint`, a Helm chart to `oci://ghcr.io/terrabyteian/charts/flint`, and static binaries, signed with cosign; see [installing with Helm](docs/helm.md), and [releasing](docs/releasing.md) for how to cut and verify a release.

## Contributing

Contributions are welcome under the Developer Certificate of Origin; see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

flint is licensed under the [Apache License 2.0](LICENSE).
