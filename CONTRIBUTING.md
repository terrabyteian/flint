# Contributing to flint

Thanks for helping build flint.
Read the [design document](docs/design.md) before starting on anything beyond a small fix; it records the decisions the code relies on.

## Developer Certificate of Origin

flint uses the [Developer Certificate of Origin](https://developercertificate.org/) (DCO) instead of a contributor license agreement.
Every commit must carry a `Signed-off-by` line certifying that you wrote the change or otherwise have the right to submit it under the project's license:

```sh
git commit -s
```

This adds `Signed-off-by: Your Name <you@example.com>` using your git `user.name` and `user.email`.
To sign off commits you already made on a branch, run `git rebase --signoff main`.

Outside contributors must sign off every commit.
The `dco` job in CI runs [`scripts/check-dco.sh`](scripts/check-dco.sh) on every pull request and fails on any commit without a `Signed-off-by` line matching its author; commits authored by the project owner are exempt.

## Standard library only

flint builds with the Go standard library and nothing else.

- Do not add `require` directives to `go.mod`, and do not commit a `go.sum`.
- `golang.org/x/...` modules count as external and are not allowed either.
- If you need something the standard library lacks, write it in flint, with tests.

Tools that never ship in the binary are fine in CI: real clients such as docker, crane, oras, pip, uv, twine, cargo, npm, pnpm, Yarn, Bun, Maven, Gradle, and the go command, and the OCI distribution conformance suite.

## Tests

- Every change to behavior comes with tests, run with `go test -race ./...`.
- Prefer table-driven tests and the `testing` package; there is no assertion library.
- Storage and metadata code needs crash and fault-injection tests for its durability claims, not only happy-path tests.
- Protocol code is checked against real clients and conformance suites as those harnesses land.

## Running checks locally

CI runs these on every pull request and push to `main`; run them before you push:

```sh
gofmt -l .                # must print nothing; fix with gofmt -w .
go vet ./...
go test -race ./...
scripts/check-deps.sh     # fails on any dependency outside the standard library
```

CI also builds `./cmd/flint` with `CGO_ENABLED=0` for linux and darwin on amd64 and arm64.
To check one target locally:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /dev/null ./cmd/flint
```

It also builds the container image for linux/amd64 and linux/arm64 from the [`Dockerfile`](Dockerfile); see [releasing](docs/releasing.md#building-the-image-locally) to build it locally.
Changes to the Helm chart in [`deploy/helm/flint`](deploy/helm/flint) are checked by `scripts/check-chart.sh`, which needs helm, yq, and kubeconform; see [releasing](docs/releasing.md#checking-the-chart-locally).

CI also runs the official OCI distribution conformance suite, against a hosted repository and against a virtual repository that publishes to one, [`scripts/e2e-oci.sh`](scripts/e2e-oci.sh), and then [`scripts/e2e-gc.sh`](scripts/e2e-gc.sh), which deletes an image, moves the clock of an `e2e` build of flint past the grace period, runs garbage collection, and pulls everything left, against a running flint; the `oci` job in [`ci.yml`](.github/workflows/ci.yml) shows the configuration, and each script's header lists the clients it needs.
The `proxy` job runs [`scripts/e2e-proxy.sh`](scripts/e2e-proxy.sh), which pulls real images from Docker Hub and ghcr.io through proxy repositories, and [`scripts/e2e-virtual.sh`](scripts/e2e-virtual.sh), which pushes through a virtual repository over a hosted repository and those proxies and pulls Docker Hub, ghcr.io, and pushed images through it with crane, docker, and containerd as the mirror of both registries; both pull again after restarting flint with its upstreams unreachable.
The `helm` job runs [`scripts/e2e-helm.sh`](scripts/e2e-helm.sh) with Helm 3 and Helm 4, which pushes charts with `helm push` and uses them through the [classic Helm repository view](docs/helm-repository.md).
The `pypi` job runs [`scripts/e2e-pypi.sh`](scripts/e2e-pypi.sh), which publishes packages with twine and uv publish and installs them, and real projects from pypi.org, with pip and uv through hosted, proxy, and virtual PyPI repositories, then installs again after restarting flint with its upstream unreachable.
The `generic` job runs [`scripts/e2e-generic.sh`](scripts/e2e-generic.sh), which uploads, downloads, and lists files with curl and wget in hosted and virtual generic files repositories, and downloads flint's own release binaries through proxy repositories of its GitHub releases, checking them against their published checksums, then downloads again after restarting flint with its upstreams unreachable.
The `oidc` job runs [`scripts/e2e-oidc.sh`](scripts/e2e-oidc.sh), which signs in to flint through a real OpenID Connect provider, Dex, with curl following the authorization code flow, checks the user and groups flint synced, creates an API token with the session, and pushes and pulls an image with docker and uploads a file with curl using that token.
The `cargo` job runs [`scripts/e2e-cargo.sh`](scripts/e2e-cargo.sh), which publishes crates with `cargo publish`, yanks and searches them, and builds crates depending on them and on crates.io through hosted, proxy, and virtual Cargo repositories, then builds again after restarting flint with its upstream unreachable.
The `npm` job runs [`scripts/e2e-npm.sh`](scripts/e2e-npm.sh) with npm 10 and npm 11: against a hosted npm repository, it publishes, changes dist-tags, deprecates, unpublishes, and logs in with npm, and installs and publishes with npm, pnpm, Yarn classic, Yarn Berry, and Bun; through a proxy of registry.npmjs.org and a virtual repository, every client installs public and hosted packages, a second hosted repository playing a malicious upstream proves dependency-confusion protection and member filters, and after a restart with the upstream unreachable every client installs again from its lockfile.
The `maven` job runs [`scripts/e2e-maven.sh`](scripts/e2e-maven.sh), which deploys a library, its sources and javadoc, and a snapshot twice with Maven, publishes with Gradle 8 and Gradle 9, and builds projects with real dependencies from Maven Central through hosted, proxy, and virtual Maven repositories, then builds again with empty local caches after restarting flint with its upstream unreachable.
The `ui` job runs [`scripts/e2e-ui.sh`](scripts/e2e-ui.sh), which pushes an OCI image and its signature and uploads a PyPI package, then drives the web UI with curl as a browser would: it checks what anonymous visitors see, signs in, browses the image, its manifest, layers, and signature, and the package, creates an API token, uses it, and revokes it, checks that forms are refused from another site, and signs out.
The `go` job runs [`scripts/e2e-go.sh`](scripts/e2e-go.sh), which builds a module with real dependencies from proxy.golang.org with the go command through proxy and virtual Go repositories over TLS, with checksum database lookups going through flint, then builds it again with an empty module cache after restarting flint with its upstreams unreachable.

## Pull requests

- Keep pull requests focused on one change.
- Update `docs/design.md` in the same pull request when a change alters a recorded decision or interface.
- By submitting a pull request you agree to license your contribution under the [Apache License 2.0](LICENSE).
