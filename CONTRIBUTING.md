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

## Standard library only

flint builds with the Go standard library and nothing else.

- Do not add `require` directives to `go.mod`, and do not commit a `go.sum`.
- `golang.org/x/...` modules count as external and are not allowed either.
- If you need something the standard library lacks, write it in flint, with tests.

Tools that never ship in the binary are fine in CI: real clients such as docker, crane, oras, pip, uv, and twine, and the OCI distribution conformance suite.

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

## Pull requests

- Keep pull requests focused on one change.
- Update `docs/design.md` in the same pull request when a change alters a recorded decision or interface.
- By submitting a pull request you agree to license your contribution under the [Apache License 2.0](LICENSE).
