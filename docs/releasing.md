# Releasing flint

A release is cut by pushing a version tag.
The [release workflow](../.github/workflows/release.yml) builds and publishes everything from that tag, using only the workflow's `GITHUB_TOKEN` and its GitHub OIDC identity; the repository stores no secrets.

## What a release publishes

| Artifact | Where |
| --- | --- |
| Multi-arch image (`linux/amd64`, `linux/arm64`) | `ghcr.io/terrabyteian/flint:<tag>` |
| Image signature (cosign, keyless) | stored next to the image in `ghcr.io/terrabyteian/flint` |
| SPDX SBOM of the image, as a signed cosign attestation | stored next to the image in `ghcr.io/terrabyteian/flint` |
| Static binaries `flint-{linux,darwin}-{amd64,arm64}` | assets of the GitHub release for the tag |
| `SHA256SUMS` and its cosign bundle `SHA256SUMS.sigstore.json` | assets of the GitHub release |
| The same SBOM, `flint-<tag>.spdx.json` | asset of the GitHub release |
| Helm chart, version `<tag>` without the `v` | `oci://ghcr.io/terrabyteian/charts/flint` |
| Chart signature (cosign, keyless) | stored next to the chart in `ghcr.io/terrabyteian/charts/flint` |
| The chart package `flint-<version>.tgz` | asset of the GitHub release |

Every binary, and the binary inside the image, reports the tag from `flint version`.
The chart's `appVersion` is the tag, so it deploys the image of the same release unless `image.tag` or `image.digest` says otherwise; the chart is published only after that image.
Tags containing a hyphen, such as `v0.2.0-rc.1`, produce a GitHub pre-release.
The workflow does not move a `latest` image tag; deployments pin a version or a digest.

flint's own image and chart stay on ghcr.io permanently, so a broken flint can always be redeployed without depending on itself.

## Cutting a release

1. Make sure `main` is green and contains everything the release should ship.
2. Create an annotated tag on the commit and push it:

   ```sh
   git checkout main && git pull
   git tag -a v0.1.0 -m "flint v0.1.0"
   git push origin v0.1.0
   ```

   Tags must look like `v1.2.3` or `v1.2.3-rc.1`; the workflow refuses anything else.
3. Watch the **Release** workflow run in the Actions tab.
   When it finishes, the GitHub release exists with generated notes, which you can edit.
4. **First release only:** new ghcr.io packages are private.
   In the repository's *Packages* settings, open the `flint` and `charts/flint` packages and change each one's visibility to public so clusters can pull them without credentials.

Pushing a tag is the only way to start a release.
To recover from a failed run, for example after a transient failure, open the run in the Actions tab and choose *Re-run failed jobs*.
Re-running the GitHub release job replaces the assets of a release that already exists.

## Verifying a release

Signing is keyless: each signature is tied to the release workflow's identity, recorded in the public Sigstore transparency log.
The certificate identity is the workflow file at the tag it ran from, and the issuer is GitHub Actions.
Install [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) v3 or later (the release workflow signs with v3), then set:

```sh
TAG=v0.1.0
IDENTITY="https://github.com/terrabyteian/flint/.github/workflows/release.yml@refs/tags/$TAG"
ISSUER=https://token.actions.githubusercontent.com
```

### The image

```sh
cosign verify ghcr.io/terrabyteian/flint:$TAG \
  --certificate-identity "$IDENTITY" --certificate-oidc-issuer "$ISSUER"
```

Verify by the digest you deploy, too: `cosign verify ghcr.io/terrabyteian/flint@sha256:...` with the same flags.

### The SBOM attestation

```sh
cosign verify-attestation ghcr.io/terrabyteian/flint:$TAG --type spdxjson \
  --certificate-identity "$IDENTITY" --certificate-oidc-issuer "$ISSUER"
```

The attested SBOM is the same document as the release's `flint-<tag>.spdx.json` asset.

### The chart

```sh
cosign verify ghcr.io/terrabyteian/charts/flint:${TAG#v} \
  --certificate-identity "$IDENTITY" --certificate-oidc-issuer "$ISSUER"
```

Chart tags have no `v`: the chart for `v0.1.0` is `ghcr.io/terrabyteian/charts/flint:0.1.0`.

### The binaries

Download the binary, `SHA256SUMS`, and `SHA256SUMS.sigstore.json` from the GitHub release, then:

```sh
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "$IDENTITY" --certificate-oidc-issuer "$ISSUER"
sha256sum --check --ignore-missing SHA256SUMS   # on macOS: shasum -a 256 --check --ignore-missing SHA256SUMS
```

## Building the image locally

The [`Dockerfile`](../Dockerfile) cross-compiles the static binary on the build host and copies it into a `FROM scratch` image, so a multi-arch build needs no emulation:

```sh
docker buildx build --platform linux/amd64,linux/arm64 --build-arg VERSION=v0.0.0-dev .
docker buildx build --load --build-arg VERSION=v0.0.0-dev -t flint:dev .
docker run --rm flint:dev version
```

The image runs as the non-root user `65532:65532`, contains only the `flint` binary at `/flint` and CA certificates for TLS to upstream registries, and keeps its data in `/var/lib/flint`, which should be a persistent volume.
Its default command is `flint serve`, which reads its configuration from `/etc/flint/config.json` (see [configuration](configuration.md)).

CI builds the image for both architectures on every pull request without pushing it, and runs `flint version` in the amd64 image.

## Checking the chart locally

CI lints and renders the chart with its default values, [`helm-values.example.yaml`](helm-values.example.yaml), and each values file in `deploy/helm/flint/ci`, validates the manifests with kubeconform, and checks each rendered configuration with `flint config check`.
To run the same checks, install helm, [yq](https://github.com/mikefarah/yq), and [kubeconform](https://github.com/yannh/kubeconform), then:

```sh
scripts/check-chart.sh
```

To package the chart the way a release does:

```sh
helm package deploy/helm/flint --version 0.1.0 --app-version v0.1.0
```
