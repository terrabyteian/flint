# Helm chart repositories

Helm charts pushed to a hosted OCI repository with `helm push` can also be served as a classic Helm chart repository, the kind `helm repo add` uses.
Tools that read only classic repositories, such as older Helm releases, `helm repo` workflows, and GitOps tools configured with a repository URL, then use the same charts as `oci://` clients, without a second copy or a second upload step.

To deploy flint itself with Helm, see [installing with Helm](helm.md) instead.

## Turn it on

Set `helmIndex` on a hosted OCI repository in the [configuration](configuration.md#repositories):

```json
{
  "repositories": [
    {"name": "charts", "format": "oci", "type": "hosted", "helmIndex": true}
  ]
}
```

Proxy repositories cannot offer the view: a proxy holds only the charts pulled through it, so its index could list only those.

## Push charts

Uploads stay `helm push` over OCI; the classic repository has no upload API.

```sh
helm registry login registry.example -u ci-bot           # password or API token
helm package ./mychart
helm push mychart-1.2.0.tgz oci://registry.example/charts
helm push other-0.3.0.tgz oci://registry.example/charts/team
```

`helm push` stores a chart at `<repository>/<path>/<chart name>:<version>`, writing a `+` in the version as `_`.
If a provenance file (`mychart-1.2.0.tgz.prov`, from `helm package --sign`) lies next to the package, `helm push` uploads it too.

## Use the classic repository

The charts directly below the repository are served at `/helm/<repository>/`, and those below a deeper path at `/helm/<repository>/<path>/`:

```sh
helm repo add flint https://registry.example/helm/charts --username ci-bot --password "$TOKEN"
helm repo add flint-team https://registry.example/helm/charts/team --username ci-bot --password "$TOKEN"
helm search repo flint/
helm install demo flint/mychart --version 1.2.0
helm pull flint/mychart --version 1.2.0 --verify          # checks the provenance file
```

Each view serves:

| Path | Content |
| --- | --- |
| `index.yaml` | The chart index. |
| `charts/<name>-<version>.tgz` | A chart, byte for byte the archive `helm push` uploaded. |
| `charts/<name>-<version>.tgz.prov` | Its provenance file, when one was pushed. |

## The index

- **What it lists.** Every tag in the view whose manifest is a Helm chart: its config media type is `application/vnd.cncf.helm.config.v1+json`, as `helm push` writes it. Only tags named as `helm push` names them are listed, so a chart is listed once however many other tags point to it: the image name must be the chart's name and the tag its version (with `_` for `+`). Each chart's versions are listed in tag order; Helm sorts them itself. Two charts whose file names `<name>-<version>.tgz` are the same, such as `a` 1.0.0-1.0.0 and `a-1.0.0` 1.0.0, are both left out.
- **Entries.** Each entry is the chart's metadata (`Chart.yaml` as `helm push` stored it in the config blob), plus `digest`, the chart archive's sha256, `created`, when the chart was first pushed, and `urls`, the chart's path relative to the repository, so the index works however clients reach flint. Charts pushed before flint recorded push times have no `created`.
- **Format.** The index is served as JSON with `Content-Type: application/json`, though its name is `index.yaml`. Helm 3.17 and later, and Helm 4, detect JSON and parse it as JSON; earlier Helm 3 releases parse it as YAML, of which JSON is a subset.
- **Caching.** flint builds the index from the repository's metadata when it is first asked for, keeps it in memory, and rebuilds it only after a tag in the view is pushed, moved, or deleted. The `ETag` changes with the tags, so `helm repo update` and other clients that send `If-None-Match` get `304 Not Modified` while nothing changed.

## Mutability

Chart versions follow the OCI repository's tags:

- With `immutableTags`, a chart version is permanent: pushing different content under the same version is refused, and chart files are served with a one-year `Cache-Control` lifetime.
- Without it, pushing a chart version again replaces it: the index lists the new archive's digest, and chart files are served with `Cache-Control: no-cache`.
- Deleting a chart version's tag, such as with `crane delete`, removes it from the index.

## Access

The view needs the `read` role on the repository, exactly like a pull, and anonymous clients may read it when the repository has `anonymousPull`.
Clients send HTTP basic credentials, a password or an [API token](auth.md#api-tokens), as `helm repo add --username --password` does; tokens from the Docker token endpoint are not accepted.
A request without valid credentials gets `401` with `WWW-Authenticate: Basic realm="flint"`, and one without permission gets `403`.
