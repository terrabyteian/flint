# containerd registry mirrors

A [proxy repository](configuration.md#proxy-repositories) can serve as a containerd registry mirror, so every node of a cluster pulls Docker Hub images through flint without changing any image reference: a pod that asks for `nginx:1.27` gets it from flint's cache, and keeps getting it when Docker Hub is down or rate-limits the cluster.

## flint

Declare a proxy repository for each upstream, with anonymous pulls, since containerd sends mirror requests without credentials:

```json
{
  "repositories": [
    {
      "name": "dockerhub",
      "format": "oci",
      "type": "proxy",
      "anonymousPull": true,
      "proxy": {"url": "https://registry-1.docker.io"}
    },
    {
      "name": "ghcr",
      "format": "oci",
      "type": "proxy",
      "anonymousPull": true,
      "proxy": {"url": "https://ghcr.io"}
    }
  ]
}
```

Each repository is addressed by its path prefix, `https://flint.example.internal/v2/dockerhub/...`, so one flint mirrors any number of upstreams.

## containerd

containerd reads mirror settings from one `hosts.toml` file per upstream registry, under the directory its `config_path` names.
Point the CRI plugin at that directory in `/etc/containerd/config.toml`, then restart containerd:

```toml
# containerd 2.x
[plugins."io.containerd.cri.v1.images".registry]
  config_path = "/etc/containerd/certs.d"

# containerd 1.x
[plugins."io.containerd.grpc.v1.cri".registry]
  config_path = "/etc/containerd/certs.d"
```

Then, for Docker Hub, `/etc/containerd/certs.d/docker.io/hosts.toml`:

```toml
server = "https://registry-1.docker.io"

[host."https://flint.example.internal/v2/dockerhub"]
  capabilities = ["pull", "resolve"]
  override_path = true
```

- The host URL ends with flint's `/v2/` plus the proxy repository's name, and `override_path = true` tells containerd to use that path as the registry API root instead of adding its own `/v2/`. containerd then requests `/v2/dockerhub/library/nginx/manifests/1.27`, which flint serves from the `dockerhub` repository.
- `resolve` lets containerd resolve tags through flint, so tag lookups are cached and survive upstream outages too; without it, only blobs come from flint.
- containerd adds a `ns=docker.io` query parameter to mirror requests, naming the registry of the image. A proxy repository ignores it: the repository in the path decides the upstream. A [virtual repository](#one-mirror-for-several-registries) uses it to pick the member.
- If flint is unreachable, containerd falls back to `server`, the upstream itself.

Other upstreams work the same way, such as `/etc/containerd/certs.d/ghcr.io/hosts.toml`:

```toml
server = "https://ghcr.io"

[host."https://flint.example.internal/v2/ghcr"]
  capabilities = ["pull", "resolve"]
  override_path = true
```

## One mirror for several registries

An [OCI virtual repository](configuration.md#oci-virtual-repositories) whose members are proxies of several registries serves as the mirror of all of them at one URL.
containerd names the registry of each image in the `ns` parameter of its mirror requests, and the virtual repository answers a request with `ns` only from its proxy members of that registry: `ns=docker.io` from a proxy of `https://registry-1.docker.io`, `ns=ghcr.io` from a proxy of `https://ghcr.io`, and so on.
So `docker.io/library/nginx` comes from Docker Hub and `ghcr.io/acme/tool` from ghcr.io even if both registries have an image of the same name, and a registry the virtual repository has no proxy of is answered `404`, after which containerd tries its next host.
Hosted members are not asked for mirror requests, since the image reference names an upstream registry.

Add the virtual repository next to the proxies, with anonymous pulls:

```json
{
  "repositories": [
    {"name": "docker-local", "format": "oci", "type": "hosted"},
    {"name": "dockerhub", "format": "oci", "type": "proxy", "proxy": {"url": "https://registry-1.docker.io"}},
    {"name": "ghcr", "format": "oci", "type": "proxy", "proxy": {"url": "https://ghcr.io"}},
    {"name": "quay", "format": "oci", "type": "proxy", "proxy": {"url": "https://quay.io"}},
    {
      "name": "docker",
      "format": "oci",
      "type": "virtual",
      "anonymousPull": true,
      "virtual": {"members": ["docker-local", "dockerhub", "ghcr", "quay"], "publishTo": "docker-local"}
    }
  ]
}
```

The proxies need no `anonymousPull` of their own: pulling through the virtual repository needs only its own.
Then point every registry's `hosts.toml` at the same URL, `/v2/` plus the virtual repository's name.
`/etc/containerd/certs.d/docker.io/hosts.toml`:

```toml
server = "https://registry-1.docker.io"

[host."https://flint.example.internal/v2/docker"]
  capabilities = ["pull", "resolve"]
  override_path = true
```

`/etc/containerd/certs.d/ghcr.io/hosts.toml`:

```toml
server = "https://ghcr.io"

[host."https://flint.example.internal/v2/docker"]
  capabilities = ["pull", "resolve"]
  override_path = true
```

`/etc/containerd/certs.d/quay.io/hosts.toml`:

```toml
server = "https://quay.io"

[host."https://flint.example.internal/v2/docker"]
  capabilities = ["pull", "resolve"]
  override_path = true
```

Adding a registry later takes a proxy repository, a member entry, and one more `hosts.toml`.
The same virtual repository also serves clients that address flint directly, without `ns`: `docker pull flint.example.internal/docker/library/nginx` asks the members in order, and `docker push flint.example.internal/docker/team/app` pushes to `docker-local`.

## TLS and plain HTTP

If flint's certificate comes from a private CA, add `ca = "/etc/containerd/certs.d/flint-ca.crt"` to the `[host...]` table.
If flint serves plain HTTP, use an `http://` host URL, such as `http://flint.example.internal:5000/v2/dockerhub`.

containerd reads `hosts.toml` files when it pulls, so changes to them need no restart.
Kubernetes distributions that generate containerd's configuration from their own registry settings have their own way to write these files; the result must be the `hosts.toml` above.

## Checking it

Pull through the mirror with `ctr`, which needs the directory named explicitly, or with `crictl`, which goes through the CRI plugin:

```sh
sudo ctr images pull --hosts-dir /etc/containerd/certs.d docker.io/library/alpine:3.20
sudo crictl pull alpine:3.20
```

flint logs each request, and its metrics count them: `flint_proxy_requests_total{repository="dockerhub"}` grows with `fetched` results for the first pull of an image and `hit` or `revalidated` results after that.
Through a virtual repository, the counts are the members': a pull of `ghcr.io/...` through `/v2/docker` counts under `repository="ghcr"`, and each request's log line names the `member` that served it.
