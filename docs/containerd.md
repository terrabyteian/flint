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
- containerd adds a `ns=docker.io` query parameter to mirror requests. flint ignores it: the repository in the path decides the upstream.
- If flint is unreachable, containerd falls back to `server`, the upstream itself.

Other upstreams work the same way, such as `/etc/containerd/certs.d/ghcr.io/hosts.toml`:

```toml
server = "https://ghcr.io"

[host."https://flint.example.internal/v2/ghcr"]
  capabilities = ["pull", "resolve"]
  override_path = true
```

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
