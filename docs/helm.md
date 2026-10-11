# Installing with Helm

The Helm chart in [`deploy/helm/flint`](../deploy/helm/flint) runs flint on Kubernetes 1.30 or later.
Each release publishes it to `oci://ghcr.io/terrabyteian/charts/flint`, signed with cosign; its version is the release tag without the `v`, and it deploys the image of the same release by default.

## Install

Start from [`helm-values.example.yaml`](helm-values.example.yaml), which serves HTTPS on a LoadBalancer address with a certificate from a cert-manager ClusterIssuer, and creates the first administrator from a Secret:

```sh
kubectl create namespace flint
kubectl create secret generic flint-admin --namespace flint \
  --from-literal=password="$(openssl rand -base64 24)"
helm install flint oci://ghcr.io/terrabyteian/charts/flint --version 0.1.0 \
  --namespace flint --values helm-values.example.yaml
kubectl rollout status statefulset/flint --namespace flint
```

Without values, the chart serves plain HTTP on a ClusterIP service at port 5000, with a 10Gi volume and no repositories.

To check a chart before installing it, verify its signature with the identity described in [releasing](releasing.md#verifying-a-release):

```sh
cosign verify ghcr.io/terrabyteian/charts/flint:0.1.0 \
  --certificate-identity "$IDENTITY" --certificate-oidc-issuer "$ISSUER"
```

## What the chart creates

- A **ConfigMap** holding `config.json`, rendered from the `config` value and mounted at `/etc/flint/config.json`. The pod restarts when it changes, because flint reads its configuration at startup.
- A **StatefulSet** with one replica. flint locks its data directory, so the chart never runs two pods on one volume: an update stops the old pod before it starts the new one, which makes updates a short outage.
- A **PersistentVolumeClaim** for `/var/lib/flint`, from the StatefulSet's claim template or `persistence.existingClaim`. Uninstalling the release keeps the claim; delete it yourself to delete the data. The volume also holds the [audit log](operations.md#audit-log), kept forever unless `config.audit.retention` limits it.
- A **Service** of type ClusterIP, NodePort, or LoadBalancer.
- A **ServiceAccount** without an API token, since flint does not call the Kubernetes API.
- Optionally a cert-manager **Certificate** and a **NetworkPolicy**.

The pod runs as the image's non-root user `65532` with a read-only root filesystem, no capabilities, and the runtime's default seccomp profile.
Its startup, liveness, and readiness probes use `/healthz` and `/readyz`.
Before flint shuts down, a `preStop` hook waits `lifecycle.preStopSleepSeconds` (default 5) so the pod leaves the Service's endpoints before flint stops accepting connections.

## Configuration

The `config` value is flint's [configuration file](configuration.md), written as YAML.
The chart sets these fields itself and refuses to render if you set them:

| Field | Set from |
| --- | --- |
| `listen` | `containerPort` (default 5000) |
| `dataDir` | always `/var/lib/flint`, the data volume |
| `tls` | `tls.enabled`: the certificate is mounted at `/etc/flint/tls` |
| `auth.bootstrapAdmin` | `bootstrapAdmin`: the password is mounted at `/etc/flint/admin/password` |
| `backup.directory` | `backup.enabled`: the backup volume is mounted at `/var/backups/flint` |

flint validates everything else when it starts, and does not start with an invalid configuration.
To check a configuration before deploying it, render it to a file and pass that to `flint config check`:

```sh
helm template flint oci://ghcr.io/terrabyteian/charts/flint --version 0.1.0 --values my-values.yaml |
  yq 'select(.kind == "ConfigMap") | .data["config.json"]' > config.json
flint config check config.json
```

Keep `config.shutdownTimeout` plus `lifecycle.preStopSleepSeconds` below `terminationGracePeriodSeconds` (defaults 25s, 5, and 40), so a shutdown finishes before the kubelet kills flint.

## Values

[`values.yaml`](../deploy/helm/flint/values.yaml) documents every value, and the chart rejects values it does not know.
The main ones:

| Value | Default | Meaning |
| --- | --- | --- |
| `image.repository` | `ghcr.io/terrabyteian/flint` | Image repository. |
| `image.tag` | the chart's appVersion | Image tag. |
| `image.digest` | none | Image digest, which takes precedence over the tag. |
| `config` | log level info, no repositories | flint's configuration; see above. |
| `containerPort` | `5000` | The port flint listens on. |
| `service.type` | `ClusterIP` | `ClusterIP`, `NodePort`, or `LoadBalancer`. |
| `service.port` | `5000` | The Service's port. |
| `service.loadBalancerIP`, `service.annotations` | none | For load balancers that take a fixed address or annotations, such as MetalLB. |
| `service.externalTrafficPolicy` | Kubernetes' default | `Local` keeps client addresses for flint's logs. |
| `tls.enabled` | `false` | Serve HTTPS. Needs `tls.existingSecret` or `tls.certManager.enabled`. |
| `tls.existingSecret` | none | A `kubernetes.io/tls` secret to serve. |
| `tls.certManager.enabled` | `false` | Create a cert-manager Certificate from `tls.certManager.issuerRef`. Its names are `tls.certManager.dnsNames` and `ipAddresses` plus the Service's cluster names. |
| `bootstrapAdmin.enabled`, `bootstrapAdmin.existingSecret` | `false`, none | Create the first administrator from a password in a Secret; see below. |
| `upstreamSecrets` | none | Secrets with proxy repositories' upstream passwords; see below. |
| `persistence.enabled` | `true` | Keep data on a volume; disabled, it is an `emptyDir` lost with the pod. |
| `persistence.size`, `persistence.storageClass` | `10Gi`, cluster default | The claim template. Kubernetes does not let a StatefulSet's claim template change after install: to grow the volume, resize the claim directly if its storage class allows it. |
| `persistence.existingClaim` | none | Use this claim instead of the claim template. |
| `backup.enabled`, `backup.existingClaim`, `backup.volume` | `false`, none, none | Mount a volume for [backups](backup.md); see below. |
| `lifecycle.preStopSleepSeconds` | `5` | The wait before shutdown; 0 disables it. |
| `networkPolicy.enabled`, `networkPolicy.from` | `false`, any source | Admit traffic only to flint's port, from the listed peers. |
| `resources`, `nodeSelector`, `tolerations`, `affinity`, `priorityClassName` | none | Pod scheduling and resources. |

### TLS

flint reloads its certificate when the mounted secret changes, so cert-manager renewals take effect without a restart, within about a minute of the secret changing.
To terminate TLS in a proxy instead, leave `tls.enabled` off and list the proxy's addresses in `config.trustedProxies`.

### First administrator

flint creates its first administrator at startup from a password file, while no administrator exists ([authentication](auth.md#users-and-the-first-administrator)).
The chart mounts that file from the key `password` of a Secret you create:

```sh
kubectl create secret generic flint-admin --namespace flint \
  --from-literal=password="$(openssl rand -base64 24)"
```

```yaml
bootstrapAdmin:
  enabled: true
  username: admin             # the default
  existingSecret: flint-admin
```

The chart sets `config.auth.bootstrapAdmin` itself and refuses to render if you set it.
flint reads the Secret only while no administrator exists, so it may be deleted after the first start; the volume is optional, so a missing Secret does not stop the pod from starting.
Without `bootstrapAdmin`, flint starts with no administrator and logs a warning, and nobody can use the admin API.

### Upstream credentials

A [proxy repository](configuration.md#proxy-repository-settings) may authenticate to its upstream, for example with a Docker Hub account for higher pull limits.

> **Warning:** flint sends every upstream request of the repository with this account, so anyone allowed to pull from the proxy repository can read whatever the account can read upstream, including its private repositories.
> Use a dedicated account that has no private content, or an access token limited to public, read-only access, and do not combine credentials with `anonymousPull` unless the account can read only public content.

Put the password or access token in a Secret under the key `password`, and list it in `upstreamSecrets` under a name; the chart mounts it at `/etc/flint/upstream/<name>/password`, the path to give as the repository's `passwordFile`:

```sh
kubectl create secret generic dockerhub-credentials --namespace flint \
  --from-literal=password="$DOCKER_HUB_ACCESS_TOKEN"
```

```yaml
config:
  repositories:
    - name: dockerhub
      format: oci
      type: proxy
      proxy:
        url: https://registry-1.docker.io
        username: my-docker-hub-user
        passwordFile: /etc/flint/upstream/dockerhub/password
upstreamSecrets:
  - name: dockerhub
    existingSecret: dockerhub-credentials
```

flint reads the file whenever it authenticates, so rotating the Secret takes effect without a restart once the kubelet updates the mount.
The Secret must exist before the pod starts.

### Backups

flint writes [backups](backup.md) to a directory it can reach, normally a volume on other storage than its data.
`backup.enabled` mounts one at `/var/backups/flint` and sets `config.backup.directory` to it: an existing claim, or any other volume source, such as NFS:

```yaml
backup:
  enabled: true
  existingClaim: flint-backups
  # or, instead of existingClaim:
  # volume:
  #   nfs:
  #     server: nas.example.internal
  #     path: /backups/flint
```

The chart does not schedule backups: [backups](backup.md#scheduling) shows a CronJob that starts one through the admin API.

## Upgrades and uninstalling

`helm upgrade` replaces the pod; flint is unavailable from the moment the old pod stops until the new one is ready.
If an upgrade leaves the pod failing, for example with a configuration flint rejects or an image tag that does not exist, upgrading again with corrected values or running `helm rollback` replaces the failing pod; the StatefulSet's `Parallel` pod management lets it do so without waiting for the pod to become ready.
`helm uninstall` leaves the data claim, `data-<statefulset>-0` such as `data-flint-0`, in place, so reinstalling with the same release name reuses the data.
