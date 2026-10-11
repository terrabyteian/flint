# Installing with Helm

The Helm chart in [`deploy/helm/flint`](../deploy/helm/flint) runs flint on Kubernetes 1.30 or later.
Each release publishes it to `oci://ghcr.io/terrabyteian/charts/flint`, signed with cosign; its version is the release tag without the `v`, and it deploys the image of the same release by default.

## Install

Start from [`helm-values.example.yaml`](helm-values.example.yaml), which serves HTTPS on a LoadBalancer address with a certificate from a cert-manager ClusterIssuer:

```sh
kubectl create namespace flint
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
- A **PersistentVolumeClaim** for `/var/lib/flint`, from the StatefulSet's claim template or `persistence.existingClaim`. Uninstalling the release keeps the claim; delete it yourself to delete the data.
- A **Service** of type ClusterIP, NodePort, or LoadBalancer.
- A **ServiceAccount** without an API token, since flint does not call the Kubernetes API.
- Optionally a cert-manager **Certificate** and a **NetworkPolicy**.

The pod runs as the image's non-root user `65532` with a read-only root filesystem, no capabilities, and the runtime's default seccomp profile.
Its startup, liveness, and readiness probes use `/healthz` and `/readyz`.
Before flint shuts down, a `preStop` hook waits `lifecycle.preStopSleepSeconds` (default 5) so the pod leaves the Service's endpoints before flint stops accepting connections.

## Configuration

The `config` value is flint's [configuration file](configuration.md), written as YAML.
The chart sets three fields itself and refuses to render if you set them:

| Field | Set from |
| --- | --- |
| `listen` | `containerPort` (default 5000) |
| `dataDir` | always `/var/lib/flint`, the data volume |
| `tls` | `tls.enabled`: the certificate is mounted at `/etc/flint/tls` |

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
| `persistence.enabled` | `true` | Keep data on a volume; disabled, it is an `emptyDir` lost with the pod. |
| `persistence.size`, `persistence.storageClass` | `10Gi`, cluster default | The claim template. Kubernetes does not let a StatefulSet's claim template change after install: to grow the volume, resize the claim directly if its storage class allows it. |
| `persistence.existingClaim` | none | Use this claim instead of the claim template. |
| `lifecycle.preStopSleepSeconds` | `5` | The wait before shutdown; 0 disables it. |
| `networkPolicy.enabled`, `networkPolicy.from` | `false`, any source | Admit traffic only to flint's port, from the listed peers. |
| `resources`, `nodeSelector`, `tolerations`, `affinity`, `priorityClassName` | none | Pod scheduling and resources. |

### TLS

flint reloads its certificate when the mounted secret changes, so cert-manager renewals take effect without a restart, within about a minute of the secret changing.
To terminate TLS in a proxy instead, leave `tls.enabled` off and list the proxy's addresses in `config.trustedProxies`.

## Upgrades and uninstalling

`helm upgrade` replaces the pod; flint is unavailable from the moment the old pod stops until the new one is ready.
If an upgrade leaves the pod failing, for example with a configuration flint rejects or an image tag that does not exist, upgrading again with corrected values or running `helm rollback` replaces the failing pod; the StatefulSet's `Parallel` pod management lets it do so without waiting for the pod to become ready.
`helm uninstall` leaves the data claim, `data-<statefulset>-0` such as `data-flint-0`, in place, so reinstalling with the same release name reuses the data.
