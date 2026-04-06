# Helm Chart

The `dwaar-ingress` Helm chart deploys the Dwaar Kubernetes ingress controller. It creates a Deployment, ServiceAccount, ClusterRole, ClusterRoleBinding, IngressClass, and a LoadBalancer Service in a single `helm install` command.

Chart version: `0.1.0` — app version: `0.1.0`

## Quick Start

```bash
helm install dwaar-ingress ./deploy/helm/dwaar-ingress \
  --namespace dwaar-system \
  --create-namespace
```

Override the admin URL to match your Dwaar service:

```bash
helm install dwaar-ingress ./deploy/helm/dwaar-ingress \
  --namespace dwaar-system \
  --create-namespace \
  --set controller.adminUrl=http://dwaar-admin:9000
```

## Chart Values

| Value | Default | Description |
|---|---|---|
| `replicaCount` | `2` | Number of controller replicas. Leader election makes one active; the second is a warm standby. |
| `image.repository` | `ghcr.io/permanu/dwaar-ingress` | Container image repository. |
| `image.pullPolicy` | `IfNotPresent` | Image pull policy. |
| `image.tag` | `""` | Image tag. Defaults to `Chart.appVersion` when empty. |
| `imagePullSecrets` | `[]` | List of image pull secret names. |
| `nameOverride` | `""` | Partial name override (replaces the chart name component). |
| `fullnameOverride` | `""` | Full release name override. |
| `serviceAccount.create` | `true` | Create a dedicated ServiceAccount. |
| `serviceAccount.annotations` | `{}` | Annotations for the ServiceAccount (use for IRSA / Workload Identity). |
| `serviceAccount.name` | `""` | ServiceAccount name override. Defaults to the fullname helper. |
| `podAnnotations` | `{}` | Annotations applied to every pod. |
| `podSecurityContext.runAsNonRoot` | `true` | Require the container to run as a non-root user. |
| `podSecurityContext.runAsUser` | `65534` | UID the container runs as (`nobody`). |
| `podSecurityContext.runAsGroup` | `65534` | GID the container runs as. |
| `podSecurityContext.fsGroup` | `65534` | Group that owns mounted volumes. |
| `podSecurityContext.seccompProfile.type` | `RuntimeDefault` | Seccomp profile for the pod. |
| `securityContext.allowPrivilegeEscalation` | `false` | Block privilege escalation in the container. |
| `securityContext.readOnlyRootFilesystem` | `true` | Mount the root filesystem read-only. |
| `securityContext.capabilities.drop` | `["ALL"]` | Drop all Linux capabilities. |
| `resources.requests.cpu` | `50m` | CPU request. |
| `resources.requests.memory` | `64Mi` | Memory request. |
| `resources.limits.cpu` | `500m` | CPU limit. |
| `resources.limits.memory` | `256Mi` | Memory limit. |
| `controller.adminUrl` | `http://dwaar-admin:9000` | Dwaar admin API base URL (`--admin-url`). |
| `controller.ingressClass` | `"dwaar"` | Only manage Ingresses with this class name (`--ingress-class`). |
| `controller.watchNamespace` | `""` | Restrict watching to one namespace (`--namespace`). Empty = all namespaces. |
| `controller.leaseName` | `dwaar-ingress-leader` | Leader election Lease name (`--lease-name`). |
| `controller.leaseNamespace` | `kube-system` | Namespace for the leader election Lease (`--lease-namespace`). |
| `controller.certDir` | `/var/lib/dwaar-ingress/certs` | Directory for materialised TLS PEM files (`--cert-dir`). |
| `health.port` | `8080` | Port for `/healthz` and `/readyz` endpoints. |
| `service.type` | `LoadBalancer` | Kubernetes Service type for the proxy. |
| `service.httpPort` | `80` | HTTP port exposed on the Service. |
| `service.httpsPort` | `443` | HTTPS port exposed on the Service. |
| `service.httpTargetPort` | `80` | Container target port for HTTP. |
| `service.httpsTargetPort` | `443` | Container target port for HTTPS. |
| `service.annotations` | `{}` | Service annotations (e.g. AWS NLB, GCP GCLB cloud-provider annotations). |
| `ingressClass.default` | `false` | Mark this IngressClass as the cluster-wide default. |
| `affinity` | _(hard pod anti-affinity)_ | Affinity rules. Default forces replicas to different nodes. |
| `nodeSelector` | `{}` | Node selector labels. |
| `tolerations` | `[]` | Pod tolerations. |
| `persistence.enabled` | `false` | Use a PersistentVolumeClaim for the cert directory instead of an emptyDir. |
| `persistence.storageClass` | `""` | StorageClass for the PVC. Uses the cluster default when empty. |
| `persistence.size` | `64Mi` | PVC size. |
| `persistence.accessModes` | `["ReadWriteOnce"]` | PVC access modes. |
| `extraEnv` | `[]` | Extra environment variables injected into the controller container (e.g. `RUST_LOG`). |

## RBAC

The chart creates one ClusterRole and one ClusterRoleBinding. When `controller.watchNamespace` is set, it additionally creates a namespace-scoped Role and RoleBinding for Secret access.

### ClusterRole

| API Group | Resources | Verbs | Reason |
|---|---|---|---|
| `networking.k8s.io` | `ingresses` | `get`, `list`, `watch` | Watch for Ingress changes. |
| `networking.k8s.io` | `ingresses/status` | `update`, `patch` | Write status conditions back to Ingress objects. |
| `networking.k8s.io` | `ingressclasses` | `get`, `list`, `watch` | Read IngressClass resources to identify controller ownership. |
| `""` (core) | `services` | `get`, `list`, `watch` | Resolve Service ClusterIPs for Ingress backends. |
| `""` (core) | `secrets` | `get`, `list`, `watch` | Read TLS Secrets cluster-wide. Only granted when `watchNamespace` is empty. |
| `coordination.k8s.io` | `leases` | `get`, `list`, `watch`, `create`, `update`, `patch` | Create and renew the leader election Lease in `kube-system`. |

### Namespace-scoped Secret Role (watchNamespace only)

When `controller.watchNamespace` is set, cluster-wide Secret access is removed from the ClusterRole. Instead, a namespace-scoped Role granting `get`, `list`, `watch` on `secrets` is created in the watched namespace and bound to the controller's ServiceAccount. This follows the principle of least privilege — the controller can only read Secrets in the namespace it watches.

## High Availability

Run two or more replicas with leader election enabled (the default). Only the leader pod processes Ingress events and mutates routes; the standby pods participate in leader election but do not touch the route table.

The default affinity rule uses hard pod anti-affinity (`requiredDuringSchedulingIgnoredDuringExecution`) with `topologyKey: kubernetes.io/hostname`. This guarantees replicas land on different nodes so a single node failure does not take down both pods.

```
Leader Pod (node A)            Standby Pod (node B)
      │                               │
      │  holds coordination.k8s.io    │  polls Lease every 2 s
      │  Lease in kube-system         │
      │  renews every 10 s            │  waits for expiry (15 s)
      ▼                               ▼
  IngressWatcher running         IngressWatcher stopped
  routes mutated via admin API   ready to take over in < 15 s
```

The readiness probe at `/readyz` returns `200` only when both `leader_ready` and `sync_ready` flags are true. During a leader transition, the new leader does not report ready until its initial informer sync completes, preventing traffic from being routed through stale state.

## Customization

**Use a custom image:**

```bash
helm install dwaar-ingress ./deploy/helm/dwaar-ingress \
  --set image.repository=registry.example.com/dwaar-ingress \
  --set image.tag=v1.2.3
```

**Tighten resource limits for a small cluster:**

```bash
helm install dwaar-ingress ./deploy/helm/dwaar-ingress \
  --set resources.requests.cpu=25m \
  --set resources.requests.memory=32Mi \
  --set resources.limits.cpu=200m \
  --set resources.limits.memory=128Mi
```

**Watch a single namespace only (tighter RBAC):**

```bash
helm install dwaar-ingress ./deploy/helm/dwaar-ingress \
  --set controller.watchNamespace=production
```

This removes cluster-wide Secret access and creates a namespace-scoped Role in `production` instead.

**Mark as the cluster-wide default IngressClass:**

```bash
helm install dwaar-ingress ./deploy/helm/dwaar-ingress \
  --set ingressClass.default=true
```

**Enable debug logging:**

```yaml
extraEnv:
  - name: RUST_LOG
    value: "dwaar_ingress=debug"
```

**Single-node dev cluster (relax anti-affinity):**

```yaml
affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 100
        podAffinityTerm:
          labelSelector:
            matchLabels:
              app.kubernetes.io/name: dwaar-ingress
          topologyKey: kubernetes.io/hostname
```

## Complete Example

Production `values.yaml` for a multi-tenant cluster:

```yaml
replicaCount: 2

image:
  repository: ghcr.io/permanu/dwaar-ingress
  pullPolicy: IfNotPresent
  tag: "0.1.0"

controller:
  adminUrl: "http://dwaar-admin.dwaar-system.svc.cluster.local:9000"
  ingressClass: "dwaar"
  watchNamespace: ""          # watch all namespaces
  leaseName: "dwaar-ingress-leader"
  leaseNamespace: "kube-system"
  certDir: "/var/lib/dwaar-ingress/certs"

health:
  port: 8080

service:
  type: LoadBalancer
  httpPort: 80
  httpsPort: 443
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-type: "nlb"
    service.beta.kubernetes.io/aws-load-balancer-scheme: "internet-facing"

ingressClass:
  default: false

resources:
  requests:
    cpu: 50m
    memory: 64Mi
  limits:
    cpu: 500m
    memory: 256Mi

podSecurityContext:
  runAsNonRoot: true
  runAsUser: 65534
  runAsGroup: 65534
  fsGroup: 65534
  seccompProfile:
    type: RuntimeDefault

securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop:
      - ALL

affinity:
  podAntiAffinity:
    requiredDuringSchedulingIgnoredDuringExecution:
      - labelSelector:
          matchLabels:
            app.kubernetes.io/name: dwaar-ingress
        topologyKey: kubernetes.io/hostname

persistence:
  enabled: true
  storageClass: "gp3"
  size: 64Mi
  accessModes:
    - ReadWriteOnce

extraEnv:
  - name: RUST_LOG
    value: "dwaar_ingress=info"
```

Apply it:

```bash
helm install dwaar-ingress ./deploy/helm/dwaar-ingress \
  --namespace dwaar-system \
  --create-namespace \
  --values production-values.yaml
```

Upgrade after changing values:

```bash
helm upgrade dwaar-ingress ./deploy/helm/dwaar-ingress \
  --namespace dwaar-system \
  --values production-values.yaml
```

## Related

- [Kubernetes Ingress Controller](kubernetes.md) — annotations, leader election details, TLS secret format
- [Zero-Downtime Deployments](zero-downtime.md) — rolling upgrade strategy for the proxy and controller
