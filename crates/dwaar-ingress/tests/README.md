# dwaar-ingress K8s Integration Tests

These tests validate the full ingress-controller flow against a real Kubernetes
cluster. They are gated behind the `k8s-integration` feature flag so that
`cargo test` in CI passes without a cluster available.

## Prerequisites

- [`kind`](https://kind.sigs.k8s.io/) (Kubernetes IN Docker)
- Docker
- `kubectl` (optional, for debugging)

## Running

```bash
# 1. Create a throwaway cluster
kind create cluster --name dwaar-test

# 2. Run only the integration tests (serial — tests share the cluster)
cargo test -p dwaar-ingress --features k8s-integration -- --test-threads=1

# 3. Tear down the cluster when done
kind delete cluster --name dwaar-test
```

The tests detect the cluster via `kube::Client::try_default()` (same kubeconfig
lookup as `kubectl`). If no cluster is reachable they print a skip notice and
return immediately — they never fail when the cluster is absent.

## What is tested

| # | Scenario | What it proves |
|---|----------|---------------|
| 1 | Create Ingress | Route appears in the admin API within 5 s |
| 2 | Update Ingress backend | Route upstream is updated when the Service changes |
| 3 | Delete Ingress | Route is removed from the admin API |
| 4 | TLS Secret + TLS Ingress | Route is marked `tls=true`; PEM files are written |
| 5 | Wrong IngressClass | Ingress targeting `nginx` class is ignored by Dwaar |
| 6 | Leader takeover | Standby acquires leadership within 15 s after lease expiry |
| 7 | Rate-limit annotation | `dwaar.dev/rate-limit: 100` is parsed from the live object |

## Cleanup

Every test deletes its own resources. The `dwaar-integration-test` namespace
and any `kube-system` Leases created during test 6 are cleaned up within each
test function. Deleting the cluster is always the safest full cleanup.

## Adding tests

- Keep each test self-contained: create resources at the top, delete them at the
  bottom (even on the happy path, so reruns don't fail on leftover objects).
- Use the `poll_until` helper rather than fixed `sleep` calls — it resolves as
  soon as the condition is met and fails fast if the deadline passes.
- Use unique resource names per test to avoid cross-test interference when
  running with `--test-threads=1`.
