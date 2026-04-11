---
title: "First-Party Analytics"
---

# First-Party Analytics

Dwaar ships a built-in analytics pipeline that is immune to ad blockers because
all traffic flows through the same origin. No third-party scripts, no cookies,
no tracking pixels. The JS beacon (`/_dwaar/a.js`, under 2.5 KB minified) is
injected automatically into every HTML response. Beacons POST back to
`/_dwaar/collect` — same domain, same TLS certificate — so browser privacy
modes and content-blocking extensions leave it alone.

In-memory aggregation uses space-efficient probabilistic structures: HyperLogLog
for unique visitor cardinality, a bounded TopK min-heap for pages and referrers,
and TDigest for Web Vitals percentiles. The total footprint is approximately
30 KB per tracked domain regardless of traffic volume.

## Quick Start

Analytics is enabled by default. Start Dwaar normally and every HTML response
served through the proxy will have the beacon script injected.

```
example.com {
    reverse_proxy localhost:3000
}
```

No Dwaarfile changes are required. Analytics can be disabled at process startup
with the `--no-analytics` flag:

```sh
dwaar run --no-analytics
```

## How It Works

```mermaid
sequenceDiagram
    participant B as Browser
    participant D as Dwaar
    participant U as Upstream
    participant A as AggregationService

    B->>D: GET /page
    D->>U: proxy request
    U->>D: 200 text/html (possibly compressed)
    D->>D: decompress (if gzip/br/deflate)
    D->>D: inject <script src="/_dwaar/a.js" defer>
    D->>D: recompress (if encode directive active)
    D->>B: modified HTML

    B->>D: GET /_dwaar/a.js
    D->>B: analytics script (served from binary)

    Note over B: page load + Web Vitals collected
    B->>D: POST /_dwaar/collect (JSON beacon)
    D->>D: decompress beacon if needed
    D->>D: parse + anonymize IP
    D->>A: BeaconEvent via mpsc channel (cap 8192)
    A->>A: update DomainMetrics (HLL, TopK, TDigest)
    A->>A: flush snapshot to stdout every 60 s
```

The injector is a streaming state machine that scans response body chunks for
`</head>` (case-insensitive). It injects the `<script>` tag immediately before
the closing tag and transitions to pass-through mode for all remaining chunks.
The scan budget is 256 KB — responses with no `</head>` in the first 256 KB pass
through unmodified.

## What Gets Collected

| Metric | Data Structure | Memory | Description |
|---|---|---|---|
| Page views (last 1 min) | Ring buffer (60 buckets) | 480 B | Per-minute counters, stale buckets lazily zeroed |
| Page views (last 60 min) | Same ring buffer | — | Sum of up to 60 minute buckets |
| Unique visitors | HyperLogLog (2% error) | ~12 KB | Cardinality estimate from anonymized IPs |
| Top 100 pages | TopK min-heap | ~10 KB | Paths by view count, O(1) hot path |
| Top 50 referrers | BoundedCounter | ~5 KB | Referring domains extracted from Referer header |
| Top 250 countries | BoundedCounter | ~20 KB | Country codes from GeoIP (when enabled) |
| Status code distribution | `[u64; 6]` | 48 B | Bucketed: 1xx/2xx/3xx/4xx/5xx/other |
| Bytes transferred | `u64` counter | 8 B | Cumulative bytes sent to clients |
| LCP percentiles | TDigest (100 centroids) | ~1 KB | P50/P75/P95/P99, batched at 100 values |
| CLS percentiles | TDigest (100 centroids) | ~1 KB | Cumulative Layout Shift |
| INP percentiles | TDigest (100 centroids) | ~1 KB | Interaction to Next Paint |

**Total per domain:** ~30 KB, bounded. A server tracking 1000 domains uses
roughly 30 MB for analytics state.

Web Vitals are reported by the browser on page exit. LCP and INP are in
milliseconds; CLS is a unitless score. TDigest accuracy is within 5% at P99
for any sample size (verified by the test suite).

## Configuration

Analytics is on by default. The only configuration is the `encode` directive
interaction (see [Interaction with Compression](#interaction-with-compression))
and the `--no-analytics` CLI flag.

```sh
# Disable analytics entirely
dwaar run --no-analytics

# Disable everything (analytics, plugins, logging, GeoIP)
dwaar run --bare
```

When `--no-analytics` is set:

- The `/_dwaar/a.js` endpoint still serves the script (it is baked into the
  binary), but the beacon endpoint `/_dwaar/collect` returns 204 without
  enqueuing events.
- No `AggregationService` background task is registered.
- No `DashMap` is populated, so `GET /analytics` returns an empty array.

## Interaction with Compression

When `encode` is active and the upstream returns a compressed HTML response,
Dwaar runs this pipeline in order:

```
upstream chunk → decompress → inject /_dwaar/a.js → recompress → client
```

The decompressor supports gzip, deflate, and brotli. It buffers up to 10 MB of
compressed input per response and caps decompressed output at 100 MB to prevent
decompression bombs. On decompression failure the raw bytes pass through and
injection is skipped.

If the upstream response is already uncompressed and `encode` is active,
injection runs on the raw bytes and the compressor sees the modified HTML.
The `Content-Length` header is always removed when injection is active because
the injected script tag changes the body size.

## Accessing Analytics

The Admin API exposes analytics over HTTP. All analytics endpoints require the
`Authorization: Bearer <DWAAR_ADMIN_TOKEN>` header.

### List all domains

```http
GET /analytics
Authorization: Bearer <token>
```

Returns a JSON array of snapshots for every domain that has received traffic
since the process started.

```json
[
  {
    "domain": "example.com",
    "page_views_1m": 42,
    "page_views_60m": 1870,
    "unique_visitors": 318,
    "top_pages": [
      { "path": "/", "views": 940 },
      { "path": "/docs", "views": 412 }
    ],
    "referrers": [
      { "domain": "google.com", "count": 203 }
    ],
    "countries": [
      { "country": "US", "count": 512 }
    ],
    "status_codes": {
      "s1xx": 0, "s2xx": 1820, "s3xx": 30, "s4xx": 18, "s5xx": 2, "other": 0
    },
    "bytes_sent": 48302080,
    "web_vitals": {
      "lcp": { "p50": 1240.0, "p75": 1890.0, "p95": 3100.0, "p99": 4800.0 },
      "cls": { "p50": 0.02, "p75": 0.05, "p95": 0.12, "p99": 0.25 },
      "inp": { "p50": 80.0, "p75": 140.0, "p95": 320.0, "p99": 600.0 }
    },
    "timestamp": "2026-04-05T14:23:01Z"
  }
]
```

### Single domain

```http
GET /analytics/example.com
Authorization: Bearer <token>
```

Returns the same structure as a single object, or 404 if the domain has
received no traffic.

**Notes on freshness:**

- `page_views_1m` and `page_views_60m` reflect the live ring buffer and update
  on every request.
- `unique_visitors` is a HyperLogLog estimate with ±2% error.
- Web Vitals percentiles may lag by up to 100 observations because TDigest
  flushes in batches. Values are always consistent with the last completed batch.
- The full snapshot is flushed to stdout as newline-delimited JSON every 60
  seconds for log aggregation pipelines.

## Privacy / Consent Gating

Analytics injection can be restricted to visitors who have given explicit consent, which aids GDPR and CCPA compliance. This is controlled by the `respect_consent` field on the `HtmlInjector` (defaults to `false` — injection is unconditional).

When `respect_consent` is `true`, each response body chunk is processed through the consent gate before injection:

- If the request carried `DNT: 1`, injection is skipped regardless of cookies.
- If the `Cookie` header contains `dwaar_consent=1` or `analytics_consent=1` (key comparison is case-insensitive; semicolon-separated pairs), injection proceeds.
- Otherwise injection is skipped and the response passes through unmodified.

Enable consent gating in the analytics configuration block:

```
example.com {
    reverse_proxy localhost:3000
    analytics {
        respect_consent true
    }
}
```

Your consent banner must set one of the recognised cookies (`dwaar_consent=1` or `analytics_consent=1`) when the visitor accepts analytics. Until that cookie is present, the analytics script is not injected.

## Beacon authentication (0.2.3)

Analytics beacons are now cryptographically authenticated. Every POST to `/_dwaar/collect` must carry a nonce and an HMAC signature produced by the server-issued token on the matching page load. Unauthenticated beacons are dropped silently.

### Why it exists

The v0.2.1 Origin/Referer check defends against cross-origin replay — an attacker hosting a malicious page at `evil.example` could not aim beacons at `victim.example/_dwaar/collect` and have them credited to the victim's stats. It does not, however, stop a same-origin forgery: any page served through the same Dwaar instance (stored XSS, user-generated HTML, compromised upstream) could mint arbitrary beacons and poison the aggregate.

The v0.2.3 beacon authentication closes that gap. Forging a beacon now requires the per-process secret, which never leaves the proxy.

### How it works

```mermaid
sequenceDiagram
    participant D as Dwaar
    participant B as Browser
    participant U as Upstream

    Note over D: At startup:
    D->>D: generate 32-byte random<br/>secret (process-wide)

    B->>D: GET /page
    D->>U: proxy request
    U-->>D: 200 text/html
    D->>D: generate random nonce
    D->>D: sig = HMAC-SHA256(secret, nonce || host || window)
    D->>D: inject <script>, <meta name="dwaar-beacon-auth"<br/>content="<nonce_b64>:<sig_hex>">
    D-->>B: modified HTML

    Note over B: page load, Web Vitals collected
    B->>B: read meta[dwaar-beacon-auth]
    B->>D: POST /_dwaar/collect<br/>{ ..., "auth": { "nonce": ..., "sig": ... } }
    D->>D: recompute HMAC for current<br/>OR previous 5-minute window
    D->>D: constant-time compare
    alt match
        D->>D: accept beacon, aggregate
    else mismatch
        D-->>B: 204 No Content<br/>(silently drop)
    end
```

The MAC covers `nonce || host || window`, where `window` is the current Unix time rounded down to a 5-minute boundary. Server-side verification accepts the current window **or** the previous one, so a page loaded at 11:59:30 still validates beacons that arrive at 12:00:05.

Comparison uses `subtle::ConstantTimeEq` to eliminate timing side-channels in the MAC check.

### What operators see

- **No config required.** The feature is always on. No Dwaarfile directive, no CLI flag.
- **No extra 4xx noise.** Rejected beacons return `204 No Content` rather than a 4xx. Under an active attack, the access log will not flood with 401/403 lines that would themselves become a denial of service against the log pipeline.
- **Secret is process-local.** A supervisor restart rotates the secret. Existing open pages whose injected nonces were signed by the old secret will see their beacons rejected until the next navigation — acceptable because analytics is a best-effort observation channel, not an audit trail.
- **No upstream coordination.** The HTML injector runs inside Dwaar, so the upstream application never sees the nonce or signature. This is a transparent upgrade for any site already relying on analytics injection.

Dropped beacons are counted internally and reflected in `dwaar_analytics_beacons_rejected_total` (if Prometheus metrics for analytics are enabled in your build).

### Related sanitization

v0.2.3 also tightens beacon input handling on the accept path:

- `sanitize_url_to_path` refuses protocol-relative URLs, control bytes, and non-path inputs; paths are capped at 512 bytes.
- `sanitize_referrer_host` extracts only the host component and caps it at 128 bytes.
- Beacons that fail sanitization are silently dropped before aggregation.

## Privacy

- **No cookies.** The analytics script does not set or read any cookies.
- **No fingerprinting.** Screen dimensions and browser language are collected
  for cohort analysis but not combined into a fingerprint identifier.
- **DNT + Sec-GPC honoured.** As of 0.2.3, `analytics.js` suppresses the beacon
  when `navigator.doNotTrack === "1"` **or** `navigator.globalPrivacyControl === true`.
  No beacon, no aggregation, no `country` lookup.
- **fetch keepalive on unload.** As of 0.2.3, the unload-time beacon uses
  `fetch(url, { keepalive: true })` instead of a synchronous `XMLHttpRequest`.
  Synchronous XHR on `unload` is deprecated in every major browser and blocks
  navigation on the main thread; `keepalive` delegates the flush to the network
  layer so the outgoing request survives the page teardown without stalling the
  next navigation.
- **IP anonymization.** Client IPs are masked before being stored: IPv4
  addresses are truncated to `/24` (last octet zeroed); IPv6 addresses are
  truncated to `/48` (last 80 bits zeroed). The original IP is never persisted.
  As of 0.2.3, the same `/48` mask is applied on both the client-side path
  (server-derived IP from the connection) and the server-side path
  (aggregation buckets), so HyperLogLog cardinality is consistent no matter
  which code path produced the event.
- **First-party only.** The beacon endpoint is `/_dwaar/collect` on the same
  origin as the page. No data leaves your infrastructure.
- **No cross-site tracking.** Each domain's `DomainMetrics` is isolated. There
  is no shared identifier across domains.

## Complete Example

```
example.com {
    reverse_proxy localhost:3000
    encode gzip zstd br
    tls auto
    header Strict-Transport-Security "max-age=31536000; includeSubDomains"
}

api.example.com {
    reverse_proxy localhost:4000
    encode gzip
}
```

Both sites have analytics enabled. `example.com` uses `encode` so Dwaar will
decompress, inject, and recompress HTML responses. The Admin API is configured
separately and is not part of the Dwaarfile.

## Related

- [Admin API](../reference/admin-api.md) — full endpoint reference including
  authentication and rate limiting
- [Prometheus Metrics](./prometheus.md) — request rate, error rate, and latency
  exported in Prometheus text format
- [Logging](./logging.md) — structured request logs (separate from analytics
  aggregation)
