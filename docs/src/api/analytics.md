# Analytics API

Dwaar collects first-party analytics in-process — no external service, no sampling, no data leaving your server. The Analytics API exposes per-domain aggregates through the Admin API. Data is available within seconds of traffic hitting the proxy; the aggregation window refreshes every 60 seconds.

---

## Endpoints

Both endpoints require authentication on TCP connections. See [Admin API — Authentication](admin.md#authentication).

### GET /analytics

Return snapshots for every domain that has received traffic since process start. Returns an empty array `[]` if no requests have been observed yet.

```bash
# Unix socket (no token needed)
curl --unix-socket /var/run/dwaar-admin.sock \
     http://localhost/analytics

# TCP
curl -H "Authorization: Bearer $DWAAR_ADMIN_TOKEN" \
     http://127.0.0.1:6190/analytics
```

**Response** `200 OK` — JSON array of [domain snapshots](#response-schema).

### GET /analytics/{domain}

Return the snapshot for a single domain.

```bash
curl -H "Authorization: Bearer $DWAAR_ADMIN_TOKEN" \
     http://127.0.0.1:6190/analytics/www.example.com
```

**Response** `200 OK` — single [domain snapshot](#response-schema).

**Status codes for both endpoints**

| Code | Meaning |
|---|---|
| `200` | Snapshot returned |
| `400` | Domain contains invalid characters |
| `401` | Missing or invalid bearer token (TCP only) |
| `404` | No analytics recorded for this domain (`GET /analytics/{domain}` only) |
| `429` | Rate limit exceeded |
| `500` | Internal serialization error |

---

## Response Schema

Each domain snapshot is a flat JSON object. All counts are cumulative since process start unless noted.

```
AnalyticsSnapshot
├── domain              string    — hostname (lowercase)
├── page_views_1m       integer   — requests in the last 1 minute
├── page_views_60m      integer   — requests in the last 60 minutes
├── unique_visitors     integer   — distinct client IPs seen since start
├── top_pages           array     — top paths by request count (up to 10)
│   ├── path            string
│   └── views           integer
├── referrers           array     — top referrer domains by count (up to 10)
│   ├── domain          string
│   └── count           integer
├── countries           array     — top countries by count (up to 10)
│   ├── country         string    — ISO 3166-1 alpha-2 code (e.g. "US")
│   └── count           integer
├── status_codes        object    — HTTP response class breakdown
│   ├── s1xx            integer
│   ├── s2xx            integer
│   ├── s3xx            integer
│   ├── s4xx            integer
│   ├── s5xx            integer
│   └── other           integer
├── bytes_sent          integer   — total response bytes sent since start
├── web_vitals          object    — Core Web Vitals percentiles
│   ├── lcp             object    — Largest Contentful Paint (milliseconds)
│   │   ├── p50         float
│   │   ├── p75         float
│   │   ├── p95         float
│   │   └── p99         float
│   ├── cls             object    — Cumulative Layout Shift (unitless score)
│   │   ├── p50         float
│   │   ├── p75         float
│   │   ├── p95         float
│   │   └── p99         float
│   └── inp             object    — Interaction to Next Paint (milliseconds)
│       ├── p50         float
│       ├── p75         float
│       ├── p95         float
│       └── p99         float
└── timestamp           string    — RFC 3339 time when snapshot was taken
```

**Notes on `web_vitals` precision.** Percentiles are computed with a TDigest (~1–5% accuracy). The Admin API reads without flushing the pending buffer, so values may lag by up to 100 observations behind live traffic. The buffer flushes automatically at the 60-second aggregation cycle. Fields read `0.0` when no Web Vitals data has been reported yet.

---

## Example Response

```json
{
  "domain": "www.example.com",
  "page_views_1m": 84,
  "page_views_60m": 3902,
  "unique_visitors": 1247,
  "top_pages": [
    { "path": "/", "views": 1540 },
    { "path": "/blog", "views": 820 },
    { "path": "/pricing", "views": 610 },
    { "path": "/docs", "views": 490 },
    { "path": "/about", "views": 260 }
  ],
  "referrers": [
    { "domain": "google.com", "count": 730 },
    { "domain": "twitter.com", "count": 290 },
    { "domain": "lobste.rs", "count": 115 }
  ],
  "countries": [
    { "country": "US", "count": 880 },
    { "country": "DE", "count": 210 },
    { "country": "IN", "count": 157 }
  ],
  "status_codes": {
    "s1xx": 0,
    "s2xx": 3748,
    "s3xx": 88,
    "s4xx": 61,
    "s5xx": 5,
    "other": 0
  },
  "bytes_sent": 284319744,
  "web_vitals": {
    "lcp": {
      "p50": 1240.5,
      "p75": 1890.0,
      "p95": 3420.0,
      "p99": 5100.0
    },
    "cls": {
      "p50": 0.02,
      "p75": 0.07,
      "p95": 0.18,
      "p99": 0.32
    },
    "inp": {
      "p50": 85.0,
      "p75": 140.0,
      "p95": 310.0,
      "p99": 480.0
    }
  },
  "timestamp": "2026-04-05T14:22:08Z"
}
```

---

## Web Vitals Fields

Web Vitals are reported by in-browser JavaScript and forwarded to Dwaar's analytics collector. Each metric is tracked as a streaming percentile distribution using TDigest; no raw events are stored.

| Field | Metric | Unit | What it measures | Good | Poor |
|---|---|---|---|---|---|
| `lcp` | Largest Contentful Paint | milliseconds | Time until the largest image or text block is rendered | ≤ 2500 ms | > 4000 ms |
| `cls` | Cumulative Layout Shift | unitless score | Total unexpected layout shift during the page lifetime | ≤ 0.1 | > 0.25 |
| `inp` | Interaction to Next Paint | milliseconds | Worst interaction latency observed during the page session | ≤ 200 ms | > 500 ms |

Each metric exposes four percentile fields:

| Field | Meaning |
|---|---|
| `p50` | Median experience — what a typical visitor sees |
| `p75` | Used by Google's CrUX field data for ranking signals |
| `p95` | Near-worst-case — useful for catching regressions affecting a significant tail |
| `p99` | Worst observed in practice |

Percentiles are computed over all observations since process start. They do not reset between aggregation cycles. All values are `0.0` when no Web Vitals data has been received for the domain.

---

## Related

- [Analytics Feature Overview](../features/analytics.md) — how analytics collection works and how to configure the JS beacon
- [Admin API](admin.md) — authentication, rate limits, and all other endpoints
- [Prometheus Metrics](../observability/prometheus.md) — request counters and latency histograms in Prometheus format
