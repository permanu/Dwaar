# Analytics API

> This page will be documented when analytics are implemented (ISSUE-028, ISSUE-029).

The Analytics API exposes per-domain metrics collected by Dwaar's first-party analytics engine.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/analytics/{domain}` | Current aggregates |
| GET | `/analytics/{domain}/live` | SSE stream of real-time events |

## Response Format

```json
{
  "domain": "example.com",
  "period": "24h",
  "page_views": 12450,
  "unique_visitors": 3200,
  "top_pages": [
    { "path": "/", "views": 5000 },
    { "path": "/about", "views": 2100 }
  ],
  "referrers": {
    "google.com": 1500,
    "twitter.com": 800,
    "direct": 900
  },
  "countries": {
    "US": 1200,
    "IN": 800,
    "DE": 400
  },
  "web_vitals": {
    "lcp_p50": 1200,
    "lcp_p95": 3500,
    "cls_p50": 0.05,
    "fid_p50": 12
  }
}
```
