# Request Lifecycle

> This page will be detailed as the proxy is implemented.

Every HTTP request passes through Pingora's `ProxyHttp` trait hooks in this order:

```
TCP Accept → TLS Handshake (SNI → load cert)
  → early_request_filter  (rate limiting, IP blocking)
  → request_filter         (bot detection, visitor tracking, serve /_dwaar/*)
  → upstream_peer          (route table lookup)
  → upstream_request_filter (add proxy headers)
  → [proxy to upstream]
  → response_filter        (security headers, compression setup)
  → response_body_filter   (analytics injection, compression)
  → logging                (structured log entry, analytics aggregation)
```

Each hook can inspect, modify, or short-circuit the request.
