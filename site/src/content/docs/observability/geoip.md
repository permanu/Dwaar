---
title: "GeoIP"
---

# GeoIP

Dwaar maps each client IP address to a two-letter ISO 3166-1 country code using MaxMind's GeoLite2-Country database. The result flows into request logs and analytics snapshots without any per-request heap allocation. Private, loopback, and reserved addresses always return no country.

---

## Quick Start

Pass the path to your GeoLite2-Country `.mmdb` file at startup:

```sh
dwaar --config ./Dwaarfile
```

GeoIP is enabled by default whenever an `.mmdb` database is found at the configured path. To disable it entirely:

```sh
dwaar --no-geoip
```

`--bare` also disables GeoIP along with logging, plugins, and analytics.

---

## How It Works

`GeoLookup` opens the database once at startup via `mmap`. The OS loads pages on demand and evicts them under memory pressure — the ~5 MB country database typically fits entirely in the page cache on any modern server.

After construction, lookups are lock-free. `GeoLookup` is `Send + Sync` and shared across all Pingora worker threads via `Arc`. Each request calls `lookup_country` exactly once; the result is stored in `PluginCtx.country` and copied into the request log and analytics beacon before the connection closes.

```
Request arrives
     |
     v
GeoLookup::lookup_country(client_ip)   ← lock-free mmap read
     |
     +-- Some("US")  →  PluginCtx.country = "US"
     +-- None        →  field omitted from log / analytics
```

Lookup failures (address not in database, private IPs, decode errors) are logged at `DEBUG` level and treated as `None`. They are never surfaced as errors to the client.

---

## Database Setup

GeoLite2-Country is free to download with a MaxMind account.

| Step | Action |
|------|--------|
| 1 | Create a free account at [maxmind.com](https://www.maxmind.com/en/geolite2/signup) |
| 2 | Navigate to **Account > Downloads** and download `GeoLite2-Country.mmdb` |
| 3 | Place the file at `/etc/dwaar/geoip/GeoLite2-Country.mmdb` |
| 4 | Start Dwaar — it discovers the file at the default path automatically |

MaxMind updates GeoLite2 databases on the first Tuesday of each month. Replace the file with an atomic rename (`mv GeoLite2-Country.mmdb.new GeoLite2-Country.mmdb`) and send `SIGHUP` to reload config; the new file is opened on the next startup or reload.

**Default search paths** (checked in order at startup):

1. `fixtures/GeoLite2-Country-Test.mmdb` (only in test environments)
2. `/usr/share/GeoIP/GeoLite2-Country.mmdb`
3. `/etc/dwaar/geoip/GeoLite2-Country.mmdb`

Dwaar logs the path, database type, IP version, and node count at `INFO` level when the file opens successfully:

```
INFO GeoIP database loaded  db_type=GeoLite2-Country  ip_version=6  node_count=855870
```

---

## Integration with Logging

When GeoIP is enabled, every request log entry gains a `country` field:

```json
{
  "time": "2026-04-05T12:00:00Z",
  "method": "GET",
  "host": "example.com",
  "path": "/api/v1/data",
  "status": 200,
  "country": "DE",
  ...
}
```

`country` is a two-character uppercase ISO 3166-1 alpha-2 code (e.g., `"US"`, `"DE"`, `"IN"`). The field is omitted entirely when no country can be determined — private IPs, unrecognized addresses, or when `--no-geoip` is set.

See [Request Logging](logging.md) for the full field reference.

---

## Integration with Analytics

The analytics pipeline stores `country` on each raw analytics event. Country distribution is available in aggregated snapshots, letting you see traffic breakdown by origin without any third-party service.

The `country` field on `AnalyticsEvent` is populated from `PluginCtx.country` after the GeoIP lookup completes. When GeoIP is disabled or the lookup returns no result, the field is `None` and excluded from aggregation buckets.

See [First-Party Analytics](analytics.md) for snapshot structure and query examples.

---

## Configuration

GeoIP has no Dwaarfile directives — it is controlled entirely via CLI flags.

| Flag | Effect |
|------|--------|
| _(no flag)_ | GeoIP enabled; database discovered from default paths |
| `--no-geoip` | GeoIP disabled; `country` field absent from all outputs |
| `--bare` | Disables GeoIP along with logging, plugins, and analytics |

There is no flag to specify a custom `.mmdb` path at the command line. Place the file at one of the default paths listed above.

---

## City-Level Lookups

The `city` Cargo feature enables `GeoLookup::lookup_city`, which uses the GeoLite2-City database (~45 MB) and returns finer-grained data:

| Field | Type | Example |
|-------|------|---------|
| `country` | `Option<String>` | `"DE"` |
| `city` | `Option<String>` | `"Berlin"` |
| `subdivision` | `Option<String>` | `"BE"` |
| `postal_code` | `Option<String>` | `"10115"` |
| `latitude` | `Option<f64>` | `52.5200` |
| `longitude` | `Option<f64>` | `13.4050` |

Enable the feature in `Cargo.toml`:

```toml
dwaar-geo = { path = "crates/dwaar-geo", features = ["city"] }
```

Download `GeoLite2-City.mmdb` from your MaxMind account and replace the country database path. The city database is a strict superset — `lookup_country` continues to work with it.

City-level data is not currently surfaced in request logs or the analytics pipeline. It is available for custom native plugins that call `GeoLookup::lookup_city` directly.

---

## Related

- [Request Logging](logging.md) — full `RequestLog` field reference including `country`
- [First-Party Analytics](analytics.md) — country distribution in aggregated snapshots
