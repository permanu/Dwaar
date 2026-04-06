---
title: "DNS-01 Challenge (Wildcards)"
---

# DNS-01 Challenge (Wildcards)

Provision wildcard certificates and certificates for servers that are not reachable on port 80 by using DNS validation instead of HTTP. Dwaar creates a `_acme-challenge` TXT record in your DNS zone via the Cloudflare API, waits for the ACME CA to verify it, downloads the certificate, then cleans up the record.

---

## Quick Start

```
*.example.com {
    tls {
        dns cloudflare {env.CF_API_TOKEN}
    }
    reverse_proxy localhost:3000
}
```

Set `CF_API_TOKEN` in the environment before starting Dwaar. The wildcard certificate for `*.example.com` is provisioned on startup and renewed automatically.

---

## How It Works

```mermaid
sequenceDiagram
    participant D as Dwaar
    participant CF as Cloudflare API
    participant CA as ACME CA
    participant CS as CertStore

    D->>CF: POST /zones/{id}/dns_records<br/>_acme-challenge.example.com TXT &lt;token&gt;
    CF-->>D: record_id

    D->>CA: ACME challenge ready
    CA->>CF: DNS lookup _acme-challenge.example.com
    CF-->>CA: TXT &lt;token&gt;
    CA-->>D: challenge validated

    D->>CA: finalize(CSR for *.example.com)
    CA-->>D: wildcard certificate chain (PEM)

    D->>CS: write *.example.com.pem + *.example.com.key
    D->>CF: DELETE /zones/{id}/dns_records/{record_id}
    CF-->>D: 200 OK
```

Dwaar uses `curl` (via `tokio::process::Command`) to call the Cloudflare REST API. The API token is passed to `curl` through stdin — never on the command line — so it does not appear in the process argument list visible via `ps aux`.

Zone discovery is automatic: Dwaar walks up the domain labels (e.g. `sub.example.com` → `example.com`) to find the matching Cloudflare zone ID. TXT records are created with a TTL of 120 seconds to minimize propagation delay.

---

## When to Use DNS-01

| Scenario | Use DNS-01? |
|----------|-------------|
| Wildcard certificate (`*.example.com`) | Yes — HTTP-01 cannot issue wildcards |
| Server behind a firewall, no port 80 access | Yes |
| Internal hostname not reachable from the internet | Yes |
| Standard single-domain on a public server | No — [Automatic HTTPS](automatic-https.md) is simpler |
| Multi-domain cert covering several subdomains | Yes |

DNS-01 is the only ACME challenge type that can issue wildcard certificates. It also works for servers on private networks, as long as Dwaar can reach the Cloudflare API over HTTPS.

---

## Configuration

```
<domain> {
    tls {
        dns cloudflare <api_token>
    }
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `cloudflare` | yes | DNS provider name. Currently the only supported provider. |
| `<api_token>` | yes | Cloudflare API token with `Zone:DNS:Edit` permission. Use `{env.VAR}` to read from the environment. |

### Environment variable interpolation

Pass the token through an environment variable to keep it out of the Dwaarfile:

```
*.example.com {
    tls {
        dns cloudflare {env.CF_API_TOKEN}
    }
    reverse_proxy localhost:3000
}
```

Dwaar expands `{env.CF_API_TOKEN}` at parse time. If the variable is not set, startup fails with a clear error rather than running with an empty token.

### Multiple wildcard domains

Each site block configures its own DNS challenge independently:

```
*.example.com {
    tls {
        dns cloudflare {env.CF_API_TOKEN}
    }
    reverse_proxy localhost:3000
}

*.internal.example.com {
    tls {
        dns cloudflare {env.CF_API_TOKEN}
    }
    reverse_proxy localhost:4000
}
```

Both zones must be accessible with the same token, or use separate tokens with appropriate scoping.

---

## Cloudflare API Token

Create a scoped API token at [https://dash.cloudflare.com/profile/api-tokens](https://dash.cloudflare.com/profile/api-tokens):

1. Click **Create Token**.
2. Use the **Edit zone DNS** template, or create a custom token with:
   - **Permissions:** `Zone` → `DNS` → `Edit`
   - **Zone Resources:** `Include` → `Specific zone` → select your zone (or `All zones` for a multi-zone setup)
3. Set an expiry date if your security policy requires it.
4. Copy the token and store it in an environment variable or secrets manager.

The token needs no other permissions. Restrict it to the minimum required zones to limit blast radius if the token is ever compromised.

> **Do not use your Global API Key.** Global keys have unrestricted access to your entire Cloudflare account. A scoped API token with only `Zone:DNS:Edit` is the correct approach.

---

## Supported Providers

| Provider | Directive |
|----------|-----------|
| Cloudflare | `dns cloudflare <token>` |

Cloudflare is the only DNS provider currently built into Dwaar. Support for additional providers (Route 53, Azure DNS, Google Cloud DNS) is planned.

---

## Complete Example

```
{
    email ops@example.com
}

# Wildcard for all subdomains
*.example.com {
    tls {
        dns cloudflare {env.CF_API_TOKEN}
    }

    # Route by subdomain inside the wildcard block
    @api    host api.example.com
    @admin  host admin.example.com

    handle @api {
        reverse_proxy localhost:8080
    }

    handle @admin {
        forward_auth authelia:9091 {
            uri          /api/authz/forward-auth
            copy_headers Remote-User Remote-Groups
            transport    tls
        }
        reverse_proxy localhost:9090
    }

    handle {
        reverse_proxy localhost:3000
    }
}

# Apex domain — standard HTTP-01 (no wildcard needed)
example.com {
    reverse_proxy localhost:3000
}
```

`CF_API_TOKEN` is read from the environment at startup. The wildcard certificate covers every subdomain under `example.com`. The apex domain `example.com` uses the default HTTP-01 challenge because it does not require wildcard coverage.

---

## Related

- [Automatic HTTPS](automatic-https.md) — HTTP-01 challenge for standard single domains, no DNS provider needed
- [Manual Certificates](manual-certs.md) — bring your own cert and key files with `tls /cert.pem /key.pem`
- [Self-Signed Certificates](self-signed.md) — `tls internal` for local development without any ACME interaction
