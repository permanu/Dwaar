---
title: "Basic Auth"
---

# Basic Auth

HTTP Basic Authentication with bcrypt password hashing. Credentials are loaded once at config parse time into a hash map keyed by username; per-request cost is one `O(1)` map lookup plus one bcrypt verification. Password hashes are never logged or exposed in debug output — `Debug` implementations on all credential types redact hash fields.

---

## Quick Start

```
admin.example.com {
    basic_auth {
        alice $2b$12$W9qnDhPDIYYMMsVN5LRVZ.MCFhJJ0lMjx5Uagb0RTMP1bJG2xjhzS
    }
    reverse_proxy localhost:8080
}
```

Requests without valid credentials receive `401 Unauthorized` with a `WWW-Authenticate: Basic realm="Restricted"` header. The browser shows its built-in credential prompt.

---

## How It Works

HTTP Basic Authentication (RFC 7617) encodes credentials as `username:password` in Base64 and sends them in the `Authorization` request header on every request.

```
Authorization: Basic YWxpY2U6aHVudGVyMg==
```

Dwaar's `BasicAuthPlugin` processes this header as follows:

1. Strip the `Basic ` scheme prefix (case-insensitive, per RFC 7617 §2).
2. Decode the Base64 payload into a temporary buffer wrapped in `Zeroizing<Vec<u8>>` — the plaintext is wiped from memory when the buffer drops at the end of the request.
3. Split on the first colon to extract username and password. Passwords may contain colons.
4. Look up the username in the credential map. If the username does not exist, verify against a pre-computed dummy hash to prevent timing-based user enumeration — bcrypt dominates the request cost, making known and unknown usernames indistinguishable by latency.
5. If bcrypt verification succeeds and the username exists in the map, set the authenticated username in the request context and call `PluginAction::Continue`. Otherwise, respond with `401`.

On `401`, the response includes:

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic realm="<realm>"
Content-Length: 0
```

The realm string is sanitised at config load time — double quotes, backslashes, and CRLF characters are stripped to prevent header injection.

---

## Generating Password Hashes

Basic auth stores **bcrypt hashes only** — never plaintext passwords. Generate a hash before writing your Dwaarfile.

**Using `htpasswd` (Apache utils, available on most systems):**

```bash
# Create a new credentials file
htpasswd -nbB alice 'mypassword'
# alice:$2y$05$...

# Extract just the hash
htpasswd -nbB alice 'mypassword' | cut -d: -f2
```

**Using Python:**

```bash
python3 -c "import bcrypt; print(bcrypt.hashpw(b'mypassword', bcrypt.gensalt(rounds=12)).decode())"
```

**Using the `bcrypt` crate in a Rust one-liner:**

```bash
cargo run --example gen-hash -- mypassword
```

**Choosing a cost factor:** The default for `htpasswd -B` is cost 5 (very fast, not recommended for production). Use cost 12 for production deployments — it takes approximately 300 ms per verification on modern hardware, which is acceptable for human login flows and makes brute-force attacks impractical.

```bash
# htpasswd with explicit cost
htpasswd -nbBC 12 alice 'mypassword'
```

Dwaar infers the cost of the dummy hash from the first credential's hash, so the dummy verification time matches your real hashes regardless of which cost factor you chose.

---

## Configuration

```
basic_auth [<realm>] {
    <username> <bcrypt_hash>
    ...
}
```

The directive also accepts the alias `basicauth` (no underscore).

| Token | Type | Required | Description |
|-------|------|----------|-------------|
| `realm` | string | no | Realm name sent in `WWW-Authenticate`. Defaults to `"Restricted"` if omitted. |
| `username` | string | yes (at least one) | The login name. Must not contain a colon. |
| `bcrypt_hash` | string | yes | A bcrypt hash produced by `htpasswd -B`, `bcrypt::hash()`, or equivalent. Must start with `$2b$` or `$2y$`. |

**Multiple users:** Add one `username hash` line per user. All users share the same realm.

```
basic_auth "Internal Tools" {
    alice  $2b$12$W9qnDhPDIYYMMsVN5LRVZ.MCFhJJ0lMjx5Uagb0RTMP1bJG2xjhzS
    bob    $2b$12$3QK9ZvY8DhXsPm2T6n0FxOmJ1gRhtNYkLxbNjAFE4v0pHhXxiVVLG
    carlos $2b$12$hN8mKzR4pSY0GcL3fD2TKedT8WbQzXnVpP9jsLEMWf5U1OuAK4S6i
}
```

**Custom realm:**

```
basic_auth "Acme Admin Panel" {
    admin $2b$12$W9qnDhPDIYYMMsVN5LRVZ.MCFhJJ0lMjx5Uagb0RTMP1bJG2xjhzS
}
```

---

## Security Considerations

**Always use Basic Auth over HTTPS.** The `Authorization` header is Base64-encoded, not encrypted. Over plain HTTP, any network observer can decode the credentials trivially. Dwaar's automatic HTTPS (`tls auto`) handles certificate provisioning — there is no reason to run Basic Auth over HTTP in production.

**Bcrypt cost factor guidance:**

| Environment | Recommended cost | Approx. verify time |
|-------------|-----------------|---------------------|
| Development / testing | 4 | < 1 ms |
| Staging | 10 | ~100 ms |
| Production | 12 | ~300 ms |
| High-security admin panels | 14 | ~1 200 ms |

Higher cost makes each brute-force attempt proportionally slower. Cost 12 is the current industry minimum for production use.

**Timing attack mitigation:** When a username is not found, Dwaar still runs bcrypt verification against a pre-computed dummy hash of the same cost as your real hashes. This closes the timing oracle that would otherwise let an attacker enumerate valid usernames by comparing response latency.

**Credential storage:** Password hashes in your Dwaarfile are sensitive. Restrict file permissions (`chmod 600 Dwaarfile`) and avoid committing the file to public version control. Consider externalising credentials via environment variable substitution if your deployment pipeline requires it.

**Browser credential caching:** Browsers cache Basic Auth credentials for the duration of the browser session. Users cannot "log out" without closing the browser or clearing credentials. For use cases that require explicit logout, use [Forward Auth](forward-auth.md) with a session-based auth service instead.

---

## Complete Example

```
# Global config
{
    email ops@example.com
}

# Public site
www.example.com {
    reverse_proxy localhost:3000
    header {
        Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
        X-Content-Type-Options nosniff
        X-Frame-Options DENY
    }
}

# Admin panel — IP-restricted and password-protected
admin.example.com {
    # Restrict to internal network first; unknown IPs never reach the auth check
    ip_filter {
        allow 10.0.0.0/8
        allow 192.168.0.0/16
        default deny
    }

    basic_auth "Acme Admin Panel" {
        alice $2b$12$W9qnDhPDIYYMMsVN5LRVZ.MCFhJJ0lMjx5Uagb0RTMP1bJG2xjhzS
        bob   $2b$12$3QK9ZvY8DhXsPm2T6n0FxOmJ1gRhtNYkLxbNjAFE4v0pHhXxiVVLG
    }

    reverse_proxy localhost:9000
    rate_limit 10/s

    header {
        Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
        X-Content-Type-Options nosniff
        Cache-Control "no-store"
    }
}

# Internal metrics endpoint — single technical user
metrics.example.com {
    basic_auth {
        prometheus $2b$12$hN8mKzR4pSY0GcL3fD2TKedT8WbQzXnVpP9jsLEMWf5U1OuAK4S6i
    }
    reverse_proxy localhost:9090
}
```

The admin panel stacks two layers of access control: `ip_filter` blocks all non-internal IPs with a `403` before the request ever reaches `basic_auth`, so the bcrypt cost is never paid for external probes.

---

## Related

- [Forward Auth](forward-auth.md) — delegate auth to an external service; supports logout and session management
- [Security Headers](security-headers.md) — add `Strict-Transport-Security`, `Cache-Control: no-store`, and other headers
- [Automatic HTTPS](../tls/automatic-https.md) — enable TLS with a single directive; required when using Basic Auth
