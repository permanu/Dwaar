---
title: "Manual Certificates"
---

# Manual Certificates

Supply your own certificate and private key files instead of letting Dwaar provision certificates automatically. Dwaar reads the files at startup, registers the cert with the SNI resolver, and begins serving HTTPS immediately — no ACME challenge, no DNS configuration required.

On every successful config hot-reload, Dwaar swaps in the current cert paths from the Dwaarfile. If you have rotated the files on disk and trigger a reload, the new certificate takes effect without restarting the process.

---

## Quick Start

```txt
example.com {
    tls /etc/dwaar/tls/example.com.pem /etc/dwaar/tls/example.com.key
    reverse_proxy localhost:3000
}
```

Replace the paths with the absolute paths to your certificate (PEM) and private key (PEM) files.

---

## When to Use

| Scenario | Reason |
|---|---|
| Enterprise CA | Your organisation issues certificates from an internal PKI that clients already trust. Automatic ACME issuance is unnecessary. |
| Pre-provisioned certificates | A platform team or secrets manager (Vault, AWS ACM, cert-manager) provisions and rotates certificates outside of Dwaar. |
| Air-gapped environments | No outbound internet access means ACME HTTP/DNS challenges are not possible. |
| Wildcard certificates | You hold a wildcard cert covering `*.example.com` and want to use it across multiple sites without per-domain ACME issuance. |
| Custom PKI | Development or staging environments use an internal CA whose certificates your test clients trust. |

---

## Configuration

```txt
tls <cert_path> <key_path>
```

Place the `tls` directive inside a site block. `<cert_path>` and `<key_path>` must be absolute paths to readable files on the local filesystem.

### File Format Requirements

| Parameter | Format | Notes |
|---|---|---|
| `<cert_path>` | PEM | One or more `-----BEGIN CERTIFICATE-----` blocks. Include the full chain: leaf certificate first, then any intermediate certificates. Order matters — see [Certificate Chain](#certificate-chain). |
| `<key_path>` | PEM | Single `-----BEGIN PRIVATE KEY-----` or `-----BEGIN EC PRIVATE KEY-----` block. RSA, ECDSA P-256, and ECDSA P-384 are all supported. |

Dwaar does not accept DER-encoded certificates. Convert DER to PEM with:

```sh
openssl x509 -inform DER -in cert.der -out cert.pem
openssl pkcs8 -inform DER -in key.der -out key.pem
```

---

## Certificate Reload

Dwaar uses a lock-free `ArcSwap`-backed SNI resolver. When you edit the Dwaarfile and save — or send a `POST /reload` to the admin API — the config watcher:

1. Re-parses and compiles the Dwaarfile.
2. Builds a new cert-path map from all `tls <cert> <key>` directives.
3. Atomically swaps the map into the shared `DomainConfigMap`.
4. The SNI resolver picks up the new paths on the next TLS handshake via a lock-free `ArcSwap::load()` — zero copying, no mutex.

The result: rotate a certificate by updating the files on disk and triggering a config reload. In-flight TLS sessions are not terminated; only new handshakes use the updated cert.

```sh
# After writing new cert files to disk:
curl -X POST http://localhost:9000/reload
```

---

## Certificate Chain

Include the full certificate chain in `<cert_path>`, ordered leaf-first:

```
-----BEGIN CERTIFICATE-----
<leaf certificate for example.com>
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
<intermediate CA certificate>
-----END CERTIFICATE-----
```

Do not include the root CA in the chain file — browsers and TLS clients already carry trusted roots, and including the root increases handshake size without benefit.

If the intermediates are missing, clients that do not cache intermediates (strict mobile browsers, some curl versions) will fail validation with an "unable to get local issuer certificate" error.

---

## Complete Example

```txt
# Global options — bind on standard ports
{
    http_port  80
    https_port 443
}

# Redirect HTTP to HTTPS
http://example.com {
    redir https://example.com{uri} 301
}

# HTTPS site using a manually provisioned certificate
example.com {
    tls /etc/dwaar/tls/example.com.pem /etc/dwaar/tls/example.com.key

    reverse_proxy localhost:3000 {
        health_uri /healthz
        health_interval 15
    }

    header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
}
```

The `tls` directive overrides automatic provisioning for `example.com`. All other sites in the same Dwaarfile continue to use their own TLS settings independently.

---

## Related

- [Automatic HTTPS](automatic-https.md) — Let Dwaar provision and renew certificates via ACME
- [Self-Signed Certificates](self-signed.md) — Generate an internal cert for development (`tls internal`)
- [DNS Challenge](dns-challenge.md) — Issue certificates for domains that cannot serve HTTP challenges
