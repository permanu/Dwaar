# Self-Signed Certificates (Development)

`tls internal` gives you instant HTTPS for local development and CI environments without ACME, DNS records, or any external dependency. Dwaar generates a self-signed certificate at startup and serves it immediately.

## Quick Start

```
localhost {
    reverse_proxy localhost:3000
    tls internal
}
```

Start Dwaar and your site is available over HTTPS. No registration, no challenge, no waiting.

## When to Use

| Situation | Recommendation |
|---|---|
| Local development (`localhost`, `*.local`) | `tls internal` |
| CI/CD pipelines that test TLS behavior | `tls internal` |
| Internal tools on private networks without public DNS | `tls internal` |
| Docker Compose / dev containers | `tls internal` |
| Production sites with public domain names | `tls auto` (automatic HTTPS) |
| Bring-your-own cert from a private CA | `tls /cert.pem /key.pem` |

Do not use `tls internal` for anything that needs to be trusted by end users without a manual trust store step. Browsers will warn on first visit.

## How It Works

When Dwaar encounters `tls internal`, it generates a self-signed RSA 2048 certificate for the site's hostname using OpenSSL. The certificate:

- Is generated in memory on startup — nothing is written to disk.
- Has a 365-day validity window from the time Dwaar starts.
- Sets the Subject Alternative Name (SAN) to match the configured hostname.
- Has no OCSP responder URL in the AIA extension, so OCSP stapling is skipped automatically.

Because the cert lives in memory, it is regenerated on every restart. Browsers that have pinned the previous cert will show a warning after a restart — clear the browser exception and re-accept.

## Browser Warnings

Self-signed certificates are not signed by a trusted CA, so browsers show a security warning on first visit. This is expected behavior.

### Accept in browser (temporary)

In Chrome/Edge, click **Advanced** then **Proceed to localhost (unsafe)**. In Firefox, click **Advanced** then **Accept the Risk and Continue**. Safari shows a similar prompt. The exception is stored per-session or per-browser-profile.

### Add to system trust store (permanent)

To eliminate the warning permanently, add the certificate to your OS trust store. Export it first:

```sh
# Save the cert from a running Dwaar instance
openssl s_client -connect localhost:443 -servername localhost </dev/null 2>/dev/null \
  | openssl x509 > /tmp/dwaar-local.pem
```

**macOS:**

```sh
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain /tmp/dwaar-local.pem
```

**Linux (Debian/Ubuntu):**

```sh
sudo cp /tmp/dwaar-local.pem /usr/local/share/ca-certificates/dwaar-local.crt
sudo update-ca-certificates
```

**Linux (RHEL/Fedora):**

```sh
sudo cp /tmp/dwaar-local.pem /etc/pki/ca-trust/source/anchors/dwaar-local.pem
sudo update-ca-trust
```

**Windows:**

```powershell
Import-Certificate -FilePath C:\tmp\dwaar-local.pem `
  -CertStoreLocation Cert:\LocalMachine\Root
```

Because the cert is regenerated on every restart, you will need to redo this step after each Dwaar restart unless you pin the certificate to a fixed cert directory using `tls /cert.pem /key.pem` with a long-lived self-signed cert you manage yourself.

## Configuration

```
tls internal
```

That is the complete configuration. There are no sub-options.

`tls internal` implies HTTPS — Dwaar will listen on port 443 (or your configured HTTPS port) and serve the generated certificate. Port 80 still accepts plain HTTP connections and redirects them to HTTPS.

## Complete Example

A realistic local development Dwaarfile with multiple services:

```
{
    # Bind to loopback only in dev
    bind 127.0.0.1
}

localhost {
    reverse_proxy localhost:3000
    tls internal
}

api.localhost {
    reverse_proxy localhost:8080
    tls internal
}

static.localhost {
    root /home/user/project/public
    file_server
    tls internal
}
```

Each site block gets its own in-memory certificate. All three are served over HTTPS with the browser warning appearing once per hostname per browser profile.

If you are working in a Docker Compose environment and need HTTPS between containers, bind to `0.0.0.0` and use the container's hostname:

```
{
    bind 0.0.0.0
}

myapp.internal {
    reverse_proxy app:3000
    tls internal
}
```

## Related

- [Automatic HTTPS](automatic-https.md) — zero-config TLS for public domains via ACME
- [Manual Certificates](manual-certs.md) — provide your own cert and key with `tls /cert.pem /key.pem`
