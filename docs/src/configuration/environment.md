# Environment Variables

> This page will be completed as features are implemented.

| Variable | Description | Default |
|----------|-------------|---------|
| `DWAAR_CONFIG` | Path to Dwaarfile | `./Dwaarfile` |
| `DWAAR_LOG_LEVEL` | Log level (error, warn, info, debug, trace) | `info` |
| `DWAAR_ADMIN_ADDR` | Admin API listen address | `unix:///var/run/dwaar.sock` |
| `DWAAR_ACME_EMAIL` | Email for Let's Encrypt registration | Required for auto TLS |
| `DWAAR_DATA_DIR` | Directory for certs, logs, analytics | `~/.dwaar/` |
