# CLI Reference

> This page will be completed as CLI features are implemented.

## Usage

```bash
dwaar [OPTIONS] [COMMAND]
```

## Commands

| Command | Description | Status |
|---------|-------------|--------|
| `dwaar` | Start the proxy | Planned |
| `dwaar validate` | Check Dwaarfile syntax | Planned |
| `dwaar fmt` | Format Dwaarfile | Planned |
| `dwaar routes` | List active routes | Planned |
| `dwaar certs` | List managed certificates | Planned |
| `dwaar reload` | Reload configuration | Planned |
| `dwaar upgrade` | Zero-downtime binary upgrade | Planned |
| `dwaar version` | Show version | Implemented |

## Global Options

| Option | Description | Default |
|--------|-------------|---------|
| `--config <path>` | Path to Dwaarfile | `./Dwaarfile` |
| `--test` | Validate config and exit | — |
| `--version` | Show version | — |
