# Contributing to Dwaar

Thank you for your interest in contributing to Dwaar. This document covers everything you need to get started.

## Table of Contents

- [License](#license)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Pull Request Process](#pull-request-process)
- [Commit Convention](#commit-convention)
- [Release Process](#release-process)
- [Issue Guidelines](#issue-guidelines)
- [AI Policy](#ai-policy)
- [Code Standards](#code-standards)

## License

Dwaar is licensed under the [Business Source License 1.1](LICENSE), converting to AGPL-3.0 on the Change Date. By submitting a pull request, you agree that your contributions will be licensed under the same terms.

If you have questions about licensing, see [LICENSE](LICENSE) or contact us at hello@permanu.com.

## Getting Started

### Prerequisites

- **Rust** (stable, latest) — install via [rustup](https://rustup.rs)
- **Docker** — for integration tests
- **OpenSSL** development headers — for TLS support

### Setup

```bash
# Clone the repository
git clone https://github.com/permanu/Dwaar.git
cd Dwaar

# Build all crates
cargo build --workspace

# Run tests
cargo test --workspace

# Run lints
cargo clippy --workspace -- -D warnings

# Format code
cargo fmt --check
```

### Project Structure

```
dwaar/
├── crates/
│   ├── dwaar-core/         # ProxyHttp impl, route table
│   ├── dwaar-config/       # Dwaarfile parser, validation
│   ├── dwaar-tls/          # ACME, cert management, SNI
│   ├── dwaar-analytics/    # JS injection, beacon, aggregation
│   ├── dwaar-plugins/      # Plugin trait, built-in plugins
│   ├── dwaar-admin/        # Admin API service
│   ├── dwaar-docker/       # Docker label discovery
│   ├── dwaar-geo/          # GeoIP lookup
│   ├── dwaar-log/          # Request logging, batch writer
│   └── dwaar-cli/          # Binary entry point, CLI
├── tests/                  # Integration tests
├── benches/                # Criterion benchmarks
├── fixtures/               # Test certs, configs
└── scripts/                # Release and maintenance scripts
```

## Development Workflow

### 1. Find or Create an Issue

All contributions should be tied to an issue. Before starting work:

- Check [existing issues](https://github.com/permanu/Dwaar/issues) for something you'd like to work on
- Issues labeled `good first issue` are ideal for newcomers
- Issues labeled `help wanted` are open for external contributions
- **Do not submit PRs for issues labeled `needs-decision` or `needs-design`** — these require maintainer consensus first

For non-trivial changes, open an issue to discuss the approach before writing code.

### 2. Branch Strategy

```bash
# Create a branch from main
git checkout -b feat/your-feature main

# Or for fixes
git checkout -b fix/your-fix main
```

Branch naming convention:
- `feat/description` — new features
- `fix/description` — bug fixes
- `perf/description` — performance improvements
- `refactor/description` — code restructuring
- `test/description` — test additions
- `docs/description` — documentation changes

### 3. Make Your Changes

- Write code that follows our [Code Standards](#code-standards)
- Add tests for new functionality
- Update documentation if behavior changes
- Keep changes focused — one logical change per PR

### 4. Verify Before Pushing

```bash
# Format
cargo fmt

# Lint (must pass with zero warnings)
cargo clippy --workspace -- -D warnings

# Test
cargo test --workspace

# Build release (catches optimization-level issues)
cargo build --workspace --release
```

## Pull Request Process

### PR Requirements

Every PR must:

1. **Reference an issue** — link the related issue in the PR description
2. **Pass CI** — format, lint, test, build
3. **Include tests** — no untested code ships
4. **Be focused** — one logical change per PR
5. **Have a clear description** — what changed, why, and how to verify

### PR Template

When you open a PR, fill out the template completely:

- **Summary** — what this PR does and why
- **Related Issue** — link to the GitHub issue
- **Changes** — bullet list of what changed
- **Test Plan** — how the changes were tested
- **Checklist** — all items must be checked

### Review Process

1. A maintainer will review your PR within 3 business days
2. Address review feedback by pushing new commits (don't force-push during review)
3. Once approved, a maintainer will merge via **squash-and-merge**
4. Your branch will be deleted after merge

### Legal

By submitting a pull request, you represent that:

- You have the right to submit the contribution under the project's license
- Your contribution does not include code from incompatibly-licensed sources
- You agree to license your contribution under the BSL 1.1 terms as described in [LICENSE](LICENSE)

## Commit Convention

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

### Types

| Type | When to use |
|------|-------------|
| `feat` | New feature |
| `fix` | Bug fix |
| `perf` | Performance improvement |
| `refactor` | Code restructuring (no behavior change) |
| `test` | Adding or updating tests |
| `docs` | Documentation changes |
| `ci` | CI/CD changes |
| `chore` | Maintenance (dependencies, scripts) |

### Scopes

Use the crate name as scope:

```
feat(core): add wildcard route matching
fix(tls): handle cert cache miss for unknown SNI
test(analytics): add integration test for beacon collection
perf(log): switch to crossbeam channel for batch writer
docs(config): document rate_limit directive
```

### Rules

- Subject line: imperative mood, lowercase, no period, max 72 characters
- Body: explain *what* and *why*, not *how* (the code shows how)
- Reference issues: `Closes #123` or `Refs #456`

## Release Process

Dwaar follows [Semantic Versioning](https://semver.org/):

```
MAJOR.MINOR.PATCH

0.x.y  — Pre-1.0: minor versions may include breaking changes
1.0.0+ — Stable: breaking changes only in major versions
```

### Version Tags

Every release is a Git tag:

```
v0.1.0
v0.2.0
v1.0.0
```

### Release Steps

1. **Update version** in all `Cargo.toml` files
2. **Update CHANGELOG.md** — move "Unreleased" items to new version section
3. **Bump license date** — `./scripts/bump-license-date.sh <version>`
4. **Create PR** — title: `release: v0.x.y`
5. **Merge** — squash-and-merge to main
6. **Tag** — `git tag v0.x.y && git push origin v0.x.y`
7. **CI builds and publishes** — binaries, Docker image, GitHub Release

### Release Categories

| Type | Version bump | Example |
|------|-------------|---------|
| Breaking API change | MAJOR | Route struct field removed |
| New feature | MINOR | New Dwaarfile directive |
| Bug fix | PATCH | Fix cert renewal timing |
| Security fix | PATCH (immediate) | TLS vulnerability |

## Issue Guidelines

### Before Opening an Issue

1. Search [existing issues](https://github.com/permanu/Dwaar/issues) to avoid duplicates
2. Check the [CHANGELOG](CHANGELOG.md) — your issue may be fixed in a newer version
3. For questions, use [GitHub Discussions](https://github.com/permanu/Dwaar/discussions)

### Bug Reports

Include:
- Dwaar version (`dwaar version`)
- OS and architecture
- Minimal reproduction steps
- Expected vs actual behavior
- Relevant logs or error output

### Feature Requests

Include:
- Problem statement — what are you trying to do?
- Proposed solution — how should Dwaar solve it?
- Alternatives considered — what else did you try?

## AI Policy

We welcome contributions that use AI tools (Copilot, Claude, ChatGPT, etc.) with these requirements:

1. **You are responsible for the code you submit.** AI-generated code must meet the same quality, test, and review standards as human-written code.
2. **Review AI output carefully.** Do not submit code you don't understand.
3. **Disclose significant AI usage** in the PR description if the majority of the implementation was AI-generated. A simple note like "Implementation assisted by [tool]" is sufficient.
4. **AI-generated tests are not sufficient on their own.** You must verify tests actually catch the bugs they claim to test.

## Code Standards

### Rust

- **clippy**: must pass with `-D warnings` (zero warnings, fixed not suppressed)
- **fmt**: `cargo fmt` is non-negotiable
- **Errors**: `thiserror` for library crates, `anyhow` only in `dwaar-cli`
- **No `unwrap()`** in library code — use `expect()` with context or propagate with `?`
- **No `unsafe`** without a justifying comment and a tracking issue to remove it
- **No `clone()` to fight the borrow checker** — fix the ownership model instead
- Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)

### Tests

Every feature must have tests. The type depends on what changed:

| Change | Required tests |
|--------|---------------|
| Core proxy logic | Unit + integration |
| Config parsing | Unit + property-based (proptest) |
| TLS handling | Integration (real handshake) |
| Analytics | Integration + E2E |
| Admin API | Integration (HTTP assertions) |
| Performance paths | Criterion benchmarks |

### Documentation

- Public functions and types must have doc comments
- Non-obvious logic must have inline comments explaining *why*
- Architecture decisions should be noted in the PR description

---

## Questions?

- **General questions**: [GitHub Discussions](https://github.com/permanu/Dwaar/discussions)
- **Bug reports**: [GitHub Issues](https://github.com/permanu/Dwaar/issues)
- **Security issues**: See [SECURITY.md](SECURITY.md)
- **Licensing**: hello@permanu.com
- **Code of Conduct**: See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
