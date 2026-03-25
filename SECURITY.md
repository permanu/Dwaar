# Security Policy

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please report vulnerabilities through one of:

1. **GitHub Security Advisories** (preferred): [Report a vulnerability](https://github.com/permanu/Dwaar/security/advisories/new)
2. **Email**: security@permanu.com

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Impact assessment (what an attacker could achieve)
- Suggested fix (if you have one)
- Your name/handle for attribution (if desired)

### What to Expect

| Timeline | Action |
|----------|--------|
| **24 hours** | Acknowledgment of your report |
| **72 hours** | Initial assessment and severity classification |
| **7 days** | Plan for fix or mitigation communicated |
| **30 days** | Fix released (90 days for complex issues) |

### Disclosure Policy

We follow **coordinated disclosure**:

- We will work with you to understand and address the issue
- We will credit you in the advisory (unless you prefer anonymity)
- We ask that you do not disclose the vulnerability publicly until a fix is released
- If we are unresponsive for more than 14 days, you may disclose at your discretion

### Safe Harbor

We consider security research conducted in good faith to be authorized. We will not pursue legal action against researchers who:

- Make a good faith effort to avoid privacy violations, data destruction, and service disruption
- Only interact with accounts they own or with explicit permission
- Report vulnerabilities through the channels above
- Allow reasonable time for remediation before disclosure

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release | Yes |
| Previous minor | Security fixes only |
| Older versions | No |

## Scope

The following are in scope:

- Dwaar proxy binary (`dwaar`)
- All crates in the `crates/` directory
- TLS implementation and certificate handling
- Admin API authentication and authorization
- Request/response processing pipeline
- Analytics data collection and storage

The following are out of scope:

- Third-party dependencies (report to the upstream project)
- Issues in Pingora itself (report to [Cloudflare](https://github.com/cloudflare/pingora/security))
- Social engineering attacks
- Denial of service via resource exhaustion (unless disproportionate)
