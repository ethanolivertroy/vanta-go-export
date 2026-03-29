# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release | Yes |
| Previous releases | No |

## Reporting a Vulnerability

If you discover a security vulnerability in vanta-go-export, please report it responsibly using GitHub's private vulnerability reporting:

1. Go to the [Security Advisories page](https://github.com/ethanolivertroy/vanta-go-export/security/advisories)
2. Click "Report a vulnerability"
3. Provide details about the vulnerability

Please do **not** open a public issue for security vulnerabilities.

## Response Timeline

- Acknowledgment within 48 hours
- Assessment and fix timeline communicated within 1 week

## Security Measures

This project employs the following security measures:

- **Dependency management:** Dependabot with weekly updates and automated merging of non-major patches
- **Vulnerability scanning:** govulncheck for Go-specific vulnerabilities
- **Static analysis:** GitHub CodeQL for code-level security issues
- **Supply chain security:** Google OSV Scanner for dependency vulnerabilities; all GitHub Actions pinned to commit SHAs
- **Transport security:** Explicit TLS 1.2 minimum on all HTTP connections and HTTPS-only redirect validation for file downloads
- **Data protection:** Restrictive directory permissions (0700) and file permissions (0600) for exported compliance data
- **Input validation:** Path traversal and symlink protection, filename sanitization, and CSV formula escaping
