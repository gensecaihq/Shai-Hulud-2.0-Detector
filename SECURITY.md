# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.x.x   | :white_check_mark: |
| 1.x.x   | :x: (no ChainDrop coverage — upgrade) |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability in the Shai-Hulud 2.0 Detector tool itself, please report it responsibly.

### How to Report

1. **Do NOT open a public issue** for security vulnerabilities
2. **Email the maintainers** with details of the vulnerability
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Initial response**: Within 48 hours
- **Status update**: Within 7 days
- **Fix timeline**: Depends on severity
  - Critical: 24-48 hours
  - High: 7 days
  - Medium: 30 days
  - Low: Next release

### Scope

#### In Scope

- Vulnerabilities in the detector code
- Issues that could lead to false negatives (missing detections)
- Information disclosure vulnerabilities
- Denial of service in the scanning process

#### Out of Scope

- The Shai-Hulud 2.0 attack itself (report to npm/GitHub)
- Packages listed in our database (that's the point!)
- Social engineering attacks
- Physical security

### Safe Harbor

We consider security research conducted in good faith to be:

- Authorized in accordance with this policy
- Protected from legal action by us
- Helpful to the community

We will not pursue civil or criminal action against researchers who:

- Act in good faith
- Avoid privacy violations
- Do not destroy data
- Report findings to us

## Security Best Practices

When using this tool, we recommend:

1. **Regular Updates**: Keep the action version updated
2. **Fail on Critical**: Enable `fail-on-critical: true`
3. **Schedule Scans**: Run daily scans via cron
4. **Monitor Outputs**: Alert on any detections
5. **Multi-layer Defense**: Use alongside other security tools

## Acknowledgments

We thank security researchers who have helped improve this tool:

- *Your name could be here!*

---

Thank you for helping keep the open-source community safe.
