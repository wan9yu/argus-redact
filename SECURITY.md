# Security Policy

argus-redact processes PII. We take security issues seriously.

## Reporting a Vulnerability

Please **do not open a public GitHub issue** for security reports. Email:

**wangyu@go2imagination.com**

Include:

- A description of the issue
- Steps to reproduce (or a proof-of-concept)
- Affected versions
- Any suggested remediation

We aim to acknowledge reports within 5 business days and will coordinate a disclosure timeline with you.

## Scope

In scope:

- PII detection bypass — inputs that leak PII past `redact()`
- Key leakage — pseudonym codes that inadvertently encode the original value
- Offset or span computation bugs that corrupt text or cross boundaries unsafely
- Dependency CVEs that affect runtime behavior

Out of scope:

- Downstream products built on argus-redact (report to their maintainers)
- Detection-quality issues (false positives / false negatives are regular bugs — file public issues)
- Performance issues unrelated to security

## Supported Versions

Only the latest minor release receives security fixes. Users on older versions should upgrade.
