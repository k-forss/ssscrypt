# Security Policy

## ⚠ Audit status

ssscrypt has **not been externally audited**. It is designed for homelab PKI use
(offline root CA ceremonies, personal key management). Do not rely on it for
high-value secrets without independent review.

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅         |

## Reporting a vulnerability

If you discover a security issue, **do not open a public GitHub issue**.

Instead, use one of these channels:

1. **GitHub Security Advisories** (preferred):
   <https://github.com/k-forss/ssscrypt/security/advisories/new>

2. **Email**: security@forss.cc
- Encrypt with the PGP fingerprint below if the issue is sensitive.

### What to include

- ssscrypt in title if using mail
- Description of the vulnerability
- Steps to reproduce (minimal example preferred)
- Impact assessment (what can an attacker do?)
- Suggested fix, if any

### Response timeline

- **Acknowledgement**: within 48 hours
- **Assessment**: within 7 days
- **Fix + disclosure**: coordinated with reporter, typically within 30 days

### PGP fingerprint

If you need to encrypt your report:

```
45D4 3871 F014 FFF2 9D82  3C76 3810 BA93 74FD 5E67
```

Fetch: `gpg --keyserver keys.openpgp.org --recv-keys 45D43871F014FFF29D823C763810BA9374FD5E67`

## Scope

The following are in scope:

- Cryptographic weaknesses (key derivation, SSS, XChaCha20-Poly1305, Ed25519 usage)
- Share leakage (incomplete zeroization, side channels)
- Signature bypass or forgery
- Mnemonic encoding correctness (bit packing, checksum)
- Memory safety issues

Out of scope:

- Denial of service via malformed input (low severity, CLI tool)
- Issues in upstream dependencies (report those upstream, but let us know)
- Social engineering of share holders
