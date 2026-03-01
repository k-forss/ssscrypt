# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] — 2026-03-01

First public release — encrypt files with Shamir secret sharing, split the
key into QR cards with mnemonic backup words.

**Breaking** (vs v0.1.0): GF(2³²) polynomial changed from 0x8D to 0x0040_0007
(primitive, [Partow table](https://www.partow.net/programming/polynomials/index.html)).
Shares created with v0.1.0 are incompatible.

### Added

- **Encryption / decryption** with XChaCha20-Poly1305 + Ed25519 signatures
- **Shamir secret sharing** over GF(2³²) with a known primitive polynomial
  (`x³² + x²² + x² + x + 1`, first degree-32 entry in
  [Partow's table](https://www.partow.net/programming/polynomials/index.html))
- **QR share cards** (`.share.jpg`) with mnemonic backup words
  (30 words per share, 1024-word BIP-style list)
- **Self-describing QR URI format** — `ssscrypt:share:v1:<base64url>:<crc32>`
  with CRC-32 corruption check and legacy raw-binary fallback
- **Interactive share collector** — pre-load from folder, then gather
  remaining via:
  - Raw-mode terminal with shadow autocomplete and case enforcement
  - Live camera QR scanner window (via `nokhwa` + `eframe`)
- **Key rotation** (`rotate`) — decrypt with old shares, re-encrypt with a
  new key, no plaintext on disk
- **Share re-split** (`gen-shares`) — reconstruct key from existing shares
  and emit a new set with random x values
- **X.509 helpers** — `x509 create-root` and `x509 sign-csr`
  (pure Rust via `rcgen` 0.14, no OpenSSL)
- Per-share Ed25519 validation — each share is individually verifiable
  against the header pubkey
- Pubkey pinning for unanchored operations:
  - `--pin-pubkey` — full 64-character hex pubkey
  - `--pin-fpr` — fingerprint prefix (colon-separated hex from share card)
  - `--anchor-encrypted` — extract pubkey from an existing encrypted file
- Key and share fingerprints (BLAKE3, truncated) printed during creation
  and displayed on QR cards for TOFU verification
- Comprehensive zeroization of master key, private key, and plaintext
  after use
- Text-format share and encrypted files (key-value lines, base64 payloads)
- Compact binary QR payload format (137+ bytes)
- Share filename convention with optional group name
- Stdin/stdout piping for all encrypt/decrypt operations
- Pre-push hook (`scripts/setup-hooks.sh`) running fmt, clippy, and tests
- Build provenance attestation and VirusTotal scanning in release CI
- Portable single binary — links only glibc; camera/GUI via runtime `dlopen`
