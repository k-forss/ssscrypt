# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-02-28

### Added

- **Encryption / decryption** with XChaCha20-Poly1305 + Ed25519 signatures
- **Shamir secret sharing** over GF(2³²) — split a 32-byte master key into *n* shares, any *k* reconstruct
- **QR share cards** (`.share.jpg`) with mnemonic backup words (30 words per share, 1024-word BIP-style list)
- **Interactive share collector** — pre-load from folder, then gather remaining via:
  - Raw-mode terminal with shadow autocomplete and case enforcement
  - Live camera QR scanner window (via `nokhwa` + `eframe`)
- **Key rotation** (`rotate`) — decrypt with old shares, re-encrypt with a new key, no plaintext on disk
- **Share re-split** (`gen-shares`) — reconstruct key from existing shares and emit a new set with random x values
- **X.509 helpers** — `x509 create-root` and `x509 sign-csr` (pure Rust via `rcgen`, no OpenSSL)
- Per-share Ed25519 validation — each share is individually verifiable against the header pubkey
- Pubkey pinning (`--pin-pubkey`, `--anchor-encrypted`) for unanchored operations
- Comprehensive zeroization of master key, private key, and plaintext after use
- Text-format share and encrypted files (key-value lines, base64 payloads)
- Compact binary QR payload format (137+ bytes)
- Share filename convention with optional group name
- Stdin/stdout piping for all encrypt/decrypt operations
