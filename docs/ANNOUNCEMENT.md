# ssscrypt — Encrypt files with Shamir secret sharing, QR cards & mnemonic words

I built a tool for offline PKI key ceremonies: **ssscrypt** encrypts files with a random symmetric key, splits that key into Shamir shares, and emits each share as both a text file and a QR card with 30 mnemonic backup words.

**Repo**: https://github.com/k-forss/ssscrypt

## The problem

When you run your own root CA (homelab, small org), you need to protect the root private key. The standard advice is "encrypt it and split the passphrase" — but what does that actually look like in practice?

I wanted:
- **K-of-N threshold** — any 3 of 5 key holders can reconstruct, fewer reveal nothing
- **Physical share cards** — print QR codes on paper, store in separate locations
- **Mnemonic backup** — 30 English words per share, in case the QR fades or a scanner isn't available
- **No OpenSSL dependency** — single binary, reproducible builds
- **Interactive ceremony UX** — raw-mode terminal with autocomplete for mnemonic input, live camera QR scanning

## What it does

```bash
# Create a root CA, encrypt the key, split into 3-of-5 shares
ssscrypt x509 create-root \
  --cn "Homelab Root CA" \
  --threshold 3 -n 5 --new-shares-dir shares/

# Later: sign an intermediate CA certificate
ssscrypt x509 sign-csr \
  --key-enc root-key.enc --issuer-cert root-ca.pem \
  --csr intermediate.csr.pem --out-cert intermediate.pem \
  --shares-dir shares/
```

Each share gets a `.share.txt` (text format) and a `.share.jpg` (QR card with mnemonic words). To reconstruct, you can:
- Point `--shares-dir` at a folder of share files
- Type mnemonic words into the interactive terminal (shadow autocomplete, case enforcement)
- Scan QR cards with a webcam (live camera window via eframe/nokhwa)

All three methods feed into the same collector. Once the threshold is met, reconstruction proceeds.

## Technical details

- **Crypto**: XChaCha20-Poly1305 (AEAD), Ed25519 (per-share + full-file signatures), Blake3 (KDF)
- **Shamir**: GF(2³²) — each coefficient is a `u32`, 8 coefficients for a 32-byte secret
- **Shares**: 30 mnemonic words each (1024-word list, 10-bit word + 1-bit case encoding, 10-bit checksum)
- **Binary**: Portable Linux binary — glibc only, camera/GUI libs loaded via `dlopen` at runtime
- **Pure Rust**: No OpenSSL, no C crypto. X.509 via `rcgen`, zeroization via `zeroize` crate

## Not audited

This has **not** been externally audited. The individual primitives are well-regarded, but the protocol composition is custom. Suitable for homelab use — review the source before trusting with anything more.

## Feedback welcome

I'd love feedback on the cryptographic design, UX, or anything else. Issues and PRs welcome.
