# AI Disclosure

This project was developed with significant AI assistance (GitHub Copilot / Claude).

## What that means in practice

- **Architecture, implementation, tests, and documentation** were all produced
  collaboratively between a human author and an AI coding assistant.
- **GF(2³²) field arithmetic and Shamir secret sharing** (`src/sss.rs`) are
  custom implementations, not pulled from a library. These were written with AI
  assistance and have unit tests, but have **not** been formally audited.
- **Standard cryptographic primitives** — XChaCha20-Poly1305 (`chacha20poly1305`),
  Ed25519 (`ed25519-dalek`), BLAKE3 (`blake3`), ECDSA/X.509 (`rcgen`) — come
  from established Rust crates maintained by the broader community.
- **QR encoding/decoding, terminal UI, CLI scaffolding, file format handling** —
  all developed with AI assistance.

## Why disclose this

Cryptographic tooling demands trust. Users deserve to know how the code was
produced so they can calibrate their own review effort accordingly.

This is an **initial release** intended to get more eyes on the security-critical
parts. If you're evaluating this tool for real use, please review the source —
especially `src/sss.rs`, `src/crypto.rs`, and `src/mnemonic.rs` — and open
issues for anything that looks wrong.

## What hasn't been done

- No formal audit or third-party security review
- No fuzzing campaign (yet)
- No constant-time guarantees on the GF(2³²) arithmetic

Contributions and scrutiny are welcome.
