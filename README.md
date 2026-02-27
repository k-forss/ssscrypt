# ssscrypt

Encrypt files with a random symmetric key, split that key using threshold secret sharing (Shamir over GF(256)), and emit share files (base64-encoded).

Designed for homelab PKI / offline root key handling. Builds as a single portable Linux binary — links only glibc; camera/GUI libraries are loaded at runtime via `dlopen` and gracefully skipped when unavailable.

> **Warning**: Review, test, and consider external audit before trusting with high-value keys.

## Build

```bash
cargo build --release
```

## Commands

All commands that accept `--in` / `--out` default to stdin / stdout when omitted.

Share collection: commands that need shares use an **interactive collector** — pre-load from a folder, then gather remaining shares via terminal mnemonic input and a live camera QR scanner window. If the folder already has enough shares, the collector returns immediately.

Share directory conventions:
- `--shares-dir` — pre-load existing shares from this directory (auto-discovers `*.share.txt`)
- `--new-shares-dir` — write new shares to this directory

When writing shares, both a `.share.txt` text file and a `.share.jpg` QR card image (with mnemonic backup words) are generated for each share.

### encrypt

Encrypt a file. Either generates a new random master key and creates shares, or uses an existing key reconstructed from shares.

```bash
# New key — encrypt file, create 3-of-5 shares
ssscrypt encrypt --in root.key --out root.key.enc \
  --threshold 3 -n 5 --new-shares-dir shares/

# New key — pipe in, pipe out
cat root.key | ssscrypt encrypt \
  --threshold 3 -n 5 --new-shares-dir shares/ > root.key.enc

# Existing key — encrypt another file with the same master key (⚠ unanchored)
ssscrypt encrypt --in backup.key --out backup.key.enc \
  --shares-dir shares/ \
  --pin-pubkey 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

Share files created in `--new-shares-dir`:
```
shares/v1-k3-x1.share.txt
shares/v1-k3-x1.share.jpg    # QR card with mnemonic words
shares/v1-k3-x2.share.txt
shares/v1-k3-x2.share.jpg
...
shares/v1-k3-x5.share.txt
shares/v1-k3-x5.share.jpg
```

### decrypt

Decrypt a file using shares. **Anchored** — the header pubkey validates shares.

```bash
# File to file
ssscrypt decrypt --in root.key.enc --out root.key --shares-dir shares/

# Pipe in, pipe out
cat root.key.enc | ssscrypt decrypt --shares-dir shares/ > root.key
```

The header contains the pubkey and threshold hint. Each share is validated individually against the header pubkey before reconstruction is attempted.

### rotate

Decrypt with old shares and re-encrypt with a new key + new shares. **Anchored** — old ciphertext header provides the anchor.

```bash
# Threshold is inherited from old shares if omitted
ssscrypt rotate --in old.enc --out new.enc \
  --shares-dir shares_old/ \
  -n 5 --new-shares-dir shares_new/

# Override threshold for the new share set
ssscrypt rotate --in old.enc --out new.enc \
  --shares-dir shares_old/ \
  -k 3 -n 5 --new-shares-dir shares_new/
```

### gen-shares

Reconstruct master key from existing shares and re-split into a new set. **Unanchored** — use `--pin-pubkey` or `--anchor-encrypted`.

Threshold and group are inherited from the collected shares — `gen-shares` re-splits the *same* key, so these properties cannot be changed (use `rotate` to create a new key with different parameters).

New shares are assigned **random x values** (from 1 to 2^32-1) to minimise accidental collision with outstanding shares whose x values are unknown.

```bash
# Pin with pubkey hex
ssscrypt gen-shares \
  --shares-dir shares_old/ \
  -n 5 --new-shares-dir shares_new/ \
  --pin-pubkey 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

# Pin from an existing encrypted file's header
ssscrypt gen-shares \
  --shares-dir shares_old/ \
  -n 5 --new-shares-dir shares_new/ \
  --anchor-encrypted root-key.enc
```

### x509

X.509 certificate helpers (pure Rust via `rcgen` — no OpenSSL). CLI args as overrides for scriptable use.

#### x509 create-root

```bash
# Fully interactive
ssscrypt x509 create-root

# With overrides
ssscrypt x509 create-root \
  --cn "Homelab Root CA" --org "Example Inc" \
  --days 3650 \
  --out-cert root-ca.pem --out-key-enc root-key.enc \
  --threshold 3 -n 5 --new-shares-dir shares/
```

#### x509 sign-csr

```bash
# Fully interactive
ssscrypt x509 sign-csr

# With overrides
ssscrypt x509 sign-csr \
  --key-enc root-key.enc --issuer-cert root-ca.pem \
  --csr intermediate.csr.pem --out-cert intermediate.pem \
  --days 1825 --is-ca --pathlen 0 \
  --shares-dir shares/
```

## Encrypt flow

1. Read plaintext fully into memory
2. Obtain master key:
   - **New key**: generate 32 random bytes
   - **Existing key**: reconstruct from shares via interactive collector, verify against `--pin-pubkey` or `--anchor-encrypted`
3. Derive Ed25519 keypair: `blake3(key=master_key, "ssscrypt-signing-key")` → 32-byte seed → Ed25519 keypair
4. Derive data key: `blake3(key=master_key, "ssscrypt-data-key")` → 32-byte XChaCha20-Poly1305 key
5. Generate random 24-byte nonce
6. Encrypt plaintext: XChaCha20-Poly1305 single-shot → ciphertext‖tag (16 bytes)
7. Build header (67+ bytes): magic, version, threshold, nonce, pubkey, group
8. Sign: Ed25519 sign(header‖ciphertext‖tag) → 64-byte signature
9. Write output: header‖ciphertext‖tag‖signature
10. If new key: split master key → create shares → sign each share → write `.share.txt` + `.share.jpg` QR cards to `--new-shares-dir`
11. Zeroize master key, private key, plaintext

## Decrypt flow

1. Read encrypted file fully into memory
2. Parse header → extract pubkey (anchor), threshold hint, nonce, group
3. Gather shares via interactive collector (pre-load from `--shares-dir`, then terminal mnemonic input + live camera QR scanner)
4. Validate each share:
   - Check magic, version, valid x (≠ 0)
   - Verify Ed25519 signature against header pubkey
   - Reject shares whose embedded pubkey doesn't match header pubkey
   - Report valid/invalid shares to stderr
5. Group valid shares, check ≥ threshold available
6. Reconstruct master key from K valid shares
7. Derive Ed25519 keypair, verify derived pubkey matches header pubkey (fast "wrong shares" check)
8. Verify Ed25519 signature over header‖ciphertext‖tag (full file integrity)
9. Derive data key, decrypt ciphertext
10. Write plaintext
11. Zeroize

## Share ingestion (consensus rules)

When auto-discovering shares from `--shares-dir`:

1. Read all `*.share.txt` files, parse each independently
2. Reject shares that fail: magic/version check, signature verification, or pubkey mismatch (if an anchor is available)
3. Group remaining valid shares by embedded pubkey
4. If an anchor pubkey is available (from header, `--pin-pubkey`, or `--anchor-encrypted`): select only the matching group
5. If no anchor: select the group with the most shares. If multiple groups tie at ≥K shares → **fail with error**, require `--pin-pubkey`
6. Check for duplicate `x` values within the selected group → reject duplicates
7. Verify ≥ K shares remain

This ensures deterministic behavior even if the shares directory accidentally contains shares from different key sets.

## File formats

Both encrypted files and share files use a human-readable **text format** on disk — key-value lines with base64-encoded binary payloads. The binary (packed) format is used only inside QR codes.

### Encrypted file (`.enc`)

```
# ssscrypt encrypted file — DO NOT EDIT
# Decryption requires threshold secret sharing.

version: 1
threshold: 3
group: Homelab Root CA
pubkey: 0123456789abcdef…  (64 hex chars, Ed25519 public key)
data: <base64>             (nonce ‖ ciphertext ‖ AEAD tag)
signature: <base64>        (Ed25519 over the signed message)
```

| Field       | Format    | Description                                          |
|-------------|-----------|------------------------------------------------------|
| version     | decimal   | `1` (implies XChaCha20-Poly1305 + Ed25519)           |
| threshold   | decimal   | UX hint — shares required (also embedded in shares)  |
| group       | UTF-8     | human-readable name (e.g. certificate CN)            |
| pubkey      | hex       | 32-byte Ed25519 public key derived from master key   |
| data        | base64    | nonce (24 B) ‖ ciphertext ‖ AEAD tag (16 B)         |
| signature   | base64    | Ed25519 over header ‖ ciphertext ‖ tag (64 B)       |

The group is included in the signed region — it cannot be modified without invalidating the signature. The AEAD tag authenticates the ciphertext; the Ed25519 signature additionally authenticates the header fields and provides a stable key identifier for full-file integrity.

### Share file (`.share.txt`)

```
# ssscrypt share — DO NOT EDIT
# Modifying this file will invalidate the cryptographic signature.

version: 1
threshold: 3
group: Homelab Root CA
pubkey: 0123456789abcdef…  (64 hex chars)
data: <base64>             (x ‖ y — share index + GF(2^32) evaluation)
signature: <base64>        (Ed25519 over the signed payload)
```

| Field       | Format    | Description                                     |
|-------------|-----------|------------------------------------------------ |
| version     | decimal   | share format version (`1`)                      |
| threshold   | decimal   | shares required to reconstruct                  |
| group       | UTF-8     | human-readable name (e.g. certificate CN)       |
| pubkey      | hex       | 32-byte Ed25519 pubkey (grouping / matching)    |
| data        | base64    | x (4 B, big-endian u32) ‖ y (32 B, GF(2^32) value) |
| signature   | base64    | Ed25519 over all preceding fields (64 B)        |

Shares are **file-independent** — the same shares can decrypt any file encrypted with that master key. `share_count` is intentionally omitted — it becomes stale when shares are re-split with `gen-shares`. The threshold and pubkey are sufficient for grouping and reconstruction.

### QR payload (binary format)

Inside QR codes, shares are packed into a compact binary format:

| Field        | Offset | Size    | Description                                     |
|--------------|--------|---------|-------------------------------------------------|
| magic        | 0      | 2       | `SS`                                            |
| version      | 2      | 1       | share format version (1)                        |
| threshold k  | 3      | 1       | shares required to reconstruct                  |
| x            | 4      | 4       | share index (big-endian u32)                    |
| y            | 8      | 32      | share data (GF(2^32) evaluation)                |
| pubkey       | 40     | 32      | Ed25519 pubkey (standalone grouping / matching) |
| group_len    | 72     | 1       | length of UTF-8 group name (0–255)              |
| group        | 73     | 0–255   | human-readable name (e.g. certificate CN)       |
| signature    | 73+N   | 64      | Ed25519 over bytes 0..73+N                      |

Minimum: 137 bytes (group empty).

### Share QR card (`.share.jpg`)

A JPEG card generated alongside every `.share.txt` file. Contains:
- A QR code encoding the share's binary payload
- 30 mnemonic backup words (1024-word list, 10-bit word + 1-bit case encoding, 10-bit checksum)
- Metadata label (group, threshold, share index)

Shares can be recovered by scanning the QR code with a camera or by typing the mnemonic words into the interactive collector.

### Share filename convention

- Without group: `v{version}-k{threshold}-x{x}.share.txt` — e.g. `v1-k3-x1.share.txt`
- With group: `{group}-v{version}-k{threshold}-x{x}.share.txt` — e.g. `Homelab_Root_CA-v1-k3-x1.share.txt`

The filename is informational; the tool parses the binary content.

## Design decisions

- **In-memory processing**: Files are read/written whole. Appropriate for the target use case (PKI keys, certificates — small files). No streaming/chunking complexity.
- **XChaCha20-Poly1305**: 24-byte nonce eliminates nonce collision risk with random generation. The AEAD tag authenticates the ciphertext; the Ed25519 signature additionally authenticates the header and provides a stable key identifier and full-file integrity.
- **Per-share validation via Ed25519**: An Ed25519 keypair is deterministically derived from the master key. Each share is signed so it can be validated individually against a known pubkey — no other shares needed. Enables "try another share" workflows via the interactive collector (mnemonic input, camera QR scanning).
- **Pubkey in shares**: Allows grouping shares ("do these belong together?") and validating shares without the encrypted file.
- **Group field**: Human-readable name (e.g. certificate CN) embedded in the signed region of both encrypted files and shares. Helps identify which key set a share belongs to.
- **QR cards + mnemonic words**: Every share is written as both a `.share.txt` file and a `.share.jpg` QR card with mnemonic backup words. Shares can be recovered by scanning the QR code or typing the words.
- **Interactive collector**: All commands that need shares use a unified collector — pre-load from a folder, then gather remaining shares via terminal mnemonic input and a live camera QR scanner. Camera errors are non-fatal (graceful runtime fallback).
- **Shares are portable**: Not bound to a specific file. Same master key can protect multiple files. Note: the pubkey in the header links ciphertexts encrypted with the same master key (acceptable for homelab PKI).
- **gen-shares is self-contained**: Enough shares → reconstruct master key → re-derive signing key → sign new shares. No encrypted file needed.
- **Encrypt with existing shares**: Multiple files can be encrypted with the same master key by providing existing shares to reconstruct from.
- **Anchored vs unanchored workflows**: `decrypt` and `rotate` are anchored by the ciphertext header pubkey — substitution attacks are not possible. `encrypt --shares-dir` and `gen-shares` are unanchored and should use `--pin-pubkey` or `--anchor-encrypted` to prevent key substitution (see Operational Safety).
- **Portable binary**: All crypto and core logic is pure Rust (`chacha20poly1305`, `ed25519-dalek`, `rcgen`). The binary links only glibc at build time. Camera/GUI libraries (`nokhwa`, `eframe`/`winit`) use runtime `dlopen` for X11/Wayland/GL — the camera window works when desktop libs are present and is gracefully skipped on headless systems.

## Operational safety

> The `--shares-dir` auto-discovery is designed for **ceremony convenience on an air-gapped machine**. Treat it as a temporary staging area, not long-term storage. Do not store multiple shares together outside of a ceremony.

### Key substitution risk

An attacker who can replace **all** shares in a `--shares-dir` folder can trick unanchored operations (`encrypt --shares-dir`, `gen-shares`) into using an attacker-controlled key. They cannot decrypt existing ciphertext, but can cause new data to be encrypted under their key.

**Mitigation**: For unanchored operations, pin the expected pubkey:
- `--pin-pubkey <hex>` — full 64-character hex pubkey (printed during key creation)
- `--anchor-encrypted <file>` — extract expected pubkey from an existing encrypted file's header

Write down the pubkey hex on paper during the initial ceremony and verify it during subsequent operations.

### Recommended environment

- Perform key ceremonies on an air-gapped machine
- Disable core dumps: `ulimit -c 0`
- Use encrypted swap or disable swap entirely
- Master key and private key are zeroized after use (in-process), but physical memory forensics may still apply

## Share recovery methods

- **Folder auto-discovery**: `--shares-dir` loads all `*.share.txt` files
- **QR card scanning**: Live camera window (via `nokhwa` + `eframe`) scans QR codes in real time
- **Mnemonic word input**: 30 words per share, entered one at a time in raw-mode terminal with shadow autocomplete, case enforcement, and fuzzy correction

All methods feed into the same interactive collector, which deduplicates shares and returns once the threshold is met.
