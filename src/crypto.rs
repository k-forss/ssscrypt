//! Cryptographic operations: key derivation, encryption, signing, share validation.
//!
//! Key hierarchy (domain-separated via blake3):
//!
//! ```text
//!   master_key (32 bytes, random or reconstructed)
//!     ├─ blake3(key=master, "ssscrypt-signing-key") → Ed25519 seed → keypair
//!     └─ blake3(key=master, "ssscrypt-data-key")    → XChaCha20-Poly1305 key
//! ```

use anyhow::{bail, Context, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroize;

use crate::encrypted::{EncryptedFile, Header};
use crate::share::{Share, SHARE_VERSION};
use crate::sss::{RawShare, SECRET_LEN};

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/// Domain string for deriving Ed25519 signing seed from master key.
const SIGNING_DOMAIN: &str = "ssscrypt-signing-key";
/// Domain string for deriving encryption key from master key.
const DATA_DOMAIN: &str = "ssscrypt-data-key";

/// Derived keys from a master secret.
pub struct DerivedKeys {
    pub signing: SigningKey,
    pub data_key: [u8; 32],
}

impl Drop for DerivedKeys {
    fn drop(&mut self) {
        // SigningKey implements ZeroizeOnDrop (ed25519-dalek `zeroize` feature),
        // so it auto-zeroizes when dropped after this method returns.
        self.data_key.zeroize();
    }
}

/// Derive Ed25519 signing key and XChaCha20-Poly1305 data key from master secret.
pub fn derive_keys(master: &[u8; SECRET_LEN]) -> DerivedKeys {
    let mut sign_seed = blake3::derive_key(SIGNING_DOMAIN, master);
    let data_key = blake3::derive_key(DATA_DOMAIN, master);
    let signing = SigningKey::from_bytes(&sign_seed);
    sign_seed.zeroize();
    DerivedKeys { signing, data_key }
}

/// Get the public key bytes from a signing key.
pub fn pubkey_bytes(key: &SigningKey) -> [u8; 32] {
    key.verifying_key().to_bytes()
}

// ---------------------------------------------------------------------------
// Encryption / decryption
// ---------------------------------------------------------------------------

/// Encrypt plaintext into an `EncryptedFile`.
///
/// 1. Encrypt with XChaCha20-Poly1305 (random nonce).
/// 2. Build header with pubkey and threshold hint.
/// 3. Sign header‖ciphertext.
pub fn encrypt(
    plaintext: &[u8],
    keys: &DerivedKeys,
    threshold: u8,
    group: &str,
) -> Result<EncryptedFile> {
    // Generate random 24-byte nonce.
    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    // Encrypt.
    let cipher = XChaCha20Poly1305::new_from_slice(&keys.data_key).expect("key is 32 bytes");
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("encryption failed: {e}"))?;

    // Build header.
    let header = Header {
        version: 1,
        threshold,
        nonce: nonce_bytes,
        pubkey: pubkey_bytes(&keys.signing),
        group: group.to_string(),
    };

    // Sign header‖ciphertext.
    let header_bytes = header.to_bytes()?;
    let mut msg = Vec::with_capacity(header_bytes.len() + ciphertext.len());
    msg.extend_from_slice(&header_bytes);
    msg.extend_from_slice(&ciphertext);
    let sig = keys.signing.sign(&msg);

    Ok(EncryptedFile {
        header,
        ciphertext,
        signature: sig.to_bytes(),
    })
}

/// Decrypt an `EncryptedFile`, returning plaintext.
///
/// 1. Verify derived pubkey matches header.
/// 2. Verify Ed25519 signature over header‖ciphertext.
/// 3. Decrypt ciphertext.
pub fn decrypt(file: &EncryptedFile, keys: &DerivedKeys) -> Result<Vec<u8>> {
    // Check pubkey match (fast "wrong shares" check).
    let derived_pubkey = pubkey_bytes(&keys.signing);
    if derived_pubkey != file.header.pubkey {
        bail!(
            "derived pubkey does not match header pubkey — wrong shares?\n\
             derived:  {}\n\
             expected: {}",
            hex::encode(&derived_pubkey),
            hex::encode(&file.header.pubkey)
        );
    }

    // Verify file signature.
    let verifying = keys.signing.verifying_key();
    let signed = file.signed_bytes()?;
    let sig = ed25519_dalek::Signature::from_bytes(&file.signature);
    verifying
        .verify(&signed, &sig)
        .context("file signature verification failed")?;

    // Decrypt.
    let nonce = XNonce::from_slice(&file.header.nonce);
    let cipher = XChaCha20Poly1305::new_from_slice(&keys.data_key).expect("key is 32 bytes");
    let plaintext = cipher
        .decrypt(nonce, file.ciphertext.as_ref())
        .map_err(|e| anyhow::anyhow!("decryption failed (corrupted data?): {e}"))?;

    Ok(plaintext)
}

// ---------------------------------------------------------------------------
// Share signing / verification
// ---------------------------------------------------------------------------

/// Sign a raw SSS share, producing a full `Share` with pubkey and signature.
///
/// # Errors
///
/// Returns an error if the group name exceeds 255 bytes (via
/// [`Share::signed_bytes`]), since the binary share format cannot encode a
/// longer group name.
pub fn sign_share(raw: &RawShare, keys: &DerivedKeys, threshold: u8, group: &str) -> Result<Share> {
    let mut share = Share {
        version: SHARE_VERSION,
        threshold,
        x: raw.x,
        y: raw.y,
        pubkey: pubkey_bytes(&keys.signing),
        group: group.to_string(),
        signature: [0u8; 64],
    };

    let msg = share.signed_bytes()?;
    let sig = keys.signing.sign(&msg);
    share.signature = sig.to_bytes();
    Ok(share)
}

/// Verify a share's Ed25519 signature against its embedded pubkey.
pub fn verify_share_signature(share: &Share) -> Result<()> {
    let pubkey = VerifyingKey::from_bytes(&share.pubkey).context("share: invalid pubkey")?;
    let msg = share.signed_bytes()?;
    let sig = ed25519_dalek::Signature::from_bytes(&share.signature);
    pubkey
        .verify(&msg, &sig)
        .context("share signature verification failed")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Share consensus
// ---------------------------------------------------------------------------

/// Result of share ingestion: a validated, consistent set.
pub struct ValidatedShares {
    pub shares: Vec<Share>,
    pub pubkey: [u8; 32],
    pub threshold: u8,
}

/// Ingest shares from files: validate, group by pubkey, apply consensus rules.
///
/// `anchor_pubkey`: if available (from header, --pin-pubkey, or --anchor-encrypted),
/// only shares matching this pubkey are accepted. Otherwise, select the largest
/// unambiguous group.
#[cfg(test)]
fn ingest_shares(
    raw_shares: Vec<Share>,
    anchor_pubkey: Option<&[u8; 32]>,
) -> Result<ValidatedShares> {
    if raw_shares.is_empty() {
        bail!("no share files found");
    }

    // Step 1: Validate each share signature, keep valid ones.
    let mut valid: Vec<Share> = Vec::new();
    let mut rejected = 0usize;

    for share in &raw_shares {
        match verify_share_signature(share) {
            Ok(()) => valid.push(share.clone()),
            Err(e) => {
                eprintln!("  rejected share x={}: {e}", share.x);
                rejected += 1;
            }
        }
    }

    if valid.is_empty() {
        bail!("all {rejected} shares failed signature verification");
    }

    // Step 2: If anchor provided, filter to matching pubkey.
    if let Some(anchor) = anchor_pubkey {
        valid.retain(|s| &s.pubkey == anchor);
        if valid.is_empty() {
            bail!("no shares match the expected pubkey (anchor)");
        }
    }

    // Step 3: Group by pubkey.
    let mut groups: std::collections::HashMap<[u8; 32], Vec<Share>> =
        std::collections::HashMap::new();
    for share in valid {
        groups.entry(share.pubkey).or_default().push(share);
    }

    // Step 4: Select group.
    let selected = if groups.len() == 1 {
        groups.into_values().next().unwrap()
    } else {
        // Multiple groups — pick the largest, fail on tie.
        let mut sorted: Vec<_> = groups.into_values().collect();
        sorted.sort_by_key(|b| std::cmp::Reverse(b.len()));

        if sorted[0].len() == sorted[1].len() {
            bail!(
                "ambiguous shares: {} groups with {} shares each — use --pin-pubkey to disambiguate",
                sorted.iter().filter(|g| g.len() == sorted[0].len()).count(),
                sorted[0].len()
            );
        }
        sorted.into_iter().next().unwrap()
    };

    // Step 5: Deduplicate x values (keep first seen).
    let mut seen_x: std::collections::HashSet<u32> = std::collections::HashSet::new();
    let mut deduped: Vec<Share> = Vec::new();
    for share in selected {
        if seen_x.insert(share.x) {
            deduped.push(share);
        } else {
            eprintln!("  warning: ignoring duplicate share x={}", share.x);
        }
    }

    let threshold = deduped[0].threshold;
    let pubkey = deduped[0].pubkey;

    if deduped.len() < threshold as usize {
        bail!(
            "need at least {} shares, have {} valid",
            threshold,
            deduped.len()
        );
    }

    eprintln!(
        "  {} valid share(s) for key {} (threshold {})",
        deduped.len(),
        &hex::encode(&pubkey)[..16],
        threshold
    );

    Ok(ValidatedShares {
        shares: deduped,
        pubkey,
        threshold,
    })
}

/// Convert validated shares back to raw shares for SSS reconstruction.
pub fn shares_to_raw(shares: &[Share]) -> Vec<RawShare> {
    shares.iter().map(|s| RawShare { x: s.x, y: s.y }).collect()
}

/// Generate a fresh 32-byte master key.
pub fn generate_master_key() -> [u8; SECRET_LEN] {
    let mut key = [0u8; SECRET_LEN];
    OsRng.fill_bytes(&mut key);
    key
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sss;

    #[test]
    fn key_derivation_deterministic() {
        let master = [0x42u8; 32];
        let k1 = derive_keys(&master);
        let k2 = derive_keys(&master);
        assert_eq!(pubkey_bytes(&k1.signing), pubkey_bytes(&k2.signing));
        assert_eq!(k1.data_key, k2.data_key);
    }

    #[test]
    fn key_derivation_different_domains() {
        let master = [0x42u8; 32];
        let keys = derive_keys(&master);
        // Signing seed and data key must differ.
        let sign_seed = blake3::derive_key(SIGNING_DOMAIN, &master);
        assert_ne!(sign_seed, keys.data_key);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let master = generate_master_key();
        let keys = derive_keys(&master);
        let plaintext = b"hello, world!";

        let encrypted = encrypt(plaintext, &keys, 3, "").unwrap();
        let decrypted = decrypt(&encrypted, &keys).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let master1 = generate_master_key();
        let master2 = generate_master_key();
        let keys1 = derive_keys(&master1);
        let keys2 = derive_keys(&master2);

        let encrypted = encrypt(b"secret data", &keys1, 2, "").unwrap();
        assert!(decrypt(&encrypted, &keys2).is_err());
    }

    #[test]
    fn sign_verify_share_roundtrip() {
        let master = generate_master_key();
        let keys = derive_keys(&master);
        let raw_shares = sss::split(&master, 3, 5).unwrap();

        for raw in &raw_shares {
            let signed = sign_share(raw, &keys, 3, "").unwrap();
            assert!(verify_share_signature(&signed).is_ok());
        }
    }

    #[test]
    fn tampered_share_rejected() {
        let master = generate_master_key();
        let keys = derive_keys(&master);
        let raw_shares = sss::split(&master, 2, 3).unwrap();
        let mut signed = sign_share(&raw_shares[0], &keys, 2, "").unwrap();
        signed.y[0] ^= 0xff; // corrupt
        assert!(verify_share_signature(&signed).is_err());
    }

    #[test]
    fn full_flow_encrypt_split_reconstruct_decrypt() {
        let master = generate_master_key();
        let keys = derive_keys(&master);
        let plaintext = b"the quick brown fox jumps over the lazy dog";

        // Encrypt.
        let encrypted = encrypt(plaintext, &keys, 3, "").unwrap();

        // Split master key into shares.
        let raw_shares = sss::split(&master, 3, 5).unwrap();
        let signed_shares: Vec<Share> = raw_shares
            .iter()
            .map(|r| sign_share(r, &keys, 3, "").unwrap())
            .collect();

        // Reconstruct from a subset.
        let subset = vec![
            signed_shares[0].clone(),
            signed_shares[2].clone(),
            signed_shares[4].clone(),
        ];
        let validated =
            ingest_shares(subset, Some(&keys.signing.verifying_key().to_bytes())).unwrap();

        let raw = shares_to_raw(&validated.shares);
        let recovered_master = sss::combine(&raw, validated.threshold).unwrap();

        // Derive keys from recovered master and decrypt.
        let recovered_keys = derive_keys(&recovered_master);
        let decrypted = decrypt(&encrypted, &recovered_keys).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn ingest_rejects_mismatched_pubkeys_with_anchor() {
        let master1 = generate_master_key();
        let master2 = generate_master_key();
        let keys1 = derive_keys(&master1);
        let keys2 = derive_keys(&master2);
        let raw = sss::split(&master1, 2, 3).unwrap();

        // Sign with keys2 (wrong keys).
        let shares: Vec<Share> = raw
            .iter()
            .map(|r| sign_share(r, &keys2, 2, "").unwrap())
            .collect();
        let anchor = pubkey_bytes(&keys1.signing);
        assert!(ingest_shares(shares, Some(&anchor)).is_err());
    }

    #[test]
    fn encrypted_file_serialization_roundtrip() {
        let master = generate_master_key();
        let keys = derive_keys(&master);
        let encrypted = encrypt(b"test", &keys, 2, "").unwrap();

        let bytes = encrypted.to_bytes();
        let parsed = EncryptedFile::from_bytes(&bytes).unwrap();

        let decrypted = decrypt(&parsed, &keys).unwrap();
        assert_eq!(decrypted, b"test");
    }
}
