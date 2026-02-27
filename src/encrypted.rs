//! Encrypted file format: header, serialization, and display.
//!
//! ## Binary layout (variable, ≥131 bytes)
//!
//! | Field        | Offset    | Size      | Description                         |
//! |--------------|-----------|-----------|-------------------------------------|
//! | magic        | 0         | 8         | `SSSENC01`                          |
//! | version      | 8         | 1         | format version (1)                  |
//! | threshold    | 9         | 1         | K — shares required to decrypt      |
//! | nonce        | 10        | 24        | XChaCha20-Poly1305 nonce            |
//! | pubkey       | 34        | 32        | Ed25519 public key                  |
//! | group_len    | 66        | 1         | length of UTF-8 group name (0–255)  |
//! | group        | 67        | 0–255     | human-readable name                 |
//! | ciphertext   | 67+N      | variable  | encrypted data                      |
//! | signature    | end−64    | 64        | Ed25519 over bytes 0..end−64        |
//!
//! The group is included in the signed region — it cannot be modified
//! without invalidating the signature.
//!
//! ## Text file format
//!
//! ```text
//! # ssscrypt encrypted file — DO NOT EDIT
//! # Decryption requires threshold secret sharing.
//!
//! version: 1
//! threshold: 2
//! group: ForssCloud Root CA
//! pubkey: abcdef0123456789...
//! data: <base64(nonce ++ ciphertext)>
//! signature: <base64(signature)>
//! ```

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use std::collections::HashMap;
use std::fmt;

const ENC_MAGIC: &[u8; 8] = b"SSSENC01";
const ENC_VERSION: u8 = 1;

/// Maximum group name length in bytes.
const MAX_GROUP_LEN: usize = 255;

/// Fixed header fields before group:
/// magic(8) + version(1) + threshold(1) + nonce(24) + pubkey(32) + group_len(1).
const PRE_GROUP_LEN: usize = 67;

/// Ed25519 signature size.
const SIG_LEN: usize = 64;

/// Nonce size (XChaCha20-Poly1305).
const NONCE_LEN: usize = 24;

/// Minimum binary size: pre_group(67) + group_len=0 + signature(64).
const MIN_BIN_SIZE: usize = PRE_GROUP_LEN + SIG_LEN;

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------

/// File header — metadata for decryption.
#[derive(Clone)]
pub struct Header {
    pub version: u8,
    pub threshold: u8,
    pub nonce: [u8; 24],
    pub pubkey: [u8; 32],
    pub group: String,
}

impl Header {
    /// Serialize the header to its binary representation (variable-length).
    ///
    /// # Errors
    ///
    /// Returns an error if the UTF-8 group name is longer than [`MAX_GROUP_LEN`]
    /// bytes, since the on-disk format reserves only a single byte for the
    /// group length.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let group_bytes = self.group.as_bytes();
        let group_len = group_bytes.len();
        if group_len > MAX_GROUP_LEN {
            bail!(
                "encrypted: group name is {} bytes, exceeds maximum of {MAX_GROUP_LEN}",
                group_len
            );
        }
        let total = PRE_GROUP_LEN + group_len;
        let mut buf = Vec::with_capacity(total);

        buf.extend_from_slice(ENC_MAGIC);
        buf.push(self.version);
        buf.push(self.threshold);
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&self.pubkey);
        buf.push(group_len as u8);
        buf.extend_from_slice(&group_bytes[..group_len]);

        Ok(buf)
    }
}

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let pk: String = self.pubkey.iter().map(|b| format!("{b:02x}")).collect();
        if self.group.is_empty() {
            write!(f, "v{} k={} pk={}", self.version, self.threshold, &pk[..16])
        } else {
            write!(
                f,
                "v{} k={} pk={} group={:?}",
                self.version,
                self.threshold,
                &pk[..16],
                self.group
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Encrypted file
// ---------------------------------------------------------------------------

/// In-memory representation of a complete encrypted file.
#[derive(Clone)]
pub struct EncryptedFile {
    pub header: Header,
    pub ciphertext: Vec<u8>,
    pub signature: [u8; 64],
}

impl EncryptedFile {
    /// The bytes covered by the Ed25519 signature: header ‖ ciphertext.
    pub fn signed_bytes(&self) -> Result<Vec<u8>> {
        let hdr = self.header.to_bytes()?;
        let mut out = Vec::with_capacity(hdr.len() + self.ciphertext.len());
        out.extend_from_slice(&hdr);
        out.extend_from_slice(&self.ciphertext);
        Ok(out)
    }

    // -------------------------------------------------------------------
    // Binary format
    // -------------------------------------------------------------------

    /// Serialize to the full binary format (header ‖ ciphertext ‖ signature).
    #[cfg(test)]
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let signed = self.signed_bytes().unwrap();
        let mut out = Vec::with_capacity(signed.len() + SIG_LEN);
        out.extend_from_slice(&signed);
        out.extend_from_slice(&self.signature);
        out
    }

    /// Parse from the binary format.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < MIN_BIN_SIZE {
            bail!(
                "encrypted file too small: {} bytes (need >= {MIN_BIN_SIZE})",
                bytes.len()
            );
        }
        if &bytes[0..8] != ENC_MAGIC {
            bail!("bad magic (expected 'SSSENC01')");
        }

        let version = bytes[8];
        if version != ENC_VERSION {
            bail!("unsupported version {version}");
        }

        let threshold = bytes[9];

        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&bytes[10..34]);

        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(&bytes[34..66]);

        let group_len = bytes[66] as usize;
        let header_end = PRE_GROUP_LEN + group_len;

        if bytes.len() < header_end + SIG_LEN {
            bail!(
                "encrypted file truncated: group_len={group_len}, \
                 need >= {} bytes, got {}",
                header_end + SIG_LEN,
                bytes.len()
            );
        }

        let group = String::from_utf8(bytes[67..67 + group_len].to_vec())
            .context("group is not valid UTF-8")?;

        let ciphertext_end = bytes.len() - SIG_LEN;
        let ciphertext = bytes[header_end..ciphertext_end].to_vec();

        let mut signature = [0u8; 64];
        signature.copy_from_slice(&bytes[ciphertext_end..]);

        Ok(Self {
            header: Header {
                version,
                threshold,
                nonce,
                pubkey,
                group,
            },
            ciphertext,
            signature,
        })
    }

    // -------------------------------------------------------------------
    // Text format
    // -------------------------------------------------------------------

    /// Serialize to the human-readable text file format.
    pub fn to_text(&self) -> String {
        let pk_hex = hex_full(&self.header.pubkey);

        // data = nonce(24) ++ ciphertext
        let mut data_bytes = Vec::with_capacity(NONCE_LEN + self.ciphertext.len());
        data_bytes.extend_from_slice(&self.header.nonce);
        data_bytes.extend_from_slice(&self.ciphertext);
        let data_b64 = B64.encode(&data_bytes);
        let sig_b64 = B64.encode(self.signature);

        let mut out = String::new();
        out.push_str("# ssscrypt encrypted file — DO NOT EDIT\n");
        out.push_str("# Decryption requires threshold secret sharing.\n");
        out.push('\n');
        out.push_str(&format!("version: {}\n", self.header.version));
        out.push_str(&format!("threshold: {}\n", self.header.threshold));
        out.push_str(&format!("group: {}\n", self.header.group));
        out.push_str(&format!("pubkey: {}\n", pk_hex));
        out.push_str(&format!("data: {}\n", data_b64));
        out.push_str(&format!("signature: {}\n", sig_b64));
        out
    }

    /// Parse from the human-readable text file format.
    pub fn from_text(text: &str) -> Result<Self> {
        let fields = parse_kv(text);

        let version: u8 = fields
            .get("version")
            .context("missing 'version' field")?
            .parse()
            .context("invalid version")?;
        if version != ENC_VERSION {
            bail!("unsupported version {version}");
        }

        let threshold: u8 = fields
            .get("threshold")
            .context("missing 'threshold' field")?
            .parse()
            .context("invalid threshold")?;

        let group = fields
            .get("group")
            .map(|s| s.as_str())
            .unwrap_or("")
            .to_string();
        let group_len = group.len();
        if group_len > MAX_GROUP_LEN {
            bail!("encrypted: group name is {group_len} bytes, exceeds maximum of {MAX_GROUP_LEN}");
        }

        let pubkey_hex = fields.get("pubkey").context("missing 'pubkey' field")?;
        let pubkey = parse_hex_32(pubkey_hex).context("invalid pubkey hex")?;

        let data_b64 = fields.get("data").context("missing 'data' field")?;
        let data_bytes = B64.decode(data_b64.trim()).context("invalid data base64")?;

        if data_bytes.len() < NONCE_LEN {
            bail!(
                "data too short: need >= {NONCE_LEN} bytes (nonce), got {}",
                data_bytes.len()
            );
        }
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&data_bytes[..NONCE_LEN]);
        let ciphertext = data_bytes[NONCE_LEN..].to_vec();

        let sig_b64 = fields
            .get("signature")
            .context("missing 'signature' field")?;
        let sig_bytes = B64
            .decode(sig_b64.trim())
            .context("invalid signature base64")?;
        if sig_bytes.len() != SIG_LEN {
            bail!("signature must be {SIG_LEN} bytes, got {}", sig_bytes.len());
        }
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&sig_bytes);

        Ok(Self {
            header: Header {
                version,
                threshold,
                nonce,
                pubkey,
                group,
            },
            ciphertext,
            signature,
        })
    }

    /// Auto-detect format and parse.
    ///
    /// If `data` starts with the binary magic, parse as binary.
    /// Otherwise attempt text format.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() >= 8 && &data[..8] == ENC_MAGIC {
            Self::from_bytes(data)
        } else {
            let text = std::str::from_utf8(data)
                .context("encrypted file is not valid binary or UTF-8 text")?;
            Self::from_text(text)
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers (duplicated from share.rs for module independence)
// ---------------------------------------------------------------------------

fn hex_full(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parse simple `key: value` text format.
fn parse_kv(text: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let mut current_key: Option<String> = None;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = trimmed.split_once(':') {
            let key = key.trim().to_string();
            let value = value.trim().to_string();
            current_key = Some(key.clone());
            map.insert(key, value);
        } else if let Some(ref key) = current_key {
            // Continuation line — append for long base64 values.
            if let Some(existing) = map.get_mut(key) {
                existing.push_str(trimmed);
            }
        }
    }

    map
}

/// Parse a 64-character hex string into a 32-byte array.
fn parse_hex_32(hex: &str) -> Result<[u8; 32]> {
    let hex = hex.trim();
    if hex.len() != 64 {
        bail!("expected 64 hex chars (32 bytes), got {} chars", hex.len());
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .with_context(|| format!("invalid hex at position {}", i * 2))?;
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_header() -> Header {
        Header {
            version: ENC_VERSION,
            threshold: 2,
            nonce: [0x11; 24],
            pubkey: [0x22; 32],
            group: String::new(),
        }
    }

    fn grouped_header() -> Header {
        Header {
            version: ENC_VERSION,
            threshold: 3,
            nonce: [0x33; 24],
            pubkey: [0x44; 32],
            group: "ForssCloud Root CA".to_string(),
        }
    }

    fn dummy_encrypted() -> EncryptedFile {
        EncryptedFile {
            header: dummy_header(),
            ciphertext: vec![0xAA; 48],
            signature: [0xBB; 64],
        }
    }

    fn grouped_encrypted() -> EncryptedFile {
        EncryptedFile {
            header: grouped_header(),
            ciphertext: vec![0xCC; 48],
            signature: [0xDD; 64],
        }
    }

    #[test]
    fn header_bytes_no_group() {
        let hdr = dummy_header();
        let bytes = hdr.to_bytes().unwrap();
        assert_eq!(bytes.len(), PRE_GROUP_LEN);
        assert_eq!(&bytes[..8], ENC_MAGIC);
        assert_eq!(bytes[66], 0); // group_len = 0
    }

    #[test]
    fn header_bytes_with_group() {
        let hdr = grouped_header();
        let bytes = hdr.to_bytes().unwrap();
        let group_name = "ForssCloud Root CA";
        assert_eq!(bytes.len(), PRE_GROUP_LEN + group_name.len());
        assert_eq!(bytes[66], group_name.len() as u8);
    }

    #[test]
    fn header_group_too_long_rejected() {
        let mut hdr = dummy_header();
        hdr.group = "x".repeat(256);
        assert!(hdr.to_bytes().is_err());
    }

    #[test]
    fn binary_roundtrip_no_group() {
        let enc = dummy_encrypted();
        let bytes = enc.to_bytes();
        let parsed = EncryptedFile::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.header.threshold, 2);
        assert_eq!(parsed.header.group, "");
        assert_eq!(parsed.ciphertext, vec![0xAA; 48]);
        assert_eq!(parsed.signature, [0xBB; 64]);
    }

    #[test]
    fn binary_roundtrip_with_group() {
        let enc = grouped_encrypted();
        let bytes = enc.to_bytes();
        let parsed = EncryptedFile::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.header.group, "ForssCloud Root CA");
        assert_eq!(parsed.header.threshold, 3);
        assert_eq!(parsed.ciphertext, vec![0xCC; 48]);
    }

    #[test]
    fn text_roundtrip_no_group() {
        let enc = dummy_encrypted();
        let text = enc.to_text();
        assert!(text.contains("DO NOT EDIT"));
        assert!(text.contains("version: 1"));
        assert!(text.contains("threshold: 2"));
        let parsed = EncryptedFile::from_text(&text).unwrap();
        assert_eq!(parsed.header.nonce, enc.header.nonce);
        assert_eq!(parsed.ciphertext, enc.ciphertext);
        assert_eq!(parsed.signature, enc.signature);
    }

    #[test]
    fn text_roundtrip_with_group() {
        let enc = grouped_encrypted();
        let text = enc.to_text();
        assert!(text.contains("group: ForssCloud Root CA"));
        let parsed = EncryptedFile::from_text(&text).unwrap();
        assert_eq!(parsed.header.group, "ForssCloud Root CA");
        assert_eq!(parsed.header.threshold, 3);
    }

    #[test]
    fn parse_auto_detect_binary() {
        let enc = grouped_encrypted();
        let bytes = enc.to_bytes();
        let parsed = EncryptedFile::parse(&bytes).unwrap();
        assert_eq!(parsed.header.group, "ForssCloud Root CA");
    }

    #[test]
    fn parse_auto_detect_text() {
        let enc = grouped_encrypted();
        let text = enc.to_text();
        let parsed = EncryptedFile::parse(text.as_bytes()).unwrap();
        assert_eq!(parsed.header.group, "ForssCloud Root CA");
    }

    #[test]
    fn signed_bytes_covers_header_and_ciphertext() {
        let enc = grouped_encrypted();
        let signed = enc.signed_bytes().unwrap();
        let full = enc.to_bytes();
        assert_eq!(signed.len(), full.len() - SIG_LEN);
        assert_eq!(&signed[..], &full[..full.len() - SIG_LEN]);
    }

    #[test]
    fn bad_magic_rejected() {
        let mut bytes = dummy_encrypted().to_bytes();
        bytes[0] = b'X';
        assert!(EncryptedFile::from_bytes(&bytes).is_err());
    }

    #[test]
    fn truncated_file_rejected() {
        assert!(EncryptedFile::from_bytes(&[0u8; 10]).is_err());
    }

    #[test]
    fn display_header() {
        let hdr = grouped_header();
        let s = format!("{hdr}");
        assert!(s.contains("ForssCloud Root CA"));
        assert!(s.contains("k=3"));
    }

    #[test]
    fn display_header_no_group() {
        let hdr = dummy_header();
        let s = format!("{hdr}");
        assert!(s.contains("k=2"));
        assert!(!s.contains("group="));
    }
}
