//! Share file format: serialization, deserialization, and display.
//!
//! ## Binary layout (variable, 137+ bytes)
//!
//! Used for QR encoding and constructing signed messages:
//!
//! | Field        | Offset    | Size     | Description                          |
//! |--------------|-----------|----------|--------------------------------------|
//! | magic        | 0         | 2        | `SS`                                 |
//! | version      | 2         | 1        | share format version (1)             |
//! | threshold    | 3         | 1        | K — shares required to reconstruct   |
//! | x            | 4         | 4        | share evaluation point (big-endian)  |
//! | y            | 8         | 32       | share data (GF(2^32) evaluation)     |
//! | pubkey       | 40        | 32       | Ed25519 public key                   |
//! | group_len    | 72        | 1        | length of UTF-8 group name (0–255)   |
//! | group        | 73        | 0–255    | human-readable name (e.g. cert name) |
//! | signature    | 73+N      | 64       | Ed25519 over bytes 0..73+N           |
//!
//! The group is included in the signed region — it cannot be modified
//! without invalidating the signature.
//!
//! ## Text file format (`.share.txt`)
//!
//! ```text
//! # ssscrypt share — DO NOT EDIT
//! # Modifying this file will invalidate the cryptographic signature.
//!
//! version: 1
//! threshold: 2
//! group: ForssCloud Root CA
//! pubkey: abcdef0123456789...
//! data: <base64(x ++ y)>
//! signature: <base64(signature)>
//! ```

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use std::collections::HashMap;
use std::fmt;
use std::path::Path;
use zeroize::Zeroize;

const SHARE_MAGIC: &[u8; 2] = b"SS";
pub const SHARE_VERSION: u8 = 1;

/// Minimum binary share size: pre_group(73) + group_len=0 + signature(64).
const SHARE_MIN_SIZE: usize = 137;

/// Maximum group name length in bytes.
const MAX_GROUP_LEN: usize = 255;

/// Fixed fields before the group: magic(2)+ver(1)+threshold(1)+x(4)+y(32)+pubkey(32)+group_len(1).
const PRE_GROUP_LEN: usize = 73;

/// Ed25519 signature size.
const SIG_LEN: usize = 64;

/// Share data size in bytes: x(4) + y(32).
const DATA_LEN: usize = 36;

/// On-disk / in-memory representation of a single share.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Share {
    pub version: u8,
    pub threshold: u8,
    pub x: u32,
    pub y: [u8; 32],
    pub pubkey: [u8; 32],
    pub group: String,
    pub signature: [u8; 64],
}

impl Share {
    /// Serialize to the variable-length binary format (for QR codes).
    ///
    /// # Errors
    ///
    /// Returns an error if the group name exceeds [`MAX_GROUP_LEN`] bytes,
    /// since the on-disk format reserves only a single byte for the group
    /// length field.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let group_bytes = self.group.as_bytes();
        let group_len = group_bytes.len();
        if group_len > MAX_GROUP_LEN {
            bail!(
                "share: group name is {} bytes, exceeds maximum of {MAX_GROUP_LEN}",
                group_len
            );
        }
        let total = PRE_GROUP_LEN + group_len + SIG_LEN;
        let mut buf = Vec::with_capacity(total);

        buf.extend_from_slice(SHARE_MAGIC);
        buf.push(self.version);
        buf.push(self.threshold);
        buf.extend_from_slice(&self.x.to_be_bytes());
        buf.extend_from_slice(&self.y);
        buf.extend_from_slice(&self.pubkey);
        buf.push(group_len as u8);
        buf.extend_from_slice(&group_bytes[..group_len]);
        buf.extend_from_slice(&self.signature);

        Ok(buf)
    }

    /// The bytes covered by the Ed25519 signature (everything before signature).
    pub fn signed_bytes(&self) -> Result<Vec<u8>> {
        let full = self.to_bytes()?;
        Ok(full[..full.len() - SIG_LEN].to_vec())
    }

    /// Parse from the variable-length binary format.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < SHARE_MIN_SIZE {
            bail!(
                "share: expected at least {} bytes, got {}",
                SHARE_MIN_SIZE,
                bytes.len()
            );
        }
        if &bytes[0..2] != SHARE_MAGIC {
            bail!("share: bad magic (expected 'SS')");
        }
        let version = bytes[2];
        if version != SHARE_VERSION {
            bail!("share: unsupported version {version}");
        }

        let threshold = bytes[3];
        let x = u32::from_be_bytes(bytes[4..8].try_into().unwrap());

        let mut y = [0u8; 32];
        y.copy_from_slice(&bytes[8..40]);

        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(&bytes[40..72]);

        let group_len = bytes[72] as usize;
        let expected_size = PRE_GROUP_LEN + group_len + SIG_LEN;
        if bytes.len() < expected_size {
            bail!(
                "share: group_len={group_len} but only {} bytes (need {expected_size})",
                bytes.len()
            );
        }

        let group = String::from_utf8(bytes[73..73 + group_len].to_vec())
            .context("share: group is not valid UTF-8")?;

        let sig_start = 73 + group_len;
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&bytes[sig_start..sig_start + SIG_LEN]);

        Ok(Self {
            version,
            threshold,
            x,
            y,
            pubkey,
            group,
            signature,
        })
    }

    /// Encode full binary to base64.
    #[cfg(test)]
    fn to_base64(&self) -> String {
        B64.encode(self.to_bytes().unwrap())
    }

    /// Decode from full binary base64.
    #[cfg(test)]
    fn from_base64(s: &str) -> Result<Self> {
        let bytes = B64.decode(s.trim()).context("share: invalid base64")?;
        Self::from_bytes(&bytes)
    }

    // -----------------------------------------------------------------------
    // Text format
    // -----------------------------------------------------------------------

    /// Serialize to the human-readable text file format.
    pub fn to_text(&self) -> String {
        let pk_hex = hex_full(&self.pubkey);

        let mut data_bytes = Vec::with_capacity(DATA_LEN);
        data_bytes.extend_from_slice(&self.x.to_be_bytes());
        data_bytes.extend_from_slice(&self.y);
        let data_b64 = B64.encode(&data_bytes);
        let sig_b64 = B64.encode(self.signature);

        let mut out = String::new();
        out.push_str("# ssscrypt share — DO NOT EDIT\n");
        out.push_str("# Modifying this file will invalidate the cryptographic signature.\n");
        out.push('\n');
        out.push_str(&format!("version: {}\n", self.version));
        out.push_str(&format!("threshold: {}\n", self.threshold));
        out.push_str(&format!("group: {}\n", self.group));
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
            .context("share: missing 'version' field")?
            .parse()
            .context("share: invalid version")?;
        if version != SHARE_VERSION {
            bail!("share: unsupported version {version}");
        }

        let threshold: u8 = fields
            .get("threshold")
            .context("share: missing 'threshold' field")?
            .parse()
            .context("share: invalid threshold")?;

        let group = fields
            .get("group")
            .map(|s| s.as_str())
            .unwrap_or("")
            .to_string();
        let group_len = group.as_bytes().len();
        if group_len > MAX_GROUP_LEN {
            bail!(
                "share: group name is {group_len} bytes, exceeds maximum of {MAX_GROUP_LEN}"
            );
        }

        let pubkey_hex = fields
            .get("pubkey")
            .context("share: missing 'pubkey' field")?;
        let pubkey = parse_hex_32(pubkey_hex).context("share: invalid pubkey hex")?;

        let data_b64 = fields
            .get("data")
            .context("share: missing 'data' field")?;
        let data_bytes = B64
            .decode(data_b64.trim())
            .context("share: invalid data base64")?;
        if data_bytes.len() != DATA_LEN {
            bail!(
                "share: data must be {} bytes, got {}",
                DATA_LEN,
                data_bytes.len()
            );
        }
        let x = u32::from_be_bytes(data_bytes[0..4].try_into().unwrap());
        let mut y = [0u8; 32];
        y.copy_from_slice(&data_bytes[4..36]);

        let sig_b64 = fields
            .get("signature")
            .context("share: missing 'signature' field")?;
        let sig_bytes = B64
            .decode(sig_b64.trim())
            .context("share: invalid signature base64")?;
        if sig_bytes.len() != SIG_LEN {
            bail!(
                "share: signature must be {} bytes, got {}",
                SIG_LEN,
                sig_bytes.len()
            );
        }
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&sig_bytes);

        Ok(Self {
            version,
            threshold,
            x,
            y,
            pubkey,
            group,
            signature,
        })
    }

    /// Read from a `.share.txt` file.
    pub fn from_file(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read share file {:?}", path))?;
        Self::from_text(&text)
            .with_context(|| format!("parse share file {:?}", path))
    }

    /// Write to a `.share.txt` file.
    pub fn to_file(&self, path: &Path) -> Result<()> {
        std::fs::write(path, self.to_text())
            .with_context(|| format!("write share file {:?}", path))
    }

    /// Generate the filename for this share.
    ///
    /// If a group is set: `{group}-v{ver}-k{k}-x{x}.share.txt`
    /// Otherwise: `v{ver}-k{k}-x{x}.share.txt`
    pub fn filename(&self) -> String {
        if self.group.is_empty() {
            format!(
                "v{}-k{}-x{}.share.txt",
                self.version, self.threshold, self.x
            )
        } else {
            let safe: String = self
                .group
                .chars()
                .map(|c| {
                    if c.is_alphanumeric() || c == '-' || c == '_' {
                        c
                    } else {
                        '_'
                    }
                })
                .collect();
            let safe = &safe[..safe.len().min(60)];
            format!(
                "{}-v{}-k{}-x{}.share.txt",
                safe, self.version, self.threshold, self.x
            )
        }
    }
}

impl fmt::Debug for Share {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("Share");
        s.field("version", &self.version)
            .field("threshold", &self.threshold)
            .field("x", &self.x)
            .field("y", &hex_short(&self.y))
            .field("pubkey", &hex_short(&self.pubkey));
        if !self.group.is_empty() {
            s.field("group", &self.group);
        }
        s.finish()
    }
}

impl fmt::Display for Share {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.group.is_empty() {
            write!(
                f,
                "share x={} (k={}) pubkey={}",
                self.x,
                self.threshold,
                hex_short(&self.pubkey),
            )
        } else {
            write!(
                f,
                "share x={} (k={}) pubkey={} group={:?}",
                self.x,
                self.threshold,
                hex_short(&self.pubkey),
                self.group,
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hex_short(bytes: &[u8]) -> String {
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    if hex.len() > 16 {
        format!("{}…", &hex[..16])
    } else {
        hex
    }
}

fn hex_full(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parse simple `key: value` text format.
///
/// Skips comment lines (`#`) and empty lines.
/// For multi-line values (data, signature), continuation lines without
/// a colon are appended to the previous field.
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
            // Continuation line — append to current field (for long base64).
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
        bail!(
            "expected 64 hex chars (32 bytes), got {} chars",
            hex.len()
        );
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

    fn dummy_share() -> Share {
        Share {
            version: SHARE_VERSION,
            threshold: 3,
            x: 1,
            y: [0xaa; 32],
            pubkey: [0xbb; 32],
            group: String::new(),
            signature: [0xcc; 64],
        }
    }

    fn grouped_share() -> Share {
        Share {
            version: SHARE_VERSION,
            threshold: 2,
            x: 3,
            y: [0xab; 32],
            pubkey: [0xcd; 32],
            group: "ForssCloud Root CA".to_string(),
            signature: [0xef; 64],
        }
    }

    #[test]
    fn roundtrip_bytes_no_group() {
        let share = dummy_share();
        let bytes = share.to_bytes().unwrap();
        assert_eq!(bytes.len(), SHARE_MIN_SIZE);

        let parsed = Share::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.version, share.version);
        assert_eq!(parsed.threshold, share.threshold);
        assert_eq!(parsed.x, share.x);
        assert_eq!(parsed.y, share.y);
        assert_eq!(parsed.pubkey, share.pubkey);
        assert_eq!(parsed.group, "");
        assert_eq!(parsed.signature, share.signature);
    }

    #[test]
    fn roundtrip_bytes_with_group() {
        let share = grouped_share();
        let bytes = share.to_bytes().unwrap();
        assert_eq!(bytes.len(), SHARE_MIN_SIZE + share.group.len());

        let parsed = Share::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.group, "ForssCloud Root CA");
        assert_eq!(parsed.x, share.x);
        assert_eq!(parsed.threshold, share.threshold);
        assert_eq!(parsed.pubkey, share.pubkey);
    }

    #[test]
    fn roundtrip_base64() {
        let share = grouped_share();
        let b64 = share.to_base64();
        let parsed = Share::from_base64(&b64).unwrap();
        assert_eq!(parsed.to_bytes().unwrap(), share.to_bytes().unwrap());
    }

    #[test]
    fn roundtrip_text_format() {
        let share = grouped_share();
        let text = share.to_text();

        // Verify human-readable fields.
        assert!(text.contains("DO NOT EDIT"));
        assert!(text.contains("group: ForssCloud Root CA"));
        assert!(text.contains("threshold: 2"));
        assert!(text.contains("version: 1"));
        assert!(text.contains("pubkey:"));
        assert!(text.contains("data:"));
        assert!(text.contains("signature:"));

        let parsed = Share::from_text(&text).unwrap();
        assert_eq!(parsed.group, "ForssCloud Root CA");
        assert_eq!(parsed.x, 3);
        assert_eq!(parsed.threshold, 2);
        assert_eq!(parsed.to_bytes().unwrap(), share.to_bytes().unwrap());
    }

    #[test]
    fn text_format_no_group() {
        let share = dummy_share();
        let text = share.to_text();
        assert!(text.contains("group:"));
        let parsed = Share::from_text(&text).unwrap();
        assert_eq!(parsed.group, "");
    }

    #[test]
    fn bad_magic_rejected() {
        let mut bytes = dummy_share().to_bytes().unwrap();
        bytes[0] = b'X';
        assert!(Share::from_bytes(&bytes).is_err());
    }

    #[test]
    fn bad_length_rejected() {
        assert!(Share::from_bytes(&[0u8; 10]).is_err());
    }

    #[test]
    fn truncated_group_rejected() {
        let mut bytes = grouped_share().to_bytes().unwrap();
        bytes.truncate(75);
        assert!(Share::from_bytes(&bytes).is_err());
    }

    #[test]
    fn group_too_long_rejected() {
        let mut share = dummy_share();
        share.group = "x".repeat(256);
        assert!(share.to_bytes().is_err());
        assert!(share.signed_bytes().is_err());
    }

    #[test]
    fn filename_no_group() {
        let share = dummy_share();
        assert_eq!(share.filename(), "v1-k3-x1.share.txt");
    }

    #[test]
    fn filename_with_group() {
        let share = grouped_share();
        let name = share.filename();
        assert!(name.starts_with("ForssCloud_Root_CA-v1"));
        assert!(name.ends_with(".share.txt"));
    }

    #[test]
    fn display_format() {
        let share = dummy_share();
        let s = format!("{share}");
        assert!(s.contains("x=1"));
        assert!(s.contains("k=3"));
    }

    #[test]
    fn display_with_group() {
        let share = grouped_share();
        let s = format!("{share}");
        assert!(s.contains("ForssCloud Root CA"));
    }

    #[test]
    fn max_group_length() {
        let mut share = dummy_share();
        // Exactly at the limit — should succeed.
        share.group = "A".repeat(MAX_GROUP_LEN);
        assert!(share.to_bytes().is_ok());
        // One byte over — should fail.
        share.group = "A".repeat(MAX_GROUP_LEN + 1);
        assert!(share.to_bytes().is_err());
    }

    #[test]
    fn signed_bytes_excludes_signature() {
        let share = grouped_share();
        let full = share.to_bytes().unwrap();
        let signed = share.signed_bytes().unwrap();
        assert_eq!(signed.len(), full.len() - SIG_LEN);
        assert_eq!(&signed[..], &full[..full.len() - SIG_LEN]);
    }

    #[test]
    fn text_parser_handles_continuation_lines() {
        let share = dummy_share();
        let text = share.to_text();
        // Simulate wrapped data and signature lines by moving their values
        // onto indented continuation lines.
        let text = text.replace("data: ", "data: \n    ");
        let text = text.replace("signature: ", "signature: \n    ");
        let parsed = Share::from_text(&text).unwrap();
        assert_eq!(parsed.x, share.x);
    }

    #[test]
    fn text_parser_ignores_comments() {
        let share = dummy_share();
        let mut text = share.to_text();
        text.insert_str(0, "# extra comment\n\n");
        text.push_str("# trailing comment\n");
        let parsed = Share::from_text(&text).unwrap();
        assert_eq!(parsed.x, share.x);
    }
}
