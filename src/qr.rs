//! QR share-card renderer.
//!
//! Produces a printable image (JPEG or PNG) containing:
//!
//! 1. **Label** — human-readable group name at the top (from the share)
//! 2. **QR code** — self-describing URI encoding the full binary share
//! 3. **Mnemonic words** — 30 case-encoded tokens as a manual-entry fallback
//!
//! The output is a pre-rendered raster image — pure pixel data with no
//! embedded text objects, metadata, or indexable strings.  Unlike PDF or
//! PostScript, an image cannot be scraped from filesystem caches without
//! OCR, which is a dramatically higher bar for an attacker.
//!
//! ## QR payload format
//!
//! The QR code encodes a self-describing URI string:
//!
//! ```text
//! ssscrypt:share:v1:<base64url(binary_share)>:<crc32_hex>
//! ```
//!
//! - `binary_share`: the full binary-serialized share (see [`Share::to_bytes`])
//! - `crc32_hex`: CRC-32/ISO-HDLC of the raw binary bytes, 8 hex digits
//!
//! The URI prefix makes the payload identifiable by any QR reader, and the
//! CRC guards against scan corruption (the Ed25519 signature also provides
//! integrity, but the CRC gives an immediate error before attempting parse).

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use font8x8::UnicodeFonts;
use image::codecs::jpeg::JpegEncoder;
use image::{GrayImage, ImageEncoder, Luma};
use qrcode::{EcLevel, QrCode};
#[cfg(test)]
use rqrr::PreparedImage;
use std::io::BufWriter;
use std::path::Path;

use crate::share::Share;

// ---------------------------------------------------------------------------
// Layout constants (pixels, targeting 300 DPI print)
// ---------------------------------------------------------------------------

/// Minimum card width in pixels (~3.3″ at 300 DPI).
const CARD_MIN_WIDTH: u32 = 1000;

/// Outer margin.
const MARGIN: u32 = 40;

/// Pixels per QR module.
const QR_MODULE_PX: u32 = 10;

/// QR quiet zone in modules (spec requires ≥ 4).
const QR_QUIET_MODULES: u32 = 4;

/// Font scale for the title/label line (8px base × scale).
const SCALE_TITLE: u32 = 4; // → 32px

/// Font scale for share metadata lines.
const SCALE_INFO: u32 = 3; // → 24px

/// Font scale for mnemonic word grid and notes.
const SCALE_WORDS: u32 = 3; // → 24px

/// Vertical gap between elements.
const GAP: u32 = 12;

/// Horizontal rule thickness.
const HR_THICK: u32 = 2;

/// JPEG output quality (0–100).
const JPEG_QUALITY: u8 = 95;

/// Border thickness around the card.
const BORDER: u32 = 3;

// ---------------------------------------------------------------------------
// Font rendering (font8x8 — CC0 8×8 bitmap glyphs)
// ---------------------------------------------------------------------------

/// Draw a single character at `(x, y)` with the given pixel scale.
///
/// font8x8 convention: each glyph is `[u8; 8]`, one byte per row,
/// bit 0 (LSB) = leftmost pixel.
fn draw_char(img: &mut GrayImage, x: u32, y: u32, ch: char, scale: u32) {
    let glyph = font8x8::BASIC_FONTS.get(ch).unwrap_or([0u8; 8]);
    for (row, &bits) in glyph.iter().enumerate() {
        for col in 0u32..8 {
            if bits & (1 << col) != 0 {
                for sy in 0..scale {
                    for sx in 0..scale {
                        let px = x + col * scale + sx;
                        let py = y + row as u32 * scale + sy;
                        if px < img.width() && py < img.height() {
                            img.put_pixel(px, py, Luma([0u8]));
                        }
                    }
                }
            }
        }
    }
}

/// Draw a string of text at `(x, y)`.  Returns rendered width in pixels.
fn draw_text(img: &mut GrayImage, x: u32, y: u32, text: &str, scale: u32) -> u32 {
    let cw = 8 * scale;
    for (i, ch) in text.chars().enumerate() {
        draw_char(img, x + i as u32 * cw, y, ch, scale);
    }
    text.len() as u32 * cw
}

/// Pixel width of `text` at `scale`.
fn text_w(text: &str, scale: u32) -> u32 {
    text.len() as u32 * 8 * scale
}

/// Pixel height of one text line at `scale`.
const fn text_h(scale: u32) -> u32 {
    8 * scale
}

// ---------------------------------------------------------------------------
// Drawing primitives
// ---------------------------------------------------------------------------

/// Filled horizontal rule.
fn draw_hr(img: &mut GrayImage, x: u32, y: u32, width: u32) {
    for dy in 0..HR_THICK {
        for dx in 0..width {
            let px = x + dx;
            let py = y + dy;
            if px < img.width() && py < img.height() {
                img.put_pixel(px, py, Luma([0u8]));
            }
        }
    }
}

/// Draw a rectangular border (outline only).
fn draw_rect(img: &mut GrayImage, x: u32, y: u32, w: u32, h: u32, thick: u32) {
    for t in 0..thick {
        for dx in 0..w {
            // Top
            if y + t < img.height() {
                img.put_pixel(x + dx, y + t, Luma([0u8]));
            }
            // Bottom
            if y + h > t && y + h - 1 - t < img.height() {
                img.put_pixel(x + dx, y + h - 1 - t, Luma([0u8]));
            }
        }
        for dy in 0..h {
            // Left
            if x + t < img.width() {
                img.put_pixel(x + t, y + dy, Luma([0u8]));
            }
            // Right
            if x + w > t && x + w - 1 - t < img.width() {
                img.put_pixel(x + w - 1 - t, y + dy, Luma([0u8]));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// QR payload
// ---------------------------------------------------------------------------

/// QR payload URI prefix.
const QR_URI_PREFIX: &str = "ssscrypt:share:v1:";

/// Build the QR payload as a self-describing URI string.
///
/// Format: `ssscrypt:share:v1:<base64url(binary_share)>:<crc32_hex>`
///
/// # Errors
///
/// Returns an error if serializing the share via [`Share::to_bytes`] fails,
/// for example if the share contains an oversized group name.
pub fn qr_payload(share: &Share) -> Result<Vec<u8>> {
    let binary = share.to_bytes()?;
    let crc = crc32(&binary);
    let b64 = B64URL.encode(&binary);
    let uri = format!("{}{b64}:{crc:08x}", QR_URI_PREFIX);
    Ok(uri.into_bytes())
}

/// Parse a QR payload back into a `Share`.
///
/// Accepts both the new URI format (`ssscrypt:share:v1:...`) and the legacy
/// raw binary format for backwards compatibility.
pub fn parse_qr_payload(data: &[u8]) -> Result<Share> {
    // Try URI format first.
    if let Ok(text) = std::str::from_utf8(data) {
        if let Some(rest) = text.strip_prefix(QR_URI_PREFIX) {
            // Split off CRC suffix.
            let (b64_part, crc_hex) = rest.rsplit_once(':')
                .context("QR URI missing CRC32 suffix")?;
            let binary = B64URL.decode(b64_part)
                .context("QR URI: invalid base64url")?;

            // Verify CRC.
            let expected_crc = u32::from_str_radix(crc_hex, 16)
                .context("QR URI: invalid CRC32 hex")?;
            let actual_crc = crc32(&binary);
            if expected_crc != actual_crc {
                bail!(
                    "QR CRC mismatch (expected {:08x}, got {:08x}) — scan error?",
                    expected_crc,
                    actual_crc
                );
            }

            return Share::from_bytes(&binary)
                .context("failed to parse share from QR URI payload");
        }
    }

    // Fall back to legacy raw binary format.
    Share::from_bytes(data).context("failed to parse QR share payload")
}

/// CRC-32/ISO-HDLC (same as zlib/PNG/gzip).
///
/// Polynomial: 0xEDB88320 (reflected representation).
fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

// ---------------------------------------------------------------------------
// QR rendering
// ---------------------------------------------------------------------------

/// Draw a QR matrix onto the image at `(x, y)`.
fn draw_qr(img: &mut GrayImage, x: u32, y: u32, qr: &QrCode) {
    let w = qr.width();
    let colors = qr.to_colors();
    for qy in 0..w {
        for qx in 0..w {
            let dark = colors[qy * w + qx] == qrcode::Color::Dark;
            let shade = if dark { 0u8 } else { 255u8 };
            for py in 0..QR_MODULE_PX {
                for px in 0..QR_MODULE_PX {
                    let ix = x + qx as u32 * QR_MODULE_PX + px;
                    let iy = y + qy as u32 * QR_MODULE_PX + py;
                    if ix < img.width() && iy < img.height() {
                        img.put_pixel(ix, iy, Luma([shade]));
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Card renderer
// ---------------------------------------------------------------------------

/// Render a complete share card as a grayscale image.
///
/// Layout (top to bottom):
///
/// ```text
/// ┌──────────────────────────────────┐
/// │  ForssCloud Root CA              │  ← label
/// ├──────────────────────────────────┤
/// │  Share x=00000003  k=2   v1     │  ← metadata
/// │  pk: abcdef01234567...          │
/// │  fpr: a1b2:c3d4:e5f6:7890       │  ← fingerprints
/// ├──────────────────────────────────┤
/// │         ██ ██ █ ██              │
/// │         █ ███ ██ █              │  ← QR code
/// │         ...                     │
/// ├──────────────────────────────────┤
/// │  1. abandon   2. ABSORB         │
/// │  3. abstract  4. ABSURD         │  ← mnemonic words
/// │  ...                            │
/// │  UPPER = 1    lower = 0         │
/// └──────────────────────────────────┘
/// ```
pub fn render_card(share: &Share, mnemonic_words: &[String]) -> Result<GrayImage> {
    let label = &share.group;
    // ── Generate QR matrix ──────────────────────────────────────
    let payload = qr_payload(share)?;
    let qr = QrCode::with_error_correction_level(&payload, EcLevel::M)
        .context("failed to generate QR code (label may be too long)")?;
    let qr_side = qr.width() as u32 * QR_MODULE_PX;
    let quiet = QR_QUIET_MODULES * QR_MODULE_PX;
    let qr_block = qr_side + quiet * 2;

    // ── Word grid dimensions ────────────────────────────────────
    let word_cols: u32 = 4;
    let word_rows = (mnemonic_words.len() as u32 + word_cols - 1) / word_cols;
    let longest = mnemonic_words.iter().map(|w| w.len()).max().unwrap_or(8);
    // "28. ABSTRACT " = index(4) + word(longest)
    let word_cell_w = text_w(
        &format!("{:>2}. {:width$} ", 28, "", width = longest),
        SCALE_WORDS,
    );
    let words_block_w = word_cell_w * word_cols;
    let words_block_h = word_rows * (text_h(SCALE_WORDS) + GAP / 2);

    // ── Card dimensions ─────────────────────────────────────────
    let inner_margin = MARGIN + BORDER;
    let content_w = CARD_MIN_WIDTH
        .max(qr_block + inner_margin * 2)
        .max(words_block_w + inner_margin * 2);

    let inner_w = content_w - inner_margin * 2;

    // Vertical layout pass — compute positions top to bottom
    let mut y = inner_margin;

    let title_y = y;
    y += text_h(SCALE_TITLE) + GAP;

    let hr1_y = y;
    y += HR_THICK + GAP;

    let info1_y = y;
    y += text_h(SCALE_INFO) + GAP / 2;

    let info2_y = y;
    y += text_h(SCALE_INFO) + GAP / 2;

    let info3_y = y;
    y += text_h(SCALE_INFO) + GAP;

    let hr2_y = y;
    y += HR_THICK + GAP;

    let qr_y = y;
    y += qr_block + GAP;

    let hr3_y = y;
    y += HR_THICK + GAP;

    let words_y = y;
    y += words_block_h + inner_margin;

    let card_h = y;

    // ── Allocate white canvas ───────────────────────────────────
    let mut img = GrayImage::from_pixel(content_w, card_h, Luma([255u8]));

    // ── Border ──────────────────────────────────────────────────
    draw_rect(&mut img, 0, 0, content_w, card_h, BORDER);

    // ── Title ───────────────────────────────────────────────────
    let max_chars = (inner_w / (8 * SCALE_TITLE)) as usize;
    let title: String = label.chars().take(max_chars).collect();
    draw_text(&mut img, inner_margin, title_y, &title, SCALE_TITLE);

    // ── HR 1 ────────────────────────────────────────────────────
    draw_hr(&mut img, inner_margin, hr1_y, inner_w);

    // ── Share metadata ──────────────────────────────────────────
    let line1 = format!(
        "Share x={:08x}   k={}   v{}",
        share.x, share.threshold, share.version
    );
    draw_text(&mut img, inner_margin, info1_y, &line1, SCALE_INFO);

    let pk_hex: String = share.pubkey.iter().map(|b| format!("{:02x}", b)).collect();
    let fpr = crate::crypto::pubkey_fingerprint(&share.pubkey);
    let fpr_str = crate::crypto::format_fingerprint(&fpr);
    let share_fpr = share.share_fingerprint_hex();
    let pk_max = ((inner_w / (8 * SCALE_INFO)) as usize).saturating_sub(4);
    let pk_display = &pk_hex[..pk_hex.len().min(pk_max)];
    let line2 = format!("pk: {}", pk_display);
    draw_text(&mut img, inner_margin, info2_y, &line2, SCALE_INFO);

    // Extra info line: key fingerprint and share fingerprint.
    let line3 = format!("fpr: {}  share: {}", fpr_str, share_fpr);
    draw_text(&mut img, inner_margin, info3_y, &line3, SCALE_INFO);

    // ── HR 2 ────────────────────────────────────────────────────
    draw_hr(&mut img, inner_margin, hr2_y, inner_w);

    // ── QR code (centred) ───────────────────────────────────────
    let qr_x = (content_w - qr_block) / 2 + quiet;
    draw_qr(&mut img, qr_x, qr_y + quiet, &qr);

    // ── HR 3 ────────────────────────────────────────────────────
    draw_hr(&mut img, inner_margin, hr3_y, inner_w);

    // ── Mnemonic word grid (4 columns) ──────────────────────────
    for (i, word) in mnemonic_words.iter().enumerate() {
        let col = (i as u32) % word_cols;
        let row = (i as u32) / word_cols;
        let wx = inner_margin + col * word_cell_w;
        let wy = words_y + row * (text_h(SCALE_WORDS) + GAP / 2);
        let numbered = format!("{:>2}. {}", i + 1, word);
        draw_text(&mut img, wx, wy, &numbered, SCALE_WORDS);
    }

    Ok(img)
}

// ---------------------------------------------------------------------------
// File output
// ---------------------------------------------------------------------------

/// Render and save a share card to a file.
///
/// The image format is inferred from the file extension:
/// - `.jpg` / `.jpeg` — JPEG at 95% quality (recommended for printing)
/// - `.png` — lossless PNG (larger file, safest for QR scanning)
/// - anything else — defaults to PNG
pub fn save_card(share: &Share, mnemonic_words: &[String], path: &Path) -> Result<()> {
    let img = render_card(share, mnemonic_words)?;

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase());

    match ext.as_deref() {
        Some("jpg" | "jpeg") => {
            let file = BufWriter::new(
                std::fs::File::create(path)
                    .with_context(|| format!("cannot create {}", path.display()))?,
            );
            JpegEncoder::new_with_quality(file, JPEG_QUALITY)
                .write_image(
                    img.as_raw(),
                    img.width(),
                    img.height(),
                    image::ExtendedColorType::L8,
                )
                .with_context(|| format!("JPEG encode failed: {}", path.display()))?;
        }
        _ => {
            img.save(path)
                .with_context(|| format!("failed to write {}", path.display()))?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// QR scanning
// ---------------------------------------------------------------------------

/// Scan a single image file and extract the first QR code as a `Share`.
///
/// Supports any image format that the `image` crate can decode (PNG, JPEG,
/// GIF, BMP, etc.).  The image is converted to grayscale before scanning.
#[cfg(test)]
fn scan_card(path: &Path) -> Result<Share> {
    let img = image::open(path)
        .with_context(|| format!("cannot open image {}", path.display()))?
        .into_luma8();

    scan_image(&img).with_context(|| format!("no valid QR share found in {}", path.display()))
}

/// Scan a grayscale image buffer and extract the first QR code as a `Share`.
#[cfg(test)]
fn scan_image(img: &GrayImage) -> Result<Share> {
    let mut prepared = PreparedImage::prepare(img.clone());
    let grids = prepared.detect_grids();

    if grids.is_empty() {
        anyhow::bail!("no QR code detected in image");
    }

    // Try each detected grid until we find a valid share.
    let mut last_err = None;
    for grid in &grids {
        let mut data = Vec::new();
        match grid.decode_to(&mut data) {
            Ok(_meta) => match parse_qr_payload(&data) {
                Ok(share) => return Ok(share),
                Err(e) => last_err = Some(e),
            },
            Err(e) => last_err = Some(anyhow::anyhow!("QR decode error: {e:?}")),
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no valid share in QR codes")))
}

/// Scan multiple image files and return all successfully decoded shares.
///
/// Returns `(shares, errors)` — shares that decoded successfully and a list
/// of `(path, error)` pairs for images that failed.
#[cfg(test)]
fn scan_all_cards(paths: &[&Path]) -> (Vec<Share>, Vec<(std::path::PathBuf, anyhow::Error)>) {
    let mut shares = Vec::new();
    let mut errors = Vec::new();

    for &path in paths {
        match scan_card(path) {
            Ok(share) => shares.push(share),
            Err(e) => errors.push((path.to_path_buf(), e)),
        }
    }

    (shares, errors)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_share() -> Share {
        Share {
            version: 1,
            threshold: 2,
            x: 3,
            y: [0xab; 32],
            pubkey: [0xcd; 32],
            group: "ForssCloud Root CA".to_string(),
            signature: [0xef; 64],
        }
    }

    fn test_words() -> Vec<String> {
        // 28 dummy words matching mnemonic format (mixed case)
        let raw = [
            "abandon", "ABSORB", "abstract", "ABSURD", "accident", "ACCOUNT", "accuse", "ACHIEVE",
            "acoustic", "ACQUIRE", "actress", "ADVICE", "aerobic", "AFFORD", "afraid", "AIRPORT",
            "album", "ALCOHOL", "almost", "ALTER", "amazing", "AMONG", "amount", "AMUSED",
            "anchor", "ANCIENT", "anger", "ANNOUNCE",
        ];
        raw.iter().map(|s| s.to_string()).collect()
    }

    // -- QR payload --

    #[test]
    fn qr_payload_roundtrip() {
        let share = test_share();
        let payload = qr_payload(&share).unwrap();
        let parsed = parse_qr_payload(&payload).unwrap();
        assert_eq!(parsed.x, share.x);
        assert_eq!(parsed.y, share.y);
        assert_eq!(parsed.pubkey, share.pubkey);
        assert_eq!(parsed.group, "ForssCloud Root CA");
    }

    #[test]
    fn qr_payload_empty_group() {
        let mut share = test_share();
        share.group = String::new();
        let payload = qr_payload(&share).unwrap();
        let parsed = parse_qr_payload(&payload).unwrap();
        assert_eq!(parsed.group, "");
        assert_eq!(parsed.x, 3);
    }

    #[test]
    fn qr_payload_bad_data_rejected() {
        // Random garbage — neither valid URI nor valid binary share.
        assert!(parse_qr_payload(b"too short").is_err());
        assert!(parse_qr_payload(&[0u8; 10]).is_err());
        // Valid URI prefix but bad base64.
        assert!(parse_qr_payload(b"ssscrypt:share:v1:!!!:00000000").is_err());
    }

    #[test]
    fn qr_payload_crc_mismatch_rejected() {
        let share = test_share();
        let mut payload = qr_payload(&share).unwrap();
        // Corrupt the last hex digit of the CRC.
        let len = payload.len();
        payload[len - 1] ^= 0x01;
        assert!(parse_qr_payload(&payload).is_err());
    }

    // -- Card rendering --

    #[test]
    fn render_card_dimensions() {
        let img = render_card(&test_share(), &test_words()).unwrap();
        assert!(img.width() >= CARD_MIN_WIDTH);
        assert!(img.height() > 500);
    }

    #[test]
    fn render_card_has_dark_content() {
        let img = render_card(&test_share(), &test_words()).unwrap();
        let dark = img.pixels().filter(|p| p.0[0] < 128).count();
        assert!(
            dark > 1000,
            "expected dark pixels for text + QR, got {dark}"
        );
    }

    #[test]
    fn render_card_long_label_rejected() {
        let mut share = test_share();
        share.group = "A".repeat(256);
        assert!(render_card(&share, &test_words()).is_err());
    }

    #[test]
    fn render_card_empty_label() {
        let mut share = test_share();
        share.group = String::new();
        let img = render_card(&share, &test_words()).unwrap();
        assert!(img.width() >= CARD_MIN_WIDTH);
    }

    // -- File output --

    #[test]
    fn save_card_jpeg() {
        let dir = std::env::temp_dir().join("ssscrypt_test_qr_jpg");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("share.jpg");
        save_card(&test_share(), &test_words(), &path).unwrap();
        let size = std::fs::metadata(&path).unwrap().len();
        assert!(size > 100, "JPEG should have non-trivial size, got {size}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn save_card_png() {
        let dir = std::env::temp_dir().join("ssscrypt_test_qr_png");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("share.png");
        save_card(&test_share(), &test_words(), &path).unwrap();
        let size = std::fs::metadata(&path).unwrap().len();
        assert!(size > 100, "PNG should have non-trivial size, got {size}");
        std::fs::remove_dir_all(&dir).ok();
    }

    // -- QR scanning --

    #[test]
    fn scan_image_roundtrip() {
        // Render a card, then scan the QR code back out.
        let original = test_share();
        let img = render_card(&original, &test_words()).unwrap();
        let recovered = scan_image(&img).unwrap();
        assert_eq!(recovered.version, original.version);
        assert_eq!(recovered.threshold, original.threshold);
        assert_eq!(recovered.x, original.x);
        assert_eq!(recovered.y, original.y);
        assert_eq!(recovered.pubkey, original.pubkey);
        assert_eq!(recovered.group, original.group);
        assert_eq!(recovered.signature, original.signature);
    }

    #[test]
    fn scan_image_empty_group_roundtrip() {
        let mut share = test_share();
        share.group = String::new();
        let img = render_card(&share, &test_words()).unwrap();
        let recovered = scan_image(&img).unwrap();
        assert_eq!(recovered.group, "");
        assert_eq!(recovered.x, share.x);
        assert_eq!(recovered.y, share.y);
    }

    #[test]
    fn scan_card_file_roundtrip() {
        let dir = std::env::temp_dir().join("ssscrypt_test_scan_roundtrip");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("card.png");

        let original = test_share();
        save_card(&original, &test_words(), &path).unwrap();

        let recovered = scan_card(&path).unwrap();
        assert_eq!(recovered.x, original.x);
        assert_eq!(recovered.group, original.group);
        assert_eq!(recovered.to_bytes().unwrap(), original.to_bytes().unwrap());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn scan_image_no_qr_fails() {
        // A blank white image should produce no QR codes.
        let blank = GrayImage::from_pixel(200, 200, Luma([255u8]));
        assert!(scan_image(&blank).is_err());
    }

    #[test]
    fn scan_all_cards_mixed() {
        let dir = std::env::temp_dir().join("ssscrypt_test_scan_multi");
        std::fs::create_dir_all(&dir).unwrap();

        // Save two valid cards.
        let mut share1 = test_share();
        share1.x = 1;
        let path1 = dir.join("card1.png");
        save_card(&share1, &test_words(), &path1).unwrap();

        let mut share2 = test_share();
        share2.x = 2;
        let path2 = dir.join("card2.png");
        save_card(&share2, &test_words(), &path2).unwrap();

        // Save a blank (invalid) image.
        let blank = GrayImage::from_pixel(200, 200, Luma([255u8]));
        let bad_path = dir.join("blank.png");
        blank.save(&bad_path).unwrap();

        let paths: Vec<&std::path::Path> =
            vec![path1.as_path(), path2.as_path(), bad_path.as_path()];
        let (shares, errors) = scan_all_cards(&paths);

        assert_eq!(shares.len(), 2);
        assert_eq!(errors.len(), 1);

        let xs: Vec<u32> = shares.iter().map(|s| s.x).collect();
        assert!(xs.contains(&1));
        assert!(xs.contains(&2));

        std::fs::remove_dir_all(&dir).ok();
    }
}
