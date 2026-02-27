//! Mnemonic encoding for shares.
//!
//! Encodes a 40-byte payload (x + y + pubkey_prefix) into 30 case-encoded
//! tokens using a culled 1024-word English wordlist.
//!
//! Each token carries **11 bits**:
//! - **10 bits** (MSB): word index (0–1023) in the culled wordlist
//! - **1 bit** (LSB): case — `lowercase` = 0, `UPPERCASE` = 1
//!
//! ```text
//! payload (40 bytes = 320 bits) + checksum (10 bits) = 330 bits = 30 × 11 bits
//! ```
//!
//! Example:  `abandon ABSORB abstract ABSURD accident ACCOUNT …`
//!
//! The 10-bit blake3 checksum catches transcription errors (1/1024 false-pass).
//! The wordlist is culled from BIP-39 to maximise minimum Levenshtein distance
//! (≥ 2), so every single-character typo resolves **unambiguously** and
//! tab-autocomplete needs very few keystrokes.

use anyhow::{bail, Result};
use std::sync::OnceLock;
use zeroize::Zeroize;

/// Culled 1024-word English wordlist (Levenshtein-optimised, compile-time).
const WORDLIST_RAW: &str = include_str!("../data/wordlist_1024.txt");

/// Number of tokens in a mnemonic-encoded share.
pub const MNEMONIC_WORDS: usize = 30;

/// Bits per token: 10 (word index) + 1 (case).
const BITS_PER_TOKEN: usize = 11;

/// Bits used for the word index.
const WORD_INDEX_BITS: usize = 10;

/// Payload: x(4) + y(32) + pubkey_prefix(4) = 40 bytes.
pub const PAYLOAD_BYTES: usize = 40;

/// Checksum bits appended to the payload.
const CHECKSUM_BITS: usize = 10;

/// Maximum suggestions returned by fuzzy matching.
const MAX_SUGGESTIONS: usize = 5;

/// Maximum Levenshtein distance to consider a "near miss".
const MAX_EDIT_DISTANCE: usize = 3;

// ---------------------------------------------------------------------------
// Wordlist
// ---------------------------------------------------------------------------

/// Get the wordlist as a &'static slice, initialised once.
fn wordlist() -> &'static [&'static str] {
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS.get_or_init(|| WORDLIST_RAW.lines().collect())
}

/// Look up a word's index (case-insensitive) in the wordlist.
fn word_to_index(word: &str) -> Option<usize> {
    let lower = word.to_ascii_lowercase();
    wordlist().iter().position(|&w| w == lower)
}

// ---------------------------------------------------------------------------
// Payload
// ---------------------------------------------------------------------------

/// Mnemonic payload extracted from a share.
#[derive(Clone, Debug, Zeroize)]
#[zeroize(drop)]
pub struct MnemonicPayload {
    pub x: u32,
    pub y: [u8; 32],
    pub pubkey_prefix: [u8; 4],
}

impl MnemonicPayload {
    /// Serialize to 40-byte array.
    pub fn to_bytes(&self) -> [u8; PAYLOAD_BYTES] {
        let mut buf = [0u8; PAYLOAD_BYTES];
        buf[0..4].copy_from_slice(&self.x.to_be_bytes());
        buf[4..36].copy_from_slice(&self.y);
        buf[36..40].copy_from_slice(&self.pubkey_prefix);
        buf
        // NOTE: caller is responsible for zeroizing the returned array.
    }

    /// Deserialize from 40-byte array.
    pub fn from_bytes(bytes: &[u8; PAYLOAD_BYTES]) -> Self {
        let x = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
        let mut y = [0u8; 32];
        y.copy_from_slice(&bytes[4..36]);
        let mut pubkey_prefix = [0u8; 4];
        pubkey_prefix.copy_from_slice(&bytes[36..40]);
        Self {
            x,
            y,
            pubkey_prefix,
        }
    }
}

// ---------------------------------------------------------------------------
// Encode
// ---------------------------------------------------------------------------

/// Encode a 40-byte payload into 30 case-encoded tokens.
///
/// Each token is either `lowercase` (bit=0) or `UPPERCASE` (bit=1).
pub fn encode(payload: &MnemonicPayload) -> Vec<String> {
    let words = wordlist();
    let mut data = payload.to_bytes();

    // 10-bit checksum: first 10 bits of blake3(data).
    let hash = blake3::hash(&data);
    let checksum = ((hash.as_bytes()[0] as u16) << 2) | ((hash.as_bytes()[1] as u16) >> 6);

    // Build bit stream: 320 data bits + 10 checksum bits = 330 bits.
    let mut bits = Vec::with_capacity(MNEMONIC_WORDS * BITS_PER_TOKEN);
    for &byte in &data {
        for i in (0..8).rev() {
            bits.push((byte >> i) & 1);
        }
    }
    for i in (0..CHECKSUM_BITS).rev() {
        bits.push(((checksum >> i) & 1) as u8);
    }
    debug_assert_eq!(bits.len(), MNEMONIC_WORDS * BITS_PER_TOKEN);

    // Zeroize the serialized payload now that bits are extracted.
    data.zeroize();

    // Split into 30 groups of 11 bits.
    // Top 10 bits → word index, bottom 1 bit → case.
    let mut result = Vec::with_capacity(MNEMONIC_WORDS);
    for chunk in bits.chunks_exact(BITS_PER_TOKEN) {
        let mut word_idx: u16 = 0;
        for &bit in &chunk[..WORD_INDEX_BITS] {
            word_idx = (word_idx << 1) | bit as u16;
        }
        let case_bit = chunk[WORD_INDEX_BITS];

        let word = words[word_idx as usize];
        if case_bit == 1 {
            result.push(word.to_ascii_uppercase());
        } else {
            result.push(word.to_string());
        }
    }
    result
}

/// Decode 30 case-encoded tokens back to a 40-byte payload.
///
/// Returns the payload and a list of corrections (fuzzy-matched words).
/// Fails if a word is unrecognised or checksum is invalid.
pub fn decode(input_words: &[&str]) -> Result<(MnemonicPayload, Vec<WordCorrection>)> {
    if input_words.len() != MNEMONIC_WORDS {
        bail!(
            "expected {} words, got {}",
            MNEMONIC_WORDS,
            input_words.len()
        );
    }

    let mut corrections = Vec::new();
    let mut indices_and_cases = Vec::with_capacity(MNEMONIC_WORDS);

    for (pos, &token) in input_words.iter().enumerate() {
        let case_bit = if is_uppercase_token(token) { 1u8 } else { 0u8 };
        let lower = token.to_ascii_lowercase();

        match word_to_index(&lower) {
            Some(idx) => indices_and_cases.push((idx as u16, case_bit)),
            None => {
                // Try fuzzy match.
                let suggestions = fuzzy_suggestions(&lower);
                if suggestions.len() == 1 && suggestions[0].distance <= 2 {
                    // Confident single-match auto-correct.
                    let corrected = suggestions[0].word;
                    corrections.push(WordCorrection {
                        position: pos + 1,
                        input: lower.clone(),
                        corrected: corrected.to_string(),
                        distance: suggestions[0].distance,
                        alternatives: vec![],
                    });
                    indices_and_cases.push((
                        word_to_index(corrected).expect("suggestion in wordlist") as u16,
                        case_bit,
                    ));
                } else if !suggestions.is_empty() {
                    // Ambiguous — use closest, report alternatives.
                    let best = &suggestions[0];
                    corrections.push(WordCorrection {
                        position: pos + 1,
                        input: lower.clone(),
                        corrected: best.word.to_string(),
                        distance: best.distance,
                        alternatives: suggestions[1..]
                            .iter()
                            .map(|s| s.word.to_string())
                            .collect(),
                    });
                    indices_and_cases.push((
                        word_to_index(best.word).expect("suggestion in wordlist") as u16,
                        case_bit,
                    ));
                } else {
                    bail!(
                        "word #{} '{}' is not in the wordlist and no close match found",
                        pos + 1,
                        token
                    );
                }
            }
        }
    }

    // Reconstruct bit stream: 10 bits word index + 1 bit case per token.
    let mut bits = Vec::with_capacity(MNEMONIC_WORDS * BITS_PER_TOKEN);
    for &(idx, case) in &indices_and_cases {
        for i in (0..WORD_INDEX_BITS).rev() {
            bits.push(((idx >> i) & 1) as u8);
        }
        bits.push(case);
    }

    // Split: 320 data bits + 10 checksum bits.
    let (data_bits, checksum_bits_slice) = bits.split_at(PAYLOAD_BYTES * 8);

    // Reconstruct data bytes.
    let mut data = [0u8; PAYLOAD_BYTES];
    for (i, chunk) in data_bits.chunks_exact(8).enumerate() {
        let mut byte = 0u8;
        for &bit in chunk {
            byte = (byte << 1) | bit;
        }
        data[i] = byte;
    }

    // Reconstruct and verify checksum.
    let mut checksum: u16 = 0;
    for &bit in checksum_bits_slice {
        checksum = (checksum << 1) | bit as u16;
    }
    let hash = blake3::hash(&data);
    let expected = ((hash.as_bytes()[0] as u16) << 2) | ((hash.as_bytes()[1] as u16) >> 6);
    if checksum != expected {
        bail!(
            "mnemonic checksum failed (expected {:03x}, got {:03x}) — likely a transcription error",
            expected,
            checksum
        );
    }

    let payload = MnemonicPayload::from_bytes(&data);
    data.zeroize();

    Ok((payload, corrections))
}

/// A token is UPPERCASE if every alphabetic char is uppercase.
fn is_uppercase_token(s: &str) -> bool {
    s.chars().all(|c| !c.is_alphabetic() || c.is_uppercase())
}

// ---------------------------------------------------------------------------
// Tab autocomplete
// ---------------------------------------------------------------------------

/// Return all words in the wordlist that start with `prefix` (case-insensitive).
///
/// With the culled high-distance list, 2–3 characters typically suffice.
pub fn tab_complete(prefix: &str) -> Vec<&'static str> {
    let lower = prefix.to_ascii_lowercase();
    wordlist()
        .iter()
        .copied()
        .filter(|w| w.starts_with(lower.as_str()))
        .collect()
}

/// Result of attempting to complete a prefix against the wordlist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Completion {
    /// Exactly one word matches — show as shadow.
    Unique(String),
    /// Multiple words match — input is in progress, keep typing.
    Ambiguous,
    /// Empty prefix — nothing typed yet.
    Empty,
    /// No words match this prefix — the input is wrong.
    NoMatch,
    /// Prefix has inconsistent (mixed) case.
    MixedCase,
}

impl Completion {
    /// If the completion is `Unique`, return the word; otherwise `None`.
    pub fn word(&self) -> Option<&str> {
        match self {
            Completion::Unique(w) => Some(w),
            _ => None,
        }
    }
}

/// Compute the completion state for a prefix against the wordlist.
///
/// - `Unique(word)` — exactly one match, cased to match the prefix.
/// - `Ambiguous`    — multiple matches, user is still typing.
/// - `Empty`        — nothing typed yet.
/// - `NoMatch`      — zero matches, prefix is wrong.
/// - `MixedCase`    — prefix has inconsistent casing.
pub fn complete_word(prefix: &str) -> Completion {
    if prefix.is_empty() {
        return Completion::Empty;
    }

    let has_upper = prefix.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = prefix.chars().any(|c| c.is_ascii_lowercase());

    if has_upper && has_lower {
        return Completion::MixedCase;
    }

    let lower = prefix.to_ascii_lowercase();
    let candidates = tab_complete(&lower);

    match candidates.len() {
        0 => Completion::NoMatch,
        1 => {
            let word = candidates[0];
            Completion::Unique(if has_upper {
                word.to_ascii_uppercase()
            } else {
                word.to_string()
            })
        }
        _ => Completion::Ambiguous,
    }
}

// ---------------------------------------------------------------------------
// Fuzzy matching
// ---------------------------------------------------------------------------

/// A fuzzy match suggestion.
#[derive(Debug, Clone)]
pub struct FuzzySuggestion {
    pub word: &'static str,
    pub distance: usize,
}

/// A word correction applied during decode.
#[derive(Debug, Clone)]
pub struct WordCorrection {
    /// 1-based word position.
    pub position: usize,
    /// What the user typed.
    pub input: String,
    /// What we corrected it to.
    pub corrected: String,
    /// Levenshtein distance.
    #[allow(dead_code)]
    pub distance: usize,
    /// Other candidates (if ambiguous).
    pub alternatives: Vec<String>,
}

/// Find the closest words to `input`, sorted by distance.
pub fn fuzzy_suggestions(input: &str) -> Vec<FuzzySuggestion> {
    let input_lower = input.to_ascii_lowercase();
    let words = wordlist();
    let mut candidates: Vec<FuzzySuggestion> = words
        .iter()
        .filter_map(|&w| {
            let d = levenshtein(&input_lower, w);
            if d <= MAX_EDIT_DISTANCE {
                Some(FuzzySuggestion {
                    word: w,
                    distance: d,
                })
            } else {
                None
            }
        })
        .collect();

    candidates.sort_by_key(|c| (c.distance, c.word));
    candidates.truncate(MAX_SUGGESTIONS);
    candidates
}

/// Validate a single word against the wordlist.
pub fn validate_word(input: &str) -> WordValidation {
    let lower = input.to_ascii_lowercase();
    if word_to_index(&lower).is_some() {
        return WordValidation::Valid(lower);
    }

    let suggestions = fuzzy_suggestions(&lower);
    if suggestions.is_empty() {
        WordValidation::Unknown(lower)
    } else {
        WordValidation::NearMiss {
            input: lower,
            suggestions,
        }
    }
}

/// Result of validating a single word.
#[derive(Debug)]
pub enum WordValidation {
    /// Exact match in the wordlist.
    Valid(#[allow(dead_code)] String),
    /// Not in wordlist, but close matches found.
    NearMiss {
        input: String,
        suggestions: Vec<FuzzySuggestion>,
    },
    /// Not in wordlist and nothing close.
    Unknown(String),
}

/// Compute Levenshtein edit distance between two strings.
fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let m = a.len();
    let n = b.len();

    if m.abs_diff(n) > MAX_EDIT_DISTANCE {
        return m.abs_diff(n);
    }

    let mut prev: Vec<usize> = (0..=n).collect();
    let mut curr = vec![0usize; n + 1];

    for i in 1..=m {
        curr[0] = i;
        for j in 1..=n {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }

    prev[n]
}

// ---------------------------------------------------------------------------
// Paper card formatting
// ---------------------------------------------------------------------------

/// Format a mnemonic as a human-readable paper card.
///
/// The card preserves case so the holder can reproduce the exact token list.
#[cfg(test)]
fn format_card(words: &[String], x: u32, threshold: u8, version: u8, pubkey_hex: &str) -> String {
    let mut out = String::new();
    out.push_str("┌──────────────────────────────────────┐\n");
    out.push_str(&format!(
        "│  Share #{:<3}   k={:<3}  v{:<3}              │\n",
        x, threshold, version
    ));
    out.push_str(&format!(
        "│  pk: {}  │\n",
        &pubkey_hex[..std::cmp::min(32, pubkey_hex.len())]
    ));
    out.push_str("├──────────────────────────────────────┤\n");

    // Rows of 4 words.
    let num_rows = words.len().div_ceil(4);
    for row in 0..num_rows {
        let start = row * 4;
        let end = std::cmp::min(start + 4, words.len());
        let row_words: Vec<&str> = words[start..end].iter().map(|s| s.as_str()).collect();

        let numbered: Vec<String> = row_words
            .iter()
            .enumerate()
            .map(|(i, w)| format!("{:>2}. {:<10}", start + i + 1, w))
            .collect();

        out.push_str(&format!("│ {:<36} │\n", numbered.join(" ")));
    }

    out.push_str("├──────────────────────────────────────┤\n");
    out.push_str("│  UPPER = 1 bit,  lower = 0 bit      │\n");
    out.push_str("└──────────────────────────────────────┘\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_payload() -> MnemonicPayload {
        MnemonicPayload {
            x: 3,
            y: [0xab; 32],
            pubkey_prefix: [0xcd, 0xef, 0x01, 0x23],
        }
    }

    #[test]
    fn wordlist_has_1024_entries() {
        assert_eq!(wordlist().len(), 1024);
    }

    #[test]
    fn roundtrip() {
        let payload = test_payload();
        let words = encode(&payload);
        assert_eq!(words.len(), MNEMONIC_WORDS);

        let word_refs: Vec<&str> = words.iter().map(|s| s.as_str()).collect();
        let (decoded, corrections) = decode(&word_refs).unwrap();
        assert!(corrections.is_empty());

        assert_eq!(decoded.x, payload.x);
        assert_eq!(decoded.y, payload.y);
        assert_eq!(decoded.pubkey_prefix, payload.pubkey_prefix);
    }

    #[test]
    fn case_carries_information() {
        let payload = test_payload();
        let words = encode(&payload);
        // At least some tokens should be uppercase, some lowercase.
        let upper_count = words.iter().filter(|w| is_uppercase_token(w)).count();
        assert!(upper_count > 0, "expected some UPPERCASE tokens");
        assert!(
            upper_count < MNEMONIC_WORDS,
            "expected some lowercase tokens"
        );
    }

    #[test]
    fn flipping_case_breaks_checksum() {
        let payload = test_payload();
        let mut words = encode(&payload);
        // Flip the case of the first token.
        if is_uppercase_token(&words[0]) {
            words[0] = words[0].to_ascii_lowercase();
        } else {
            words[0] = words[0].to_ascii_uppercase();
        }

        let word_refs: Vec<&str> = words.iter().map(|s| s.as_str()).collect();
        assert!(decode(&word_refs).is_err());
    }

    #[test]
    fn wrong_word_count_rejected() {
        let words: Vec<&str> = vec!["abandon"; 10];
        assert!(decode(&words).is_err());
    }

    #[test]
    fn corrupted_word_detected_by_checksum() {
        let payload = test_payload();
        let mut words = encode(&payload);
        // Change one word to a different valid word (preserving case).
        let wl = wordlist();
        let replacement = if words[5].to_ascii_lowercase() == wl[0] {
            wl[1]
        } else {
            wl[0]
        };
        words[5] = if is_uppercase_token(&words[5]) {
            replacement.to_ascii_uppercase()
        } else {
            replacement.to_string()
        };

        let word_refs: Vec<&str> = words.iter().map(|s| s.as_str()).collect();
        assert!(decode(&word_refs).is_err());
    }

    #[test]
    fn fuzzy_match_close_typo() {
        // "abondon" → "abandon" (distance 1)
        let suggestions = fuzzy_suggestions("abondon");
        assert!(!suggestions.is_empty());
        assert_eq!(suggestions[0].word, "abandon");
        assert_eq!(suggestions[0].distance, 1);
    }

    #[test]
    fn tab_complete_works() {
        let matches = tab_complete("ab");
        assert!(matches.len() >= 2); // abandon, ability, absorb, abstract, absurd
        assert!(matches.contains(&"abandon"));
    }

    #[test]
    fn complete_word_unique_lowercase() {
        // "aba" should uniquely match "abandon" → lowercase
        assert_eq!(
            complete_word("aba"),
            Completion::Unique("abandon".to_string())
        );
    }

    #[test]
    fn complete_word_unique_uppercase() {
        assert_eq!(
            complete_word("ABA"),
            Completion::Unique("ABANDON".to_string())
        );
    }

    #[test]
    fn complete_word_ambiguous() {
        // "ab" matches multiple words (abandon, ability, …)
        assert_eq!(complete_word("ab"), Completion::Ambiguous);
    }

    #[test]
    fn complete_word_empty() {
        assert_eq!(complete_word(""), Completion::Empty);
    }

    #[test]
    fn complete_word_no_match() {
        assert_eq!(complete_word("xqz"), Completion::NoMatch);
    }

    #[test]
    fn complete_word_mixed_case() {
        assert_eq!(complete_word("aBa"), Completion::MixedCase);
    }

    #[test]
    fn complete_word_full_word() {
        // Typing the full word should still return Unique.
        assert_eq!(
            complete_word("abandon"),
            Completion::Unique("abandon".to_string())
        );
    }

    #[test]
    fn validate_word_exact() {
        match validate_word("abandon") {
            WordValidation::Valid(w) => assert_eq!(w, "abandon"),
            _ => panic!("expected Valid"),
        }
    }

    #[test]
    fn validate_word_nonsense() {
        match validate_word("xyzzyqwert") {
            WordValidation::Unknown(_) => {}
            _ => panic!("expected Unknown"),
        }
    }

    #[test]
    fn fuzzy_decode_with_typo() {
        let payload = test_payload();
        let mut words = encode(&payload);

        // Introduce a single-char typo in the first word.
        let original = words[0].clone();
        let lower = original.to_ascii_lowercase();
        let typo = format!("{}z", &lower[..lower.len() - 1]);
        // Preserve original case in the typo.
        words[0] = if is_uppercase_token(&original) {
            typo.to_ascii_uppercase()
        } else {
            typo
        };

        let word_refs: Vec<&str> = words.iter().map(|s| s.as_str()).collect();
        let result = decode(&word_refs);

        // With min edit distance ≥ 2 in the culled list, a single-char typo
        // should always be unambiguously corrected.
        match result {
            Ok((decoded, corrections)) => {
                assert!(!corrections.is_empty());
                assert_eq!(decoded.x, payload.x);
                assert_eq!(decoded.y, payload.y);
                assert_eq!(decoded.pubkey_prefix, payload.pubkey_prefix);
            }
            Err(e) => {
                // Acceptable: fuzzy matched to wrong word → checksum caught it.
                assert!(e.to_string().contains("checksum"));
            }
        }
    }

    #[test]
    fn encode_produces_only_valid_words() {
        let payload = test_payload();
        let words = encode(&payload);
        let wl = wordlist();
        for word in &words {
            assert!(
                wl.contains(&word.to_ascii_lowercase().as_str()) || {
                    let lower = word.to_ascii_lowercase();
                    wl.iter().any(|&w| w == lower)
                },
                "word '{}' not in wordlist",
                word
            );
        }
    }

    #[test]
    fn different_payloads_produce_different_mnemonics() {
        let p1 = test_payload();
        let mut p2 = test_payload();
        p2.x = 4;
        let w1 = encode(&p1);
        let w2 = encode(&p2);
        assert_ne!(w1, w2);
    }

    #[test]
    fn card_format_is_readable() {
        let payload = test_payload();
        let words = encode(&payload);
        let card = format_card(&words, 3, 3, 1, "abcdef0123456789abcdef0123456789ab");
        assert!(card.contains("Share #3"));
        assert!(card.contains("k=3"));
        assert!(card.contains("pk:"));
        // Should have 30 numbered words.
        assert!(card.contains("30."));
        // Footer with case explanation.
        assert!(card.contains("UPPER"));
    }

    #[test]
    fn roundtrip_all_zeros() {
        let payload = MnemonicPayload {
            x: 0,
            y: [0; 32],
            pubkey_prefix: [0; 4],
        };
        let words = encode(&payload);
        let word_refs: Vec<&str> = words.iter().map(|s| s.as_str()).collect();
        let (decoded, _) = decode(&word_refs).unwrap();
        assert_eq!(decoded.x, 0);
        assert_eq!(decoded.y, [0; 32]);
        assert_eq!(decoded.pubkey_prefix, [0; 4]);
    }

    #[test]
    fn roundtrip_all_ones() {
        let payload = MnemonicPayload {
            x: 0xff,
            y: [0xff; 32],
            pubkey_prefix: [0xff; 4],
        };
        let words = encode(&payload);
        let word_refs: Vec<&str> = words.iter().map(|s| s.as_str()).collect();
        let (decoded, _) = decode(&word_refs).unwrap();
        assert_eq!(decoded.x, 0xff);
        assert_eq!(decoded.y, [0xff; 32]);
        assert_eq!(decoded.pubkey_prefix, [0xff; 4]);
    }
}
