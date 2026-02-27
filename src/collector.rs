//! Interactive share collector.
//!
//! Combines multiple share-input methods:
//!
//! 1. **Folder** — pre-load shares from `*.share.txt` files on disk.
//! 2. **Mnemonic terminal** — interactive word-by-word input with tab-complete
//!    and fuzzy matching.
//! 3. **Camera scanner** — live QR code scanning in a GUI window
//!    (eframe/egui + nokhwa). Gracefully skipped if no camera is available.
//!
//! The collector runs until enough shares are gathered or the user quits.

use std::collections::HashSet;
use std::io::Write;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};

use crate::crypto;
use crate::mnemonic::{self, MnemonicPayload, MNEMONIC_WORDS};
use crate::share::Share;

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

/// Shared collector state visible to all input methods.
pub struct CollectorState {
    /// Shares collected so far (deduplicated by x).
    pub shares: Vec<Share>,
    /// x values already seen (for dedup).
    pub seen_x: HashSet<u32>,
    /// Threshold K (if known from first share).
    pub threshold: Option<u8>,
    /// Public key (if known from first share).
    pub pubkey: Option<[u8; 32]>,
    /// Set to true when enough shares are collected.
    pub complete: bool,
}

impl CollectorState {
    pub fn new() -> Self {
        Self {
            shares: Vec::new(),
            seen_x: HashSet::new(),
            threshold: None,
            pubkey: None,
            complete: false,
        }
    }

    /// How many more shares are needed (0 = ready).
    pub fn remaining(&self) -> usize {
        match self.threshold {
            Some(k) => (k as usize).saturating_sub(self.shares.len()),
            None => usize::MAX,
        }
    }

    /// Try to add a share. Returns true if accepted (new, valid).
    pub fn try_add(&mut self, share: Share) -> AddResult {
        // Dedup by x.
        if self.seen_x.contains(&share.x) {
            return AddResult::Duplicate(share.x);
        }

        // Verify signature.
        if let Err(e) = crypto::verify_share_signature(&share) {
            return AddResult::InvalidSignature(share.x, e.to_string());
        }

        // Check consistency (pubkey + threshold must match).
        if let Some(expected_pk) = &self.pubkey {
            if share.pubkey != *expected_pk {
                return AddResult::PubkeyMismatch(share.x);
            }
        }
        if let Some(expected_t) = self.threshold {
            if share.threshold != expected_t {
                return AddResult::ThresholdMismatch(share.x, expected_t, share.threshold);
            }
        }

        // Accept it.
        let x = share.x;
        if self.pubkey.is_none() {
            self.pubkey = Some(share.pubkey);
        }
        if self.threshold.is_none() {
            self.threshold = Some(share.threshold);
        }
        self.seen_x.insert(x);
        self.shares.push(share);

        if self.remaining() == 0 {
            self.complete = true;
        }

        AddResult::Accepted(x)
    }

    /// Add a share decoded from a mnemonic.
    ///
    /// Mnemonic-decoded shares carry only `x`, `y`, and a 4-byte pubkey
    /// prefix — no full pubkey or signature. We skip signature verification
    /// and instead verify the prefix against the known pubkey (if any).
    /// The resulting share gets the full pubkey and threshold from context.
    pub fn try_add_mnemonic(&mut self, payload: MnemonicPayload) -> AddResult {
        // Dedup by x.
        if self.seen_x.contains(&payload.x) {
            return AddResult::Duplicate(payload.x);
        }

        // Check the 4-byte pubkey prefix against the known pubkey.
        let verified_prefix;
        if let Some(expected_pk) = &self.pubkey {
            if expected_pk[..4] != payload.pubkey_prefix {
                return AddResult::PubkeyPrefixMismatch(payload.x);
            }
            verified_prefix = true;
        } else {
            verified_prefix = false;
        }

        // Build a share with full context.
        let share = Share {
            version: 1,
            threshold: self.threshold.unwrap_or(0),
            x: payload.x,
            y: payload.y,
            pubkey: self.pubkey.unwrap_or([0u8; 32]),
            group: String::new(),
            signature: [0u8; 64], // no signature from mnemonic
        };

        let x = share.x;
        if self.pubkey.is_none() {
            // We don't know the full pubkey yet — we'll accept it
            // provisionally and verify when later shares arrive.
        }
        self.seen_x.insert(x);
        self.shares.push(share);

        if self.remaining() == 0 {
            self.complete = true;
        }

        if verified_prefix {
            AddResult::AcceptedMnemonic(x)
        } else {
            AddResult::AcceptedMnemonicUnverified(x)
        }
    }
}

/// Result of trying to add a share.
#[derive(Debug)]
pub enum AddResult {
    Accepted(u32),
    Duplicate(u32),
    InvalidSignature(u32, String),
    PubkeyMismatch(u32),
    PubkeyPrefixMismatch(u32),
    ThresholdMismatch(u32, u8, u8),
    /// Mnemonic share accepted but without signature verification —
    /// the 4-byte pubkey prefix matched.
    AcceptedMnemonic(u32),
    /// Mnemonic share accepted without prefix verification (no context yet).
    AcceptedMnemonicUnverified(u32),
}

impl std::fmt::Display for AddResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddResult::Accepted(x) => write!(f, "share #{x} accepted"),
            AddResult::AcceptedMnemonic(x) => {
                write!(f, "share #{x} accepted (mnemonic, prefix verified)")
            }
            AddResult::AcceptedMnemonicUnverified(x) => {
                write!(f, "share #{x} accepted (mnemonic, unverified)")
            }
            AddResult::Duplicate(x) => write!(f, "share #{x} already collected (duplicate)"),
            AddResult::InvalidSignature(x, e) => {
                write!(f, "share #{x} rejected: invalid signature ({e})")
            }
            AddResult::PubkeyMismatch(x) => {
                write!(
                    f,
                    "share #{x} rejected: pubkey does not match existing shares"
                )
            }
            AddResult::PubkeyPrefixMismatch(x) => {
                write!(
                    f,
                    "share #{x} rejected: pubkey prefix does not match existing shares"
                )
            }
            AddResult::ThresholdMismatch(x, expected, got) => {
                write!(
                    f,
                    "share #{x} rejected: threshold mismatch (expected {expected}, got {got})"
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Collector entry point
// ---------------------------------------------------------------------------

/// Result of interactive share collection.
pub struct CollectedShares {
    pub shares: Vec<Share>,
    pub threshold: u8,
    pub pubkey: [u8; 32],
}

/// Interactively collect shares from folder, terminal mnemonic input, and
/// optionally a live camera scanner window.
///
/// Returns the collected shares once enough are gathered.
///
/// `threshold_hint`: if known (e.g. from encrypted file header), seeds the
/// collector so it knows how many shares are needed even before the first
/// file-based share arrives.
pub fn collect_shares(
    shares_dir: Option<&std::path::Path>,
    anchor_pubkey: Option<&[u8; 32]>,
    threshold_hint: Option<u8>,
) -> Result<CollectedShares> {
    let state = Arc::new(Mutex::new(CollectorState::new()));

    // Seed with known context.
    {
        let mut st = state.lock().unwrap();
        if let Some(pk) = anchor_pubkey {
            st.pubkey = Some(*pk);
        }
        if let Some(t) = threshold_hint {
            st.threshold = Some(t);
        }
    }

    // Channel for shares discovered by the camera scanner thread.
    let (cam_tx, cam_rx) = mpsc::channel::<Share>();
    // Channel for camera log messages (avoids interleaving with terminal input).
    let (cam_log_tx, cam_log_rx) = mpsc::channel::<String>();

    // ----- Phase 1: Load from folder -----
    if let Some(dir) = shares_dir {
        let loaded = crate::io::load_shares(dir)?;
        let mut st = state.lock().unwrap();

        for share in loaded {
            let result = st.try_add(share);
            eprintln!("  folder: {result}");
        }
        eprintln!(
            "  loaded from folder: {} share(s), {} more needed",
            st.shares.len(),
            match st.threshold {
                Some(_) => st.remaining().to_string(),
                None => "?".to_string(),
            }
        );
        if st.complete {
            eprintln!("  enough shares — skipping interactive mode");
            let threshold = st
                .threshold
                .ok_or_else(|| anyhow::anyhow!("threshold unknown"))?;
            let pubkey = st.pubkey.ok_or_else(|| anyhow::anyhow!("pubkey unknown"))?;
            return Ok(CollectedShares {
                shares: std::mem::take(&mut st.shares),
                threshold,
                pubkey,
            });
        }
    }

    // ----- Phase 2: Spawn camera window (if available) -----
    let camera_handle = {
        let cam_state = Arc::clone(&state);
        let cam_tx2 = cam_tx.clone();
        Some(std::thread::spawn(move || {
            // Camera errors are non-fatal — user can fall back to mnemonic.
            let log_err = cam_log_tx.clone();
            if let Err(e) = run_camera_window(cam_state, cam_tx2, cam_log_tx) {
                let _ = log_err.send(format!("camera: {e}"));
            }
        }))
    };

    // Drop our sender so cam_rx will close when the camera thread drops its copy.
    drop(cam_tx);

    // ----- Phase 3: Terminal mnemonic input loop -----
    run_terminal_loop(&state, &cam_rx, &cam_log_rx)?;

    // ----- Cleanup -----
    // If camera thread is still running, it will exit when it sees complete=true.
    if let Some(handle) = camera_handle {
        let _ = handle.join();
    }

    let st = state.lock().unwrap();
    if st.shares.is_empty() {
        bail!("no shares collected");
    }
    let threshold = st.threshold.ok_or_else(|| {
        anyhow::anyhow!("threshold unknown — need at least one file/QR share or --anchor-encrypted")
    })?;
    let pubkey = st.pubkey.ok_or_else(|| {
        anyhow::anyhow!("pubkey unknown — need at least one file/QR share or --anchor-encrypted")
    })?;
    Ok(CollectedShares {
        shares: st.shares.clone(),
        threshold,
        pubkey,
    })
}

// ---------------------------------------------------------------------------
// Terminal mnemonic input loop (raw mode with shadow completion)
// ---------------------------------------------------------------------------

fn run_terminal_loop(
    state: &Arc<Mutex<CollectorState>>,
    cam_rx: &mpsc::Receiver<Share>,
    cam_log_rx: &mpsc::Receiver<String>,
) -> Result<()> {
    use std::io::Write;
    let mut out = std::io::stderr();

    print_status(&state.lock().unwrap());
    eprintln!();
    eprintln!("Enter mnemonic words one at a time ({MNEMONIC_WORDS} words per share).");
    eprintln!("Tab/Enter accepts the shadowed completion.  Ctrl-C to quit.");
    eprintln!("Case matters: lowercase = 0, UPPERCASE = 1.");
    eprintln!();

    crossterm::terminal::enable_raw_mode()?;
    let result = run_raw_loop(state, cam_rx, cam_log_rx, &mut out);
    crossterm::terminal::disable_raw_mode()?;

    // Ensure cursor is on a fresh line after raw mode.
    write!(out, "\r\n")?;
    out.flush()?;

    result
}

/// Inner raw-mode loop.  Collects words one at a time, decodes each
/// MNEMONIC_WORDS-word group, and feeds decoded shares into the collector.
fn run_raw_loop(
    state: &Arc<Mutex<CollectorState>>,
    cam_rx: &mpsc::Receiver<Share>,
    cam_log_rx: &mpsc::Receiver<String>,
    out: &mut impl Write,
) -> Result<()> {
    let mut words: Vec<String> = Vec::new();

    loop {
        // Drain camera log messages and shares.
        drain_camera(state, cam_rx, cam_log_rx, out)?;

        // Check completion.
        if state.lock().unwrap().complete {
            write!(out, "\r\n  \x1b[32m✓ Enough shares collected!\x1b[0m\r\n")?;
            out.flush()?;
            return Ok(());
        }

        let word_num = words.len() + 1;

        match read_word(word_num, out, cam_rx, cam_log_rx, state)? {
            WordAction::Word(w) => {
                words.push(w);

                if words.len() >= MNEMONIC_WORDS {
                    // Attempt decode.
                    let refs: Vec<&str> = words.iter().map(|s| s.as_str()).collect();
                    match mnemonic::decode(&refs) {
                        Ok((payload, corrections)) => {
                            for corr in &corrections {
                                write!(
                                    out,
                                    "  auto-corrected #{}: '{}' → '{}'{}\r\n",
                                    corr.position,
                                    corr.input,
                                    corr.corrected,
                                    if corr.alternatives.is_empty() {
                                        String::new()
                                    } else {
                                        format!(" (also: {})", corr.alternatives.join(", "))
                                    }
                                )?;
                            }
                            let mut st = state.lock().unwrap();
                            let result = st.try_add_mnemonic(payload);
                            write!(out, "  mnemonic: {result}\r\n")?;
                            write_status(&st, out)?;
                            words.clear();
                            if st.complete {
                                write!(out, "\r\n  \x1b[32m✓ Enough shares collected!\x1b[0m\r\n")?;
                                out.flush()?;
                                return Ok(());
                            }
                        }
                        Err(e) => {
                            write!(out, "\r\n  \x1b[31m✗ decode error: {e}\x1b[0m\r\n")?;
                            write!(out, "  clearing — please re-enter this share\r\n\r\n")?;
                            words.clear();
                        }
                    }
                }
            }
            WordAction::Complete => {
                write!(out, "\r\n  \x1b[32m✓ Enough shares collected!\x1b[0m\r\n")?;
                out.flush()?;
                return Ok(());
            }
            WordAction::Quit => {
                write!(out, "\r\n  stopped by user\r\n")?;
                out.flush()?;
                return Ok(());
            }
        }
    }
}

// -- word-level raw input ---------------------------------------------------

enum WordAction {
    Word(String),
    /// All required shares have been collected (e.g. by the camera thread).
    Complete,
    /// User explicitly quit (Ctrl-C, "quit", etc.).
    Quit,
}

/// Read a single mnemonic word with shadow completion, case enforcement,
/// and inline validation.
fn read_word(
    word_num: usize,
    out: &mut impl Write,
    cam_rx: &mpsc::Receiver<Share>,
    cam_log_rx: &mpsc::Receiver<String>,
    state: &Arc<Mutex<CollectorState>>,
) -> Result<WordAction> {
    use crossterm::event::{self, Event, KeyCode, KeyModifiers};
    use std::time::Duration;

    let mut typed = String::new();

    loop {
        // Compute completion state (case-aware).
        let comp = mnemonic::complete_word(&typed);

        render_prompt(word_num, &typed, &comp, out)?;

        // Poll with short timeout so we can service camera events.
        if !event::poll(Duration::from_millis(100))? {
            drain_camera(state, cam_rx, cam_log_rx, out)?;
            if state.lock().unwrap().complete {
                return Ok(WordAction::Complete);
            }
            continue;
        }

        let ev = event::read()?;
        let Event::Key(key) = ev else { continue };
        // Ignore key-release events (crossterm 0.28 sends press + release).
        if key.kind != crossterm::event::KeyEventKind::Press {
            continue;
        }

        match key.code {
            // ── quit ───────────────────────────────────────────────────
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                return Ok(WordAction::Quit);
            }
            KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                return Ok(WordAction::Quit);
            }

            // ── typing ────────────────────────────────────────────────
            KeyCode::Char(c) => {
                if c == ' ' {
                    // Space = accept current word (same as Enter).
                    if let Some(w) = try_accept(&typed, &comp) {
                        show_accepted(word_num, &w, out)?;
                        return Ok(WordAction::Word(w));
                    }
                    if typed.is_empty() {
                        continue;
                    }
                    show_reject(&typed, &comp, out)?;
                    typed.clear();
                } else {
                    typed.push(c);
                }
            }

            // ── tab: fill shadow ──────────────────────────────────────
            KeyCode::Tab => {
                if let Some(w) = comp.word() {
                    typed = w.to_string();
                }
            }

            // ── enter: accept word ────────────────────────────────────
            KeyCode::Enter => {
                if typed.is_empty() {
                    continue;
                }
                // Check for quit command.
                if typed.eq_ignore_ascii_case("quit") || typed.eq_ignore_ascii_case("done") {
                    return Ok(WordAction::Quit);
                }
                if let Some(w) = try_accept(&typed, &comp) {
                    show_accepted(word_num, &w, out)?;
                    return Ok(WordAction::Word(w));
                }
                show_reject(&typed, &comp, out)?;
                typed.clear();
            }

            // ── editing ───────────────────────────────────────────────
            KeyCode::Backspace => {
                typed.pop();
            }
            KeyCode::Esc => {
                typed.clear();
            }
            _ => {}
        }
    }
}

// -- rendering helpers ------------------------------------------------------

/// Redraw the prompt line with shadow completion or inline error indicator.
fn render_prompt(
    word_num: usize,
    typed: &str,
    comp: &mnemonic::Completion,
    out: &mut impl Write,
) -> std::io::Result<()> {
    use mnemonic::Completion;
    // \r         → carriage return
    // \x1b[2K    → erase entire line
    write!(out, "\r\x1b[2K[{}/{}] > ", word_num, MNEMONIC_WORDS)?;

    match comp {
        Completion::Unique(word) => {
            write!(out, "{}", typed)?;
            if word.len() > typed.len() {
                let suffix = &word[typed.len()..];
                // Dark-grey shadow, then move cursor back.
                write!(out, "\x1b[90m{}\x1b[0m\x1b[{}D", suffix, suffix.len())?;
            }
        }
        Completion::NoMatch => {
            // Red typed text + warning glyph.
            write!(out, "\x1b[31m{}\x1b[0m \x1b[31m✗\x1b[0m", typed)?;
            // Move cursor back before the indicator (space + glyph = 2 columns).
            write!(out, "\x1b[2D")?;
        }
        Completion::MixedCase => {
            // Yellow typed text + case warning.
            write!(out, "\x1b[33m{}\x1b[0m \x1b[33m⚠\x1b[0m", typed)?;
            // Move cursor back before the indicator (space + glyph = 2 columns).
            write!(out, "\x1b[2D")?;
        }
        _ => {
            // Empty or Ambiguous — just show typed text, no decoration.
            write!(out, "{}", typed)?;
        }
    }
    out.flush()
}

/// Replace the current prompt line with a green-check accepted word.
fn show_accepted(word_num: usize, word: &str, out: &mut impl Write) -> std::io::Result<()> {
    write!(
        out,
        "\r\x1b[2K[{}/{}] \x1b[32m✓\x1b[0m {}\r\n",
        word_num, MNEMONIC_WORDS, word
    )?;
    out.flush()
}

/// Show an inline rejection message and leave cursor on a fresh line.
fn show_reject(
    typed: &str,
    comp: &mnemonic::Completion,
    out: &mut impl Write,
) -> std::io::Result<()> {
    use mnemonic::Completion;

    match comp {
        Completion::MixedCase => {
            write!(
                out,
                "\r\n  \x1b[33m⚠ mixed case — use '{}' or '{}'\x1b[0m\r\n",
                typed.to_ascii_lowercase(),
                typed.to_ascii_uppercase(),
            )?;
        }
        Completion::NoMatch => {
            // Try fuzzy suggestions for a friendlier error.
            let suggestions = mnemonic::fuzzy_suggestions(typed);
            let has_upper = typed.chars().any(|c| c.is_ascii_uppercase());
            if suggestions.is_empty() {
                write!(
                    out,
                    "\r\n  \x1b[31m✗ '{}' not in wordlist and no close match\x1b[0m\r\n",
                    typed,
                )?;
            } else {
                let list: Vec<String> = suggestions
                    .iter()
                    .map(|s| {
                        let w = if has_upper {
                            s.word.to_ascii_uppercase()
                        } else {
                            s.word.to_string()
                        };
                        format!("'{w}'")
                    })
                    .collect();
                write!(
                    out,
                    "\r\n  \x1b[33m⚠ '{}' not in wordlist — did you mean: {}?\x1b[0m\r\n",
                    typed,
                    list.join(", "),
                )?;
            }
        }
        _ => {
            // Ambiguous / Valid fall-through (shouldn't normally reach here).
            match mnemonic::validate_word(typed) {
                mnemonic::WordValidation::Valid(_) => unreachable!(),
                mnemonic::WordValidation::NearMiss { input, suggestions } => {
                    let has_upper = typed.chars().any(|c| c.is_ascii_uppercase());
                    let list: Vec<String> = suggestions
                        .iter()
                        .map(|s| {
                            let w = if has_upper {
                                s.word.to_ascii_uppercase()
                            } else {
                                s.word.to_string()
                            };
                            format!("'{w}'")
                        })
                        .collect();
                    write!(
                        out,
                        "\r\n  \x1b[33m⚠ '{input}' not in wordlist — did you mean: {}?\x1b[0m\r\n",
                        list.join(", "),
                    )?;
                }
                mnemonic::WordValidation::Unknown(w) => {
                    write!(
                        out,
                        "\r\n  \x1b[31m✗ '{w}' not in wordlist and no close match\x1b[0m\r\n",
                    )?;
                }
            }
        }
    }
    out.flush()
}

/// Accept a typed word if it can be resolved or passed through for decode-time correction.
///
/// Prefers the shadow completion (unique prefix match).  For any other non-error
/// completion state (`NoMatch`, `Empty`), the raw typed text is returned as-is so
/// that `mnemonic::decode()` can attempt fuzzy correction across the full phrase.
/// Returns `None` only for hard errors (`MixedCase`, mid-word `Ambiguous`) or empty
/// input.  No wordlist lookup is performed here.
fn try_accept(typed: &str, comp: &mnemonic::Completion) -> Option<String> {
    if typed.is_empty() {
        return None;
    }

    // Hard error states → reject.
    if matches!(comp, mnemonic::Completion::MixedCase | mnemonic::Completion::Ambiguous) {
        return None;
    }

    // If unique shadow exists, accept it.
    if let Some(w) = comp.word() {
        return Some(w.to_string());
    }

    // Full word typed — accept exact matches and near-miss words alike so that
    // mnemonic::decode() can attempt fuzzy correction across the full phrase.
    Some(typed.to_string())
}

// -- camera / status helpers ------------------------------------------------

/// Drain camera log messages and newly scanned shares without corrupting
/// the raw-mode terminal.
fn drain_camera(
    state: &Arc<Mutex<CollectorState>>,
    cam_rx: &mpsc::Receiver<Share>,
    cam_log_rx: &mpsc::Receiver<String>,
    out: &mut impl Write,
) -> Result<()> {
    // Camera log messages.
    while let Ok(msg) = cam_log_rx.try_recv() {
        write!(out, "\r\x1b[2K  {msg}\r\n")?;
    }
    // Camera-scanned shares.
    while let Ok(share) = cam_rx.try_recv() {
        // Keep the critical section small: mutate state and format the status
        // string while holding the lock, then drop the lock before any I/O.
        let (result, status_line) = {
            let mut st = state.lock().unwrap();
            let result = st.try_add(share);
            let total = st.shares.len();
            let threshold = st.threshold.map(|t| t.to_string()).unwrap_or("?".into());
            let remaining = match st.threshold {
                Some(_) => st.remaining().to_string(),
                None => "?".to_string(),
            };
            let xs: Vec<String> = st.shares.iter().map(|s| format!("#{}", s.x)).collect();
            let status = format!(
                "  status: {total}/{threshold} share(s) collected [{}], {remaining} more needed\r\n",
                xs.join(", ")
            );
            (result, status)
        };
        // All terminal I/O happens after the lock is released.
        write!(out, "\r\x1b[2K  camera: {result}\r\n")?;
        write!(out, "{status_line}")?;
    }
    out.flush()?;
    Ok(())
}

fn print_status(st: &CollectorState) {
    let total = st.shares.len();
    let threshold = st.threshold.map(|t| t.to_string()).unwrap_or("?".into());
    let remaining = match st.threshold {
        Some(_) => st.remaining().to_string(),
        None => "?".to_string(),
    };
    let xs: Vec<String> = st.shares.iter().map(|s| format!("#{}", s.x)).collect();
    eprintln!(
        "  status: {total}/{threshold} share(s) collected [{}], {remaining} more needed",
        xs.join(", ")
    );
}

fn write_status(st: &CollectorState, out: &mut impl Write) -> std::io::Result<()> {
    let total = st.shares.len();
    let threshold = st.threshold.map(|t| t.to_string()).unwrap_or("?".into());
    let remaining = match st.threshold {
        Some(_) => st.remaining().to_string(),
        None => "?".to_string(),
    };
    let xs: Vec<String> = st.shares.iter().map(|s| format!("#{}", s.x)).collect();
    write!(
        out,
        "  status: {total}/{threshold} share(s) collected [{}], {remaining} more needed\r\n",
        xs.join(", ")
    )?;
    out.flush()
}

// ---------------------------------------------------------------------------
// Camera scanner window (eframe + nokhwa + rqrr)
// ---------------------------------------------------------------------------

fn run_camera_window(
    state: Arc<Mutex<CollectorState>>,
    tx: mpsc::Sender<Share>,
    log_tx: mpsc::Sender<String>,
) -> Result<()> {
    use eframe::egui;

    // Query available cameras.
    let backend = nokhwa::native_api_backend().context("no camera backend available")?;
    let devices = nokhwa::query(backend).context("failed to query cameras")?;

    if devices.is_empty() {
        anyhow::bail!("no cameras found");
    }

    let _ = log_tx.send(format!("camera: found {} device(s):", devices.len()));
    for (i, dev) in devices.iter().enumerate() {
        let _ = log_tx.send(format!("  [{}] {}", i, dev.human_name()));
    }

    let app = ScannerApp {
        state,
        tx,
        devices: devices.clone(),
        selected_device: 0,
        scanning: true,
        camera: None,
        status_msg: "Starting...".to_string(),
        last_scan_result: String::new(),
        frame_rgb: None,
        frame_texture: None,
        frame_width: 0,
        frame_height: 0,
    };

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("ssscrypt — QR Share Scanner")
            .with_inner_size([640.0, 520.0]),
        // Allow the EventLoop to be created on a non-main thread.
        // Without this, winit panics on Linux when spawned from std::thread::spawn.
        event_loop_builder: Some(Box::new(|builder| {
            use winit::platform::x11::EventLoopBuilderExtX11;
            builder.with_any_thread(true);
        })),
        ..Default::default()
    };

    eframe::run_native(
        "ssscrypt Scanner",
        native_options,
        Box::new(|_cc| Ok(Box::new(app))),
    )
    .map_err(|e| anyhow::anyhow!("eframe error: {e}"))?;

    Ok(())
}

struct ScannerApp {
    state: Arc<Mutex<CollectorState>>,
    tx: mpsc::Sender<Share>,
    devices: Vec<nokhwa::utils::CameraInfo>,
    selected_device: usize,
    scanning: bool,
    camera: Option<nokhwa::Camera>,
    status_msg: String,
    last_scan_result: String,
    frame_rgb: Option<Vec<u8>>,
    frame_texture: Option<eframe::egui::TextureHandle>,
    frame_width: u32,
    frame_height: u32,
}

impl ScannerApp {
    fn open_camera(&mut self) {
        use nokhwa::utils::{CameraIndex, RequestedFormat, RequestedFormatType};

        // Close existing camera.
        self.camera = None;
        self.frame_texture = None;
        self.frame_rgb = None;

        let idx = CameraIndex::Index(self.selected_device as u32);
        let format = RequestedFormat::new::<nokhwa::pixel_format::RgbFormat>(
            RequestedFormatType::AbsoluteHighestResolution,
        );

        match nokhwa::Camera::new(idx, format) {
            Ok(mut cam) => {
                if let Err(e) = cam.open_stream() {
                    self.status_msg = format!("Failed to open stream: {e}");
                    return;
                }
                let res = cam.resolution();
                self.frame_width = res.width();
                self.frame_height = res.height();
                self.status_msg = format!(
                    "Camera: {} ({}×{})",
                    self.devices[self.selected_device].human_name(),
                    res.width(),
                    res.height()
                );
                self.camera = Some(cam);
            }
            Err(e) => {
                self.status_msg = format!("Failed to open camera: {e}");
            }
        }
    }

    fn grab_and_scan(&mut self) {
        let cam = match self.camera.as_mut() {
            Some(c) => c,
            None => return,
        };

        let buffer = match cam.frame() {
            Ok(b) => b,
            Err(_) => return,
        };

        let resolution = buffer.resolution();
        let w = resolution.width();
        let h = resolution.height();

        // Decode buffer to RGB.
        let decoded = match buffer.decode_image::<nokhwa::pixel_format::RgbFormat>() {
            Ok(img) => img,
            Err(_) => return,
        };

        // Store RGB for texture display.
        let rgb_data = decoded.to_vec();
        self.frame_rgb = Some(rgb_data.clone());
        self.frame_width = w;
        self.frame_height = h;

        // Invalidate texture so it gets re-created.
        self.frame_texture = None;

        if !self.scanning {
            return;
        }

        // Check if we're already done.
        {
            let st = self.state.lock().unwrap();
            if st.complete {
                self.last_scan_result = "✓ All shares collected!".to_string();
                return;
            }
        }

        // Convert to grayscale for QR scanning.
        let gray_data: Vec<u8> = rgb_data
            .chunks_exact(3)
            .map(|px| {
                // ITU-R BT.601 luma
                ((px[0] as u32 * 299 + px[1] as u32 * 587 + px[2] as u32 * 114) / 1000) as u8
            })
            .collect();

        if let Some(gray_img) = image::GrayImage::from_raw(w, h, gray_data) {
            let mut prepared = rqrr::PreparedImage::prepare(gray_img);
            let grids = prepared.detect_grids();

            for grid in &grids {
                let mut data = Vec::new();
                if grid.decode_to(&mut data).is_ok() {
                    if let Ok(share) = Share::from_bytes(&data) {
                        let x = share.x;
                        // Send to collector via channel.
                        let _ = self.tx.send(share);
                        self.last_scan_result = format!("Scanned share #{x}!");
                    }
                }
            }
        }
    }
}

impl eframe::App for ScannerApp {
    fn update(&mut self, ctx: &eframe::egui::Context, _frame: &mut eframe::Frame) {
        use eframe::egui;

        // Auto-open camera on first frame.
        if self.camera.is_none() && self.status_msg == "Starting..." {
            self.open_camera();
        }

        // Grab a frame each update cycle.
        self.grab_and_scan();

        // Check if we should close.
        let complete = {
            let st = self.state.lock().unwrap();
            st.complete
        };

        egui::TopBottomPanel::top("controls").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label("Camera:");
                let prev = self.selected_device;
                egui::ComboBox::from_id_salt("cam_select")
                    .selected_text(
                        self.devices
                            .get(self.selected_device)
                            .map(|d| d.human_name())
                            .unwrap_or_else(|| "None".to_string()),
                    )
                    .show_ui(ui, |ui| {
                        for (i, dev) in self.devices.iter().enumerate() {
                            ui.selectable_value(&mut self.selected_device, i, dev.human_name());
                        }
                    });
                if self.selected_device != prev {
                    self.open_camera();
                }

                ui.separator();

                let btn_label = if self.scanning {
                    "⏸ Pause"
                } else {
                    "▶ Scan"
                };
                if ui.button(btn_label).clicked() {
                    self.scanning = !self.scanning;
                }
            });
        });

        egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                let st = self.state.lock().unwrap();
                let total = st.shares.len();
                let threshold = st.threshold.map(|t| t.to_string()).unwrap_or("?".into());
                ui.label(format!("Shares: {total}/{threshold}"));
                ui.separator();
                ui.label(&self.status_msg);
                ui.separator();
                ui.label(&self.last_scan_result);
                if st.complete {
                    ui.separator();
                    ui.colored_label(egui::Color32::GREEN, "✓ COMPLETE");
                }
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            // Display the camera frame as a texture.
            if let Some(rgb) = &self.frame_rgb {
                let w = self.frame_width as usize;
                let h = self.frame_height as usize;

                if self.frame_texture.is_none() && w > 0 && h > 0 {
                    // Convert RGB to egui ColorImage.
                    let pixels: Vec<egui::Color32> = rgb
                        .chunks_exact(3)
                        .map(|p| egui::Color32::from_rgb(p[0], p[1], p[2]))
                        .collect();

                    if pixels.len() == w * h {
                        let color_image = egui::ColorImage {
                            size: [w, h],
                            pixels,
                            source_size: egui::Vec2::new(w as f32, h as f32),
                        };
                        self.frame_texture = Some(ctx.load_texture(
                            "camera_frame",
                            color_image,
                            egui::TextureOptions::LINEAR,
                        ));
                    }
                }

                if let Some(tex) = &self.frame_texture {
                    let available = ui.available_size();
                    let aspect = w as f32 / h.max(1) as f32;
                    let display_w = available.x.min(available.y * aspect);
                    let display_h = display_w / aspect;

                    ui.centered_and_justified(|ui| {
                        ui.image(egui::load::SizedTexture::new(
                            tex.id(),
                            egui::vec2(display_w, display_h),
                        ));
                    });
                }
            } else {
                ui.centered_and_justified(|ui| {
                    ui.label("No camera frame yet...");
                });
            }
        });

        // Auto-close when collection is complete; otherwise keep repainting.
        if complete {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        } else {
            ctx.request_repaint();
        }
    }
}
