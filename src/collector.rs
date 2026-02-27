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
    pub seen_x: HashSet<u8>,
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
        let k = self.threshold.unwrap_or(2) as usize;
        k.saturating_sub(self.shares.len())
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
    Accepted(u8),
    Duplicate(u8),
    InvalidSignature(u8, String),
    PubkeyMismatch(u8),
    PubkeyPrefixMismatch(u8),
    ThresholdMismatch(u8, u8, u8),
    /// Mnemonic share accepted but without signature verification —
    /// the 4-byte pubkey prefix matched.
    AcceptedMnemonic(u8),
    /// Mnemonic share accepted without prefix verification (no context yet).
    AcceptedMnemonicUnverified(u8),
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
                write!(f, "share #{x} rejected: pubkey does not match existing shares")
            }
            AddResult::PubkeyPrefixMismatch(x) => {
                write!(f, "share #{x} rejected: pubkey prefix does not match existing shares")
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
            st.remaining()
        );
        if st.complete {
            eprintln!("  enough shares — skipping interactive mode");
            let threshold = st.threshold.ok_or_else(|| anyhow::anyhow!("threshold unknown"))?;
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
            if let Err(e) = run_camera_window(cam_state, cam_tx2) {
                eprintln!("  camera: {e}");
            }
        }))
    };

    // Drop our sender so cam_rx will close when the camera thread drops its copy.
    drop(cam_tx);

    // ----- Phase 3: Terminal mnemonic input loop -----
    run_terminal_loop(&state, &cam_rx)?;

    // ----- Cleanup -----
    // If camera thread is still running, it will exit when it sees complete=true.
    if let Some(handle) = camera_handle {
        let _ = handle.join();
    }

    let st = state.lock().unwrap();
    if st.shares.is_empty() {
        bail!("no shares collected");
    }
    let threshold = st.threshold.ok_or_else(|| anyhow::anyhow!(
        "threshold unknown — need at least one file/QR share or --anchor-encrypted"
    ))?;
    let pubkey = st.pubkey.ok_or_else(|| anyhow::anyhow!(
        "pubkey unknown — need at least one file/QR share or --anchor-encrypted"
    ))?;
    Ok(CollectedShares {
        shares: st.shares.clone(),
        threshold,
        pubkey,
    })
}

// ---------------------------------------------------------------------------
// Terminal mnemonic input loop
// ---------------------------------------------------------------------------

fn run_terminal_loop(
    state: &Arc<Mutex<CollectorState>>,
    cam_rx: &mpsc::Receiver<Share>,
) -> Result<()> {
    use std::io::{self, BufRead, Write};

    print_status(&state.lock().unwrap());
    eprintln!();
    eprintln!("Enter mnemonic words (28 space-separated tokens per share),");
    eprintln!("or type 'done'/'quit' to stop. Words can span multiple lines.");
    eprintln!("Tab-complete: type first few chars. Case matters (UPPER=1, lower=0).");
    eprintln!();

    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let mut accumulated_words: Vec<String> = Vec::new();

    loop {
        // Check for shares arriving from the camera thread.
        while let Ok(share) = cam_rx.try_recv() {
            let mut st = state.lock().unwrap();
            let result = st.try_add(share);
            eprintln!("  camera: {result}");
            print_status(&st);
            if st.complete {
                eprintln!("\n  ✓ Enough shares collected!");
                return Ok(());
            }
        }

        // Check if we're already done.
        {
            let st = state.lock().unwrap();
            if st.complete {
                eprintln!("\n  ✓ Enough shares collected!");
                return Ok(());
            }
        }

        // Prompt.
        let word_count = accumulated_words.len();
        if word_count > 0 {
            eprint!("[{}/{}] > ", word_count, MNEMONIC_WORDS);
        } else {
            eprint!("mnemonic > ");
        }
        io::stderr().flush().ok();

        let mut line = String::new();
        let n = reader.read_line(&mut line).context("read stdin")?;
        if n == 0 {
            // EOF
            eprintln!("\n  stdin closed");
            return Ok(());
        }

        let line = line.trim();
        if line.eq_ignore_ascii_case("done") || line.eq_ignore_ascii_case("quit") {
            eprintln!("  stopped by user");
            return Ok(());
        }
        if line.eq_ignore_ascii_case("status") {
            print_status(&state.lock().unwrap());
            continue;
        }
        if line.is_empty() {
            continue;
        }

        // Collect words from this line.
        for token in line.split_whitespace() {
            // Tab-complete: if token ends with '?', show completions.
            if token.ends_with('?') {
                let prefix = &token[..token.len() - 1];
                let completions = mnemonic::tab_complete(prefix);
                if completions.is_empty() {
                    eprintln!("  no completions for '{prefix}'");
                } else {
                    eprintln!("  completions: {}", completions.join(", "));
                }
                continue;
            }

            // Validate word on the fly.
            match mnemonic::validate_word(token) {
                mnemonic::WordValidation::Valid(_) => {
                    accumulated_words.push(token.to_string());
                }
                mnemonic::WordValidation::NearMiss { input, suggestions } => {
                    eprintln!(
                        "  warning: '{}' not exact — did you mean: {}?",
                        input,
                        suggestions
                            .iter()
                            .map(|s| format!("'{}' (d={})", s.word, s.distance))
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                    // Accept it anyway, decode() will fuzzy-correct.
                    accumulated_words.push(token.to_string());
                }
                mnemonic::WordValidation::Unknown(w) => {
                    eprintln!("  error: '{w}' is not in the wordlist and no close match found");
                    eprintln!("  skipping this word — try again");
                    continue;
                }
            }
        }

        // If we've accumulated 28 words, try to decode.
        if accumulated_words.len() >= MNEMONIC_WORDS {
            let words: Vec<&str> = accumulated_words[..MNEMONIC_WORDS]
                .iter()
                .map(|s| s.as_str())
                .collect();

            match try_decode_mnemonic(&words) {
                Ok(payload) => {
                    let mut st = state.lock().unwrap();
                    let result = st.try_add_mnemonic(payload);
                    eprintln!("  mnemonic: {result}");
                    print_status(&st);
                    accumulated_words.clear();
                    if st.complete {
                        eprintln!("\n  ✓ Enough shares collected!");
                        return Ok(());
                    }
                }
                Err(e) => {
                    eprintln!("  mnemonic decode error: {e}");
                    eprintln!("  clearing words — please re-enter this share");
                    accumulated_words.clear();
                }
            }

            // Drain any excess words beyond 28 into the next batch.
            if accumulated_words.len() > MNEMONIC_WORDS {
                let overflow: Vec<String> =
                    accumulated_words.drain(MNEMONIC_WORDS..).collect();
                accumulated_words = overflow;
            }
        }
    }
}

/// Decode a 28-word mnemonic into a `MnemonicPayload`.
///
/// The mnemonic only encodes x + y + pubkey_prefix (37 bytes).
/// The caller is responsible for matching the prefix against the known
/// pubkey and filling in threshold/group/signature from context.
fn try_decode_mnemonic(words: &[&str]) -> Result<MnemonicPayload> {
    let (payload, corrections) = mnemonic::decode(words)?;

    for corr in &corrections {
        eprintln!(
            "  auto-corrected word #{}: '{}' → '{}'{}",
            corr.position,
            corr.input,
            corr.corrected,
            if corr.alternatives.is_empty() {
                String::new()
            } else {
                format!(" (also: {})", corr.alternatives.join(", "))
            }
        );
    }

    Ok(payload)
}

fn print_status(st: &CollectorState) {
    let total = st.shares.len();
    let threshold = st.threshold.map(|t| t.to_string()).unwrap_or("?".into());
    let remaining = st.remaining();
    let xs: Vec<String> = st.shares.iter().map(|s| format!("#{}", s.x)).collect();
    eprintln!(
        "  status: {total}/{threshold} share(s) collected [{}], {remaining} more needed",
        xs.join(", ")
    );
}

// ---------------------------------------------------------------------------
// Camera scanner window (eframe + nokhwa + rqrr)
// ---------------------------------------------------------------------------

fn run_camera_window(
    state: Arc<Mutex<CollectorState>>,
    tx: mpsc::Sender<Share>,
) -> Result<()> {
    use eframe::egui;

    // Query available cameras.
    let backend = nokhwa::native_api_backend().context("no camera backend available")?;
    let devices = nokhwa::query(backend).context("failed to query cameras")?;

    if devices.is_empty() {
        anyhow::bail!("no cameras found");
    }

    eprintln!("  camera: found {} device(s):", devices.len());
    for (i, dev) in devices.iter().enumerate() {
        eprintln!("    [{}] {}", i, dev.human_name());
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
                            ui.selectable_value(
                                &mut self.selected_device,
                                i,
                                dev.human_name(),
                            );
                        }
                    });
                if self.selected_device != prev {
                    self.open_camera();
                }

                ui.separator();

                let btn_label = if self.scanning { "⏸ Pause" } else { "▶ Scan" };
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

        // Request repaint to keep camera feed live.
        if !complete {
            ctx.request_repaint();
        }
    }
}
