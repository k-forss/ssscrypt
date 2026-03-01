use crate::crypto;
use crate::encrypted::EncryptedFile;
use crate::io;
use crate::share::Share;
use crate::sss;
use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use std::io::{BufRead, Write};
use std::path::PathBuf;
use time::macros::format_description;
use time::OffsetDateTime;
use zeroize::{Zeroize, Zeroizing};

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Encrypt a file and split the key into K-of-N shares (QR cards + mnemonic words)
    Encrypt(EncryptArgs),
    /// Decrypt a file by reconstructing the key from shares
    Decrypt(DecryptArgs),
    /// Rotate: decrypt with old shares, re-encrypt with a fresh key and new shares
    Rotate(RotateArgs),
    /// Re-split an existing key into a new set of shares (same key, new share files)
    GenShares(GenSharesArgs),
    /// X.509 certificate helpers: create a root CA or sign a CSR (pure Rust, no OpenSSL)
    #[command(subcommand)]
    X509(X509Command),
}

// ---------------------------------------------------------------------------
// Shared arg groups
// ---------------------------------------------------------------------------

/// Args for creating new shares (output).
#[derive(Args, Debug)]
pub struct SharesOutputArgs {
    /// Threshold K — minimum shares required to reconstruct the key.
    /// If omitted, inherited from the existing shares being collected.
    #[arg(short = 'k', long)]
    pub threshold: Option<u8>,

    /// Total number of shares N to create
    #[arg(short = 'n', long)]
    pub num_shares: u8,

    /// Directory to write new share files into
    #[arg(long)]
    pub new_shares_dir: PathBuf,
}

/// Args for file input/output (both default to stdin/stdout).
#[derive(Args, Debug)]
pub struct IoArgs {
    /// Input file (defaults to stdin)
    #[arg(long, value_name = "FILE")]
    pub r#in: Option<PathBuf>,

    /// Output file (defaults to stdout)
    #[arg(long, value_name = "FILE")]
    pub out: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// Per-command args
// ---------------------------------------------------------------------------

#[derive(Args, Debug)]
pub struct EncryptArgs {
    #[command(flatten)]
    pub io: IoArgs,

    /// Directory containing existing *.share.txt files to reconstruct key from (⚠ unanchored)
    #[arg(long)]
    pub shares_dir: Option<PathBuf>,

    /// Threshold K — minimum shares required to reconstruct the key
    #[arg(short = 'k', long)]
    pub threshold: Option<u8>,

    /// Total number of shares N to create
    #[arg(short = 'n', long)]
    pub num_shares: Option<u8>,

    /// Directory to write new share files into
    #[arg(long)]
    pub new_shares_dir: Option<PathBuf>,

    /// Human-readable group name (e.g. certificate name)
    #[arg(long, default_value = "")]
    pub group: String,

    #[command(flatten)]
    pub pin: PinArgs,
}

#[derive(Args, Debug)]
pub struct DecryptArgs {
    #[command(flatten)]
    pub io: IoArgs,

    /// Directory containing *.share.txt files (optional; interactive collection otherwise)
    #[arg(long)]
    pub shares_dir: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct RotateArgs {
    #[command(flatten)]
    pub io: IoArgs,

    /// Directory containing existing *.share.txt files (optional; interactive collection otherwise)
    #[arg(long)]
    pub shares_dir: Option<PathBuf>,

    /// New shares to create for the re-encrypted file
    #[command(flatten)]
    pub new_shares: SharesOutputArgs,

    /// Human-readable group name for new shares/file (e.g. certificate name)
    #[arg(long, default_value = "")]
    pub group: String,
}

/// Pubkey pinning for unanchored operations.
#[derive(Args, Debug)]
pub struct PinArgs {
    /// Pin expected pubkey (full 64-character hex, e.g. the pk printed during key creation)
    #[arg(long)]
    pub pin_pubkey: Option<String>,

    /// Pin expected pubkey fingerprint (hex prefix, e.g. first 16 chars from share card)
    #[arg(long)]
    pub pin_fpr: Option<String>,

    /// Extract expected pubkey from an existing encrypted file's header
    #[arg(long, value_name = "FILE")]
    pub anchor_encrypted: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct GenSharesArgs {
    /// Directory containing existing *.share.txt files (optional; interactive collection otherwise)
    #[arg(long)]
    pub shares_dir: Option<PathBuf>,

    /// Total number of new shares N to create
    #[arg(short = 'n', long)]
    pub num_shares: u8,

    /// Directory to write new share files into
    #[arg(long)]
    pub new_shares_dir: PathBuf,

    #[command(flatten)]
    pub pin: PinArgs,
}

// ---------------------------------------------------------------------------
// X.509 subcommands
// ---------------------------------------------------------------------------

#[derive(Subcommand, Debug)]
pub enum X509Command {
    /// Create a self-signed root CA, encrypt its private key, and split into shares
    CreateRoot(CreateRootArgs),
    /// Sign a CSR using an encrypted CA key (reconstructed from shares)
    SignCsr(SignCsrArgs),
}

#[derive(Args, Debug)]
pub struct CreateRootArgs {
    /// Common Name for the root certificate
    #[arg(long)]
    pub cn: Option<String>,

    /// Organization name
    #[arg(long)]
    pub org: Option<String>,

    /// Certificate validity in days
    #[arg(long)]
    pub days: Option<u32>,

    /// Certificate not-before date (YYYY-MM-DD); defaults to system clock.
    /// Use this on air-gapped machines where the RTC may be wrong.
    #[arg(long, value_name = "DATE")]
    pub not_before: Option<String>,
    #[arg(long)]
    pub out_cert: Option<PathBuf>,

    /// Output encrypted private key file (ssscrypt format)
    #[arg(long)]
    pub out_key_enc: Option<PathBuf>,

    /// Threshold K — minimum shares required to decrypt the key
    #[arg(short = 'k', long)]
    pub threshold: Option<u8>,

    /// Total number of shares N to create
    #[arg(short = 'n', long)]
    pub num_shares: Option<u8>,

    /// Directory to write share files into
    #[arg(long)]
    pub new_shares_dir: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct SignCsrArgs {
    /// Encrypted CA key file (ssscrypt format)
    #[arg(long)]
    pub key_enc: Option<PathBuf>,

    /// Issuer certificate PEM file
    #[arg(long)]
    pub issuer_cert: Option<PathBuf>,

    /// CSR to sign (PEM format)
    #[arg(long)]
    pub csr: Option<PathBuf>,

    /// Output signed certificate PEM file
    #[arg(long)]
    pub out_cert: Option<PathBuf>,

    /// Certificate validity in days
    #[arg(long)]
    pub days: Option<u32>,

    /// Certificate not-before date (YYYY-MM-DD); defaults to system clock.
    /// Use this on air-gapped machines where the RTC may be wrong.
    #[arg(long, value_name = "DATE")]
    pub not_before: Option<String>,

    /// Mark the issued certificate as a CA (skip prompt)
    #[arg(long)]
    pub is_ca: bool,

    /// Basic constraints pathlen (only relevant with --is-ca)
    #[arg(long)]
    pub pathlen: Option<u8>,

    /// Directory containing *.share.txt files (optional; interactive collection otherwise)
    #[arg(long)]
    pub shares_dir: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

pub fn run(command: Command) -> Result<()> {
    match command {
        Command::Encrypt(args) => encrypt(args),
        Command::Decrypt(args) => decrypt(args),
        Command::Rotate(args) => rotate(args),
        Command::GenShares(args) => gen_shares(args),
        Command::X509(sub) => match sub {
            X509Command::CreateRoot(args) => x509_create_root(args),
            X509Command::SignCsr(args) => x509_sign_csr(args),
        },
    }
}

// ---------------------------------------------------------------------------
// Command implementations
// ---------------------------------------------------------------------------

fn encrypt(args: EncryptArgs) -> Result<()> {
    let has_existing = args.shares_dir.is_some()
        || args.pin.pin_pubkey.is_some()
        || args.pin.anchor_encrypted.is_some();
    let has_new =
        args.threshold.is_some() || args.num_shares.is_some() || args.new_shares_dir.is_some();

    if !has_existing && !has_new {
        bail!(
            "Provide either --shares-dir (encrypt with existing key) \
             or --threshold/--num-shares/--new-shares-dir (generate new key)"
        );
    }

    // If creating new shares, all three are required.
    let new_share_params = if has_new {
        let threshold = args
            .threshold
            .ok_or_else(|| anyhow::anyhow!("--threshold required when creating new shares"))?;
        let num_shares = args
            .num_shares
            .ok_or_else(|| anyhow::anyhow!("--num-shares required when creating new shares"))?;
        let dir = args
            .new_shares_dir
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("--new-shares-dir required when creating new shares"))?
            .clone();
        validate_threshold(threshold, num_shares)?;
        Some((threshold, num_shares, dir))
    } else {
        None
    };

    // Read plaintext.
    let plaintext = Zeroizing::new(io::read_input(&args.io)?);
    eprintln!("encrypt: read {} bytes of plaintext", plaintext.len());

    // Obtain master key.
    let (master, existing_threshold) = if has_existing {
        // Resolve anchor for unanchored operation.
        let anchor = resolve_anchor(&args.pin)?;
        let pubkey_anchor = anchor.as_ref().and_then(|a| match a {
            ResolvedAnchor::Pubkey(pk) => Some(pk),
            ResolvedAnchor::FingerprintPrefix(_) => None,
        });
        let collected = gather_shares(args.shares_dir.as_deref(), pubkey_anchor, None)?;
        eprintln!(
            "encrypt: reconstructing key from {} share(s)",
            collected.shares.len()
        );
        let raw = crypto::shares_to_raw(&collected.shares);
        let master = Zeroizing::new(sss::combine(&raw, collected.threshold)?);

        // Post-reconstruction fingerprint verification.
        if let Some(ResolvedAnchor::FingerprintPrefix(ref prefix)) = anchor {
            verify_fingerprint_pin(&master, prefix)?;
        }

        (master, Some((collected.threshold, collected.pubkey)))
    } else {
        let key = Zeroizing::new(crypto::generate_master_key());
        eprintln!("encrypt: generated new random master key");
        (key, None)
    };

    // Derive keys.
    let threshold_hint = new_share_params
        .as_ref()
        .map(|(k, _, _)| *k)
        .or(existing_threshold.map(|(t, _)| t))
        .unwrap_or(2);
    let keys = crypto::derive_keys(&master);

    // Print key identity for TOFU (trust on first use).
    let pk = crypto::pubkey_bytes(&keys.signing);
    let fpr = crypto::pubkey_fingerprint(&pk);
    eprintln!(
        "encrypt: key fingerprint: {}",
        crypto::format_fingerprint(&fpr)
    );

    // Verify derived pubkey matches if using existing key.
    if let Some((_, expected_pk)) = existing_threshold {
        let derived_pk = crypto::pubkey_bytes(&keys.signing);
        if derived_pk != expected_pk {
            bail!(
                "derived pubkey does not match share pubkey — wrong shares or share substitution?"
            );
        }
        eprintln!("encrypt: verified pubkey from shares");
    }

    // Encrypt.
    let encrypted = crypto::encrypt(&plaintext, &keys, threshold_hint, &args.group)?;
    eprintln!(
        "encrypt: ciphertext {} bytes (plaintext {} + tag 16)",
        encrypted.ciphertext.len(),
        plaintext.len()
    );

    // Write encrypted output (text format).
    io::write_output(&args.io, encrypted.to_text().as_bytes())?;
    eprintln!("encrypt: wrote encrypted output");

    // Split and write shares if requested.
    if let Some((threshold, share_count, dir)) = new_share_params {
        let raw_shares = sss::split(&master, threshold, share_count)?;
        let signed_shares: Result<Vec<Share>> = raw_shares
            .iter()
            .map(|r| crypto::sign_share(r, &keys, threshold, &args.group))
            .collect();
        io::write_shares(&dir, &signed_shares?)?;
        eprintln!(
            "encrypt: wrote {}-of-{} shares to {:?}",
            threshold, share_count, dir
        );
    }

    // plaintext, master, and keys are all zeroized on drop.
    Ok(())
}

fn decrypt(args: DecryptArgs) -> Result<()> {
    // Read encrypted file.
    let data = io::read_input(&args.io)?;
    eprintln!("decrypt: read {} bytes", data.len());

    let encrypted = EncryptedFile::parse(&data).context("failed to parse encrypted file")?;
    eprintln!("decrypt: {}", encrypted.header);

    // Gather shares — anchor pubkey and threshold from header.
    let anchor = encrypted.header.pubkey;
    let threshold = encrypted.header.threshold;
    let collected = gather_shares(args.shares_dir.as_deref(), Some(&anchor), Some(threshold))?;

    // Reconstruct master key.
    let raw = crypto::shares_to_raw(&collected.shares);
    let master = Zeroizing::new(sss::combine(&raw, collected.threshold)?);
    let keys = crypto::derive_keys(&master);

    // Decrypt.
    let plaintext = Zeroizing::new(crypto::decrypt(&encrypted, &keys)?);
    eprintln!("decrypt: decrypted {} bytes of plaintext", plaintext.len());

    // Write plaintext.
    io::write_output(&args.io, &plaintext)?;

    // plaintext, master, and keys are all zeroized on drop.
    Ok(())
}

fn rotate(args: RotateArgs) -> Result<()> {
    // Read encrypted file.
    let data = io::read_input(&args.io)?;
    eprintln!("rotate: read {} bytes", data.len());

    let encrypted = EncryptedFile::parse(&data).context("failed to parse encrypted file")?;

    // Gather old shares — anchor from header.
    let anchor = encrypted.header.pubkey;
    let threshold = encrypted.header.threshold;
    let collected = gather_shares(args.shares_dir.as_deref(), Some(&anchor), Some(threshold))?;

    let raw = crypto::shares_to_raw(&collected.shares);
    let old_master = Zeroizing::new(sss::combine(&raw, collected.threshold)?);
    let old_keys = crypto::derive_keys(&old_master);
    let plaintext = Zeroizing::new(crypto::decrypt(&encrypted, &old_keys)?);
    eprintln!("rotate: decrypted {} bytes", plaintext.len());

    // Zeroize old key material as soon as it's no longer needed.
    drop(old_master);
    drop(old_keys);

    // Resolve new threshold: explicit flag > inherited from old shares.
    let new_threshold = args.new_shares.threshold.unwrap_or(collected.threshold);
    validate_threshold(new_threshold, args.new_shares.num_shares)?;

    // Generate new key, encrypt, split.
    let new_master = Zeroizing::new(crypto::generate_master_key());
    let new_keys = crypto::derive_keys(&new_master);
    let new_encrypted = crypto::encrypt(&plaintext, &new_keys, new_threshold, &args.group)?;

    // plaintext is no longer needed once encrypted; drop it eagerly.
    drop(plaintext);

    // Write re-encrypted output (text format).
    io::write_output(&args.io, new_encrypted.to_text().as_bytes())?;
    eprintln!("rotate: wrote re-encrypted output");

    // Write new shares.
    let new_raw = sss::split(&new_master, new_threshold, args.new_shares.num_shares)?;
    let new_signed: Result<Vec<Share>> = new_raw
        .iter()
        .map(|r| crypto::sign_share(r, &new_keys, new_threshold, &args.group))
        .collect();
    io::write_shares(&args.new_shares.new_shares_dir, &new_signed?)?;
    eprintln!(
        "rotate: wrote {}-of-{} new shares to {:?}",
        new_threshold, args.new_shares.num_shares, args.new_shares.new_shares_dir
    );

    // new_master and new_keys are zeroized on drop.
    Ok(())
}

fn gen_shares(args: GenSharesArgs) -> Result<()> {
    // Resolve anchor for unanchored operation.
    let anchor = resolve_anchor(&args.pin)?;
    let pubkey_anchor = anchor.as_ref().and_then(|a| match a {
        ResolvedAnchor::Pubkey(pk) => Some(pk),
        ResolvedAnchor::FingerprintPrefix(_) => None,
    });

    // Gather old shares.
    let collected = gather_shares(args.shares_dir.as_deref(), pubkey_anchor, None)?;

    // Threshold and group are inherited from the collected shares — gen-shares
    // re-splits the same key, so these properties must not change.
    let threshold = collected.threshold;
    let group = collected
        .shares
        .first()
        .map(|s| s.group.clone())
        .unwrap_or_default();
    validate_threshold(threshold, args.num_shares)?;

    // Reconstruct master key.
    let raw = crypto::shares_to_raw(&collected.shares);
    let master = Zeroizing::new(sss::combine(&raw, collected.threshold)?);
    let keys = crypto::derive_keys(&master);

    // Post-reconstruction fingerprint verification.
    if let Some(ResolvedAnchor::FingerprintPrefix(ref prefix)) = anchor {
        verify_fingerprint_pin(&master, prefix)?;
    }

    // Verify derived pubkey matches.
    let derived_pk = crypto::pubkey_bytes(&keys.signing);
    if derived_pk != collected.pubkey {
        bail!("derived pubkey does not match share pubkey — reconstruction error?");
    }

    // Split into new shares with random x values to minimize collision
    // with any outstanding shares we don't know about.
    let exclude_xs: Vec<u32> = collected.shares.iter().map(|s| s.x).collect();
    let new_raw = sss::split_random_x(&master, threshold, args.num_shares, &exclude_xs)?;
    let new_signed: Result<Vec<Share>> = new_raw
        .iter()
        .map(|r| crypto::sign_share(r, &keys, threshold, &group))
        .collect();
    io::write_shares(&args.new_shares_dir, &new_signed?)?;
    eprintln!(
        "gen-shares: wrote {}-of-{} new shares to {:?} (random x values)",
        threshold, args.num_shares, args.new_shares_dir
    );

    // master and keys are zeroized on drop.
    Ok(())
}

// ---------------------------------------------------------------------------
// X.509 command implementations
// ---------------------------------------------------------------------------

fn x509_create_root(args: CreateRootArgs) -> Result<()> {
    eprintln!("x509: Create self-signed root CA\n");

    // Resolve values — prompt for anything not provided on the command line.
    let cn = match args.cn {
        Some(v) => v,
        None => prompt("Common Name (CN)", Some("Homelab Root CA"))?,
    };
    let org = match args.org {
        Some(v) => Some(v),
        None => {
            let v = prompt("Organization (O, empty to skip)", Some(""))?;
            if v.is_empty() {
                None
            } else {
                Some(v)
            }
        }
    };
    let days: u32 = match args.days {
        Some(d) => d,
        None => prompt("Validity (days)", Some("3650"))?
            .parse()
            .context("invalid number for days")?,
    };
    let out_cert = match args.out_cert {
        Some(p) => p,
        None => PathBuf::from(prompt("Output certificate", Some("root-ca.pem"))?),
    };
    let out_key_enc = match args.out_key_enc {
        Some(p) => p,
        None => PathBuf::from(prompt("Output encrypted key", Some("root-key.enc"))?),
    };
    let threshold: u8 = match args.threshold {
        Some(t) => t,
        None => prompt("Threshold (K)", None)?
            .parse()
            .context("invalid number for threshold")?,
    };
    let shares: u8 = match args.num_shares {
        Some(s) => s,
        None => prompt("Total shares (N)", None)?
            .parse()
            .context("invalid number for shares")?,
    };
    let new_shares_dir = match args.new_shares_dir {
        Some(d) => d,
        None => PathBuf::from(prompt("Shares directory", Some("shares"))?),
    };

    eprintln!();
    validate_threshold(threshold, shares)?;

    // Resolve the not-before date (system clock unless --not-before was given).
    let not_before = resolve_not_before(args.not_before.as_deref())?;
    let not_after = not_before + time::Duration::days(days as i64);
    eprintln!(
        "x509: validity: {} → {}",
        not_before.date(),
        not_after.date()
    );

    // Generate root CA certificate + key pair.
    let (cert_pem, key_pem) =
        crate::x509::create_self_signed_root(&cn, org.as_deref(), days, not_before)?;
    eprintln!("x509: generated self-signed root CA: {}", cn);

    // Write certificate PEM.
    std::fs::write(&out_cert, &cert_pem).with_context(|| format!("write cert {:?}", out_cert))?;

    // Encrypt the private key using ssscrypt.
    let group = cn.clone();
    let master = Zeroizing::new(crypto::generate_master_key());
    let keys = crypto::derive_keys(&master);

    // Print key identity for TOFU — record this fingerprint offline.
    let pk = crypto::pubkey_bytes(&keys.signing);
    let fpr = crypto::pubkey_fingerprint(&pk);
    eprintln!(
        "x509: key fingerprint: {}  ← record this for --pin-fpr",
        crypto::format_fingerprint(&fpr)
    );

    let encrypted = crypto::encrypt(key_pem.as_bytes(), &keys, threshold, &group)?;

    // Zeroize the plaintext CA private key now that it's encrypted.
    let mut key_pem = key_pem;
    key_pem.zeroize();

    // Write encrypted key file (text format).
    std::fs::write(&out_key_enc, encrypted.to_text().as_bytes())
        .with_context(|| format!("write encrypted key {:?}", out_key_enc))?;
    eprintln!("x509: wrote encrypted key: {:?}", out_key_enc);

    // Split master key into shares and write.
    let raw_shares = sss::split(&master, threshold, shares)?;
    let signed_shares: Result<Vec<Share>> = raw_shares
        .iter()
        .map(|r| crypto::sign_share(r, &keys, threshold, &group))
        .collect();
    io::write_shares(&new_shares_dir, &signed_shares?)?;
    eprintln!(
        "x509: wrote {}-of-{} shares to {:?}",
        threshold, shares, new_shares_dir
    );

    // master and keys are zeroized on drop.
    Ok(())
}

fn x509_sign_csr(args: SignCsrArgs) -> Result<()> {
    eprintln!("x509: Sign CSR\n");

    // Resolve values — prompt for anything not provided on the command line.
    let key_enc = match args.key_enc {
        Some(p) => p,
        None => PathBuf::from(prompt("Encrypted CA key file", Some("root-key.enc"))?),
    };
    let issuer_cert = match args.issuer_cert {
        Some(p) => p,
        None => PathBuf::from(prompt("Issuer certificate PEM", Some("root-ca.pem"))?),
    };
    let csr_path = match args.csr {
        Some(p) => p,
        None => PathBuf::from(prompt("CSR to sign (PEM)", None)?),
    };
    let out_cert = match args.out_cert {
        Some(p) => p,
        None => PathBuf::from(prompt("Output signed certificate", Some("signed.pem"))?),
    };
    let days: u32 = match args.days {
        Some(d) => d,
        None => prompt("Validity (days)", Some("1825"))?
            .parse()
            .context("invalid number for days")?,
    };
    let is_ca = if args.is_ca {
        true
    } else {
        prompt_yes_no("Issue as CA certificate?", false)?
    };
    let pathlen = if is_ca {
        match args.pathlen {
            Some(p) => Some(p),
            None => {
                let v = prompt("Path length constraint (empty = unconstrained)", Some(""))?;
                if v.is_empty() {
                    None
                } else {
                    Some(v.parse().context("invalid path length")?)
                }
            }
        }
    } else {
        None
    };
    let shares_dir: Option<PathBuf> = match args.shares_dir {
        Some(d) => Some(d),
        None => {
            let v = prompt("Shares directory (empty for interactive)", Some(""))?;
            if v.is_empty() {
                None
            } else {
                Some(PathBuf::from(v))
            }
        }
    };

    eprintln!();

    // Read encrypted key file.
    let enc_data =
        std::fs::read(&key_enc).with_context(|| format!("read encrypted key {:?}", key_enc))?;
    let encrypted = EncryptedFile::parse(&enc_data).context("parse encrypted key file")?;
    eprintln!("x509: encrypted key: {}", encrypted.header);

    // Read issuer certificate and CSR.
    let issuer_cert_pem = std::fs::read_to_string(&issuer_cert)
        .with_context(|| format!("read issuer cert {:?}", issuer_cert))?;
    let csr_pem =
        std::fs::read_to_string(&csr_path).with_context(|| format!("read CSR {:?}", csr_path))?;

    // Gather shares to decrypt the CA key (anchored by the encrypted file's pubkey).
    let anchor = encrypted.header.pubkey;
    let threshold = encrypted.header.threshold;
    let collected = gather_shares(shares_dir.as_deref(), Some(&anchor), Some(threshold))?;

    // Reconstruct master key and decrypt the CA private key.
    let raw = crypto::shares_to_raw(&collected.shares);
    let master = Zeroizing::new(sss::combine(&raw, collected.threshold)?);
    let keys = crypto::derive_keys(&master);
    let key_pem_bytes = crypto::decrypt(&encrypted, &keys)?;
    let mut key_pem =
        String::from_utf8(key_pem_bytes).context("decrypted key is not valid UTF-8")?;
    eprintln!("x509: decrypted CA private key");

    // Zeroize key material eagerly before signing.
    drop(master);
    drop(keys);

    // Resolve the not-before date (system clock unless --not-before was given).
    let not_before = resolve_not_before(args.not_before.as_deref())?;
    let not_after = not_before + time::Duration::days(days as i64);
    eprintln!(
        "x509: validity: {} → {}",
        not_before.date(),
        not_after.date()
    );

    // Sign the CSR.
    let signed_pem = crate::x509::sign_csr(
        &csr_pem,
        &issuer_cert_pem,
        &key_pem,
        days,
        not_before,
        is_ca,
        pathlen,
    )?;
    eprintln!("x509: signed certificate");

    // Zeroize the decrypted private key.
    key_pem.zeroize();

    // Write signed certificate.
    std::fs::write(&out_cert, &signed_pem)
        .with_context(|| format!("write signed cert {:?}", out_cert))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Gather shares for key reconstruction via the interactive collector.
///
/// The collector loads any shares from `shares_dir` first, then prompts
/// for remaining shares via terminal mnemonic input and (optionally)
/// a live camera QR scanner window.
///
/// If the folder already contains enough shares the collector returns
/// immediately without prompting.
fn gather_shares(
    shares_dir: Option<&std::path::Path>,
    anchor: Option<&[u8; 32]>,
    threshold_hint: Option<u8>,
) -> Result<crypto::ValidatedShares> {
    let collected = crate::collector::collect_shares(shares_dir, anchor, threshold_hint)?;
    Ok(crypto::ValidatedShares {
        shares: collected.shares,
        threshold: collected.threshold,
        pubkey: collected.pubkey,
    })
}

fn validate_threshold(threshold: u8, shares: u8) -> Result<()> {
    if threshold < 2 {
        bail!("threshold must be at least 2");
    }
    if shares < threshold {
        bail!("shares ({shares}) must be >= threshold ({threshold})");
    }
    Ok(())
}

/// Parse a `--not-before YYYY-MM-DD` value into an `OffsetDateTime` at midnight UTC.
///
/// Returns `now_utc()` when `None` is supplied.
fn resolve_not_before(raw: Option<&str>) -> Result<OffsetDateTime> {
    match raw {
        Some(s) => {
            let fmt = format_description!("[year]-[month]-[day]");
            let date = time::Date::parse(s, &fmt).with_context(|| {
                format!("invalid --not-before date: {s:?} (expected YYYY-MM-DD)")
            })?;
            Ok(date.with_hms(0, 0, 0).unwrap().assume_utc())
        }
        None => Ok(OffsetDateTime::now_utc()),
    }
}

/// Resolved anchor for pubkey pinning.
///
/// Either a full 32-byte pubkey (from `--pin-pubkey` or `--anchor-encrypted`)
/// or a fingerprint prefix (from `--pin-fpr`) used for post-reconstruction
/// verification.
pub enum ResolvedAnchor {
    /// Full pubkey — can be used to filter shares before reconstruction.
    Pubkey([u8; 32]),
    /// Fingerprint prefix (hex bytes) — verified after key reconstruction
    /// by computing BLAKE3(derived_pubkey) and checking the prefix matches.
    FingerprintPrefix(Vec<u8>),
}

/// Resolve the anchor pubkey from --pin-pubkey, --pin-fpr, or --anchor-encrypted.
fn resolve_anchor(pin: &PinArgs) -> Result<Option<ResolvedAnchor>> {
    let provided = [
        pin.pin_pubkey.is_some(),
        pin.pin_fpr.is_some(),
        pin.anchor_encrypted.is_some(),
    ];
    if provided.iter().filter(|&&b| b).count() > 1 {
        bail!("cannot use more than one of --pin-pubkey, --pin-fpr, --anchor-encrypted");
    }

    if let Some(hex_str) = &pin.pin_pubkey {
        let bytes = parse_hex_pubkey(hex_str)?;
        return Ok(Some(ResolvedAnchor::Pubkey(bytes)));
    }

    if let Some(hex_prefix) = &pin.pin_fpr {
        // Parse the hex prefix (variable length, must be even number of chars).
        let hex = hex_prefix.trim().replace(':', "");
        if hex.is_empty() {
            bail!("--pin-fpr must be a non-empty hex string");
        }
        if hex.len() % 2 != 0 {
            bail!("--pin-fpr hex must have an even number of characters (got {})", hex.len());
        }
        if hex.len() > 16 {
            bail!("--pin-fpr prefix is at most 8 bytes (16 hex chars), got {} chars", hex.len());
        }
        let mut bytes = Vec::with_capacity(hex.len() / 2);
        for i in (0..hex.len()).step_by(2) {
            bytes.push(u8::from_str_radix(&hex[i..i + 2], 16)
                .with_context(|| format!("invalid hex in --pin-fpr at position {i}"))?);
        }
        return Ok(Some(ResolvedAnchor::FingerprintPrefix(bytes)));
    }

    if let Some(path) = &pin.anchor_encrypted {
        let data = std::fs::read(path).with_context(|| format!("read anchor file {:?}", path))?;
        let encrypted = EncryptedFile::parse(&data)
            .with_context(|| format!("parse anchor file {:?}", path))?;
        eprintln!("  anchor pubkey from {:?}", path);
        return Ok(Some(ResolvedAnchor::Pubkey(encrypted.header.pubkey)));
    }

    Ok(None)
}

/// Verify a reconstructed master key's pubkey fingerprint matches a --pin-fpr prefix.
fn verify_fingerprint_pin(master: &[u8; 32], expected_prefix: &[u8]) -> Result<()> {
    let keys = crypto::derive_keys(master);
    let pubkey = crypto::pubkey_bytes(&keys.signing);
    let fpr = crypto::pubkey_fingerprint(&pubkey);

    if fpr[..expected_prefix.len()] != *expected_prefix {
        bail!(
            "reconstructed key fingerprint does not match --pin-fpr\n\
             derived:  {}\n\
             expected: {} (prefix)",
            crypto::format_fingerprint(&fpr),
            expected_prefix
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
    }
    eprintln!(
        "  verified fingerprint: {}",
        crypto::format_fingerprint(&fpr)
    );
    Ok(())
}

/// Parse a hex-encoded 32-byte pubkey.
fn parse_hex_pubkey(hex: &str) -> Result<[u8; 32]> {
    let hex = hex.trim();
    if hex.len() != 64 {
        bail!(
            "--pin-pubkey must be a 64-character hex string (32 bytes), got {} chars",
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
// Interactive prompt helpers
// ---------------------------------------------------------------------------

/// Prompt for a value on stderr, read from stdin.
///
/// Shows `[default]` in brackets when a non-empty default is provided.
/// Returns the default on empty input.  Loops until a non-empty value is
/// entered when no default is available.
fn prompt(label: &str, default: Option<&str>) -> Result<String> {
    loop {
        match default {
            Some(d) if !d.is_empty() => eprint!("  {} [{}]: ", label, d),
            _ => eprint!("  {}: ", label),
        }
        std::io::stderr().flush()?;
        let mut buf = String::new();
        std::io::stdin().lock().read_line(&mut buf)?;
        if buf.is_empty() {
            bail!("unexpected end of input");
        }
        let trimmed = buf.trim();
        if trimmed.is_empty() {
            match default {
                Some(d) => return Ok(d.to_string()),
                None => {
                    eprintln!("  value required");
                    continue;
                }
            }
        } else {
            return Ok(trimmed.to_string());
        }
    }
}

/// Prompt for yes / no on stderr, read from stdin.
fn prompt_yes_no(label: &str, default: bool) -> Result<bool> {
    loop {
        let hint = if default { "Y/n" } else { "y/N" };
        eprint!("  {} [{}]: ", label, hint);
        std::io::stderr().flush()?;
        let mut buf = String::new();
        std::io::stdin().lock().read_line(&mut buf)?;
        if buf.is_empty() {
            bail!("unexpected end of input");
        }
        match buf.trim().to_lowercase().as_str() {
            "" => return Ok(default),
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => {
                eprintln!("  enter y or n");
                continue;
            }
        }
    }
}
