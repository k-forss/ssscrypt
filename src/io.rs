use crate::cmd::IoArgs;
use crate::share::Share;
use anyhow::{Context, Result};
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

/// Read all input bytes from --in file or stdin.
pub fn read_input(io_args: &IoArgs) -> Result<Vec<u8>> {
    match &io_args.r#in {
        Some(path) => fs::read(path).with_context(|| format!("read {:?}", path)),
        None => {
            let mut buf = Vec::new();
            io::stdin().read_to_end(&mut buf).context("read stdin")?;
            Ok(buf)
        }
    }
}

/// Write output bytes to --out file or stdout.
pub fn write_output(io_args: &IoArgs, data: &[u8]) -> Result<()> {
    match &io_args.out {
        Some(path) => fs::write(path, data).with_context(|| format!("write {:?}", path)),
        None => {
            use std::io::Write;
            io::stdout().write_all(data).context("write stdout")?;
            io::stdout().flush().context("flush stdout")
        }
    }
}

/// Discover all *.share.txt files in a directory, returning sorted paths.
pub fn discover_shares(dir: &Path) -> Result<Vec<PathBuf>> {
    if !dir.is_dir() {
        anyhow::bail!("{:?} is not a directory", dir);
    }

    let mut paths: Vec<PathBuf> = fs::read_dir(dir)
        .with_context(|| format!("read directory {:?}", dir))?
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("txt")
                && path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.ends_with(".share.txt"))
            {
                Some(path)
            } else {
                None
            }
        })
        .collect();

    paths.sort();
    Ok(paths)
}

/// Load and parse all share files from a directory.
pub fn load_shares(dir: &Path) -> Result<Vec<Share>> {
    let paths = discover_shares(dir)?;
    let mut shares = Vec::with_capacity(paths.len());
    for path in &paths {
        match Share::from_file(path) {
            Ok(s) => shares.push(s),
            Err(e) => {
                eprintln!("  warning: skipping {:?}: {e}", path);
            }
        }
    }
    Ok(shares)
}

/// Write signed shares to a directory, creating it if needed.
///
/// For each share, writes both a `.share.txt` text file and a `.share.jpg`
/// QR card image with mnemonic backup words.
pub fn write_shares(dir: &Path, shares: &[Share]) -> Result<()> {
    use crate::mnemonic::{self, MnemonicPayload};
    use crate::qr;

    fs::create_dir_all(dir).with_context(|| format!("create shares directory {:?}", dir))?;
    for share in shares {
        // Write text share file.
        let path = dir.join(share.filename());
        share
            .to_file(&path)
            .with_context(|| format!("write share {:?}", path))?;
        eprintln!("  wrote {}", share.filename());

        // Generate mnemonic words and QR card JPEG.
        let payload = MnemonicPayload {
            x: share.x,
            y: share.y,
            pubkey_prefix: share.pubkey[..4].try_into().unwrap(),
        };
        let words = mnemonic::encode(&payload);

        let card_name = share.filename().replace(".share.txt", ".share.jpg");
        let card_path = dir.join(&card_name);
        match qr::save_card(share, &words, &card_path) {
            Ok(()) => eprintln!("  wrote {card_name}"),
            Err(e) => eprintln!("  warning: failed to write QR card: {e}"),
        }
    }
    Ok(())
}
