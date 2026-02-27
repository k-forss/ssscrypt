mod cmd;
mod collector;
mod crypto;
mod encrypted;
mod io;
mod mnemonic;
mod qr;
mod share;
mod sss;
mod x509;

use anyhow::Result;
use clap::Parser;

/// ssscrypt — Encrypt files with Shamir secret sharing.
///
/// Split a symmetric key into QR cards with mnemonic backup words.
/// Any K-of-N shares can reconstruct the key; fewer reveal nothing.
///
/// Crypto: XChaCha20-Poly1305 (encryption) + Ed25519 (signing) + Blake3 (KDF).
/// Shares: GF(2³²) Shamir, 30 mnemonic words each, individually signed.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: cmd::Command,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    cmd::run(cli.command)
}
