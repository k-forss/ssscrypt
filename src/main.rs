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

/// ssscrypt: Encrypt files with threshold secret sharing.
///
/// Generates a random symmetric key, encrypts your file with XChaCha20-Poly1305,
/// splits the key using Shamir secret sharing, and signs everything with Ed25519.
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: cmd::Command,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    cmd::run(cli.command)
}
