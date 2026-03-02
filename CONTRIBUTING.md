# Contributing to ssscrypt

Thanks for your interest! Contributions are welcome — bug reports, feature
ideas, docs improvements, and code patches.

## Before you start

- **Open an issue first** for anything beyond a trivial fix. This avoids
  wasted effort and lets us discuss the approach.
- Security vulnerabilities should be reported privately — see
  [SECURITY.md](SECURITY.md).

## Development setup

```bash
# Clone and build
git clone https://github.com/k-forss/ssscrypt.git
cd ssscrypt
cargo build

# Run the full check suite (same as CI)
cargo fmt --check
cargo clippy -- -D warnings
cargo test
```

## Pull request checklist

- [ ] `cargo fmt` — code is formatted
- [ ] `cargo clippy -- -D warnings` — no warnings
- [ ] `cargo test` — all tests pass
- [ ] Update `CHANGELOG.md` under `[Unreleased]` if user-facing

## Code style

- Follow existing patterns in the codebase.
- Keep functions focused and well-documented.
- Prefer explicit error handling over `.unwrap()`.

## License

By contributing you agree that your contributions will be licensed under the
same terms as the project — dual MIT / Apache-2.0.
