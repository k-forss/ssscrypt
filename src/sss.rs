//! Shamir Secret Sharing over GF(256).
//!
//! - Polynomial basis with AES irreducible polynomial 0x11b.
//! - Secret is 32 bytes; each share is (x, y[32]).
//! - Threshold K ∈ [2, 255], total shares N ∈ [K, 255].

use anyhow::{bail, Result};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

pub const SECRET_LEN: usize = 32;

/// Raw Shamir share: evaluation point and 32-byte y value.
/// Does NOT carry signing/pubkey metadata — that's in `share::Share`.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct RawShare {
    pub x: u8,
    pub y: [u8; SECRET_LEN],
}

/// Split `secret` into `n` shares with threshold `k`.
///
/// Returns `n` raw shares. The caller is responsible for signing them.
pub fn split(secret: &[u8; SECRET_LEN], k: u8, n: u8) -> Result<Vec<RawShare>> {
    if k < 2 {
        bail!("threshold must be >= 2");
    }
    if n < k {
        bail!("shares ({n}) must be >= threshold ({k})");
    }

    let mut rng = rand_core::OsRng;
    split_with_rng(secret, k, n, &mut rng)
}

/// Split with an explicit RNG (useful for deterministic tests).
fn split_with_rng<R: RngCore + CryptoRng>(
    secret: &[u8; SECRET_LEN],
    k: u8,
    n: u8,
    rng: &mut R,
) -> Result<Vec<RawShare>> {
    let kt = k as usize;

    // Generate random polynomial coefficients per byte position.
    // coeffs[byte][0] = secret byte, coeffs[byte][1..k] = random.
    let mut coeffs = vec![vec![0u8; kt]; SECRET_LEN];
    for b in 0..SECRET_LEN {
        coeffs[b][0] = secret[b];
        for d in 1..kt {
            coeffs[b][d] = rng.next_u32() as u8;
        }
    }

    let mut out = Vec::with_capacity(n as usize);
    for i in 1..=n {
        let x = i;
        let mut y = [0u8; SECRET_LEN];
        for b in 0..SECRET_LEN {
            y[b] = eval_poly(&coeffs[b], x);
        }
        out.push(RawShare { x, y });
    }

    // Zeroize coefficient memory.
    for c in &mut coeffs {
        c.zeroize();
    }

    Ok(out)
}

/// Reconstruct the secret from `k` or more shares via Lagrange interpolation.
///
/// Only the first `k` shares (by threshold) are used. Duplicate `x` values
/// are rejected. The caller should verify share signatures before calling this.
pub fn combine(shares: &[RawShare], k: u8) -> Result<[u8; SECRET_LEN]> {
    if shares.is_empty() {
        bail!("no shares provided");
    }
    if k < 2 {
        bail!("invalid threshold");
    }
    if shares.len() < k as usize {
        bail!("need at least {k} shares, have {}", shares.len());
    }

    let used = &shares[..k as usize];

    // Verify distinct x values.
    for i in 0..used.len() {
        if used[i].x == 0 {
            bail!("invalid share x=0");
        }
        for j in (i + 1)..used.len() {
            if used[i].x == used[j].x {
                bail!("duplicate share x={}", used[i].x);
            }
        }
    }

    let mut secret = [0u8; SECRET_LEN];
    for b in 0..SECRET_LEN {
        secret[b] = interpolate_at_zero(used.iter().map(|s| (s.x, s.y[b])));
    }
    Ok(secret)
}

// ---------------------------------------------------------------------------
// GF(256) arithmetic (AES polynomial 0x11b)
// ---------------------------------------------------------------------------

/// Evaluate polynomial at point x using Horner's method.
fn eval_poly(coeffs: &[u8], x: u8) -> u8 {
    let mut acc = *coeffs.last().unwrap();
    for &c in coeffs.iter().rev().skip(1) {
        acc = gf_add(gf_mul(acc, x), c);
    }
    acc
}

/// Lagrange interpolation at x = 0.
fn interpolate_at_zero<I: Iterator<Item = (u8, u8)>>(points: I) -> u8 {
    let pts: Vec<(u8, u8)> = points.collect();
    let mut acc = 0u8;
    for i in 0..pts.len() {
        let (xi, yi) = pts[i];
        let mut num = 1u8;
        let mut den = 1u8;
        for j in 0..pts.len() {
            if i == j {
                continue;
            }
            let (xj, _) = pts[j];
            num = gf_mul(num, xj);
            den = gf_mul(den, gf_add(xi, xj)); // sub = add in GF(2^8)
        }
        let li = gf_mul(num, gf_inv(den));
        acc = gf_add(acc, gf_mul(yi, li));
    }
    acc
}

#[inline]
fn gf_add(a: u8, b: u8) -> u8 {
    a ^ b
}

/// Russian-peasant multiplication mod AES polynomial.
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        if (b & 1) != 0 {
            p ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1b; // x^8 + x^4 + x^3 + x + 1 (low byte of 0x11b)
        }
        b >>= 1;
    }
    p
}

/// Multiplicative inverse via Fermat's little theorem: a^254 in GF(256).
fn gf_inv(a: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    gf_pow(a, 254)
}

fn gf_pow(mut a: u8, mut e: u16) -> u8 {
    let mut r = 1u8;
    while e > 0 {
        if (e & 1) != 0 {
            r = gf_mul(r, a);
        }
        a = gf_mul(a, a);
        e >>= 1;
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn split_combine_roundtrip() {
        let secret = [42u8; SECRET_LEN];
        let shares = split(&secret, 3, 5).unwrap();
        let recovered = combine(&shares, 3).unwrap();
        assert_eq!(secret, recovered);
    }

    #[test]
    fn different_subsets_work() {
        let mut secret = [0u8; SECRET_LEN];
        OsRng.fill_bytes(&mut secret);
        let shares = split(&secret, 4, 7).unwrap();
        let subset = vec![
            shares[1].clone(),
            shares[3].clone(),
            shares[4].clone(),
            shares[6].clone(),
        ];
        let recovered = combine(&subset, 4).unwrap();
        assert_eq!(secret, recovered);
    }

    #[test]
    fn wrong_threshold_fails() {
        let secret = [1u8; SECRET_LEN];
        assert!(split(&secret, 1, 3).is_err()); // k < 2
        assert!(split(&secret, 5, 3).is_err()); // n < k
    }

    #[test]
    fn too_few_shares_fails() {
        let secret = [7u8; SECRET_LEN];
        let shares = split(&secret, 3, 5).unwrap();
        assert!(combine(&shares[..2], 3).is_err()); // need 3, have 2
    }

    #[test]
    fn duplicate_x_rejected() {
        let secret = [9u8; SECRET_LEN];
        let shares = split(&secret, 2, 3).unwrap();
        let dupes = vec![shares[0].clone(), shares[0].clone()];
        assert!(combine(&dupes, 2).is_err());
    }

    #[test]
    fn wrong_shares_produce_wrong_secret() {
        let secret = [0xab; SECRET_LEN];
        let shares = split(&secret, 3, 5).unwrap();
        // Use shares from x=1,2 and a corrupted share
        let mut bad = shares[2].clone();
        bad.y[0] ^= 0xff;
        let subset = vec![shares[0].clone(), shares[1].clone(), bad];
        let recovered = combine(&subset, 3).unwrap();
        assert_ne!(secret, recovered);
    }

    // GF(256) sanity checks.
    #[test]
    fn gf_mul_identity() {
        for a in 0u8..=255 {
            assert_eq!(gf_mul(a, 1), a);
            assert_eq!(gf_mul(1, a), a);
            assert_eq!(gf_mul(a, 0), 0);
        }
    }

    #[test]
    fn gf_inv_roundtrip() {
        for a in 1u8..=255 {
            assert_eq!(gf_mul(a, gf_inv(a)), 1, "gf_inv failed for {a}");
        }
    }
}
