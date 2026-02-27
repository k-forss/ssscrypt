//! Shamir Secret Sharing over GF(2^32).
//!
//! - Polynomial basis with irreducible polynomial x^32 + x^7 + x^3 + x^2 + 1.
//! - Secret is 32 bytes (8 × u32 elements); each share is (x: u32, y: [u8; 32]).
//! - Threshold K ∈ [2, 255], total shares N ∈ [K, 255].

use anyhow::{bail, Result};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

pub const SECRET_LEN: usize = 32;

/// Number of GF(2^32) elements in a secret (32 bytes / 4 bytes per element).
const ELEMENTS: usize = SECRET_LEN / 4;

/// Raw Shamir share: evaluation point and 32-byte y value.
/// Does NOT carry signing/pubkey metadata — that's in `share::Share`.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct RawShare {
    pub x: u32,
    pub y: [u8; SECRET_LEN],
}

/// Split `secret` into `n` shares with threshold `k`.
///
/// Returns `n` raw shares with sequential x values (1..=n).
/// The caller is responsible for signing them.
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

/// Split `secret` into `n` shares with threshold `k`, using random x values.
///
/// Unlike [`split`], which assigns sequential x=1..=n, this picks `n` unique
/// random non-zero u32 x values.  The `exclude_xs` set lists x values to avoid
/// (e.g. x values from existing outstanding shares).
///
/// With 2^32 − 1 usable x values, collisions are astronomically unlikely even
/// without an exclusion set, but passing known x values is still good practice.
pub fn split_random_x(
    secret: &[u8; SECRET_LEN],
    k: u8,
    n: u8,
    exclude_xs: &[u32],
) -> Result<Vec<RawShare>> {
    if k < 2 {
        bail!("threshold must be >= 2");
    }
    if n < k {
        bail!("shares ({n}) must be >= threshold ({k})");
    }

    let mut rng = rand_core::OsRng;

    // Pick n unique random non-zero x values, avoiding excluded values.
    let exclude: std::collections::HashSet<u32> = exclude_xs.iter().copied().collect();
    let mut xs = Vec::with_capacity(n as usize);
    while xs.len() < n as usize {
        let x = loop {
            let v = rng.next_u32();
            if v != 0 { break v; }
        };
        if !exclude.contains(&x) && !xs.contains(&x) {
            xs.push(x);
        }
    }

    split_xs_with_rng(secret, k, &xs, &mut rng)
}

/// Split with an explicit RNG (useful for deterministic tests).
fn split_with_rng<R: RngCore + CryptoRng>(
    secret: &[u8; SECRET_LEN],
    k: u8,
    n: u8,
    rng: &mut R,
) -> Result<Vec<RawShare>> {
    let xs: Vec<u32> = (1..=n as u32).collect();
    split_xs_with_rng(secret, k, &xs, rng)
}

/// Core split: evaluate the polynomial at the given x values.
fn split_xs_with_rng<R: RngCore + CryptoRng>(
    secret: &[u8; SECRET_LEN],
    k: u8,
    xs: &[u32],
    rng: &mut R,
) -> Result<Vec<RawShare>> {
    let kt = k as usize;

    // Convert secret bytes to u32 elements (big-endian).
    let secret_elems: Vec<u32> = (0..ELEMENTS)
        .map(|i| u32::from_be_bytes(secret[i * 4..(i + 1) * 4].try_into().unwrap()))
        .collect();

    // Generate random polynomial coefficients per element.
    // coeffs[elem][0] = secret element, coeffs[elem][1..k] = random.
    let mut coeffs = vec![vec![0u32; kt]; ELEMENTS];
    for e in 0..ELEMENTS {
        coeffs[e][0] = secret_elems[e];
        for d in 1..kt {
            coeffs[e][d] = rng.next_u32();
        }
    }

    let mut out = Vec::with_capacity(xs.len());
    for &x in xs {
        let mut y = [0u8; SECRET_LEN];
        for e in 0..ELEMENTS {
            let val = eval_poly(&coeffs[e], x);
            y[e * 4..(e + 1) * 4].copy_from_slice(&val.to_be_bytes());
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
    for e in 0..ELEMENTS {
        let val = interpolate_at_zero(used.iter().map(|s| {
            let elem = u32::from_be_bytes(s.y[e * 4..(e + 1) * 4].try_into().unwrap());
            (s.x, elem)
        }));
        secret[e * 4..(e + 1) * 4].copy_from_slice(&val.to_be_bytes());
    }
    Ok(secret)
}

// ---------------------------------------------------------------------------
// GF(2^32) arithmetic — irreducible polynomial x^32 + x^7 + x^3 + x^2 + 1
// ---------------------------------------------------------------------------

/// Reduction constant: low bits of x^32 + x^7 + x^3 + x^2 + 1 (sans x^32).
const POLY: u32 = 0x8D;

/// Evaluate polynomial at point x using Horner's method.
fn eval_poly(coeffs: &[u32], x: u32) -> u32 {
    let mut acc = *coeffs.last().unwrap();
    for &c in coeffs.iter().rev().skip(1) {
        acc = gf_add(gf_mul(acc, x), c);
    }
    acc
}

/// Lagrange interpolation at x = 0.
fn interpolate_at_zero<I: Iterator<Item = (u32, u32)>>(points: I) -> u32 {
    let pts: Vec<(u32, u32)> = points.collect();
    let mut acc = 0u32;
    for i in 0..pts.len() {
        let (xi, yi) = pts[i];
        let mut num = 1u32;
        let mut den = 1u32;
        for j in 0..pts.len() {
            if i == j {
                continue;
            }
            let (xj, _) = pts[j];
            num = gf_mul(num, xj);
            den = gf_mul(den, gf_add(xi, xj)); // sub = add in GF(2^n)
        }
        let li = gf_mul(num, gf_inv(den));
        acc = gf_add(acc, gf_mul(yi, li));
    }
    acc
}

#[inline]
fn gf_add(a: u32, b: u32) -> u32 {
    a ^ b
}

/// Russian-peasant multiplication in GF(2^32).
fn gf_mul(mut a: u32, mut b: u32) -> u32 {
    let mut p = 0u32;
    for _ in 0..32 {
        if (b & 1) != 0 {
            p ^= a;
        }
        let hi = a & 0x8000_0000;
        a <<= 1;
        if hi != 0 {
            a ^= POLY;
        }
        b >>= 1;
    }
    p
}

/// Multiplicative inverse via Fermat's little theorem: a^(2^32 − 2) in GF(2^32).
fn gf_inv(a: u32) -> u32 {
    if a == 0 {
        return 0;
    }
    gf_pow(a, 0xFFFF_FFFE)
}

fn gf_pow(mut a: u32, mut e: u64) -> u32 {
    let mut r = 1u32;
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

    // GF(2^32) sanity checks.
    #[test]
    fn gf_mul_identity() {
        // Test identity for a range of values.
        for a in 0u32..=1000 {
            assert_eq!(gf_mul(a, 1), a);
            assert_eq!(gf_mul(1, a), a);
            assert_eq!(gf_mul(a, 0), 0);
        }
        // Test some large values.
        for a in [0xDEAD_BEEF, 0xCAFE_BABE, 0xFFFF_FFFF, 0x8000_0000, 0x1234_5678] {
            assert_eq!(gf_mul(a, 1), a, "identity failed for {a:#x}");
            assert_eq!(gf_mul(1, a), a, "identity failed for {a:#x}");
            assert_eq!(gf_mul(a, 0), 0, "zero mul failed for {a:#x}");
        }
    }

    #[test]
    fn gf_inv_roundtrip() {
        for a in 1u32..=1000 {
            assert_eq!(gf_mul(a, gf_inv(a)), 1, "gf_inv failed for {a}");
        }
        for a in [0xDEAD_BEEF, 0xCAFE_BABE, 0xFFFF_FFFF, 0x8000_0000, 0x1234_5678] {
            assert_eq!(gf_mul(a, gf_inv(a)), 1, "gf_inv failed for {a:#x}");
        }
    }

    #[test]
    fn split_random_x_roundtrip() {
        let mut secret = [0u8; SECRET_LEN];
        OsRng.fill_bytes(&mut secret);
        let shares = split_random_x(&secret, 3, 5, &[]).unwrap();
        assert_eq!(shares.len(), 5);

        // All x values should be unique and non-zero.
        let mut xs: Vec<u32> = shares.iter().map(|s| s.x).collect();
        xs.sort();
        xs.dedup();
        assert_eq!(xs.len(), 5);
        assert!(xs.iter().all(|&x| x != 0));

        // Any 3 shares should reconstruct correctly.
        let subset = vec![shares[0].clone(), shares[2].clone(), shares[4].clone()];
        let recovered = combine(&subset, 3).unwrap();
        assert_eq!(secret, recovered);
    }

    #[test]
    fn split_random_x_non_sequential() {
        // With u32 random x values, they should virtually never be sequential.
        let secret = [0xcd; SECRET_LEN];
        let shares = split_random_x(&secret, 2, 5, &[]).unwrap();
        let xs: Vec<u32> = shares.iter().map(|s| s.x).collect();
        assert_ne!(xs, vec![1, 2, 3, 4, 5], "random u32 x values should not be sequential");
    }

    #[test]
    fn split_random_x_excludes_values() {
        let secret = [0xab; SECRET_LEN];
        let exclude: Vec<u32> = (1..=100).collect();
        let shares = split_random_x(&secret, 2, 5, &exclude).unwrap();
        for share in &shares {
            assert!(
                !exclude.contains(&share.x),
                "share x={} should not be in exclude set",
                share.x,
            );
        }
        // Should still reconstruct correctly.
        let recovered = combine(&shares, 2).unwrap();
        assert_eq!(secret, recovered);
    }
}
