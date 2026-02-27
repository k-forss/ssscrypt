//! X.509 certificate operations: self-signed root CA and CSR signing.
//!
//! Uses `rcgen` for pure-Rust certificate generation — no OpenSSL linkage.

use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName,
    DnType, IsCa, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use time::{Duration, OffsetDateTime};

/// Generate a self-signed root CA certificate and its ECDSA P-256 key pair.
///
/// `not_before` sets the certificate validity start; pass `OffsetDateTime::now_utc()`
/// when a real clock is available, or an explicit date on air-gapped machines.
///
/// Returns `(cert_pem, key_pem)`.
pub fn create_self_signed_root(
    cn: &str,
    org: Option<&str>,
    days: u32,
    not_before: OffsetDateTime,
) -> Result<(String, String)> {
    let key_pair =
        KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).context("generate ECDSA P-256 key pair")?;

    let mut params = CertificateParams::default();

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    if let Some(o) = org {
        dn.push(DnType::OrganizationName, o);
    }
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

    params.not_before = not_before;
    params.not_after = not_before + Duration::days(days as i64);

    let cert = params
        .self_signed(&key_pair)
        .context("generate self-signed root CA")?;

    Ok((cert.pem(), key_pair.serialize_pem()))
}

/// Sign a CSR with an issuer certificate and private key.
///
/// Parses the issuer cert and key from PEM, reconstructs the issuer `Certificate`
/// for rcgen, then signs the CSR with the requested validity and CA settings.
///
/// Returns the signed certificate PEM.
/// `not_before` sets the certificate validity start; pass `OffsetDateTime::now_utc()`
/// when a real clock is available, or an explicit date on air-gapped machines.
pub fn sign_csr(
    csr_pem: &str,
    issuer_cert_pem: &str,
    issuer_key_pem: &str,
    days: u32,
    not_before: OffsetDateTime,
    is_ca: bool,
    pathlen: Option<u8>,
) -> Result<String> {
    // Reconstruct issuer Certificate from existing PEM.
    let issuer_params =
        CertificateParams::from_ca_cert_pem(issuer_cert_pem).context("parse issuer cert PEM")?;
    let issuer_key = KeyPair::from_pem(issuer_key_pem).context("parse issuer key PEM")?;
    let issuer_cert = issuer_params
        .self_signed(&issuer_key)
        .context("reconstruct issuer certificate for signing")?;

    // Parse CSR.
    let mut csr = CertificateSigningRequestParams::from_pem(csr_pem).context("parse CSR PEM")?;

    // Validity period.
    csr.params.not_before = not_before;
    csr.params.not_after = not_before + Duration::days(days as i64);

    // CA / key-usage settings.
    if is_ca {
        csr.params.is_ca = match pathlen {
            Some(n) => IsCa::Ca(BasicConstraints::Constrained(n)),
            None => IsCa::Ca(BasicConstraints::Unconstrained),
        };
        csr.params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    } else {
        csr.params.is_ca = IsCa::NoCa;
        csr.params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
    }

    let signed = csr
        .signed_by(&issuer_cert, &issuer_key)
        .context("sign CSR")?;

    Ok(signed.pem())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_root_roundtrip() {
        let now = OffsetDateTime::now_utc();
        let (cert_pem, key_pem) =
            create_self_signed_root("Test Root CA", Some("Test Org"), 365, now).unwrap();
        assert!(cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(key_pem.starts_with("-----BEGIN PRIVATE KEY-----"));

        // Key should be parseable back.
        let kp = KeyPair::from_pem(&key_pem).unwrap();
        assert!(kp.is_compatible(&PKCS_ECDSA_P256_SHA256));
    }

    #[test]
    fn sign_csr_roundtrip() {
        let now = OffsetDateTime::now_utc();
        // Generate a root CA.
        let (issuer_cert_pem, issuer_key_pem) =
            create_self_signed_root("Test Root CA", None, 3650, now).unwrap();

        // Generate a subject key and CSR.
        let subject_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut csr_params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Intermediate CA");
        csr_params.distinguished_name = dn;
        let csr = csr_params.serialize_request(&subject_key).unwrap();
        let csr_pem = csr.pem().unwrap();

        // Sign it.
        let signed_pem = sign_csr(
            &csr_pem,
            &issuer_cert_pem,
            &issuer_key_pem,
            1825,
            now,
            true,
            Some(0),
        )
        .unwrap();
        assert!(signed_pem.starts_with("-----BEGIN CERTIFICATE-----"));
    }
}
