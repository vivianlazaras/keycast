//! Certificate generation utilities supporting both self-signed
//! and CA-signed certificates, with shared logic and robust error handling.
//!
//! This module produces a [`KeyHash`] structure containing metadata about
//! the generated keypair and the hash-derived hostname, along with both
//! the rcgen [`KeyPair`] and resulting [`Certificate`].
use base64::Engine;
use base64::engine::general_purpose::STANDARD as base64_encode;
use rcgen::{
    Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose,
    PublicKeyData, SigningKey,
};
use rsa::RsaPrivateKey;
use time::OffsetDateTime;

use super::{Encoding, HashAlgorithm, KeyAlg, KeyHash};
use pkcs8::EncodePrivateKey;

use thiserror::Error;
use rcgen::Issuer;

// -------------------------------------------------------------------------
// ERROR TYPE
// -------------------------------------------------------------------------

/// Errors returned during certificate generation.
#[derive(Debug, Error)]
pub enum CertGenError {
    #[error("failed to convert private key to PKCS#8 PEM: {0}")]
    PemEncoding(String),

    #[error("failed to construct rcgen KeyPair: {0}")]
    KeyPair(String),

    #[error("failed to hash public key: {0}")]
    Hash(String),

    #[error("failed to construct certificate parameters: {0}")]
    Params(String),

    #[error("failed to generate self-signed certificate: {0}")]
    SelfSigned(String),

    #[error("failed to generate CA-signed certificate: {0}")]
    SignedBy(String),
}

// -------------------------------------------------------------------------
// SHARED HELPER
// -------------------------------------------------------------------------

/// Builds shared certificate parameters and constructs a `.local.` hostname.
///
/// The hostname format is:
///
/// ```text
/// <base64-hash-of-public-key>.local.
/// ```
///
/// # Returns
///
/// `(hash_string, CertificateParams)`
///
fn build_cert_params<H: HashAlgorithm>(
    hasher: &H,
    keypair: &KeyPair,
    validity: (OffsetDateTime, OffsetDateTime),
    mut extra_names: Vec<String>,
) -> Result<(String, CertificateParams), CertGenError> {
    // Hash public key DER
    let der = keypair.der_bytes();

    let hash_bytes = hasher
        .hash(der);

    let hash = base64_encode.encode(hash_bytes);

    // Create derived local hostname
    let hostname = format!("{}.local.", hash);

    // Include user-supplied + generated SAN names
    extra_names.push(hostname.clone());

    let mut params = CertificateParams::new(extra_names)
        .map_err(|e| CertGenError::Params(format!("{:?}", e)))?;

    let (not_before, not_after) = validity;

    // Distinguished Name (only CN for now)
    params
        .distinguished_name
        .push(DnType::CommonName, hostname.clone());

    params.use_authority_key_identifier_extension = true;
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);

    params.not_before = not_before;
    params.not_after = not_after;

    Ok((hash, params))
}

// -------------------------------------------------------------------------
// PUBLIC API
// -------------------------------------------------------------------------

/// Generate a **self-signed certificate** using the provided RSA private key.
///
/// # Arguments
///
/// ### `hasher: &H`
/// A hash algorithm implementing [`HashAlgorithm`].  
/// Used to compute a hash over the certificate’s **public key DER** bytes.
///  
/// This hash is:
/// * base64-encoded  
/// * embedded in the returned [`KeyHash`] struct  
/// * used to generate a DNS name like `"<hash>.local."`
///
/// ---
///
/// ### `privkey: &RsaPrivateKey`
/// The **subject and issuer key** (because self-signed).  
/// Used to:
/// * Generate the subject public key
/// * Sign the certificate
///
/// ---
///
/// ### `validity: (OffsetDateTime, OffsetDateTime)`
/// A tuple specifying:
///
/// * `not_before` — when the certificate becomes valid  
/// * `not_after` — when it expires  
///
/// These map directly into the X.509 validity fields.
///
/// ---
///
/// ### `extra_names: Vec<String>`
/// Additional DNS Subject Alternative Names (SANs).  
/// The function automatically appends a generated name:
///
/// ```text
/// <base64-hash>.local.
/// ```
///
/// ---
///
/// # Returns
///  
/// On success:
/// ```text
/// (KeyHash, KeyPair, Certificate)
/// ```
///
/// * `KeyHash` — metadata about the key, including hash, algorithm, encoding  
/// * `KeyPair` — rcgen keypair containing **public** and **private** key  
/// * `Certificate` — the self-signed X.509 certificate  
///
pub fn generate_self_signed_cert<H: HashAlgorithm>(
    hasher: &H,
    privkey: &RsaPrivateKey,
    validity: (OffsetDateTime, OffsetDateTime),
    extra_names: Vec<String>,
) -> Result<(KeyHash, KeyPair, Certificate), CertGenError> {
    // Convert RSA -> PEM
    let privkey_pem = privkey
        .to_pkcs8_pem(Default::default())
        .map_err(|e| CertGenError::PemEncoding(format!("{:?}", e)))?;

    // Build rcgen keypair
    let keypair = KeyPair::from_pkcs8_pem_and_sign_algo(&privkey_pem, &rcgen::PKCS_RSA_SHA256)
        .map_err(|e| CertGenError::KeyPair(format!("{:?}", e)))?;

    // Shared logic (hash, CN, SANs, validity, usages)
    let (hash, params) = build_cert_params(hasher, &keypair, validity, extra_names)?;

    // Self-sign
    let cert = params
        .self_signed(&keypair)
        .map_err(|e| CertGenError::SelfSigned(format!("{:?}", e)))?;

    Ok((
        KeyHash {
            key_alg: KeyAlg::Rsa2048,
            key_encoding: Encoding::Base64Der,
            hash_alg: hasher.name(),
            hash,
        },
        keypair,
        cert,
    ))
}

/// Generate a certificate **signed by an external issuer**, such as a CA.
///
/// # Arguments
///
/// ### `hasher: &H`
/// Same behavior as in [`generate_self_signed_cert`]:
///  
/// * Hashes public key DER  
/// * Hash is included in SAN and returned in [`KeyHash`]  
///
/// ---
///
/// ### `privkey: &RsaPrivateKey`
/// The private key used for the **subject** certificate only.  
///  
/// This key does **not** sign the certificate in this function —  
/// the `signing_key` (the CA) performs the signing.
///
/// ---
///
/// ### `signing_key: &S`
/// An external key implementing [`SigningKey`], typically a CA signing key.
///
/// Used to **sign** the subject certificate.
///
/// ---
///
/// ### `issuer_cert: &Certificate`
/// The certificate corresponding to the `signing_key`.
///
/// This is embedded as the issuer of the resulting certificate.
///
/// ---
///
/// ### `validity: (OffsetDateTime, OffsetDateTime)`
/// Same semantics as in the self-signed variant.
///
/// ---
///
/// ### `extra_names: Vec<String>`
/// Additional SANs for the subject certificate.
///
/// The derived name:
///
/// ```text
/// <base64-hash>.local.
/// ```
///
/// is appended automatically.
///
/// ---
///
/// # Returns
///
/// On success:
///
/// ```text
/// (KeyHash, KeyPair, Certificate)
/// ```
///
/// * `KeyHash` — metadata describing the subject key  
/// * `KeyPair` — the subject’s keypair  
/// * `Certificate` — X.509 certificate signed by the provided issuer  
///
pub fn generate_signed_cert<H: HashAlgorithm, S: SigningKey>(
    hasher: &H,
    privkey: &RsaPrivateKey,
    signing_key: &S,
    validity: (OffsetDateTime, OffsetDateTime),
    extra_names: Vec<String>,
) -> Result<(KeyHash, KeyPair, Certificate), CertGenError> {
    // Convert subject key to PEM
    let privkey_pem = privkey
        .to_pkcs8_pem(Default::default())
        .map_err(|e| CertGenError::PemEncoding(format!("{:?}", e)))?;

    let keypair = KeyPair::from_pkcs8_pem_and_sign_algo(&privkey_pem, &rcgen::PKCS_RSA_SHA256)
        .map_err(|e| CertGenError::KeyPair(format!("{:?}", e)))?;

    // Shared logic (hash, SANs, DN, validity)
    let (hash, params) = build_cert_params(hasher, &keypair, validity, extra_names)?;

    let issuer = Issuer::new(params.clone(), signing_key);
    // Sign using external issuer
    let cert = params
        .signed_by(&keypair, &issuer)
        .map_err(|e| CertGenError::SignedBy(format!("{:?}", e)))?;

    Ok((
        KeyHash {
            key_alg: KeyAlg::Rsa2048,
            key_encoding: Encoding::Base64Der,
            hash_alg: hasher.name(),
            hash,
        },
        keypair,
        cert,
    ))
}
