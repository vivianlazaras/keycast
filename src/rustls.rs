use crate::discovery::Discovery;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::{CertificateError, ClientConfig, Error as TlsError};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use sha2::{Digest, Sha256};
use std::{sync::Arc};
use x509_parser::prelude::*;

/// A rustls verifier that validates the certificate’s SPKI hash against
/// the Discovery record’s `enc_pubkey_hash`.
#[derive(Debug)]
pub struct RustlsVerifier {
    /// Discovery metadata for the service we’re connecting to.
    discovery: Discovery,
    default_verifier: Arc<dyn ServerCertVerifier>,
}

impl RustlsVerifier {
    pub fn new(discovery: Discovery, default_verifier: Arc<dyn ServerCertVerifier>) -> Self {
        Self {
            discovery,
            default_verifier,
        }
    }

    /// Extract SubjectPublicKeyInfo bytes (the raw public key BIT STRING)
    fn extract_spki_bytes(cert_der: &[u8]) -> Result<Vec<u8>, TlsError> {
        let (_, parsed) = X509Certificate::from_der(cert_der)
            .map_err(|_| TlsError::General("failed to parse certificate DER".into()))?;
        Ok(parsed
            .tbs_certificate
            .subject_pki
            .subject_public_key
            .data
            .to_vec())
    }

    fn compute_hash(spki_bytes: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(spki_bytes);
        hasher.finalize().to_vec()
    }

    /// Convert the discovery’s `enc_pubkey_hash` string into bytes.
    /// Adjust this based on your keycast encoding (e.g. base32, hex, multibase).
    fn expected_hash(&self) -> Result<Vec<u8>, TlsError> {
        base64::decode(&self.discovery.enc_pubkey_hash)
            .map_err(|_| TlsError::General("invalid hex in enc_pubkey_hash".into()))
    }

    /// Optionally: build a ready-to-use rustls ClientConfig.
    pub fn client_config(self: &Arc<Self>) -> Arc<ClientConfig> {
        let verifier = self.clone();
        let mut cfg = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        Arc::new(cfg)
    }
}

impl ServerCertVerifier for RustlsVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer,
        intermediates: &[CertificateDer],
        server_name: &ServerName,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        match self.default_verifier.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(ok) => Ok(ok),
            Err(e) => {
                if let rustls::Error::InvalidCertificate(ref reason) = e {
                    if matches!(reason, CertificateError::UnknownIssuer) {
                        let spki = Self::extract_spki_bytes(end_entity)?;
                        let hash = Self::compute_hash(&spki);

                        if self.expected_hash()? == hash
                            && server_name.to_str() == self.discovery.host
                        {
                            log::info!(
                                "🔐 TOFU: unknown issuer, attempting reverification after temporary trust of {}",
                                server_name.to_str()
                            );

                            //let cert = rustls::Certificate(end_entity.clone().into_owned());
                            let mut roots = rustls::RootCertStore::empty();
                            roots.add(end_entity.clone()).map_err(|err| {
                                TlsError::General(format!(
                                    "Failed to add cert to temporary root store: {}",
                                    err
                                ))
                            })?;

                            // Try full verification again
                            let re_verifier =
                                rustls::client::WebPkiServerVerifier::builder(roots.into())
                                    .build()
                                    .unwrap();
                            match re_verifier.verify_server_cert(
                                end_entity,
                                intermediates,
                                server_name,
                                ocsp_response,
                                now,
                            ) {
                                Ok(ok) => {
                                    log::info!(
                                        "✅ TOFU: reverification succeeded, persisting trust for {}",
                                        server_name.to_str()
                                    );
                                    // Only now persist the certificate
                                    if let Err(err) = std::fs::create_dir_all("/var/lib/tofu") {
                                        log::warn!("Could not create TOFU dir: {}", err);
                                    }
                                    let store_path =
                                        format!("/var/lib/tofu/{}.der", server_name.to_str());
                                    if let Err(err) =
                                        std::fs::write(&store_path, end_entity.as_ref())
                                    {
                                        log::warn!("Could not save trusted cert: {}", err);
                                    }

                                    Ok(ok)
                                }
                                Err(err) => {
                                    log::warn!(
                                        "❌ TOFU: reverification failed after trusting {} — not persisting certificate",
                                        server_name.to_str()
                                    );
                                    Err(err)
                                }
                            }
                        } else {
                            log::warn!(
                                "❌ TOFU: hash or hostname mismatch for {}",
                                server_name.to_str()
                            );
                            Err(e)
                        }
                    } else {
                        Err(e)
                    }
                } else {
                    Err(e)
                }
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.default_verifier
            .verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.default_verifier
            .verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.default_verifier.supported_verify_schemes()
    }
}
