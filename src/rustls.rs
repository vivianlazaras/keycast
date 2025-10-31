use crate::crypto::HashAlgorithm;
use crate::discovery::Discovery;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::{CertificateError, ClientConfig, Error as TlsError};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use std::sync::Arc;
use x509_parser::prelude::*;

/// A rustls verifier that validates the certificate’s SPKI hash against
/// the Discovery record’s `enc_pubkey_hash`.
#[derive(Clone, Debug)]
pub struct RustlsVerifier {
    /// Discovery metadata for the service we’re connecting to.
    discovery: Discovery,
    default_verifier: Arc<dyn ServerCertVerifier>,
    hasher: Arc<dyn HashAlgorithm>,
}

impl RustlsVerifier {
    pub fn new(
        discovery: Discovery,
        default_verifier: Arc<dyn ServerCertVerifier>,
        hasher: Arc<dyn HashAlgorithm>,
    ) -> Self {
        Self {
            discovery,
            default_verifier,
            hasher,
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

    fn compute_hash(&self, spki_bytes: &[u8]) -> Vec<u8> {
        self.hasher.hash(spki_bytes)
    }

    /// Convert the discovery’s `enc_pubkey_hash` string into bytes.
    /// Adjust this based on your keycast encoding (e.g. base32, hex, multibase).
    fn expected_hash(&self) -> Result<Vec<u8>, TlsError> {
        base64::decode(&self.discovery.pubkey_hash.hash)
            .map_err(|_| TlsError::General("invalid hex in enc_pubkey_hash".into()))
    }

    /// This code is basically a copy of `rustls::WebPkiServerVerifier`s implementation of ServerCertVerifier.
    /// excluding code to leverage trust anchors bc this method should only be called after domain name public key hash match.
    fn verify_server_certificate(&self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime
    ) -> Result<ServerCertVerified, Error> {
        let cert = ParsedCertificate::try_from(end_entity)?;

        let crl_refs = self.crls.iter().collect::<Vec<_>>();

        let revocation = if self.crls.is_empty() {
            None
        } else {
            // Note: unwrap here is safe because RevocationOptionsBuilder only errors when given
            //       empty CRLs.
            Some(
                webpki::RevocationOptionsBuilder::new(crl_refs.as_slice())
                    // Note: safe to unwrap here - new is only fallible if no CRLs are provided
                    //       and we verify this above.
                    .unwrap()
                    .with_depth(self.revocation_check_depth)
                    .with_status_policy(self.unknown_revocation_policy)
                    .with_expiration_policy(self.revocation_expiration_policy)
                    .build(),
            )
        };
        // verify_server_cert_signed_by_trust_anchor_impl
        
        if !ocsp_response.is_empty() {
            trace!("Unvalidated OCSP response: {:?}", ocsp_response.to_vec());
        }

        verify_server_name(&cert, server_name)?;
        Ok(ServerCertVerified::assertion())
    }

    /// Optionally: build a ready-to-use rustls ClientConfig.
    pub fn client_config(&self) -> Arc<ClientConfig> {
        let verifier = Arc::new(self.clone());
        let cfg = ClientConfig::builder()
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
                        let hash = self.compute_hash(&spki);

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
