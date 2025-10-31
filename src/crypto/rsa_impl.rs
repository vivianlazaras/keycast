use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs8::{EncodePrivateKey, EncodePublicKey},
};

use super::*;
use rand::rngs::OsRng;
use rsa::traits::PublicKeyParts;

pub fn generate_rsa_pkcs8_pair() -> (String, String) {
    // Generate a 2048-bit RSA private key
    let mut rng = OsRng;

    let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate key");

    // Convert to PKCS#8 PEM
    let private_key_pem = private_key
        .to_pkcs8_pem(Default::default())
        .expect("failed to encode private key");

    // Extract public key and encode as PEM
    let public_key = private_key.to_public_key();
    let public_key_pem = public_key
        .to_public_key_pem(Default::default())
        .expect("failed to encode public key");

    (private_key_pem.to_string(), public_key_pem)
}

pub fn generate_rsa_pair() -> (RsaPrivateKey, RsaPublicKey) {
    let mut rng = OsRng;

    let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate key");
    let public_key = private_key.to_public_key();

    (private_key, public_key)
}

impl ToPublicKeyDer for rsa::RsaPublicKey {
    fn key_algorithm(&self) -> KeyAlg {
        if self.size() >= 4096 {
            KeyAlg::Rsa4096
        } else {
            KeyAlg::Rsa2048
        }
    }
}
