use super::*;
use ed25519_dalek::VerifyingKey;

impl ToPublicKeyDer for VerifyingKey {
    fn key_algorithm(&self) -> KeyAlg {
        KeyAlg::Ed25519
    }
}
