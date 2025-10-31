use super::*;
use sha2::{Digest, Sha256, Sha512};
/// Compute the SHA-256 hash of `input` and return it as a lowercase hex string.
///
/// This is a **fast** cryptographic hash suitable for checksums, content-addressing,
/// or inputs to signatures. **Do not** use SHA-256 alone for password hashing.
///
/// # Example
///
/// ```
/// let base64 = keycast::crypto::sha256_base64("hello");
/// assert_eq!(base64.len(), 44); // 32 bytes -> 64 hex chars
/// ```
pub fn sha256_base64(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    base64::encode(result)
}

#[derive(Debug)]
pub struct Sha256Alg;
#[derive(Debug)]
pub struct Sha512Alg;

impl HashAlgorithm for Sha256Alg {
    fn name(&self) -> HashAlg {
        HashAlg::Sha256
    }
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        Sha256::digest(data).to_vec()
    }
}

impl HashAlgorithm for Sha512Alg {
    fn name(&self) -> HashAlg {
        HashAlg::Sha512
    }
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        Sha512::digest(data).to_vec()
    }
}
