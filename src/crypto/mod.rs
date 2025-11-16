use crate::errors::BeaconError;
/// Module for cryptography utility functions.
///
use serde_derive::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

use crate::utils::*;

#[cfg(feature = "rsa")]
pub mod rsa_impl;

#[cfg(feature = "certgen")]
pub mod certgen;

#[cfg(feature = "sha2")]
pub mod sha2_impl;

#[cfg(feature = "ed25519")]
pub mod ed25519;

/// A public key that can be represented as PKCS#8 (SPKI) in DER or PEM form.
pub trait ToPublicKeyDer: pkcs8::EncodePublicKey {
    /// Optionally return the algorithm used by this key (for metadata).
    fn key_algorithm(&self) -> KeyAlg;
}

pub trait HashAlgorithm: std::fmt::Debug + Send + Sync {
    /// Returns a human-readable name, e.g. "SHA256" or "BLAKE3"
    fn name(&self) -> HashAlg;

    /// Computes the hash of arbitrary data, returning the raw digest bytes.
    fn hash(&self, data: &[u8]) -> Vec<u8>;
}

/// Encoding format of the public key material
///
/// # Examples
///
/// ```
/// use keycast::crypto::Encoding;
/// use std::str::FromStr;
///
/// let e = Encoding::HexPem;
/// assert_eq!(e.to_string(), "hxp");
///
/// let parsed: Encoding = "hxp".parse().unwrap();
/// assert_eq!(parsed, Encoding::HexPem);
///
/// // round-trip check
/// assert_eq!(parsed.to_string(), "hxp");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Encoding {
    /// PEM (text) encoded, hash computed over hex
    HexPem,
    /// PEM (text) encoded, hash computed over base64
    Base64Pem,
    /// DER (binary) encoded, hex representation
    HexDer,
    /// DER (binary) encoded, base64 representation
    Base64Der,
}

impl fmt::Display for Encoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Encoding::HexPem => "hxp",
            Encoding::Base64Pem => "b64p",
            Encoding::HexDer => "hxd",
            Encoding::Base64Der => "b64d",
        };
        write!(f, "{s}")
    }
}

impl FromStr for Encoding {
    type Err = BeaconError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "hxp" => Ok(Encoding::HexPem),
            "b64p" => Ok(Encoding::Base64Pem),
            "hxd" => Ok(Encoding::HexDer),
            "b64d" => Ok(Encoding::Base64Der),
            _ => Err(BeaconError::InvalidEncoding(s.to_string())),
        }
    }
}

/// Type of asymmetric key algorithm
///
/// # Examples
///
/// ```
/// use keycast::crypto::KeyAlg;
/// use std::str::FromStr;
///
/// let alg = KeyAlg::Ed25519;
/// assert_eq!(alg.to_string(), "ed25519");
///
/// let parsed: KeyAlg = "ed25519".parse().unwrap();
/// assert_eq!(parsed, KeyAlg::Ed25519);
///
/// // round-trip consistency
/// assert_eq!(parsed.to_string(), "ed25519");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyAlg {
    Rsa2048,
    Rsa4096,
    Ed25519,
    X25519,
    EcdsaP256,
    EcdsaP384,
    Kyber512,
    Kyber768,
    Kyber1024,
    Dilithium2,
    Dilithium3,
    Dilithium5,
}

impl fmt::Display for KeyAlg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            KeyAlg::Rsa2048 => "rsa2048",
            KeyAlg::Rsa4096 => "rsa4096",
            KeyAlg::Ed25519 => "ed25519",
            KeyAlg::X25519 => "x25519",
            KeyAlg::EcdsaP256 => "p256",
            KeyAlg::EcdsaP384 => "p384",
            KeyAlg::Kyber512 => "kyb512",
            KeyAlg::Kyber768 => "kyb768",
            KeyAlg::Kyber1024 => "kyb1024",
            KeyAlg::Dilithium2 => "dil2",
            KeyAlg::Dilithium3 => "dil3",
            KeyAlg::Dilithium5 => "dil5",
        };
        write!(f, "{s}")
    }
}

impl FromStr for KeyAlg {
    type Err = BeaconError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "rsa2048" => Ok(KeyAlg::Rsa2048),
            "rsa4096" => Ok(KeyAlg::Rsa4096),
            "ed25519" => Ok(KeyAlg::Ed25519),
            "x25519" => Ok(KeyAlg::X25519),
            "p256" => Ok(KeyAlg::EcdsaP256),
            "p384" => Ok(KeyAlg::EcdsaP384),
            "kyb512" => Ok(KeyAlg::Kyber512),
            "kyb768" => Ok(KeyAlg::Kyber768),
            "kyb1024" => Ok(KeyAlg::Kyber1024),
            "dil2" => Ok(KeyAlg::Dilithium2),
            "dil3" => Ok(KeyAlg::Dilithium3),
            "dil5" => Ok(KeyAlg::Dilithium5),
            _ => Err(BeaconError::InvalidKeyAlgorithim(s.to_string())),
        }
    }
}

/// Supported hashing algorithms for deriving key fingerprints
///
/// # Examples
///
/// ```
/// use keycast::crypto::HashAlg;
/// use std::str::FromStr;
///
/// let h = HashAlg::Blake3;
/// assert_eq!(h.to_string(), "b3");
///
/// let parsed: HashAlg = "b3".parse().unwrap();
/// assert_eq!(parsed, HashAlg::Blake3);
///
/// // round-trip consistency
/// assert_eq!(parsed.to_string(), "b3");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashAlg {
    Sha256,
    Sha384,
    Sha512,
    Blake2b,
    Blake3,
    Shake128,
    Shake256,
}

impl fmt::Display for HashAlg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            HashAlg::Sha256 => "s256",
            HashAlg::Sha384 => "s384",
            HashAlg::Sha512 => "s512",
            HashAlg::Blake2b => "b2b",
            HashAlg::Blake3 => "b3",
            HashAlg::Shake128 => "sh128",
            HashAlg::Shake256 => "sh256",
        };
        write!(f, "{s}")
    }
}

impl FromStr for HashAlg {
    type Err = BeaconError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "s256" => Ok(HashAlg::Sha256),
            "s384" => Ok(HashAlg::Sha384),
            "s512" => Ok(HashAlg::Sha512),
            "b2b" => Ok(HashAlg::Blake2b),
            "b3" => Ok(HashAlg::Blake3),
            "sh128" => Ok(HashAlg::Shake128),
            "sh256" => Ok(HashAlg::Shake256),
            _ => Err(BeaconError::InvalidHashAlgorithim(s.to_string())),
        }
    }
}

/// Compact representation of a key fingerprint, used for discovery and trust-on-first-use.
///
/// # Examples
///
/// ```
/// use keycast::crypto::{Encoding, KeyAlg, HashAlg, KeyHash};
/// use std::str::FromStr;
///
/// let original = KeyHash {
///     key_encoding: Encoding::Base64Der,
///     key_alg: KeyAlg::Ed25519,
///     hash_alg: HashAlg::Blake3,
///     hash: "deadbeefcafebabe".to_string(),
/// };
///
/// let as_str = original.to_string();
/// assert_eq!(as_str, "b3:ed25519:b64d:deadbeefcafebabe");
///
/// let parsed: KeyHash = as_str.parse().unwrap();
/// assert_eq!(parsed, original);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyHash {
    pub key_encoding: Encoding,
    pub key_alg: KeyAlg,
    pub hash_alg: HashAlg,
    pub hash: String,
}

impl KeyHash {
    pub fn from_pubkey<H: HashAlgorithm, K: ToPublicKeyDer>(
        key: K,
        hasher: &H,
        encoding: Encoding,
    ) -> Result<Self, BeaconError> {
        let der = key.to_public_key_der()?;
        let digest = hasher.hash(der.as_bytes());

        let hash_str = match encoding {
            Encoding::HexPem | Encoding::HexDer => hex::encode(&digest),
            Encoding::Base64Pem | Encoding::Base64Der => base64_encode(&digest),
        };

        Ok(Self {
            key_encoding: encoding,
            key_alg: key.key_algorithm(),
            hash_alg: hasher.name(),
            hash: hash_str,
        })
    }
}

impl fmt::Display for KeyHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Example compact form: "b3:p256:hxd:b3deadbeef..."
        write!(
            f,
            "{}:{}:{}:{}",
            self.hash_alg, self.key_alg, self.key_encoding, self.hash
        )
    }
}

impl FromStr for KeyHash {
    type Err = BeaconError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 4 {
            return Err(BeaconError::InvalidKeyHashFormat(
                s.to_string(),
                parts.len(),
            ));
        }

        Ok(Self {
            hash_alg: parts[0].parse()?,
            key_alg: parts[1].parse()?,
            key_encoding: parts[2].parse()?,
            hash: parts[3].to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn encoding_roundtrip() {
        let variants = [
            Encoding::HexPem,
            Encoding::Base64Pem,
            Encoding::HexDer,
            Encoding::Base64Der,
        ];

        for &e in &variants {
            let s = e.to_string();
            let parsed = Encoding::from_str(&s).expect("Failed to parse Encoding");
            assert_eq!(parsed, e, "Encoding round-trip failed for {}", s);
        }
    }

    #[test]
    fn keyalg_roundtrip() {
        let variants = [
            KeyAlg::Rsa2048,
            KeyAlg::Rsa4096,
            KeyAlg::Ed25519,
            KeyAlg::X25519,
            KeyAlg::EcdsaP256,
            KeyAlg::EcdsaP384,
            KeyAlg::Kyber512,
            KeyAlg::Kyber768,
            KeyAlg::Kyber1024,
            KeyAlg::Dilithium2,
            KeyAlg::Dilithium3,
            KeyAlg::Dilithium5,
        ];

        for &alg in &variants {
            let s = alg.to_string();
            let parsed = KeyAlg::from_str(&s).expect("Failed to parse KeyAlg");
            assert_eq!(parsed, alg, "KeyAlg round-trip failed for {}", s);
        }
    }

    #[test]
    fn hashalg_roundtrip() {
        let variants = [
            HashAlg::Sha256,
            HashAlg::Sha384,
            HashAlg::Sha512,
            HashAlg::Blake2b,
            HashAlg::Blake3,
            HashAlg::Shake128,
            HashAlg::Shake256,
        ];

        for &h in &variants {
            let s = h.to_string();
            let parsed = HashAlg::from_str(&s).expect("Failed to parse HashAlg");
            assert_eq!(parsed, h, "HashAlg round-trip failed for {}", s);
        }
    }

    #[test]
    fn keyhash_roundtrip() {
        // sample KeyHash instances
        let hashes = [
            KeyHash {
                key_encoding: Encoding::HexPem,
                key_alg: KeyAlg::Rsa2048,
                hash_alg: HashAlg::Sha256,
                hash: "deadbeef".to_string(),
            },
            KeyHash {
                key_encoding: Encoding::Base64Der,
                key_alg: KeyAlg::Ed25519,
                hash_alg: HashAlg::Blake3,
                hash: "cafebabe".to_string(),
            },
            KeyHash {
                key_encoding: Encoding::HexDer,
                key_alg: KeyAlg::Kyber768,
                hash_alg: HashAlg::Shake256,
                hash: "feedface".to_string(),
            },
        ];

        for original in &hashes {
            let s = original.to_string();
            let parsed: KeyHash = s.parse().expect("Failed to parse KeyHash");
            assert_eq!(parsed, *original, "KeyHash round-trip failed for {}", s);
        }
    }
}
