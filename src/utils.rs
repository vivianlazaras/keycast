use base64::engine::general_purpose::{STANDARD, GeneralPurpose};
use base64::Engine;

pub const DEFAULT_ENGINE: GeneralPurpose = STANDARD;

pub fn base64_encode(bytes: &[u8]) -> String {
    DEFAULT_ENGINE.encode(bytes)
}

pub fn base64_decode(encoded: &[u8]) -> Result<Vec<u8>, crate::errors::BeaconError> {
    Ok(DEFAULT_ENGINE.decode(encoded)?)
}