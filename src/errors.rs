use thiserror::Error;
use std::io;
use std::net::AddrParseError;


/// Errors that can occur during multicast discovery and advertisement.
#[derive(Debug, Error)]
pub enum BeaconError {
    
    /// Error during UDP socket binding or multicast join.
    #[error("Network error: {0}")]
    NetworkError(#[from] io::Error),

    /// The provided address is not a valid multicast address.
    #[error("Provided address {0} is not a multicast address")]
    NotMulticastAddress(std::net::IpAddr),

    /// The provided multicast group address could not be parsed.
    #[error("Invalid multicast group address: {0}")]
    InvalidGroupAddress(#[from] AddrParseError),

    /// The discovered service record was missing required properties.
    #[error("Missing required property: {0}")]
    MissingProperty(&'static str),

    /// A property value was present but could not be parsed.
    #[error("Failed to parse property '{0}': {1}")]
    PropertyParseError(&'static str, String),

    /// General serialization or deserialization failure.
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    /// Internal or unexpected error, preserved as message.
    #[error("Internal error: {0}")]
    Internal(String),

    /// mDNS error
    #[error("mdns_sd error: {0}")]
    MdnsError(#[from] mdns_sd::Error),
}

pub type Result<T> = std::result::Result<T, BeaconError>;
