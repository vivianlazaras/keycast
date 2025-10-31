//! This module provides a means by which to create a reqwest Client
//! that uses the custom TOFU ServerCertVerifier `RustlsVerifier`

use crate::rustls::RustlsVerifier;
use reqwest::Client;

pub fn reqwest_client(verifier: RustlsVerifier) -> Result<reqwest::Client, reqwest::Error> {
    let config = verifier.client_config();
    let client = Client::builder().use_preconfigured_tls(config).build()?;

    Ok(client)
}
