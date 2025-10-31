use keycast::crypto::sha2_impl::Sha256Alg;
use keycast::discovery::{Beacon, ServiceIdent, WaitFor}; // replace with your crate name
use keycast::errors::Result;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .unwrap();
    println!("[Discover] Searching for _verdant._tcp.local. services...");
    let ident = ServiceIdent::TCP("verdant".to_string());
    let hasher = Arc::new(Sha256Alg);
    match Beacon::discover(ident, WaitFor::FirstDiscovery, None).await {
        Ok(beacons) => {
            if !beacons.is_empty() {
                println!("[Discover] Found {} beacons:", beacons.len());
                let mut iter = beacons.into_iter();
                while let Some(b) = iter.next() {
                    println!("discovered: {:?}", b);
                    let url = format!("{}/", b.host);
                    let client = b
                        .reqwest_client(hasher.clone())
                        .expect("failed to create client");
                    let builder = client.get(url).send().await.unwrap();
                }
            }
        }

        Err(e) => {
            eprintln!("[Discover] Error: {:?}", e);
        }
    }

    Ok(())
}
