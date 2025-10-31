use keycast::crypto::rsa_impl::generate_rsa_pair;
use keycast::crypto::{Encoding, KeyHash, sha2_impl::Sha256Alg};
use keycast::discovery::{Beacon, ServiceIdent};
use keycast::errors::Result;
use mdns_sd::DaemonEvent;

#[tokio::main]
async fn main() -> Result<()> {
    let (_privkey, pubkey) = generate_rsa_pair();

    let ident = ServiceIdent::TCP("verdant".to_string());
    let hasher = Sha256Alg;
    let key = KeyHash::from_pubkey(pubkey, &hasher, Encoding::Base64Der).unwrap();
    let beacon = Beacon::new(ident, key).await;
    println!("beacon: {:?}", beacon);
    let handle = beacon.advertise().await?;

    println!("[Advertiser] Beacon broadcasting. Press Ctrl+C to exit.");

    println!("[Advertiser] Shutting down.");

    //handle.multicast.abort();
    while let Ok(event) = handle.monitor.recv() {
        println!("Daemon event: {:?}", &event);
        if let DaemonEvent::Error(e) = event {
            println!("Failed: {}", e);
            break;
        }
    }
    Ok(())
}
