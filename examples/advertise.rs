use mdns_sd::DaemonEvent;
use keycast::crypto::generate_rsa_pkcs8_pair;
use keycast::errors::Result;
use keycast::discovery::{Beacon, ServiceIdent};

#[tokio::main]
async fn main() -> Result<()> {

    let (_privkey, pubkey) = generate_rsa_pkcs8_pair();
    let (_encode_key, validate_key) = generate_rsa_pkcs8_pair();

    let ident = ServiceIdent::TCP("verdant".to_string());

    let beacon = Beacon::new(ident, &pubkey, &validate_key).await;

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
