# KeyCast

KeyCast is the begining of a project to leverage mDNS for public key hashing as a domain name. This approach would allow a domain name for mDNS to be somewhat self evident, and thus not require a certificate authority if the server can complete a challenge.

In the meantime however this crate operates as a convience wrapper around mdns_sd

## Advertising a service:

```
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
```

## Discovering a local service

```
use keycast::discovery::{Beacon, ServiceIdent, WaitFor}; // replace with your crate name
use keycast::errors::Result;

#[tokio::main]
async fn main() -> Result<()> {
    println!("[Discover] Searching for _verdant._tcp.local. services...");
    let ident = ServiceIdent::TCP("verdant".to_string());

    match Beacon::discover(ident, WaitFor::FirstDiscovery, None).await {
        Ok(beacons) => {
            if !beacons.is_empty() {
                println!("[Discover] Found {} beacons:", beacons.len());
                let mut iter = beacons.into_iter();
                while let Some(b) = iter.next() {
                    println!("discovered: {:?}", b);
                }
            }
        }

        Err(e) => {
            eprintln!("[Discover] Error: {:?}", e);
        }
    }

    Ok(())
}
```