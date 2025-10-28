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
                    println!(
                        "  - ID: {}\n    Name: {:?}\n    Addrs: {:?}:{}\n",
                        b.host, b.name, b.addrs, b.port
                    );
                }
            }
        }

        Err(e) => {
            eprintln!("[Discover] Error: {:?}", e);
        }
    }

    Ok(())
}
