//! # KeyCast
//!
//! A crate for handling decentralized DNS by leveraging mDNS and asymmetric key encryption models.
//! A public key of a peer within this crate's model can be trusted by verifying that the hash of the public key
//! produces the domain name (minus .local.) that is advertised with mDNS.
//!
//! ## Advertising an mDNS service
//! ```no_run
//! use mdns_sd::DaemonEvent;
//! use keycast::crypto::generate_rsa_pkcs8_pair;
//! use keycast::errors::Result;
//! use keycast::discovery::{Beacon, ServiceIdent};
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!
//!     let (_privkey, pubkey) = generate_rsa_pkcs8_pair();
//!     let ident = ServiceIdent::TCP("verdant".to_string());
//!
//!     let beacon = Beacon::new(ident, &pubkey).await;
//!
//!     let handle = beacon.advertise().await?;
//!
//!     println!("[Advertiser] Beacon broadcasting. Press Ctrl+C to exit.");
//!
//!     println!("[Advertiser] Shutting down.");
//!
//!     //handle.multicast.abort();
//!     while let Ok(event) = handle.monitor.recv() {
//!         println!("Daemon event: {:?}", &event);
//!         if let DaemonEvent::Error(e) = event {
//!             println!("Failed: {}", e);
//!             break;
//!         }
//!     }
//!     Ok(())
//! }
//! ```
//! ## Discovering peers on the network
//! ```no_run
//!
//! use keycast::discovery::{Beacon, ServiceIdent, WaitFor}; // replace with your crate name
//! use keycast::errors::Result;
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     println!("[Discover] Searching for _verdant._tcp.local. services...");
//!     let ident = ServiceIdent::TCP("verdant".to_string());
//!     match Beacon::discover(ident, WaitFor::FirstDiscovery, None).await {
//!         Ok(beacons) => {
//!             if !beacons.is_empty() {
//!                 println!("[Discover] Found {} beacons:", beacons.len());
//!                 let mut iter = beacons.into_iter();
//!                 while let Some(b) = iter.next() {
//!                     println!(
//!                         "  - ID: {}\n    Name: {:?}\n    Addrs: {:?}:{}\n",
//!                         b.host, b.name, b.addrs, b.port
//!                     );
//!                 }
//!             }
//!         }
//!
//!         Err(e) => {
//!             eprintln!("[Discover] Error: {:?}", e);
//!         }
//!     }
//!
//!     Ok(())
//! }
//!
//! ```
pub mod crypto;
pub mod discovery;
pub mod errors;
#[cfg(feature = "pkcs11")]
pub mod pkcs11;
#[cfg(feature = "rustls-reqwest")]
pub mod reqwest;
#[cfg(feature = "rustls-verifier")]
pub mod rustls;
#[cfg(feature = "rustls-verifier")]
pub mod sign;
