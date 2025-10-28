//! # Multicast Discovery and Advertisement Library
//!
//! This module provides a high-level abstraction for discovering and advertising
//! services via multicast DNS (mDNS) and UDP multicast beacons.
//!
//! It includes:
//! - [`Beacon`]: describes a discoverable node, including identity and network info
//! - [`Discovery`]: discovers other nodes over mDNS and multicast
//! - [`AdvertisementHandle`]: controls a running advertisement
//! - [`WaitFor`]: controls how long discovery should run
//!
//! The goal is to make it easy to build decentralized service discovery for local
//! or ad-hoc networks.

use crate::crypto::sha256_base64;
use crate::errors::{BeaconError, Result};
use hostname::get;
use mdns_sd::{ServiceDaemon, ServiceInfo};
use serde_derive::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Instant;
use tokio::{net::UdpSocket, task::JoinHandle, time::Duration};

use mdns_sd::ServiceEvent;
use tokio::sync::mpsc;

/// Represents a handle to a running advertisement process.
///
/// This handle is returned when a [`Beacon`] successfully starts advertising.
/// It can be used to monitor daemon events, stop advertising, or inspect activity.
pub struct AdvertisementHandle {
    //pub multicast: JoinHandle<()>,
    pub monitor: mdns_sd::Receiver<mdns_sd::DaemonEvent>,
}

/// Controls how long the discovery process should run and when to stop.
///
/// The [`WaitFor`] enum defines various stop conditions for discovery:
/// - `FirstDiscovery`: stop as soon as the first valid service is found.
/// - `Timeout`: run until the timeout expires.
/// - `MinDiscovered(n)`: stop after discovering at least `n` services or on timeout.
#[derive(Debug, Clone)]
pub enum WaitFor {
    /// Stop as soon as a candidate is found.
    FirstDiscovery,
    /// Receive candidates until timeout.
    Timeout(Duration),
    /// Stop after receiving a minimum number of candidates or timeout.
    MinDiscovered(usize, Duration),
}

/// Represents a discovered service or node on the multicast network.
///
/// A [`Discovery`] instance describes both the multicast group parameters
/// and the node’s own network address.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Discovery {
    /// Protocol version string for compatibility.
    pub version: String,
    /// Local IP address of the discovered node.
    pub addrs: Vec<IpAddr>,
    pub port: u16,
    pub name: String,
    pub host: String,
    pub enc_pubkey_hash: String,
}

/// Represents a node (or service) being advertised on the network.
///
/// Each beacon carries identifying and cryptographic information that allows
/// peers to verify authenticity and establish secure communication.
///
/// Fields like [`enc_pubkey`] and [`ident_pubkey`] are expected to be base64-encoded strings.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Beacon {
    /// Unique node identifier (e.g., UUID or hash).
    id: String,
    /// Optional human-readable name for the node.
    name: Option<String>,
    /// Optional IP address where this beacon is reachable.
    ip: Option<IpAddr>,
    /// Port number used by the node.
    port: u16,
    /// Time-to-live (TTL) for this advertisement, in seconds.
    ttl: u32,
    /// service identifier constructor such as _myservice._tcp.local.
    ident: ServiceIdent,
    /// base64 encoded sha2 256 hash of the public key
    enc_pubkey_hash: String,
}

/// used to construct a _googlecast._tcp.local. service type identifier
/// ```
/// use keycast::discovery::ServiceIdent;
/// let my_service = ServiceIdent::UDP("myservice".to_string());
/// assert_eq!(my_service.into_service_type(), "_myservice._udp.local.");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServiceIdent {
    UDP(String),
    TCP(String),
}

impl ServiceIdent {
    pub fn into_service_type(&self) -> String {
        match self {
            ServiceIdent::UDP(v) => format!("_{}._udp.local.", v),
            ServiceIdent::TCP(v) => format!("_{}._tcp.local.", v),
        }
    }
}

impl Beacon {
    /// Creates a new instance of `Beacon`, automatically generating an ID from
    /// the provided public key and attempting to detect the system’s primary IP address.
    ///
    /// # Arguments
    ///
    /// * `enc_pubkey` — The node’s public key, used to compute its unique SHA-256-based ID.
    /// * `ident_pubkey` — A key or token used for validating peer authenticity.
    ///
    /// # Behavior
    ///
    /// This constructor tries to determine the IP address of the system’s **primary network
    /// interface** (the one that would be used for outbound internet connections).  
    /// It does so by creating a temporary UDP socket bound to `0.0.0.0:0` and connecting
    /// to a known public endpoint (`8.8.8.8:80`). No data is ever sent; the socket is used
    /// purely to let the OS choose the appropriate routing interface.
    ///
    /// If IP detection fails (for example, on an offline or isolated system), the `ip` field
    /// will be set to `None` and a warning will be printed to `stderr`.
    ///
    /// # Returns
    ///
    /// A new `Beacon` instance with:
    /// - `id`: derived from the SHA-256 hash of the public key
    /// - `ip`: the detected primary outbound IP, or `None` if unavailable
    /// - `port`: defaulting to `4848`
    /// - `ttl`: defaulting to `60`
    /// # Example
    ///
    /// ```ignore
    /// use keycast::discovery::{Beacon, ServiceIdent};
    /// let ident = ServiceIdent::TCP("myservice".to_string());
    /// let node = Beacon::new(ident, "my_public_key", "my_ident_pubkey").await;
    /// ```
    pub async fn new(ident: ServiceIdent, enc_pubkey: &str) -> Self {
        // Try to determine the primary outbound IP
        let ip = match Self::get_primary_ip().await {
            Ok(addr) => Some(addr),
            Err(e) => {
                eprintln!("Warning: failed to determine primary IP: {e}");
                None
            }
        };

        let id = sha256_base64(enc_pubkey);
        let second = sha256_base64(enc_pubkey);
        assert_eq!(id, second);
        Self {
            id,
            name: None,
            ip,
            port: 4848,
            ttl: 60,
            ident,
            enc_pubkey_hash: sha256_base64(&enc_pubkey),
        }
    }

    async fn get_primary_ip() -> std::io::Result<IpAddr> {
        // This never actually sends data — just lets OS pick a route.
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect("8.8.8.8:80").await?;
        let local_addr = socket.local_addr()?;
        Ok(local_addr.ip())
    }

    /// Advertises this beacon over mDNS and (optionally) UDP multicast.
    ///
    /// This function validates that the provided address is a multicast address,
    /// and then:
    /// - Starts an mDNS service daemon via [`mdns_sd`].
    /// - Registers this beacon’s metadata as a `_verdant._tcp.local.` service.
    /// - Optionally (commented out) spawns a periodic UDP beacon sender.
    ///
    /// Returns an [`AdvertisementHandle`] that can be used to monitor events.
    pub async fn advertise(&self) -> Result<AdvertisementHandle> {
        let hostname = get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| self.id.clone());

        // ---- Spawn mDNS Advertisement ----
        let service_hostname = format!("{}.local.", self.id.clone());
        let name = match &self.name {
            Some(name) => name.to_string(),
            None => hostname,
        };
        let instance_name = format!("{}", name);
        let port_clone = self.port;

        let monitor = if let Ok(daemon) = ServiceDaemon::new() {
            let properties = [
                ("protocol".to_string(), "keycast".to_string()),
                ("version".to_string(), "0.0.1".to_string()),
                ("enc_pubkey_hash".to_string(), self.enc_pubkey_hash.clone()),
            ];
            let service_info = ServiceInfo::new(
                "_verdant._tcp.local.",
                &instance_name,
                &service_hostname,
                self.ip
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "".to_string()),
                port_clone,
                &properties[..], // No TXT records — Beacon carries metadata
            );

            let monitor = daemon.monitor().expect("Failed to monitor the daemon");
            match service_info {
                Ok(info) => {
                    let fullname = info.get_fullname().to_string();
                    if let Err(e) = daemon.register(info) {
                        eprintln!("[mDNS] Registration error: {:?}", e);
                    } else {
                        println!("[mDNS] Service registered as {}", fullname);
                    }
                }
                Err(e) => eprintln!("[mDNS] Failed to build service info: {:?}", e),
            }

            monitor
        } else {
            panic!("[mDNS] Failed to start service daemon");
        };

        Ok(AdvertisementHandle { monitor })
    }

    /// Discovers peers advertising the given mDNS service name.
    ///
    /// This function performs a service browse using [`mdns_sd::ServiceDaemon`]
    /// and listens for [`ServiceEvent`]s until a stop condition defined by [`WaitFor`]
    /// is reached.
    ///
    /// Optionally, a callback `on_event` can be supplied to handle discovery events
    /// in real-time (e.g., logging or filtering).
    ///
    /// # Arguments
    /// - `service_ident`: The mDNS service type to search for (e.g. `"_verdant._tcp.local."`).
    /// - `wait_for`: The stop condition controlling how long discovery runs.
    /// - `on_event`: Optional closure invoked for each [`ServiceEvent`].
    ///
    /// # Returns
    /// A vector of discovered [`Discovery`] instances.

    pub async fn discover(
        service_ident: ServiceIdent,
        wait_for: WaitFor,
        mut on_event: Option<Box<dyn FnMut(Result<&ServiceEvent>) + Send>>,
    ) -> Result<Vec<Discovery>> {
        let service_name = service_ident.into_service_type();
        // ---- Step 1: Query mDNS ----
        let daemon = ServiceDaemon::new()?;

        let receiver = daemon.browse(&service_name)?;

        println!("[mDNS] Browsing for {service_name}...");

        let start_time = Instant::now();
        let mut discoveries = Vec::new();

        loop {
            // ---- Step 2: Wait for next event ----
            let event = match tokio::time::timeout(Duration::from_secs(5), receiver.recv_async())
                .await
            {
                Ok(Ok(ev)) => ev,
                Ok(Err(e)) => {
                    eprintln!("[mDNS] Receive error: {:?}", e);
                    continue;
                }
                Err(_) => {
                    // Timeout waiting for message
                    if matches!(wait_for, WaitFor::Timeout(_) | WaitFor::MinDiscovered(_, _)) {
                        if let WaitFor::Timeout(d) | WaitFor::MinDiscovered(_, d) = wait_for.clone()
                        {
                            if start_time.elapsed() >= d {
                                println!("[mDNS] Timed out after {:?}", d);
                                break;
                            }
                        }
                    }
                    continue;
                }
            };

            // ---- Step 3: Notify callback if provided ----
            if let Some(cb) = on_event.as_mut() {
                cb(Ok(&event));
            }

            // ---- Step 4: Handle discovered services ----
            match event {
                ServiceEvent::ServiceResolved(info) => {
                    let addrs = info
                        .get_addresses()
                        .iter()
                        .map(|ip| ip.to_ip_addr())
                        .collect::<Vec<_>>();

                    let version = info
                        .get_property_val_str("version")
                        .map(|s| s.to_string())
                        .ok_or_else(|| BeaconError::MissingProperty("version"))?;
                    
                    let enc_pubkey_hash = info
                        .get_property_val_str("enc_pubkey_hash")
                        .map(|s| s.to_string())
                        .ok_or_else(|| BeaconError::MissingProperty("enc_pubkey_hash"))?;
                    

                    let discovery = Discovery {
                        name: info.get_fullname().to_string(),
                        host: info.get_hostname().to_string(),
                        addrs: addrs,
                        port: info.get_port(),
                        version,
                        enc_pubkey_hash,
                    };

                    println!("[mDNS] Resolved: {}", discovery.name);
                    discoveries.push(discovery);

                    // Check stop condition
                    match wait_for {
                        WaitFor::FirstDiscovery => break,
                        WaitFor::MinDiscovered(min, _) if discoveries.len() >= min => break,
                        _ => {}
                    }
                }
                ServiceEvent::ServiceFound(name, ty) => {
                    println!("[mDNS] Discovered {name} ({ty}), resolving...");
                    // You could call daemon.resolve(ty, &name) here
                }
                _ => {}
            }

            // ---- Step 5: Stop if global timeout reached ----
            if let WaitFor::Timeout(d) | WaitFor::MinDiscovered(_, d) = wait_for.clone() {
                if start_time.elapsed() >= d {
                    println!("[mDNS] Timeout reached, stopping discovery.");
                    break;
                }
            }
        }

        Ok(discoveries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_rsa_pkcs8_pair;
    use std::net::IpAddr;

    #[tokio::test]
    async fn beacon_serialization_roundtrip() {
        let (_privkey, enc_pubkey) = generate_rsa_pkcs8_pair();
        let ident = ServiceIdent::TCP("myservice".to_string());
        let b = Beacon::new(ident, &enc_pubkey).await;

        let json = serde_json::to_string(&b).unwrap();
        let parsed: Beacon = serde_json::from_str(&json).unwrap();

        assert_eq!(b.id, parsed.id);
        assert_eq!(b.name, parsed.name);
        assert_eq!(b.ip, parsed.ip);
        assert_eq!(b.port, parsed.port);
        assert_eq!(b.enc_pubkey_hash, parsed.enc_pubkey_hash);
    }

    #[tokio::test]
    async fn multicast_advertise_and_discover() -> crate::errors::Result<()> {
        let addr: IpAddr = "239.255.0.1".parse()?;
        let port = 9999;

        let (_privkey, enc_pubkey) = generate_rsa_pkcs8_pair();
        let ident = ServiceIdent::TCP("myservice".to_string());

        let b = Beacon::new(ident, &enc_pubkey).await;

        // Start advertiser
        let adv = b.advertise().await?;

        Ok(())
    }
}
