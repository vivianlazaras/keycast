use rcgen::{Certificate as RcgenCert, CertificateParams};
use rocket::config::TlsConfig;
use rocket::{Config, get, routes};
use std::sync::Arc;
//use rustls::{Certificate as RustlsCert, PrivateKey};
use keycast::crypto::{KeyHash, sha2_impl::Sha256Alg};
use rustls_pki_types::PrivateKeyDer;
use rustls_pki_types::PrivatePkcs8KeyDer;
use rustls_pki_types::pem::SectionKind::PrivateKey;
use tokio::task;
// Example beacon placeholders — replace with your real types
use keycast::discovery::{Beacon, ServiceIdent};
use mdns_sd::DaemonEvent;

#[get("/")]
fn hello() -> &'static str {
    "hello world"
}

async fn advertise(key: KeyHash) -> task::JoinHandle<()> {
    task::spawn(async move {
        // Placeholder example — assumes Beacon::new and .advertise() exist
        let ident = ServiceIdent::TCP("verdant".to_string());

        let beacon = Beacon::new(ident, key).await;
        println!("beacon: {:?}", beacon);
        let handle = beacon.advertise().await.unwrap();

        println!("[Advertiser] Beacon broadcasting. Press Ctrl+C to exit.");

        while let Ok(event) = handle.monitor.recv() {
            println!("Daemon event: {:?}", &event);
            if let DaemonEvent::Error(e) = event {
                eprintln!("Failed: {}", e);
                break;
            }
        }

        println!("[Advertiser] Shutting down.");
    })
}

#[rocket::main]
async fn main() -> Result<(), rocket::Error> {
    // --- 1. Generate certificate using KeyHash + Sha256Alg ---
    let sha256 = Sha256Alg;
    // If generate_cert requires an issuer, pass one here
    let (keyhash, pair, cert) = KeyHash::generate_cert(&sha256);

    let cert_pem = cert.pem().clone();
    let key_pem = pair.serialize_pem();

    /*let rustls_cert = vec![cert_der];
    let rustls_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der.as_slice()));

    // --- 2. Build rustls::ServerConfig manually ---
    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(rustls_cert, rustls_key)
        .expect("invalid cert/key");
    */
    // --- 3. Start Rocket with custom TLS config ---
    let rocket_config = Config {
        tls: Some(TlsConfig::from_bytes(
            &cert_pem.as_bytes(),
            &key_pem.as_bytes(),
        )),
        port: 4848,
        ..Config::default()
    };

    // Optionally launch your background advertiser
    let _advertiser = advertise(keyhash).await;

    rocket::custom(rocket_config)
        .mount("/", routes![hello])
        .launch()
        .await?;

    Ok(())
}
