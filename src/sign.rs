use rcgen::{CertifiedKey, KeyPair};

pub struct RSACertifier {
    key: String,
}

/// I need to generate keypair, hash pubkey, then use privkey to produce the certificate.
pub fn generate_cert() {
    let keypair = KeyPair::generate().expect("failed to generate keypair");
    let pubkey_pem = keypair.public_key_pem();

    //let subject_alt_names = vec!["localhost".to_string()];
    //let CertifiedKey { cert, key_pair } = generate_simple_self_signed(subject_alt_names).unwrap();
}
