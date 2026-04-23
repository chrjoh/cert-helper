// One-off verifier: writes an ML-DSA-65 self-signed cert from cert-helper
// to a file, then you can run `openssl x509 -in /tmp/mldsa65-cert.pem -text`
// to confirm OpenSSL 3.5+ parses it back correctly.

use cert_helper::certificate::{CertBuilder, KeyType, UseesBuilderFields};

fn main() {
    let ca = CertBuilder::new()
        .common_name("cert-helper PQC verify")
        .is_ca(true)
        .key_type(KeyType::MlDsa65)
        .build_and_self_sign()
        .expect("self-sign ML-DSA-65");

    let pem = ca.x509.to_pem().expect("PEM");
    std::fs::write("./certs/mldsa65-cert.pem", &pem).unwrap();
    println!("wrote ./certs/mldsa65-cert.pem ({} bytes)", pem.len());
}
