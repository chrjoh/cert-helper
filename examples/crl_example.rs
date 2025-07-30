use cert_helper::crl::X509CrlBuilder;
use chrono::Utc;
use num_bigint::ToBigUint;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use std::fs;

fn main() {
    let rsa = Rsa::generate(2048).unwrap();
    let key = PKey::from_rsa(rsa).unwrap();

    let mut builder = X509CrlBuilder::new("Example CA");
    builder.add_revoked_cert(12345u32.to_biguint().unwrap(), Utc::now());

    let crl_der = builder.build_and_sign(&key);
    std::fs::write("crl.der", crl_der).unwrap();
    let mut builder = if let Ok(existing) = fs::read("crl.der") {
        X509CrlBuilder::from_der(&existing).expect("failed to get crl from file")
    } else {
        X509CrlBuilder::new("Example CA")
    };
    builder.add_revoked_cert(99999u32.to_biguint().unwrap(), Utc::now());
    builder.set_update_times(Utc::now(), Utc::now() + chrono::Duration::days(30));

    let crl_der = builder.build_and_sign(&key);
    fs::write("crl2.der", crl_der).expect("failed to save cfrl2");
}
