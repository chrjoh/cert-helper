use cert_helper::certificate::{CertBuilder, KeyType, UseesBuilderFields, X509Common};
use cert_helper::crl::{CrlReason, X509CrlBuilder, write_der_crl_as_pem};
use chrono::Utc;
use num_bigint::{BigUint, ToBigUint};

use std::fs;
// view crl:
//  openssl crl -in certs/crl_final.der -inform DER -text -noout
// verify crl
//  openssl crl -in certs/crl_final.der -inform DER -text -noout -CAfile  certs/crl_signer_cert.pem
fn main() {
    let ca = CertBuilder::new()
        .common_name("My Test Ca")
        .is_ca(true)
        .key_type(KeyType::Ed25519)
        .build_and_self_sign()
        .unwrap();
    let mut builder = X509CrlBuilder::new(ca);
    builder.add_revoked_cert(12345u32.to_biguint().unwrap(), Utc::now());

    let crl_der = builder.build_and_sign();
    // write result as simple der file
    std::fs::write("./certs/crl.der", &crl_der).unwrap();
    write_der_crl_as_pem(&crl_der, "./certs", "crl_first.pem")
        .expect("failed to save crl as pem file");
    let ca = CertBuilder::new()
        .common_name("My Test Ca")
        .is_ca(true)
        .key_type(KeyType::Ed25519)
        .build_and_self_sign()
        .unwrap();
    let revocked = CertBuilder::new()
        .common_name("My Test")
        .build_and_self_sign()
        .unwrap();
    ca.save("./certs", "crl_signer").unwrap();
    let bytes = revocked.x509.serial_number().to_bn().unwrap().to_vec();

    let mut builder = if let Ok(existing) = fs::read("./certs/crl.der") {
        X509CrlBuilder::from_der(&existing, ca).expect("failed to get crl from file")
    } else {
        X509CrlBuilder::new(ca)
    };
    builder.add_revoked_cert_with_reason(
        BigUint::from_bytes_be(&bytes),
        Utc::now(),
        vec![CrlReason::KeyCompromise],
    );
    builder.set_update_times(Utc::now(), Utc::now() + chrono::Duration::days(30));

    let crl_der = builder.build_and_sign();
    std::fs::write("./certs/crl_final.der", &crl_der).unwrap();
    write_der_crl_as_pem(&crl_der, "./certs", "crl_final.pem")
        .expect("failed to save crl as pem file");
    println!("Done");
}
