use cert_helper::certificate::{CertBuilder, UseesBuilderFields};
use cert_helper::crl::X509CrlBuilder;
use chrono::Utc;
use num_bigint::{BigUint, ToBigUint};

use std::fs;

fn main() {
    let ca = CertBuilder::new()
        .common_name("My Test Ca")
        .is_ca(true)
        .build_and_self_sign()
        .unwrap();
    let mut builder = X509CrlBuilder::new(ca);
    builder.add_revoked_cert(12345u32.to_biguint().unwrap(), Utc::now());

    let crl_der = builder.build_and_sign();
    std::fs::write("crl.der", crl_der).unwrap();
    let ca = CertBuilder::new()
        .common_name("My Test Ca")
        .is_ca(true)
        .build_and_self_sign()
        .unwrap();
    let revocked = CertBuilder::new()
        .common_name("My Test")
        .build_and_self_sign()
        .unwrap();

    let bytes = revocked.x509.serial_number().to_bn().unwrap().to_vec();

    let mut builder = if let Ok(existing) = fs::read("crl.der") {
        X509CrlBuilder::from_der(&existing, ca).expect("failed to get crl from file")
    } else {
        X509CrlBuilder::new(ca)
    };
    builder.add_revoked_cert(BigUint::from_bytes_be(&bytes), Utc::now());
    builder.set_update_times(Utc::now(), Utc::now() + chrono::Duration::days(30));

    let crl_der = builder.build_and_sign();
    fs::write("crl2.der", crl_der).expect("failed to save crl2");
}
