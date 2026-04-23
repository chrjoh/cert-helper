// CRL workflow signed by an ML-DSA-65 CA. Mirrors `crl_example.rs` but with
// a post-quantum signer, demonstrating that cert-helper's CRL builder works
// end-to-end with PQC keys.
//
// Inspect / verify the resulting CRL with:
//   openssl crl -in ./certs/pqc_crl_final.der -inform DER -text -noout
//   openssl crl -in ./certs/pqc_crl_final.der -inform DER -text -noout \
//       -CAfile ./certs/pqc_crl_signer_cert.pem

use cert_helper::certificate::{CertBuilder, KeyType, UseesBuilderFields, X509Common};
use cert_helper::crl::{CrlReason, X509CrlBuilder, X509CrlWrapper, write_der_crl_as_pem};
use chrono::Utc;
use num_bigint::{BigUint, ToBigUint};
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all("./certs")?;

    println!("Generating ML-DSA-65 CRL-signing CA...");
    let ca = CertBuilder::new()
        .common_name("PQC CRL Issuer")
        .organization("cert-helper examples")
        .is_ca(true)
        .key_type(KeyType::MlDsa65)
        .build_and_self_sign()?;
    ca.save("./certs", "pqc_crl_signer")?;

    // First pass: write a CRL with a single made-up serial number.
    println!("Issuing initial CRL with a dummy revoked serial...");
    let mut builder = X509CrlBuilder::new(ca.clone());
    builder.add_revoked_cert(12_345u32.to_biguint().unwrap(), Utc::now());

    let wrapper = builder.build_and_sign()?;
    let crl_der = wrapper.to_der()?;
    std::fs::write("./certs/pqc_crl.der", &crl_der)?;
    write_der_crl_as_pem(&crl_der, "./certs", "pqc_crl_first.pem")?;
    println!(
        "  ./certs/pqc_crl.der ({} bytes), ./certs/pqc_crl_first.pem",
        crl_der.len()
    );

    // Second pass: load the existing CRL, revoke a real leaf cert with a
    // reason code, extend nextUpdate, re-sign.
    println!("Generating a leaf to revoke...");
    let revoked = CertBuilder::new()
        .common_name("revoked.example")
        .build_and_sign(&ca)?;
    let serial_bytes = revoked.x509.serial_number().to_bn().unwrap().to_vec();

    println!("Updating CRL with the leaf's serial + reason=KeyCompromise...");
    let mut builder = if let Ok(existing) = fs::read("./certs/pqc_crl.der") {
        X509CrlBuilder::from_der(&existing, ca.clone()).expect("parse existing CRL")
    } else {
        X509CrlBuilder::new(ca.clone())
    };
    builder.add_revoked_cert_with_reason(
        BigUint::from_bytes_be(&serial_bytes),
        Utc::now(),
        vec![CrlReason::KeyCompromise],
    );
    builder.set_update_times(Utc::now(), Utc::now() + chrono::Duration::days(30));

    let wrapper = builder.build_and_sign()?;
    let crl_der = wrapper.to_der()?;
    std::fs::write("./certs/pqc_crl_final.der", &crl_der)?;
    write_der_crl_as_pem(&crl_der, "./certs", "pqc_crl_final.pem")?;
    println!(
        "  ./certs/pqc_crl_final.der ({} bytes), ./certs/pqc_crl_final.pem",
        crl_der.len()
    );

    // Round-trip: read the PEM back and verify signature + revocation status.
    println!("Verifying CRL signature + revocation check...");
    let wrapper = X509CrlWrapper::read_as_pem("./certs/pqc_crl_final.pem")?;
    let signature_ok = wrapper.verify_signature(ca.x509.public_key().as_ref().unwrap())?;
    assert!(signature_ok, "ML-DSA-65-signed CRL should verify against CA public key");

    let is_revoked = wrapper.revoked(revoked.x509.serial_number());
    assert!(is_revoked, "leaf should be listed as revoked");

    println!("Done — PQC CRL signed, serialized, re-parsed, and verified.");
    Ok(())
}
