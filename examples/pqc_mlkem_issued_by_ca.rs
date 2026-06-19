// Demonstrates the only valid issuance path for an ML-KEM (FIPS 203) key.
//
// ML-KEM is a key-encapsulation mechanism: it cannot produce signatures, so an
// ML-KEM certificate can be neither self-signed nor requested via a CSR. It must
// be issued by a separate signing CA. Its KeyUsage, if present, must be exactly
// `keyEncipherment` and nothing else.
//
// This example:
//   1. creates a self-signed CA (classical, but an ML-DSA CA would work too),
//   2. uses it to issue an MlKem512 leaf certificate with keyEncipherment usage,
//   3. saves both under ./certs/mlkem/.
//
// Inspect with:
//   openssl x509 -in ./certs/mlkem/mlkem512_leaf_cert.pem -text -noout

use cert_helper::certificate::{CertBuilder, KeyType, Usage, UseesBuilderFields, X509Common};
use std::collections::HashSet;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all("./certs/mlkem")?;

    // 1. Self-signed signing CA.
    println!("Creating signing CA...");
    let ca = CertBuilder::new()
        .common_name("cert-helper ML-KEM example CA")
        .country_name("SE")
        .organization("cert-helper examples")
        .is_ca(true)
        .build_and_self_sign()?;
    ca.save("./certs/mlkem/", "ca")?;

    // 2. ML-KEM-512 leaf issued by the CA. keyEncipherment is the only KeyUsage
    //    bit ML-KEM may assert.
    println!("Issuing ML-KEM-512 leaf certificate...");
    let leaf = CertBuilder::new()
        .common_name("mlkem512.example.com")
        .country_name("SE")
        .organization("cert-helper examples")
        .key_type(KeyType::MlKem512)
        .key_usage(HashSet::from([Usage::encipherment]))
        .build_and_sign(&ca)?;
    leaf.save("./certs/mlkem/", "mlkem512_leaf")?;

    let der_len = leaf.x509.to_der()?.len();
    println!(
        "\nWrote ./certs/mlkem/mlkem512_leaf_cert.pem ({} bytes DER)",
        der_len
    );
    println!("Inspect with:");
    println!("  openssl x509 -in ./certs/mlkem/mlkem512_leaf_cert.pem -text -noout");
    Ok(())
}
