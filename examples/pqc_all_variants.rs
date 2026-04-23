// Generates one self-signed certificate for each of the six PQC `KeyType`
// variants and saves them under ./certs/pqc/. Useful for seeing what each
// algorithm's signature/key pair looks like (sizes vary by two orders of
// magnitude between ML-DSA-44 and SLH-DSA-SHA2-256s).
//
// Inspect with:
//   openssl x509 -in ./certs/pqc/mldsa65_cert.pem -text -noout
//   openssl pkey -in ./certs/pqc/mldsa65_pkey.pem -text -noout

use cert_helper::certificate::{CertBuilder, KeyType, UseesBuilderFields, X509Common};
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all("./certs/pqc")?;

    // (KeyType, filename stem, human label)
    let variants: &[(KeyType, &str, &str)] = &[
        (KeyType::MlDsa44, "mldsa44", "ML-DSA-44 (FIPS 204)"),
        (KeyType::MlDsa65, "mldsa65", "ML-DSA-65 (FIPS 204)"),
        (KeyType::MlDsa87, "mldsa87", "ML-DSA-87 (FIPS 204)"),
        (
            KeyType::SlhDsaSha2_128s,
            "slhdsa_sha2_128s",
            "SLH-DSA-SHA2-128s (FIPS 205)",
        ),
        (
            KeyType::SlhDsaSha2_192s,
            "slhdsa_sha2_192s",
            "SLH-DSA-SHA2-192s (FIPS 205)",
        ),
        (
            KeyType::SlhDsaSha2_256s,
            "slhdsa_sha2_256s",
            "SLH-DSA-SHA2-256s (FIPS 205)",
        ),
    ];

    for (key_type, stem, label) in variants {
        println!("Generating {}...", label);
        let ca = CertBuilder::new()
            .common_name(&format!("PQC sample — {}", label))
            .country_name("SE")
            .organization("cert-helper examples")
            .is_ca(true)
            .key_type(key_type.clone())
            .build_and_self_sign()?;

        ca.save("./certs/pqc/", stem)?;

        let der_len = ca.x509.to_der()?.len();
        println!("  wrote ./certs/pqc/{}_cert.pem ({} bytes DER)", stem, der_len);
    }

    println!("\nAll six PQC variants written to ./certs/pqc/");
    println!("Inspect any of them with:");
    println!("  openssl x509 -in ./certs/pqc/mldsa65_cert.pem -text -noout");
    Ok(())
}
