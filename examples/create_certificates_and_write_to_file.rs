use cert_helper::certificate::{
    CertBuilder, Certificate, CsrBuilder, CsrOptions, HashAlg, KeyType, Usage, UseesBuilderFields,
    X509Common, verify_cert,
};
use std::fs;

/// Create three certificates as a chain
/// ca->middle->leaf
/// saves the crtificates and private keys in the folder certs
/// at the end we verify the certificate cahin just created
fn main() -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all("./certs")?;
    println!("Generating CA certificate and key...");
    let ca = CertBuilder::new()
        .common_name("My Test Ca")
        .country_name("SE")
        .state_province("Stockholm")
        .organization("my org")
        .locality_time("Stockholm")
        .is_ca(true)
        .key_type(KeyType::Ed25519)
        .signature_alg(HashAlg::SHA512)
        .alternative_names(vec!["ca.com", "www.ca.com"])
        .key_usage([Usage::certsign, Usage::crlsign].into_iter().collect());
    let root_cert = ca.build_and_self_sign()?;
    root_cert.save("./certs/", "ed_ca")?;

    println!("Generating CA certificate and key...");
    let ca = CertBuilder::new()
        .common_name("My Test Ca")
        .country_name("SE")
        .state_province("Stockholm")
        .organization("my org")
        .locality_time("Stockholm")
        .is_ca(true)
        .key_type(KeyType::Ed25519)
        .signature_alg(HashAlg::SHA512)
        .alternative_names(vec!["ca.com", "www.ca.com"])
        .key_usage([Usage::certsign, Usage::crlsign].into_iter().collect());
    let root_cert = ca.build_and_self_sign()?;
    root_cert.save("./certs/", "mytestca")?;

    let ca_cert =
        Certificate::load_cert_and_key("./certs/mytestca_cert.pem", "./certs/mytestca_pkey.pem")?;
    println!("Creating a certificate signed by the CA...");

    let middle = CertBuilder::new()
        .common_name("example.com")
        .country_name("SE")
        .state_province("Stockholm")
        .locality_time("Stockholm")
        .organization("my org")
        .is_ca(true)
        .alternative_names(vec!["example.com", "www.example.com"])
        .key_usage([Usage::certsign, Usage::crlsign].into_iter().collect());

    let middle_cert = middle.build_and_sign(&ca_cert)?;
    middle_cert.save("./certs/", "example.com")?;
    println!("Creating a certificate signed by the Middle CA cert...");
    let leaf = CertBuilder::new()
        .common_name("example2.com")
        .country_name("SE")
        .state_province("Stockholm")
        .organization("My org")
        .locality_time("Stockholm")
        .alternative_names(vec!["example2.com", "www.example2.com"])
        .key_usage(
            [
                Usage::contentcommitment,
                Usage::encipherment,
                Usage::serverauth,
            ]
            .into_iter()
            .collect(),
        );
    let leaf_cert = leaf.build_and_sign(&middle_cert)?;
    leaf_cert.save("./certs/", "example2.com")?;
    std::fs::write("./certs/leaf_cert.der", leaf_cert.x509.to_der().unwrap()).unwrap();
    println!("All certificates and keys have been generated.");
    match verify_cert(&leaf_cert.x509, &ca_cert.x509, vec![&middle_cert.x509]) {
        Ok(true) => println!("verify ok"),
        _ => println!("failed verify"),
    }

    // csr
    let csr_builder = CsrBuilder::new()
        .common_name("example2.com")
        .country_name("SE")
        .state_province("Stockholm")
        .organization("My org")
        .locality_time("Stockholm")
        .alternative_names(vec!["example2.com", "www.example2.com"])
        .key_usage(
            [
                Usage::contentcommitment,
                Usage::encipherment,
                Usage::serverauth,
            ]
            .into_iter()
            .collect(),
        );
    let csr = csr_builder.certificate_signing_request()?;
    csr.save("./certs", "my_test")?;
    let ca = CertBuilder::new()
        .common_name("My Test Ca")
        .country_name("SE")
        .state_province("Stockholm")
        .organization("my org")
        .locality_time("Stockholm")
        .is_ca(true)
        .key_type(KeyType::P521)
        .signature_alg(HashAlg::SHA512)
        .alternative_names(vec!["ca.com", "www.ca.com"])
        .key_usage([Usage::certsign, Usage::crlsign].into_iter().collect());
    let root_cert = ca.build_and_self_sign()?;
    root_cert.save("./certs", "ca_new_cert_from_csr")?;
    let options = CsrOptions::new().is_ca(true);

    let new_cert_from_csr = csr.build_signed_certificate(&root_cert, options)?;
    new_cert_from_csr.save("./certs", "new_cert_from_csr")?;

    Ok(())
}
