#![cfg(feature = "pqc")]

use cert_helper::certificate::{CertBuilder, CsrBuilder, CsrOptions, KeyType, UseesBuilderFields};
use cert_helper::crl::X509CrlBuilder;
use chrono::Utc;
use num_bigint::BigUint;
use openssl::x509::X509Crl;
use x509_parser::parse_x509_certificate;

fn roundtrip_self_signed(key_type: KeyType, expected_oid: &str) {
    let label = format!("{:?}", key_type);
    let ca = CertBuilder::new()
        .common_name("pqc-test")
        .is_ca(true)
        .key_type(key_type)
        .build_and_self_sign()
        .expect("PQC self-sign should succeed");

    let der = ca.x509.to_der().expect("DER export");
    let (_, parsed) = parse_x509_certificate(&der).expect("x509-parser accepts PQC cert");

    let sig_oid = parsed.signature_algorithm.algorithm.to_id_string();
    assert_eq!(
        sig_oid, expected_oid,
        "signature algorithm OID mismatch for {}",
        label
    );

    // Issuer == subject for self-signed
    assert_eq!(
        ca.x509.issuer_name().to_der().ok(),
        ca.x509.subject_name().to_der().ok()
    );
}

#[test]
fn test_mldsa44_self_signed_roundtrip() {
    roundtrip_self_signed(KeyType::MlDsa44, "2.16.840.1.101.3.4.3.17");
}

#[test]
fn test_mldsa65_self_signed_roundtrip() {
    roundtrip_self_signed(KeyType::MlDsa65, "2.16.840.1.101.3.4.3.18");
}

#[test]
fn test_mldsa87_self_signed_roundtrip() {
    roundtrip_self_signed(KeyType::MlDsa87, "2.16.840.1.101.3.4.3.19");
}

#[test]
fn test_slhdsa_sha2_128s_self_signed_roundtrip() {
    roundtrip_self_signed(KeyType::SlhDsaSha2_128s, "2.16.840.1.101.3.4.3.20");
}

#[test]
fn test_slhdsa_sha2_192s_self_signed_roundtrip() {
    roundtrip_self_signed(KeyType::SlhDsaSha2_192s, "2.16.840.1.101.3.4.3.22");
}

#[test]
fn test_slhdsa_sha2_256s_self_signed_roundtrip() {
    roundtrip_self_signed(KeyType::SlhDsaSha2_256s, "2.16.840.1.101.3.4.3.24");
}

#[test]
fn test_mldsa_cert_signs_crl() {
    let ca = CertBuilder::new()
        .common_name("My PQC Ca")
        .is_ca(true)
        .key_type(KeyType::MlDsa65)
        .build_and_self_sign()
        .unwrap();
    let revoked = CertBuilder::new()
        .common_name("My Leaf")
        .build_and_self_sign()
        .unwrap();

    let public_key = ca.x509.public_key().clone();
    let mut builder = X509CrlBuilder::new(ca);
    let bytes = revoked.x509.serial_number().to_bn().unwrap().to_vec();
    builder.add_revoked_cert(BigUint::from_bytes_be(&bytes), Utc::now());

    let wrapper = builder.build_and_sign().expect("PQC CRL signing");
    let crl_der = wrapper.to_der().unwrap();
    assert!(!crl_der.is_empty());

    let crl = X509Crl::from_der(crl_der.as_slice()).unwrap();
    let verified = crl.verify(public_key.as_ref().unwrap()).unwrap();
    assert!(
        verified,
        "PQC-signed CRL should verify against CA public key"
    );
}

#[test]
fn test_mldsa_signs_classical_csr() {
    let ca = CertBuilder::new()
        .common_name("My PQC Ca")
        .is_ca(true)
        .key_type(KeyType::MlDsa65)
        .build_and_self_sign()
        .unwrap();

    let csr = CsrBuilder::new()
        .common_name("leaf")
        .key_type(KeyType::RSA2048)
        .certificate_signing_request()
        .expect("CSR build");

    let cert = csr
        .build_signed_certificate(&ca, CsrOptions::new())
        .expect("PQC CA must sign a classical CSR");

    // The issuer on the leaf matches the CA subject.
    assert_eq!(
        cert.x509.issuer_name().to_der().ok(),
        ca.x509.subject_name().to_der().ok()
    );
}

#[test]
fn test_classical_ca_signs_mldsa_csr() {
    let ca = CertBuilder::new()
        .common_name("My Classical Ca")
        .is_ca(true)
        .build_and_self_sign()
        .unwrap();

    let csr = CsrBuilder::new()
        .common_name("pqc-leaf")
        .key_type(KeyType::MlDsa65)
        .certificate_signing_request()
        .expect("PQC CSR build");

    let cert = csr
        .build_signed_certificate(&ca, CsrOptions::new())
        .expect("classical CA must sign a PQC CSR");

    // Leaf's public-key algorithm should be ML-DSA-65.
    let der = cert.x509.to_der().unwrap();
    let (_, parsed) = parse_x509_certificate(&der).unwrap();
    let spki_alg = parsed
        .tbs_certificate
        .subject_pki
        .algorithm
        .algorithm
        .to_id_string();
    assert_eq!(
        spki_alg, "2.16.840.1.101.3.4.3.18",
        "leaf SPKI should be ML-DSA-65 OID"
    );
}

#[test]
fn test_slhdsa_256s_large_signature_survives_pem_roundtrip() {
    // SLH-DSA-SHA2-256s signatures are ~50 KB — sanity check that
    // PEM/DER serialization round-trips without truncation.
    let ca = CertBuilder::new()
        .common_name("SLH large")
        .is_ca(true)
        .key_type(KeyType::SlhDsaSha2_256s)
        .build_and_self_sign()
        .unwrap();

    let der1 = ca.x509.to_der().unwrap();
    let pem = ca.x509.to_pem().unwrap();
    let reparsed = openssl::x509::X509::from_pem(&pem).unwrap();
    let der2 = reparsed.to_der().unwrap();

    assert_eq!(der1, der2, "DER bytes must survive PEM round-trip");
    assert!(
        der1.len() > 20_000,
        "SLH-DSA-SHA2-256s cert unexpectedly small ({} bytes)",
        der1.len()
    );
}
