use cert_helper::certificate::{
    CertBuilder, Certificate, CsrBuilder, CsrOptions, HashAlg, KeyType, Usage, UseesBuilderFields,
    create_cert_chain_from_cert_list, verify_cert,
};
use cert_helper::crl::{CrlReason, X509CrlBuilder, X509CrlWrapper};
use chrono::Utc;
use num_bigint::BigUint;
use openssl::hash::MessageDigest;
use openssl::hash::hash;
use openssl::nid::Nid;
use openssl::x509::{X509, X509Crl};
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

#[test]
fn create_minimal_self_signed_cert() -> Result<(), Box<dyn std::error::Error>> {
    let ca = CertBuilder::new().common_name("My Test Ca").is_ca(true);
    let root_cert = ca.build_and_self_sign()?;
    let x509 = root_cert.x509;
    assert_eq!(
        x509.issuer_name().to_der().ok(),
        x509.subject_name().to_der().ok()
    );
    if !has_ca_cert_and_crl_sign_with_basic_const_critical(&x509) {
        return Err(
            "Missing Certificate Sign or CRL Sign usage or basic const. not critical".into(),
        );
    }
    Ok(())
}

#[test]
fn create_minimal_ed25519_self_signed_cert() -> Result<(), Box<dyn std::error::Error>> {
    let ca = CertBuilder::new()
        .common_name("My Test Ca")
        .is_ca(true)
        .key_type(KeyType::Ed25519);
    let root_cert = ca.build_and_self_sign()?;
    let x509 = root_cert.x509;
    assert_eq!(
        x509.issuer_name().to_der().ok(),
        x509.subject_name().to_der().ok()
    );
    if !has_ca_cert_and_crl_sign_with_basic_const_critical(&x509) {
        return Err(
            "Missing Certificate Sign or CRL Sign usage or basic const. not critical".into(),
        );
    }
    Ok(())
}
#[test]
fn test_add_multiple_key_usage() -> Result<(), Box<dyn std::error::Error>> {
    let ca = CertBuilder::new()
        .common_name("My Test")
        .key_usage(HashSet::from_iter([Usage::serverauth]))
        .key_usage(HashSet::from_iter([Usage::contentcommitment]));
    let root_cert = ca.build_and_self_sign()?;
    let x509 = root_cert.x509;
    let checker = |x509: &X509| -> bool {
        if let Ok(text) = x509.to_text() {
            let text = String::from_utf8_lossy(&text);
            text.contains("X509v3 Key Usage")
                && text.contains("Non Repudiation")
                && text.contains("X509v3 Extended Key Usage")
                && text.contains("TLS Web Server Authentication")
        } else {
            false
        }
    };

    if !checker(&x509) {
        return Err("Missing Key and extended Key usage".into());
    }
    Ok(())
}
#[test]
fn must_not_create_cert_with_non_ca_signer_cert() -> Result<(), Box<dyn std::error::Error>> {
    let ca = CertBuilder::new().common_name("My Test Ca");
    let root_cert = ca.build_and_self_sign()?;
    let leaf = CertBuilder::new().common_name("My Test");
    let leaf_cert = leaf.build_and_sign(&root_cert);
    assert!(leaf_cert.is_err(), "Expected an error but got Ok");
    Ok(())
}

#[test]
fn test_create_self_signed_certificate() -> Result<(), Box<dyn std::error::Error>> {
    let ca = CertBuilder::new()
        .common_name("My Test Ca")
        .country_name("SE")
        .state_province("Stockholm")
        .organization("my org")
        .locality_time("Stockholm")
        .is_ca(true)
        .key_type(KeyType::P521)
        .signature_alg(HashAlg::SHA512)
        .key_usage([Usage::certsign, Usage::crlsign].into_iter().collect());

    let root_cert = ca.build_and_self_sign()?;

    let x509 = root_cert.x509;

    // 1. Self-signed: issuer == subject
    assert_eq!(
        x509.issuer_name().to_der().ok(),
        x509.subject_name().to_der().ok()
    );
    // Make sure alt names was added
    let alt_names = &x509.subject_alt_names().unwrap();
    let dns_value = alt_names.get(0).and_then(|name| name.dnsname());
    assert_eq!(dns_value, Some("My Test Ca"));

    let subject = &x509.subject_name();
    let cn = subject.entries_by_nid(Nid::COMMONNAME).next().unwrap();
    assert_eq!(cn.data().as_utf8()?.to_string(), "My Test Ca");
    let country = subject.entries_by_nid(Nid::COUNTRYNAME).next().unwrap();
    assert_eq!(country.data().as_utf8()?.to_string(), "SE");

    let sig_alg = &x509.signature_algorithm().object();
    assert_eq!(sig_alg.nid(), Nid::ECDSA_WITH_SHA512);
    let pubkey = &x509.public_key()?;
    assert!(pubkey.ec_key().is_ok());
    // make sure we have the public key in the certificate
    assert_eq!(
        pubkey.ec_key()?.public_key_to_der().ok(),
        root_cert.pkey.unwrap().public_key_to_der().ok()
    );
    let actual_ski = x509.subject_key_id().expect("SKI should be present");

    let pubkey = x509.public_key()?;
    let pubkey_der = pubkey.public_key_to_der()?;
    let expected_ski = hash(MessageDigest::sha1(), &pubkey_der)?;

    assert_eq!(actual_ski.as_slice(), expected_ski.as_ref());
    assert_eq!(
        x509.authority_key_id().unwrap().as_slice(),
        x509.subject_key_id().unwrap().as_slice()
    );

    Ok(())
}

#[test]
fn test_reading_cert_creatded_by_openssl() {
    let mut cert_pem_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    cert_pem_file.push("tests/fixtures/cert.pem");
    let mut key_pem_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    key_pem_file.push("tests/fixtures/key.pem");
    let cert = Certificate::load_cert_and_key(cert_pem_file, key_pem_file);
    assert!(cert.is_ok());
}

#[test]
fn test_create_signed_certificate() -> Result<(), Box<dyn std::error::Error>> {
    let ca = CertBuilder::new()
        .common_name("My Test Ca")
        .country_name("SE")
        .state_province("Stockholm")
        .organization("my org")
        .locality_time("Stockholm")
        .is_ca(true)
        .key_type(KeyType::P521)
        .signature_alg(HashAlg::SHA512)
        .key_usage([Usage::certsign, Usage::crlsign].into_iter().collect());
    let root_cert = ca.build_and_self_sign()?;

    let middle = CertBuilder::new()
        .common_name("example.com")
        .country_name("SE")
        .state_province("Stockholm")
        .locality_time("Stockholm")
        .organization("my org")
        .is_ca(true)
        .alternative_names(vec!["example.com", "www.example.com"])
        .key_usage([Usage::certsign, Usage::crlsign].into_iter().collect());

    let middle_cert = middle.build_and_sign(&root_cert)?;

    assert_eq!(
        middle_cert.x509.issuer_name().to_der().unwrap(),
        root_cert.x509.subject_name().to_der().unwrap()
    );
    assert!(&middle_cert.x509.subject_key_id().is_some());
    assert!(&middle_cert.x509.authority_key_id().is_some());
    assert_eq!(
        middle_cert.x509.authority_key_id().unwrap().as_slice(),
        root_cert.x509.subject_key_id().unwrap().as_slice()
    );
    Ok(())
}

#[test]
fn test_create_signed_certificate_with_ca_key_ed25519() -> Result<(), Box<dyn std::error::Error>> {
    let ca = CertBuilder::new()
        .common_name("My Test Ca")
        .country_name("SE")
        .state_province("Stockholm")
        .organization("my org")
        .locality_time("Stockholm")
        .is_ca(true)
        .key_type(KeyType::Ed25519)
        .key_usage([Usage::certsign, Usage::crlsign].into_iter().collect());
    let root_cert = ca.build_and_self_sign()?;

    let middle = CertBuilder::new()
        .common_name("example.com")
        .country_name("SE")
        .state_province("Stockholm")
        .locality_time("Stockholm")
        .organization("my org")
        .is_ca(true)
        .alternative_names(vec!["example.com", "www.example.com"])
        .key_usage([Usage::certsign, Usage::crlsign].into_iter().collect());

    let middle_cert = middle.build_and_sign(&root_cert)?;

    assert_eq!(
        middle_cert.x509.issuer_name().to_der().unwrap(),
        root_cert.x509.subject_name().to_der().unwrap()
    );
    assert!(&middle_cert.x509.subject_key_id().is_some());
    assert!(&middle_cert.x509.authority_key_id().is_some());
    assert_eq!(
        middle_cert.x509.authority_key_id().unwrap().as_slice(),
        root_cert.x509.subject_key_id().unwrap().as_slice()
    );
    Ok(())
}
#[test]
fn test_verify_certificate_chain() -> Result<(), Box<dyn std::error::Error>> {
    let ca_one = CertBuilder::new()
        .common_name("My Test Ca")
        .country_name("SE")
        .state_province("Stockholm")
        .organization("my org")
        .locality_time("Stockholm")
        .is_ca(true)
        .key_type(KeyType::P521)
        .signature_alg(HashAlg::SHA512)
        .key_usage([Usage::certsign, Usage::crlsign].into_iter().collect());
    let root_cert_one = ca_one.build_and_self_sign()?;

    let ca_two = CertBuilder::new()
        .common_name("My Test Ca")
        .country_name("SE")
        .state_province("Stockholm")
        .organization("my org")
        .locality_time("Stockholm")
        .is_ca(true)
        .key_type(KeyType::P521)
        .signature_alg(HashAlg::SHA512)
        .key_usage([Usage::certsign, Usage::crlsign].into_iter().collect());
    let root_cert_two = ca_two.build_and_self_sign()?;

    let middle = CertBuilder::new()
        .common_name("example.com")
        .country_name("SE")
        .state_province("Stockholm")
        .locality_time("Stockholm")
        .organization("my org")
        .is_ca(true)
        .alternative_names(vec!["example.com", "www.example.com"])
        .key_usage([Usage::certsign, Usage::crlsign].into_iter().collect());

    let middle_cert = middle.build_and_sign(&root_cert_one)?;
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

    // this is a correct signed certificate chain and should be verified as true
    let result = verify_cert(
        &leaf_cert.x509,
        &root_cert_one.x509,
        vec![&middle_cert.x509],
    );
    assert_eq!(result.unwrap(), true);

    // root_cert_two have not been used to sign middle_cert so should be false
    let result = verify_cert(
        &leaf_cert.x509,
        &root_cert_two.x509,
        vec![&middle_cert.x509],
    );
    assert_eq!(result.unwrap(), false);
    Ok(())
}
#[test]
fn test_verify_certificate_chain_with_middle_cert_key_ed25519()
-> Result<(), Box<dyn std::error::Error>> {
    let ca_one = CertBuilder::new()
        .common_name("My Test Ca")
        .country_name("SE")
        .state_province("Stockholm")
        .organization("my org")
        .locality_time("Stockholm")
        .is_ca(true)
        .key_type(KeyType::P521)
        .signature_alg(HashAlg::SHA512)
        .key_usage([Usage::certsign, Usage::crlsign].into_iter().collect());
    let root_cert_one = ca_one.build_and_self_sign()?;

    let ca_two = CertBuilder::new()
        .common_name("My Test Ca")
        .country_name("SE")
        .state_province("Stockholm")
        .organization("my org")
        .locality_time("Stockholm")
        .is_ca(true)
        .key_type(KeyType::P521)
        .signature_alg(HashAlg::SHA512)
        .key_usage([Usage::certsign, Usage::crlsign].into_iter().collect());
    let root_cert_two = ca_two.build_and_self_sign()?;

    let middle = CertBuilder::new()
        .common_name("example.com")
        .country_name("SE")
        .state_province("Stockholm")
        .locality_time("Stockholm")
        .organization("my org")
        .key_type(KeyType::Ed25519)
        .is_ca(true)
        .alternative_names(vec!["example.com", "www.example.com"])
        .key_usage([Usage::certsign, Usage::crlsign].into_iter().collect());

    let middle_cert = middle.build_and_sign(&root_cert_one)?;
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

    // this is a correct signed certificate chain and should be verified as true
    let result = verify_cert(
        &leaf_cert.x509,
        &root_cert_one.x509,
        vec![&middle_cert.x509],
    );
    assert_eq!(result.unwrap(), true);

    // root_cert_two have not been used to sign middle_cert so should be false
    let result = verify_cert(
        &leaf_cert.x509,
        &root_cert_two.x509,
        vec![&middle_cert.x509],
    );
    assert_eq!(result.unwrap(), false);
    Ok(())
}
#[test]
fn sort_list_of_certificates_in_signing_order() -> Result<(), Box<dyn std::error::Error>> {
    let cert = CertBuilder::new().common_name("Cert-1").is_ca(true);
    let cert_1 = cert.build_and_self_sign()?;
    let cert = CertBuilder::new().common_name("Cert-2").is_ca(true);
    let cert_2 = cert.build_and_sign(&cert_1)?;
    let cert = CertBuilder::new().common_name("Cert-3").is_ca(true);
    let cert_3 = cert.build_and_sign(&cert_2)?;
    let cert = CertBuilder::new().common_name("Cert-4").is_ca(true);
    let cert_4 = cert.build_and_sign(&cert_3)?;
    let cert = CertBuilder::new().common_name("Cert-5");
    let cert_5 = cert.build_and_sign(&cert_4)?;
    let certs = vec![
        cert_3.x509,
        cert_1.x509,
        cert_4.x509,
        cert_5.x509,
        cert_2.x509,
    ];
    let result = create_cert_chain_from_cert_list(certs);
    let sorted = result.unwrap();
    assert_eq!(get_clean_subject_name(&sorted[0]), Some("Cert-1".into()));
    assert_eq!(get_clean_subject_name(&sorted[1]), Some("Cert-2".into()));
    assert_eq!(get_clean_subject_name(&sorted[2]), Some("Cert-3".into()));
    assert_eq!(get_clean_subject_name(&sorted[3]), Some("Cert-4".into()));
    assert_eq!(get_clean_subject_name(&sorted[4]), Some("Cert-5".into()));
    Ok(())
}

#[test]
fn create_a_certificate_signing_request() -> Result<(), Box<dyn std::error::Error>> {
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
    let subject_name = csr.csr.subject_name();
    let mut cn = subject_name.entries_by_nid(Nid::COMMONNAME);
    let name = cn.next().unwrap().data().as_utf8().unwrap().to_string();
    assert_eq!(name, "example2.com");
    Ok(())
}

#[test]
fn create_a_certificate_signing_request_with_ed25519() -> Result<(), Box<dyn std::error::Error>> {
    let csr_builder = CsrBuilder::new()
        .common_name("example2.com")
        .country_name("SE")
        .state_province("Stockholm")
        .organization("My org")
        .locality_time("Stockholm")
        .key_type(KeyType::Ed25519)
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
    let subject_name = csr.csr.subject_name();
    let mut cn = subject_name.entries_by_nid(Nid::COMMONNAME);
    let name = cn.next().unwrap().data().as_utf8().unwrap().to_string();
    assert_eq!(name, "example2.com");
    Ok(())
}
#[test]
fn create_signed_certificate_from_csr() -> Result<(), Box<dyn std::error::Error>> {
    let ca = CertBuilder::new().common_name("My Test Ca").is_ca(true);
    let root_cert = ca.build_and_self_sign()?;
    let csr_builder = CsrBuilder::new().common_name("example2.com");
    let csr = csr_builder.certificate_signing_request()?;
    let cert = csr.build_signed_certificate(&root_cert, CsrOptions::new())?;

    assert_eq!(
        get_clean_subject_name(&cert.x509),
        Some("example2.com".into())
    );
    assert_eq!(
        cert.x509.issuer_name().to_der().unwrap(),
        root_cert.x509.subject_name().to_der().unwrap()
    );
    assert!(&cert.x509.subject_key_id().is_some());
    assert!(&cert.x509.authority_key_id().is_some());
    assert_eq!(
        cert.x509.authority_key_id().unwrap().as_slice(),
        root_cert.x509.subject_key_id().unwrap().as_slice()
    );
    Ok(())
}
#[test]
fn create_signed_certificate_from_csr_with_signer_key_ed25519()
-> Result<(), Box<dyn std::error::Error>> {
    let ca = CertBuilder::new()
        .common_name("My Test Ca")
        .is_ca(true)
        .key_type(KeyType::Ed25519);
    let root_cert = ca.build_and_self_sign()?;
    let csr_builder = CsrBuilder::new().common_name("example2.com");
    let csr = csr_builder.certificate_signing_request()?;
    let cert = csr.build_signed_certificate(&root_cert, CsrOptions::new())?;

    assert_eq!(
        get_clean_subject_name(&cert.x509),
        Some("example2.com".into())
    );
    assert_eq!(
        cert.x509.issuer_name().to_der().unwrap(),
        root_cert.x509.subject_name().to_der().unwrap()
    );
    assert!(&cert.x509.subject_key_id().is_some());
    assert!(&cert.x509.authority_key_id().is_some());
    assert_eq!(
        cert.x509.authority_key_id().unwrap().as_slice(),
        root_cert.x509.subject_key_id().unwrap().as_slice()
    );
    Ok(())
}

#[test]
fn create_signed_ca_certificate_from_csr() -> Result<(), Box<dyn std::error::Error>> {
    let ca = CertBuilder::new().common_name("My Test Ca").is_ca(true);
    let root_cert = ca.build_and_self_sign()?;
    let csr_builder = CsrBuilder::new().common_name("example2.com");
    let csr = csr_builder.certificate_signing_request()?;
    let cert = csr.build_signed_certificate(&root_cert, CsrOptions::new().is_ca(true))?;

    assert_eq!(
        get_clean_subject_name(&cert.x509),
        Some("example2.com".into())
    );
    if !has_ca_cert_and_crl_sign_with_basic_const_critical(&cert.x509) {
        return Err(
            "Missing Certificate Sign or CRL Sign usage or basic const. not critical".into(),
        );
    }
    assert_eq!(
        cert.x509.issuer_name().to_der().unwrap(),
        root_cert.x509.subject_name().to_der().unwrap()
    );
    assert_eq!(count_key_usage_extension_fields(&cert.x509), 1);

    Ok(())
}

#[test]
fn test_no_multiple_key_usages() -> Result<(), Box<dyn std::error::Error>> {
    let ca = CertBuilder::new().common_name("My Test Ca").is_ca(true);
    let root_cert = ca.build_and_self_sign()?;
    let csr_builder = CsrBuilder::new()
        .common_name("example2.com")
        .key_usage(HashSet::from([Usage::contentcommitment]));
    let csr = csr_builder.certificate_signing_request()?;
    let cert = csr.build_signed_certificate(&root_cert, CsrOptions::new().is_ca(true))?;

    assert_eq!(count_key_usage_extension_fields(&cert.x509), 1);
    Ok(())
}

#[test]
fn test_parse_crl_from_der() {
    let ca = CertBuilder::new()
        .common_name("My Test Ca")
        .is_ca(true)
        .build_and_self_sign()
        .unwrap();
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/fixtures/rfc5280_CRL.crl");
    let der = fs::read(path).unwrap();
    let builder = X509CrlBuilder::from_der(&der, ca);
    assert!(builder.is_ok());
    let crl = builder.unwrap();
    assert_eq!(crl.revoked().len(), 1);
    assert_eq!(crl.revoked()[0].reasons().len(), 1);
    assert_eq!(crl.revoked()[0].reasons()[0], CrlReason::KeyCompromise);
}

#[test]
fn test_parse_crl_from_der_signed_with_key_ed25519() {
    let ca = CertBuilder::new()
        .common_name("My Test Ca")
        .is_ca(true)
        .key_type(KeyType::Ed25519)
        .build_and_self_sign()
        .unwrap();
    let crl_der = X509CrlBuilder::new(ca.clone()).build_and_sign();
    let builder = X509CrlBuilder::from_der(&crl_der, ca);
    assert!(builder.is_ok());
}
#[test]
fn test_creating_crl_with_revocked_certificate() {
    let ca = CertBuilder::new()
        .common_name("My Test Ca")
        .is_ca(true)
        .build_and_self_sign()
        .unwrap();
    let revocked = CertBuilder::new()
        .common_name("My Test")
        .build_and_self_sign()
        .unwrap();
    let public_key = ca.x509.public_key().clone();
    let mut builder = X509CrlBuilder::new(ca);
    let bytes = revocked.x509.serial_number().to_bn().unwrap().to_vec();
    builder.add_revoked_cert(BigUint::from_bytes_be(&bytes), Utc::now());
    let crl_der = builder.build_and_sign();
    assert!(!crl_der.is_empty());
    // verify signature
    let crl = X509Crl::from_der(crl_der.as_slice());
    let result = crl.unwrap().verify(public_key.as_ref().unwrap());
    assert_eq!(result.unwrap(), true);
}
#[test]
fn test_clr_wrapper() {
    let ca = CertBuilder::new()
        .common_name("My Test Ca")
        .is_ca(true)
        .build_and_self_sign()
        .unwrap();
    let revocked_one = CertBuilder::new()
        .common_name("My Test")
        .build_and_self_sign()
        .unwrap();
    let revocked_two = CertBuilder::new()
        .common_name("My Test")
        .build_and_self_sign()
        .unwrap();
    let public_key = ca.x509.public_key().clone();
    let revoked_serial_to_check = revocked_one.x509.serial_number();
    let mut builder = X509CrlBuilder::new(ca.clone());

    let bytes = revocked_one.x509.serial_number().to_bn().unwrap().to_vec();
    builder.add_revoked_cert(BigUint::from_bytes_be(&bytes), Utc::now());
    let bytes = revocked_two.x509.serial_number().to_bn().unwrap().to_vec();
    builder.add_revoked_cert(BigUint::from_bytes_be(&bytes), Utc::now());

    let crl_der = builder.build_and_sign();
    assert!(!crl_der.is_empty());
    let crl_wrapper = X509CrlWrapper::from_der(crl_der.as_slice()).unwrap();
    // verify signature
    let result = crl_wrapper.verify_signature(public_key.as_ref().unwrap());
    assert_eq!(result.unwrap(), true);
    // check that certifificate is revoked
    let mut is_revoked = crl_wrapper.revoked(revoked_serial_to_check);
    assert_eq!(is_revoked, true);
    // check that non revoked is not found
    let not_revocked = CertBuilder::new()
        .common_name("My Test")
        .build_and_self_sign()
        .unwrap();
    is_revoked = crl_wrapper.revoked(not_revocked.x509.serial_number());
    assert_eq!(is_revoked, false);
}

#[test]
fn test_creating_crl_with_revocked_certificate_and_signer_key_ed25519() {
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
    let public_key = ca.x509.public_key().clone();
    let mut builder = X509CrlBuilder::new(ca);
    let bytes = revocked.x509.serial_number().to_bn().unwrap().to_vec();
    builder.add_revoked_cert(BigUint::from_bytes_be(&bytes), Utc::now());
    let crl_der = builder.build_and_sign();
    assert!(!crl_der.is_empty());
    // verify signature
    let crl = X509Crl::from_der(crl_der.as_slice());
    let result = crl.unwrap().verify(public_key.as_ref().unwrap());
    assert_eq!(result.unwrap(), true);
}
#[test]
fn test_creating_and_parse_crl_with_no_revocked_certificates() {
    let ca = CertBuilder::new()
        .common_name("My Test Ca")
        .is_ca(true)
        .build_and_self_sign()
        .unwrap();
    let builder = X509CrlBuilder::new(ca);
    let crl_der = builder.build_and_sign();
    assert!(!crl_der.is_empty());

    let ca = CertBuilder::new()
        .common_name("My Test Ca")
        .is_ca(true)
        .build_and_self_sign()
        .unwrap();
    let parsed = X509CrlBuilder::from_der(&crl_der, ca);
    assert!(parsed.is_ok());
}
fn get_clean_subject_name(x509: &X509) -> Option<String> {
    let subject_name = x509.subject_name();
    if let Some(entry) = subject_name.entries_by_nid(Nid::COMMONNAME).next() {
        if let Ok(data) = entry.data().as_utf8() {
            return Some(data.to_string());
        }
    }
    None
}

/// Note: only used for simple check in test not valid in
/// real senarios as we scan the text version of the certificate and the user
/// can supply these fields in for example organization.
///
/// Check the function can_sign_cert in certificate.rs file on how to do
/// correct check by fetching the exact extesnsions.
fn has_ca_cert_and_crl_sign_with_basic_const_critical(cert: &X509) -> bool {
    if let Ok(text) = cert.to_text() {
        let text = String::from_utf8_lossy(&text);
        text.contains("X509v3 Key Usage")
            && text.contains("Certificate Sign")
            && text.contains("CRL Sign")
            && text.contains("CA:TRUE")
            && text.contains("X509v3 Basic Constraints: critical")
    } else {
        false
    }
}

fn count_key_usage_extension_fields(cert: &X509) -> usize {
    if let Ok(text) = cert.to_text() {
        let text = String::from_utf8_lossy(&text);
        text.matches("X509v3 Key Usage").count()
    } else {
        0
    }
}
