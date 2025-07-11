use cert_helper::certificate::{
    CertBuilder, CsrBuilder, CsrOptions, HashAlg, KeyType, Usage, UseesBuilderFields,
    create_cert_chain_from_cert_list, verify_cert,
};
use openssl::nid::Nid;
use openssl::x509::X509;
use std::collections::HashSet;

#[test]
fn create_minimal_self_signed_cert() -> Result<(), Box<dyn std::error::Error>> {
    let ca = CertBuilder::new().common_name("My Test Ca").is_ca(true);
    let root_cert = ca.build_and_self_sign()?;
    let x509 = root_cert.x509;
    assert_eq!(
        x509.issuer_name().to_der().ok(),
        x509.subject_name().to_der().ok()
    );
    if !has_ca_cert_and_crl_sign(&x509) {
        return Err("Missing Certificate Sign or CRL Sign usage".into());
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

    Ok(())
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
fn create_signed_certificate_from_csr() -> Result<(), Box<dyn std::error::Error>> {
    let ca = CertBuilder::new().common_name("My Test Ca").is_ca(true);
    let root_cert = ca.build_and_self_sign()?;
    let csr_builder = CsrBuilder::new().common_name("example2.com");
    let csr = csr_builder.certificate_signing_request()?;
    let cert = csr.build_signed_certificate(
        &root_cert,
        CsrOptions {
            valid_to: "2045-01-01".into(),
            ca: false,
        },
    )?;

    assert_eq!(
        get_clean_subject_name(&cert.x509),
        Some("example2.com".into())
    );
    assert_eq!(
        cert.x509.issuer_name().to_der().unwrap(),
        root_cert.x509.subject_name().to_der().unwrap()
    );
    Ok(())
}

#[test]
fn create_signed_ca_certificate_from_csr() -> Result<(), Box<dyn std::error::Error>> {
    let ca = CertBuilder::new().common_name("My Test Ca").is_ca(true);
    let root_cert = ca.build_and_self_sign()?;
    let csr_builder = CsrBuilder::new().common_name("example2.com").is_ca(true);
    let csr = csr_builder.certificate_signing_request()?;
    let cert = csr.build_signed_certificate(
        &root_cert,
        CsrOptions {
            valid_to: "2045-01-01".into(),
            ca: true,
        },
    )?;

    assert_eq!(
        get_clean_subject_name(&cert.x509),
        Some("example2.com".into())
    );
    if !has_ca_cert_and_crl_sign(&cert.x509) {
        return Err("Missing Certificate Sign or CRL Sign usage".into());
    }
    assert_eq!(
        cert.x509.issuer_name().to_der().unwrap(),
        root_cert.x509.subject_name().to_der().unwrap()
    );
    Ok(())
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
fn has_ca_cert_and_crl_sign(cert: &X509) -> bool {
    if let Ok(text) = cert.to_text() {
        let text = String::from_utf8_lossy(&text);
        text.contains("X509v3 Key Usage")
            && text.contains("Certificate Sign")
            && text.contains("CRL Sign")
            && text.contains("CA:TRUE")
    } else {
        false
    }
}
