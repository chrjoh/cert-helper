//! # Cert-Helper
//!
//! ## Description
//!
//! A lightweight wrapper around the OpenSSL crate for working with X.509 certificates and private keys.
//!
//! The package has not been reviewed for any security issues and is intended for testing purposes only.
//!
//! This library provides a set of utility functions to simplify common tasks such as:
//! - Creating self-signed or CA-signed certificates
//! - Generating RSA/ECDSA private keys
//! - Creating Certificate Signing Requests (CSRs)
//! - Signing certificates from CSRs using a CA certificate and key
//! - Reading and writing certificates, keys, and CSRs in PEM format
//! - Validating certificate chains and properties
//! - Create or update certificate revocation list(crl)
//!   - Note that this is a simple crl parser that only handle the fields that are included then
//!  generating a crl with this code
//!
//! ### Certificate Signing Requirements
//! To sign another certificate, the signing certificate must:
//! - Have the `CA` (Certificate Authority) flag set to `true`
//! - Include the `KeyUsage` extension with the `keyCertSign` bit enabled
//!
//! These constraints ensure that the certificate is recognized as a valid CA and can be used to issue other certificates.
//!
//! ### Use Cases
//! - Generating certificates for local development or internal services
//! - Creating a simple certificate authority for testing
//! - Validating certificate chains in custom TLS setups
//! - Creating CSRs to be signed by external or internal CAs
//! - Issuing signed certificates from CSRs for controlled certificate management
//! - Create crl for testing how a client handle certificate revocations
//!
//!
//! ## Basic Example creating a certificate and private key
//! ```rust
//! use cert_helper::certificate::{CertBuilder, Certificate, HashAlg, KeyType, Usage, verify_cert, UseesBuilderFields};
//!
//! // create a self signed certificate with several optional values set
//! let ca = CertBuilder::new()
//!     .common_name("My Test Ca")
//!     .country_name("SE")
//!     .state_province("Stockholm")
//!     .organization("my org")
//!     .locality_time("Stockholm")
//!     .is_ca(true)
//!     .key_type(KeyType::P521)
//!     .signature_alg(HashAlg::SHA512)
//!     .key_usage([Usage::certsign, Usage::crlsign].into_iter().collect());
//! let root_cert = ca.build_and_self_sign();
//! assert!(root_cert.is_ok())
//! // to write data to file you need to use X509Common to access the save
//! // ca.save("./certs/", "mytestca")?;
//!```
//! ## Basic Example creating a certificate signing request and private key
//! ```rust
//! use cert_helper::certificate::{Usage, Csr, verify_cert, UseesBuilderFields,CsrBuilder};
//!
//! // create a certificate signing request and private key
//! let csr_builder = CsrBuilder::new()
//!    .common_name("example2.com")
//!    .country_name("SE")
//!    .state_province("Stockholm")
//!    .organization("My org")
//!    .locality_time("Stockholm")
//!    .alternative_names(vec!["example2.com", "www.example2.com"])
//!    .key_usage(
//!        [
//!            Usage::contentcommitment,
//!            Usage::encipherment,
//!            Usage::serverauth,
//!        ]
//!        .into_iter()
//!        .collect(),
//!    );
//! let csr = csr_builder.certificate_signing_request();
//! assert!(csr.is_ok());
//!
//! // to write data to file you need to use X509Common to access the save
//! // csr.save("./certs/", "mytestca")?;
//!
//!```
//! ## Basic Example creating a signed certificate from a signing request
//! ```rust
//! use cert_helper::certificate::{CertBuilder, Csr, verify_cert, UseesBuilderFields, CsrBuilder,CsrOptions};
//!
//! let ca = CertBuilder::new().common_name("My Test Ca").is_ca(true);
//! let root_cert = ca.build_and_self_sign().expect("failed to create root certificate");
//!
//! let csr_builder = CsrBuilder::new().common_name("example2.com");
//! let csr = csr_builder.certificate_signing_request().expect("Failed to generate csr");
//! let options = CsrOptions::new();// used for enabling csr for CA certficates
//! let cert = csr.build_signed_certificate(&root_cert, options);
//! assert!(cert.is_ok());
//! ```
//!
//! ## Basic Example creating a chain of signed certificates and verify the chain
//! ```rust
//! use cert_helper::certificate::{CertBuilder, verify_cert, UseesBuilderFields};
//!
//! let cert = CertBuilder::new().common_name("Cert-1").is_ca(true);
//! let cert_1 = cert.build_and_self_sign().expect("Failed to create certificate");
//! let cert = CertBuilder::new().common_name("Cert-2").is_ca(true);
//! let cert_2 = cert.build_and_sign(&cert_1).expect("Failed to create certificate");
//! let cert = CertBuilder::new().common_name("Cert-3");
//! let cert_3 = cert.build_and_sign(&cert_2).expect("Failed to create certificate");
//!
//! match verify_cert(&cert_3.x509, &cert_1.x509, vec![&cert_2.x509]) {
//!    Ok(true) => println!("verify ok"),
//!    _ => println!("failed verify"),
//! }
//!
//! ```
//!
//! ## Example on how to create a certifcate revocation list(clr)
//! ```rust
//! use cert_helper::certificate::{CertBuilder, UseesBuilderFields};
//! use cert_helper::crl::X509CrlBuilder;
//! use chrono::Utc;
//! use num_bigint::BigUint;
//!
//! let ca = CertBuilder::new()
//!    .common_name("My Test Ca")
//!    .is_ca(true)
//!    .build_and_self_sign()
//!    .unwrap();
//! let mut builder = X509CrlBuilder::new(ca);
//!     let revocked = CertBuilder::new()
//!    .common_name("My Test")
//!    .build_and_self_sign()
//!    .unwrap();
//!
//! let bytes = revocked.x509.serial_number().to_bn().unwrap().to_vec();
//! builder.add_revoked_cert(BigUint::from_bytes_be(&bytes), Utc::now());
//!
//! let crl_der = builder.build_and_sign();
//! // to save crl as pem use the helper function
//! // write_der_crl_as_pem(&crl_der, "./certs", "crl.pem").expect("failed to save crl as pem file");
//!
//! ```
//!
//! ## Config
//!
//! Values that can be selected for building a certificate
//! | keyword | description | options |
//! | ----------------- | --------------------------------------------------------------------------- | ----------------------------------- |
//! | common_name | the common name this certificate shoud have, mandatory field | string: www.foo.se |
//! | key_type  | key type to be used, defaults to RSA2048 | enum: RSA2048, RSA4096, P224, P256, P384, P512 |
//! | ca | is this certificate used to sign other certificates, default value is false | boolean: true or false |
//! | country_name | the country code to use,must follow the standard defined by ISO 3166-1 alpha-2. | string: SE |
//! | organization | organisation name | string: test |
//! | state_province | some name | string: test |
//! | locality_time | Stockholm | string: Stockholm |
//! | alternative_names | list of alternative DNS names this certificate is valid for | string: valid dns names |
//! | signature_alg | which algorithm to be used for signature, default is SHA256 | enum: SHA1, SHA256, SHA384, SHA512 |
//! | valid_from | Start date then the certificate is valid, default is now | string: 2010-01-01 |
//! | valid_to | End date then the certificate is not valid, default is 1 year | string: 2020-01-01 |
//! | usage | Key usage to add to the certificates, see list below for options | list of enums, defined in Key Usage table |
//!
//! ### Key usage
//!
//! If CA is true the key usages to sign certificates and crl lists are added automatically.
//!
//! | keyword           | description                                                |
//! | ----------------- | ---------------------------------------------------------- |
//! | certsign          | allowed to sign certificates                               |
//! | crlsign           | allowed to sign crl                                        |
//! | encipherment      | allowed to enciphering private or secret keys              |
//! | clientauth        | allowed to authenticate as client                          |
//! | serverauth        | allowed ot be used for server authenthication              |
//! | signature         | allowed to perfom digital signature (For auth)             |
//! | contentcommitment | allowed to perfom document signature (prev non repudation) |

pub mod certificate;
pub mod crl;
