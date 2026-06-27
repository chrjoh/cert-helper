//! # Cert-Helper
//!
//! A lightweight helper library for managing X.509 certificates using OpenSSL.
//! Provides convenient tools for generating Certificate Signing Requests (CSRs),
//! Certificate Revocation Lists (CRLs), and handling private keys.
//!
//! ## Description
//!
//! A minimal wrapper combining `openssl`, `yasna`, and `x509-parser` crates
//! to simplify common certificate operations such as creation, signing, parsing, and revocation.
//!
//! The package has not been reviewed for any security issues and is intended for testing purposes only.
//!
//! This library provides a set of utility functions to simplify common tasks such as:
//! - Creating self-signed or CA-signed certificates
//! - Generating RSA, ECDSA,or Ed25519 private keys, note that Ed25519 do not require any hash variant
//! - Optionally, post-quantum signing keys (ML-DSA, SLH-DSA) behind the `pqc` Cargo feature — see [Post-Quantum keys](#post-quantum-keys-experimental)
//! - Creating Certificate Signing Requests (CSRs)
//! - Signing certificates from CSRs using a CA certificate and key
//! - Reading and writing certificates, keys, and CSRs in PEM format
//! - Validating certificate chains and properties
//! - Create or update certificate revocation list(crl)
//!   - Note that this is a simple crl parser that only handle the fields that are included then
//!     generating a crl with this code
//!
//! ### Post-Quantum keys (experimental)
//!
//! Build with `--features pqc` to enable NIST-standardized post-quantum
//! algorithms as new `KeyType` variants. There are two distinct families with
//! different roles and **different KeyUsage rules** — the library enforces these at
//! build time on both the certificate and CSR paths.
//!
//! **Signature keys** — FIPS 204 / FIPS 205. These sign; they cannot encrypt.
//!
//! - `MlDsa44`, `MlDsa65`, `MlDsa87` — FIPS 204 (ML-DSA, formerly Dilithium)
//! - `SlhDsaSha2_128s`, `SlhDsaSha2_192s`, `SlhDsaSha2_256s` — FIPS 205 (SLH-DSA, formerly SPHINCS+)
//!
//!   - **KeyUsage:** use `digitalSignature` (`Usage::signature`), plus
//!     `keyCertSign`/`cRLSign` (`Usage::certsign` / `Usage::crlsign`) for a CA.
//!   - **Restriction:** `keyEncipherment` (`Usage::encipherment`) is **rejected** —
//!     these algorithms are signature-only and cannot perform key encipherment.
//!   - Can self-sign, sign CSRs, sign other certificates, and sign CRLs.
//!
//! **Key-encapsulation keys** — FIPS 203. These encapsulate (encrypt); they cannot sign.
//!
//! - `MlKem512`, `MlKem768`, `MlKem1024` — FIPS 203 (ML-KEM, formerly Kyber),
//!   OIDs `2.16.840.1.101.3.4.4.{1,2,3}`
//!
//!   - **KeyUsage:** if KeyUsage is present it MUST be **exactly `keyEncipherment`**
//!     (`Usage::encipherment`) and nothing else — per
//!     [draft-ietf-lamps-kyber-certificates]. Any other bit (`digitalSignature`,
//!     `keyAgreement`, `dataEncipherment`, `keyCertSign`, `cRLSign`) is **rejected**.
//!     Although ML-KEM is a Key Encapsulation Mechanism, the LAMPS group modeled it
//!     like RSA key transport, so it lands on `keyEncipherment`, not `keyAgreement`.
//!   - **Restriction:** ML-KEM cannot produce signatures, so it can be neither
//!     self-signed (`build_and_self_sign`) nor used to sign a CSR
//!     (`certificate_signing_request`) — both return an error. Issue an ML-KEM
//!     certificate via `build_and_sign()` with a separate signing CA (e.g. an
//!     ML-DSA or ECDSA CA).
//!
//! **Runtime requirement:** OpenSSL **≥ 3.5** at build and runtime (enforced at
//! `build.rs` time) — this covers both the FIPS 204/205 signature algorithms and
//! FIPS 203 ML-KEM. The `openssl`
//! Rust crate does not yet expose safe high-level wrappers for these algorithms —
//! this implementation uses `openssl-sys` FFI directly, mirroring the Ed25519
//! digest-less signing path. Availability and stability track upstream; expect
//! churn until safe bindings land.
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
//! - Create crl for testing how a client handle certificate revocations, optionally add crl reason for the revoked certificate
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
//! ## Limiting CA chain depth with path length constraints
//!
//! `pathlen(n)` sets the BasicConstraints path-length constraint: at most `n`
//! intermediate CAs may sit below this certificate. When issuing under a chain it
//! is validated against the signer's remaining budget, so you can't mint a CA that
//! exceeds what its issuer permits.
//!
//! ```rust
//! use cert_helper::certificate::{CertBuilder, UseesBuilderFields};
//!
//! // Root CA that allows at most one CA beneath it.
//! let root = CertBuilder::new()
//!     .common_name("My Root CA")
//!     .is_ca(true)
//!     .pathlen(1)
//!     .build_and_self_sign()
//!     .expect("self-sign root");
//!
//! // Intermediate CA (pathlen 0 → may only issue end-entity certs), signed by the
//! // root. The chain is empty because the root is a self-signed trust anchor.
//! let intermediate = CertBuilder::new()
//!     .common_name("My Intermediate CA")
//!     .is_ca(true)
//!     .pathlen(0)
//!     .build_and_sign_with_chain(&root, &[])
//!     .expect("issue intermediate under root");
//!
//! assert_eq!(intermediate.x509.pathlen(), Some(0));
//! ```
//!
//! The same constraint applies when issuing from a CSR via
//! [`CsrOptions`](certificate::CsrOptions). The chain to validate against is passed
//! alongside the path length (empty here, since the signer is a self-signed root):
//!
//! ```rust
//! use cert_helper::certificate::{CertBuilder, CsrBuilder, CsrOptions, UseesBuilderFields};
//!
//! let ca = CertBuilder::new()
//!     .common_name("My Root CA")
//!     .is_ca(true)
//!     .pathlen(2)
//!     .build_and_self_sign()
//!     .expect("self-sign root");
//!
//! let csr = CsrBuilder::new()
//!     .common_name("My Intermediate CA")
//!     .certificate_signing_request()
//!     .expect("build CSR");
//!
//! let cert = csr
//!     .build_signed_certificate(&ca, CsrOptions::new().is_ca(true).pathlen(1, vec![]))
//!     .expect("issue intermediate from CSR");
//!
//! assert_eq!(cert.x509.pathlen(), Some(1));
//! ```
//!
//! ## Post-Quantum keys (experimental)
//!
//! Build with `--features pqc` to enable NIST-standardized post-quantum
//! signature algorithms as new [`KeyType`](certificate::KeyType) variants:
//!
//! - `MlDsa44`, `MlDsa65`, `MlDsa87` — FIPS 204 (ML-DSA, formerly Dilithium)
//! - `SlhDsaSha2_128s`, `SlhDsaSha2_192s`, `SlhDsaSha2_256s` — FIPS 205 (SLH-DSA, formerly SPHINCS+)
//!
//! **Runtime requirement:** OpenSSL **≥ 3.5** at build and runtime (enforced
//! in `build.rs`). The `openssl` Rust crate does not yet expose safe high-level
//! wrappers for these algorithms — this implementation uses `openssl-sys` FFI
//! directly, reusing the Ed25519 digest-less signing path. Availability and
//! stability track upstream; expect churn until safe bindings land.
//!
//! The following example only compiles when the `pqc` feature is enabled — it
//! is hidden from the default doctest build and exercised by `cargo test --features pqc`.
//!
//! ```
//! # #[cfg(feature = "pqc")] {
//! use cert_helper::certificate::{CertBuilder, KeyType, UseesBuilderFields};
//!
//! // Self-signed CA with an ML-DSA-65 key. Same builder surface as classical keys —
//! // the digest-less signing path and build-time OpenSSL 3.5+ check are implicit.
//! let ca = CertBuilder::new()
//!     .common_name("My PQC CA")
//!     .is_ca(true)
//!     .key_type(KeyType::MlDsa65)
//!     .build_and_self_sign()
//!     .expect("self-sign ML-DSA-65");
//!
//! // PQC-signed certs are interoperable with OpenSSL's verifier; the signature
//! // algorithm OID in the PEM will read "ML-DSA-65" (2.16.840.1.101.3.4.3.18).
//! assert_eq!(
//!     ca.x509.issuer_name().to_der().ok(),
//!     ca.x509.subject_name().to_der().ok()
//! );
//! # }
//! ```
//!
//! A PQC CA can also sign classical CSRs (and vice versa); see the
//! `pqc_crl_example` and `pqc_all_variants` examples in `examples/` for full
//! chain and CRL workflows.
//!
//! ## Example on how to create a certifcate revocation list(clr)
//!
//! Create a crl, with one revoked certificate that have CRL Reason: Key Compromise
//!
//! ```rust
//! use cert_helper::certificate::{CertBuilder, UseesBuilderFields};
//! use cert_helper::crl::{X509CrlBuilder,CrlReason,X509CrlWrapper};
//! use chrono::Utc;
//! use num_bigint::BigUint;
//!
//! let ca = CertBuilder::new()
//!    .common_name("My Test Ca")
//!    .is_ca(true)
//!    .build_and_self_sign()
//!    .unwrap();
//! let mut builder = X509CrlBuilder::new(ca.clone());
//!     let revocked = CertBuilder::new()
//!    .common_name("My Test")
//!    .build_and_self_sign()
//!    .unwrap();
//!
//! let bytes = revocked.x509.serial_number().to_bn().unwrap().to_vec();
//! builder.add_revoked_cert_with_reason(BigUint::from_bytes_be(&bytes),
//!                          Utc::now(),
//!                          vec![CrlReason::KeyCompromise]);
//!
//! let wrapper = builder.build_and_sign().unwrap();
//! // to save crl as pem use the helper function
//! //  wrapper.save_as_pem("./certs", "crl.pem").expect("failed to save crl as pem file");
//!
//! // use the wrapper to check sign, revocations
//! let result = wrapper.verify_signature(ca.x509.public_key().as_ref().unwrap());
//! assert!(result.unwrap());
//! let is_revoked = wrapper.revoked(revocked.x509.serial_number());
//! assert!(is_revoked);
//! ```
//!
//! ## Config
//!
//! Values that can be selected for building a certificate
//! | keyword | description | options |
//! | ----------------- | --------------------------------------------------------------------------- | ----------------------------------- |
//! | common_name | the common name this certificate shoud have, mandatory field | string: www.foo.se |
//! | key_type  | key type to be used, defaults to RSA2048 | enum: RSA2048, RSA4096, P224, P256, P384, P521, Ed25519, and with `--features pqc`: MlDsa44, MlDsa65, MlDsa87, SlhDsaSha2_128s, SlhDsaSha2_192s, SlhDsaSha2_256s |
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
//! | certificate_policy | optional certificate policies to add | AnyPolicy, DomainValidation, OrganizationValidated, IndividualValidated, ExtendedValidation|
//! | pathlen | optional CA path length: max intermediate CAs allowed below this cert (only applies when ca is true) | u32: 0, 1, 2 … |
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
