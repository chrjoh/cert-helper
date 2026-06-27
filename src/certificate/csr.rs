#[cfg(feature = "pqc")]
use super::key::reject_mlkem_signing;
use super::key::{
    is_digestless_key, select_key, sign_certificate_digestless, sign_x509_req_digestless,
};
use super::policy::append_certificate_policies;
use super::usage::get_key_usage;
#[cfg(feature = "pqc")]
use super::validate_pqc_key_usage;
use super::{
    BuilderFields, Certificate, CertificatePolicy, Usage, UseesBuilderFields, X509Common,
    X509Parts, ca_basic_constraints, can_sign_cert, create_asn1_time_from_date, select_hash,
};
use openssl::asn1::{Asn1Object, Asn1OctetString, Asn1Time};
use openssl::bn::BigNum;
use openssl::hash::{MessageDigest, hash};
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::stack::Stack;
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectAlternativeName,
};
use openssl::x509::{X509, X509Builder, X509Extension, X509NameBuilder, X509Req, X509ReqBuilder};
use std::collections::HashSet;
use std::path::Path;
use x509_parser::certification_request::X509CertificationRequest;
use x509_parser::extensions::ParsedExtension;
use x509_parser::prelude::FromDer;

/// Holds the generated Certificate Signing Request (CSR) and its associated private key.
pub struct Csr {
    /// The X.509 certificate signing request.
    pub csr: X509Req,
    /// The private key used to generate the CSR.
    ///
    /// This is optional to allow flexibility in cases where the key is managed or stored separately.
    pub pkey: Option<PKey<Private>>,
}

impl X509Parts for Csr {
    fn get_pem(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(self.csr.to_pem()?)
    }

    fn get_private_key(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        match self.pkey {
            Some(ref pkey) => Ok(pkey.private_key_to_pem_pkcs8()?),
            _ => Err("No private key found".into()),
        }
    }
    fn pem_extension(&self) -> &'static str {
        "_csr.pem"
    }
}
/// Helper trait to document that Csr implements X509Common
pub trait CsrX509Common: X509Common {}
impl CsrX509Common for Csr {}

/// Holds configuration options for creating a certificate from a Certificate Signing Request (CSR).
pub struct CsrOptions {
    valid_to: Asn1Time,
    valid_from: Asn1Time,
    ca: bool,
    policies: Vec<CertificatePolicy>,
    path_len: Option<u32>,
}
impl Default for CsrOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl CsrOptions {
    /// Creates a default `CsrOptions` instance:
    /// - `valid_from` is set to today.
    /// - `valid_to` is set to one year from today.
    /// - `ca` is set to `false`.
    pub fn new() -> Self {
        Self {
            ca: false,
            valid_from: Asn1Time::days_from_now(0).unwrap(), // today
            valid_to: Asn1Time::days_from_now(365).unwrap(), // one year from now
            policies: Default::default(),
            path_len: None,
        }
    }

    /// Sets the start date from which the certificate should be valid.
    ///
    /// # Arguments
    /// * `valid_from` - A string in the format `yyyy-mm-dd`.
    pub fn valid_from(mut self, valid_from: &str) -> Self {
        self.valid_from =
            create_asn1_time_from_date(valid_from).expect("Failed to parse valid_from date");
        self
    }

    /// Sets the end date after which the certificate should no longer be valid.
    ///
    /// # Arguments
    /// * `valid_to` - A string in the format `yyyy-mm-dd`.
    pub fn valid_to(mut self, valid_to: &str) -> Self {
        self.valid_to =
            create_asn1_time_from_date(valid_to).expect("Failed to parse valid_to date");
        self
    }

    /// Specifies whether the certificate should be a Certificate Authority (CA).
    ///
    /// # Arguments
    /// * `ca` - `true` if the certificate should be a CA, `false` otherwise.
    pub fn is_ca(mut self, ca: bool) -> Self {
        self.ca = ca;
        self
    }
    /// Add optional certificate policies
    ///
    /// # Arguments
    /// * `policies` - A list of certificate policies
    pub fn certificate_policies(mut self, policies: Vec<CertificatePolicy>) -> Self {
        self.policies = policies;
        self
    }
    /// Add optional path length, it is the max number of **non-self-issued
    /// intermediate CA certs** that may follow this cert in a chain
    ///
    /// # Arguments
    /// * `path_len`- u32
    pub fn pathlen(mut self, path_len: u32) -> Self {
        self.path_len = Some(path_len);
        self
    }
}

impl Csr {
    /// Read a certificate signing request from file
    pub fn load_csr<C: AsRef<Path>>(csr_pem_file: C) -> Result<Self, Box<dyn std::error::Error>> {
        let cert_pem = std::fs::read(csr_pem_file)?;
        let cs_req = X509Req::from_pem(&cert_pem)?;
        Ok(Self {
            csr: cs_req,
            pkey: None,
        })
    }
    /// Create a signed certificate from a certificate signing request(csr)
    pub fn build_signed_certificate(
        &self,
        signer: &Certificate,
        options: CsrOptions,
    ) -> Result<Certificate, Box<dyn std::error::Error>> {
        // Proof-of-possession: refuse to issue from a CSR whose self-signature
        // does not verify against its own public key.
        verify_csr_proof_of_possession(&self.csr)?;

        let can_sign = can_sign_cert(signer)?;
        if !can_sign {
            let err = format!(
                "Cannot sign with signer certificate {:?}: it must be a valid CA \
                 (BasicConstraints CA flag set, KeyUsage keyCertSign, within its validity \
                 period) and have an associated private key",
                signer.x509.subject_name()
            );
            return Err(err.into());
        }
        let signer_key = signer
            .pkey
            .as_ref()
            .ok_or("signer certificate has no associated private key; cannot sign")?;
        let mut builder = X509Builder::new()?;
        builder.set_version(2)?;
        builder.set_subject_name(self.csr.subject_name())?;
        builder.set_issuer_name(signer.x509.subject_name())?;
        let csr_public_key = self.csr.public_key()?;
        builder.set_pubkey(&csr_public_key)?;

        let der = self.csr.to_der()?;
        let parsed_csr = X509CertificationRequest::from_der(&der)?;

        let req_ext = parsed_csr.1.requested_extensions();
        let mut any_key_used = false;
        let mut requested: HashSet<Usage> = HashSet::new();
        if let Some(exts) = req_ext {
            for ext in exts {
                match ext {
                    ParsedExtension::KeyUsage(ku) => {
                        any_key_used = true;
                        let mut cert_sign_added = false;
                        let mut crl_sign_added = false;
                        let mut usage = openssl::x509::extension::KeyUsage::new();
                        if ku.digital_signature() {
                            usage.digital_signature();
                            requested.insert(Usage::signature);
                        }
                        if ku.key_encipherment() {
                            usage.key_encipherment();
                            requested.insert(Usage::encipherment);
                        }
                        if ku.key_cert_sign() {
                            cert_sign_added = true;
                            usage.key_cert_sign();
                            requested.insert(Usage::certsign);
                        }
                        if ku.non_repudiation() {
                            usage.non_repudiation();
                            requested.insert(Usage::contentcommitment);
                        }
                        if ku.crl_sign() {
                            crl_sign_added = true;
                            usage.crl_sign();
                            requested.insert(Usage::crlsign);
                        }

                        if options.ca {
                            if !cert_sign_added {
                                usage.key_cert_sign();
                            }
                            if !crl_sign_added {
                                usage.crl_sign();
                            }
                        }
                        builder.append_extension(usage.build()?)?;
                    }
                    ParsedExtension::ExtendedKeyUsage(eku) => {
                        let mut ext = openssl::x509::extension::ExtendedKeyUsage::new();
                        if eku.server_auth {
                            ext.server_auth();
                        }
                        if eku.client_auth {
                            ext.client_auth();
                        }
                        if eku.code_signing {
                            ext.code_signing();
                        }
                        if eku.email_protection {
                            ext.email_protection();
                        }
                        builder.append_extension(ext.build()?)?;
                    }
                    ParsedExtension::SubjectAlternativeName(san) => {
                        let mut openssl_san =
                            openssl::x509::extension::SubjectAlternativeName::new();
                        for name in &san.general_names {
                            if let x509_parser::extensions::GeneralName::DNSName(dns) = name {
                                openssl_san.dns(dns);
                            }
                        }
                        builder.append_extension(
                            openssl_san.build(&builder.x509v3_context(None, None))?,
                        )?;
                    }
                    _ => {
                        println!("Unsupported extension: {:?}", ext);
                    }
                }
            }
        }
        #[cfg(feature = "pqc")]
        validate_pqc_key_usage(&csr_public_key, &requested)?;

        if options.ca {
            let result = ca_basic_constraints(options.path_len)?;
            builder.append_extension(result)?;
            if !any_key_used {
                let key_usage = KeyUsage::new().key_cert_sign().crl_sign().build().unwrap();
                builder.append_extension(key_usage)?;
            }
        } else {
            builder.append_extension(BasicConstraints::new().build()?)?;
        }
        builder.set_not_before(&options.valid_from)?;
        builder.set_not_after(&options.valid_to)?;
        let serial_number = {
            let mut serial = BigNum::new()?;
            serial.rand(159, openssl::bn::MsbOption::MAYBE_ZERO, false)?;
            serial.to_asn1_integer()?
        };
        builder.set_serial_number(&serial_number)?;
        if signer.x509.subject_key_id().is_some() {
            let aki = AuthorityKeyIdentifier::new()
                .keyid(true)
                .issuer(false)
                .build(&builder.x509v3_context(Some(&signer.x509), None))?;
            builder.append_extension(aki)?;
        }
        let oid = Asn1Object::from_str("2.5.29.14")?; // OID för Subject Key Identifier (SKI)
        let pubkey_der = self.csr.public_key().unwrap().public_key_to_der()?;
        let ski_hash = hash(MessageDigest::sha1(), &pubkey_der)?;
        let der_encoded = yasna::construct_der(|writer| {
            writer.write_bytes(ski_hash.as_ref());
        });
        let ski_asn1 = Asn1OctetString::new_from_bytes(&der_encoded)?;
        let ext = X509Extension::new_from_der(oid.as_ref(), false, &ski_asn1)?;
        builder.append_extension(ext)?;
        append_certificate_policies(&mut builder, &options.policies)?;
        let cert: X509 = if is_digestless_key(signer_key) {
            let builder_cert = builder.build();
            sign_certificate_digestless(&builder_cert, signer_key)
                .map_err(|e| format!("Failed to sign certificate with digestless key: {}", e))?;
            builder_cert
        } else {
            builder.sign(signer_key, MessageDigest::sha256())?;
            builder.build()
        };

        Ok(Certificate {
            x509: cert,
            pkey: None,
        })
    }
}

/// Builder for creating a new certificate signing request and private key
pub struct CsrBuilder {
    fields: BuilderFields,
}
impl UseesBuilderFields for CsrBuilder {
    fn fields_mut(&mut self) -> &mut BuilderFields {
        &mut self.fields
    }
}
impl Default for CsrBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl CsrBuilder {
    /// Create a new CsrBuilder with defaults
    pub fn new() -> Self {
        Self {
            fields: BuilderFields::default(),
        }
    }

    /// Builds and returns a Certificate Signing Request (CSR) based on the configured builder fields.
    ///
    /// This function constructs the subject name, sets the public key, and adds relevant X.509 extensions
    /// such as Key Usage, Extended Key Usage, and Subject Alternative Names (SAN).
    /// It supports signing with both traditional algorithms and Ed25519.
    ///
    /// # Returns
    /// - `Ok(Csr)` if the CSR was successfully built and signed.
    /// - `Err(Box<dyn std::error::Error>)` if any step in the CSR creation process fails.
    ///
    /// # Errors
    /// This function may return errors in the following cases:
    /// - Failure to initialize or build the X509 name or request.
    /// - Failure to select or use the appropriate key type.
    /// - Failure to build or add X.509 extensions.
    /// - Failure to sign the CSR, especially with Ed25519.
    ///
    /// # Extensions Added
    /// - **Key Usage** and **Extended Key Usage**: Based on the builder's `usage` field.
    /// - **Subject Alternative Names (SAN)**: Includes all entries from `alternative_names`.
    ///
    /// # Signing Behavior
    /// - If the key type is Ed25519, uses a custom signing function.
    /// - Otherwise, signs using the selected hash algorithm.
    ///
    /// # Example
    /// ```rust
    /// use cert_helper::certificate::CsrBuilder;
    /// use crate::cert_helper::certificate::UseesBuilderFields;
    /// let builder = CsrBuilder::new().common_name("example.com");
    /// let csr = builder.certificate_signing_request().unwrap();
    /// ```
    pub fn certificate_signing_request(self) -> Result<Csr, Box<dyn std::error::Error>> {
        let mut name_builder = X509NameBuilder::new()?;
        name_builder.append_entry_by_nid(Nid::COMMONNAME, &self.fields.common_name)?;
        if !self.fields.country_name.trim().is_empty() {
            name_builder.append_entry_by_nid(Nid::COUNTRYNAME, &self.fields.country_name)?;
        }
        if !self.fields.state_province.trim().is_empty() {
            name_builder
                .append_entry_by_nid(Nid::STATEORPROVINCENAME, &self.fields.state_province)?;
        }
        if !self.fields.locality_time.trim().is_empty() {
            name_builder.append_entry_by_nid(Nid::LOCALITYNAME, &self.fields.locality_time)?;
        }
        if !self.fields.organization.trim().is_empty() {
            name_builder.append_entry_by_nid(Nid::ORGANIZATIONNAME, &self.fields.organization)?;
        }
        let name = name_builder.build();
        let mut builder = X509ReqBuilder::new()?;
        builder.set_version(0)?;
        builder.set_subject_name(&name)?;
        let pkey = select_key(&self.fields.key_type).unwrap();
        builder.set_pubkey(&pkey)?;
        let key_usage = self.fields.usage.clone().unwrap_or_default();

        // Enforce post-quantum KeyUsage rules. Run before the can't-sign guard
        // below so a contradictory KeyUsage is reported precisely.
        #[cfg(feature = "pqc")]
        validate_pqc_key_usage(&pkey, &key_usage)?;

        // ML-KEM cannot sign, and a PKCS#10 CSR requires a self-signature for
        // proof-of-possession — so an ML-KEM CSR cannot be produced here.
        #[cfg(feature = "pqc")]
        reject_mlkem_signing(
            &pkey,
            "ML-KEM (FIPS 203) is a key-encapsulation key and cannot sign a CSR \
             (PKCS#10 requires a self-signature for proof-of-possession). Issue the \
             ML-KEM certificate directly with CertBuilder::build_and_sign() using a \
             signing CA instead.",
        )?;

        let mut extensions = Stack::new()?;

        let (tracked_key_usage, tracked_extended_key_usage) = get_key_usage(&Some(key_usage));
        if tracked_key_usage.is_used() {
            extensions.push(tracked_key_usage.into_inner().build()?)?;
        }
        if tracked_extended_key_usage.is_used() {
            extensions.push(tracked_extended_key_usage.into_inner().build()?)?;
        }

        let mut san = SubjectAlternativeName::new();
        for s in &self.fields.alternative_names {
            san.dns(s);
        }
        extensions.push(san.build(&builder.x509v3_context(None))?)?;

        builder.add_extensions(&extensions)?;
        let csr: X509Req = if is_digestless_key(&pkey) {
            let builder_csr = builder.build();
            sign_x509_req_digestless(&builder_csr, &pkey)
                .map_err(|e| format!("Failed to sign certificate with digestless key: {}", e))?;
            builder_csr
        } else {
            builder.sign(&pkey, select_hash(&self.fields.signature_alg))?;
            builder.build()
        };
        Ok(Csr {
            csr,
            pkey: Some(pkey),
        })
    }
}

/// Verify a CSR's proof-of-possession.
///
/// A PKCS#10 request is self-signed with the private key matching its own public
/// key; a valid signature proves the requester possesses that private key. We
/// verify the request signature against its embedded public key and refuse to
/// issue a certificate from a request that fails
fn verify_csr_proof_of_possession(csr: &X509Req) -> Result<(), Box<dyn std::error::Error>> {
    let public_key = csr.public_key()?;
    if !csr.verify(&public_key)? {
        return Err(
            "CSR proof-of-possession check failed: the request signature does \
            not verify against its own public key"
                .into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificate::CertBuilder;
    #[cfg(feature = "pqc")]
    use crate::certificate::key::generate_pqc_key;
    #[cfg(feature = "pqc")]
    use crate::certificate::key::sign_x509_req_digestless;
    use openssl::x509::X509Req;
    #[cfg(feature = "pqc")]
    use openssl::x509::X509ReqBuilder;
    #[cfg(feature = "pqc")]
    use openssl::x509::extension::KeyUsage;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn create_ca_cert_from_csr_with_path_len() {
        let ca = CertBuilder::new()
            .common_name("My Test Ca")
            .is_ca(true)
            .pathlen(2)
            .build_and_self_sign()
            .unwrap();

        let csr = CsrBuilder::new()
            .common_name("leaf")
            .certificate_signing_request()
            .unwrap();
        let cert = csr
            .build_signed_certificate(&ca, CsrOptions::new().pathlen(1).is_ca(true))
            .unwrap();
        assert_eq!(cert.x509.pathlen(), Some(1));
    }

    #[test]
    fn create_non_ca_cert_from_csr_with_path_len() {
        let ca = CertBuilder::new()
            .common_name("My Test Ca")
            .is_ca(true)
            .pathlen(2)
            .build_and_self_sign()
            .unwrap();

        let csr = CsrBuilder::new()
            .common_name("leaf")
            .certificate_signing_request()
            .unwrap();
        let cert = csr
            .build_signed_certificate(&ca, CsrOptions::new().pathlen(1))
            .unwrap();
        assert_eq!(cert.x509.pathlen(), None);
    }

    #[test]
    fn build_signed_certificate_rejects_csr_with_bad_proof_of_possession() {
        // A CSR whose self-signature does not match its public key (proof-of-
        // possession failure) must be refused, not turned into a certificate.
        let ca = CertBuilder::new()
            .common_name("My Test Ca")
            .is_ca(true)
            .build_and_self_sign()
            .unwrap();

        let good = CsrBuilder::new()
            .common_name("leaf")
            .certificate_signing_request()
            .unwrap();

        // Flip the last byte of the DER — the tail of the signature BIT STRING —
        // so the request no longer verifies against its own public key while
        // staying structurally parseable.
        let mut der = good.csr.to_der().unwrap();
        let last = der.len() - 1;
        der[last] ^= 0xFF;
        let tampered = Csr {
            csr: X509Req::from_der(&der).unwrap(),
            pkey: None,
        };

        let err = tampered
            .build_signed_certificate(&ca, CsrOptions::new())
            .err()
            .expect("CSR with broken proof-of-possession must be rejected");
        assert!(
            err.to_string().contains("proof-of-possession"),
            "expected a proof-of-possession error, got: {err}"
        );
    }

    #[cfg(feature = "pqc")]
    #[test]
    fn do_not_allow_csr_with_pqc_key_and_encipherment_to_generate_certificate() {
        let ca = CertBuilder::new()
            .common_name("My Test Ca")
            .is_ca(true)
            .build_and_self_sign()
            .unwrap();

        let pkey = generate_pqc_key("ML-DSA-65").unwrap();
        let mut builder = X509ReqBuilder::new().unwrap();
        builder
            .set_pubkey(&pkey)
            .expect("failed to set public key in csr");
        let mut exts = Stack::new().unwrap();
        exts.push(KeyUsage::new().key_encipherment().build().unwrap())
            .unwrap();
        builder.set_version(0).unwrap();
        builder.add_extensions(&exts).unwrap();
        let req = builder.build();

        let _ = sign_x509_req_digestless(&req, &pkey);
        let csr = Csr {
            csr: req,
            pkey: None,
        };
        let err = csr
            .build_signed_certificate(&ca, CsrOptions::new())
            .err()
            .expect("a PQC signature key requesting keyEncipherment must be rejected");
        assert!(
            err.to_string().contains("keyEncipherment"),
            "expected a keyEncipherment error, got: {err}"
        );
    }

    #[test]
    fn test_reading_csr_from_file() {
        let csr_data = b"-----BEGIN CERTIFICATE REQUEST-----
MIICzDCCAbQCAQAwXTEVMBMGA1UEAwwMZXhhbXBsZTIuY29tMQswCQYDVQQGEwJT
RTESMBAGA1UECAwJU3RvY2tob2xtMRIwEAYDVQQHDAlTdG9ja2hvbG0xDzANBgNV
BAoMBk15IG9yZzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAIeAXpCG
hbIayESfdTzOO0DxIMsOAu4kUm0zF0W/+xDUHl6bGy3wlB9S9nzBG/qwqFZ27Om3
o4zrZ8K8DBx0ERWNuhMmr0Nx8QpAWBEyxOc08Gn4c3XVBBkRZSn4AIqr9DGtcUqW
tQZXvMGF6sRRljiEvOxO6zMzZKTGYwzIeQvH85cQ3uXsw0Kknsw/fcuywaAC8SS9
aqs4jiEIgzdhxdH2OVXBNGj4cjVhK309JiWFHS9XJLNV/PKC+F1nkaANQwbW5A4F
9vya4js9gk8f4SfF1u+qOJEvsDvAb+1xdjXPRzf77eGh3rC4KgGWQ6WrWfW8PItF
BDg/jskq3bJXNL8CAwEAAaAqMCgGCSqGSIb3DQEJDjEbMBkwFwYDVR0RBBAwDoIM
ZXhhbXBsZTIuY29tMA0GCSqGSIb3DQEBCwUAA4IBAQAHeeSW8C6SMVhWiMvPn7iz
FUHQedHRyPz6kTEfC01eNIbs0r4YghOAcm8PF67jncIXVrqgxo1uzq12qlV+0YYb
jps31IbQNOz0eFLYvij15ielmOYeQZZ/2vqaGi3geVobLc6Ki5tadnA/NhjTN33j
QcqDDic8riAOTbSQ6TH9KPTGJQOPk+taMpDGDHskIW0oME5iT2ewbhBHg6v/kSzy
tss2kBY5O7vo2COtbNcwX5Xp9S2LH9kVUKr0GIjuQjwbv5xl+GNdDey09W9EDACU
jcGV3++2wS4LN4h3CG4pWZ+LTXhm8ymhoWOapN95lfe3xLRAKFJwiLkGwS75++FW
-----END CERTIFICATE REQUEST-----";
        let mut csr_file = NamedTempFile::new().expect("Failed to create temp csr file");
        csr_file.write_all(csr_data).expect("Failed to write csr");
        let result = Csr::load_csr(csr_file.path());
        assert!(result.is_ok(), "Failed to load csr: {:?}", result.err());
    }
}
