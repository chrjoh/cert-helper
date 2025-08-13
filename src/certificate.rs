use chrono::{NaiveDate, NaiveDateTime, TimeZone, Utc};
use foreign_types::ForeignType;
use openssl::asn1::{Asn1Object, Asn1OctetString, Asn1Time};
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::error::ErrorStack;
use openssl::hash::{MessageDigest, hash};
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, Private};
use openssl::rsa::Rsa;
use openssl::stack::Stack;
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
};
use openssl::x509::{
    X509, X509Builder, X509Extension, X509NameBuilder, X509Req, X509ReqBuilder, X509StoreContext,
    store::X509StoreBuilder,
};
use std::collections::{HashMap, HashSet};
use std::fs::{File, create_dir_all};
use std::io::Write;
use std::path::Path;

use x509_parser::certification_request::X509CertificationRequest;
use x509_parser::extensions::ParsedExtension;
use x509_parser::parse_x509_certificate;
use x509_parser::prelude::FromDer;

unsafe extern "C" {
    pub fn X509_sign(
        x: *mut openssl_sys::X509,
        pkey: *mut openssl_sys::EVP_PKEY,
        md: *const openssl_sys::EVP_MD,
    ) -> ::std::os::raw::c_int;
}

unsafe extern "C" {
    pub fn X509_REQ_sign(
        req: *mut openssl_sys::X509_REQ,
        pkey: *mut openssl_sys::EVP_PKEY,
        md: *const openssl_sys::EVP_MD,
    ) -> ::std::os::raw::c_int;
}

fn sign_certificate_ed25519(
    cert: &X509,
    pkey: &PKey<openssl::pkey::Private>,
) -> Result<(), String> {
    if pkey.id() != Id::ED25519 {
        return Err("sign_certificate_ed25519 called with non-Ed25519 key".to_string());
    }
    let cert_ptr = cert.as_ptr();
    let pkey_ptr = pkey.as_ptr();

    let result = unsafe { X509_sign(cert_ptr, pkey_ptr, std::ptr::null()) };

    if result > 0 {
        Ok(())
    } else {
        Err("Failed to sign certificate with Ed25519".to_string())
    }
}

fn sign_x509_req_ed25519(req: &X509Req, pkey: &PKey<Private>) -> Result<(), String> {
    if pkey.id() != Id::ED25519 {
        return Err("sign_x509_req_ed25519 called with non-Ed25519 key".to_string());
    }

    let req_ptr = req.as_ptr();
    let pkey_ptr = pkey.as_ptr();

    let result = unsafe { X509_REQ_sign(req_ptr, pkey_ptr, std::ptr::null()) };

    if result > 0 {
        Ok(())
    } else {
        Err("Failed to sign X509Req with Ed25519".to_string())
    }
}

macro_rules! vec_str_to_hs {
    ($vec:expr) => {
        $vec.iter()
            .map(|s| s.to_string())
            .collect::<HashSet<String>>()
    };
}
/// Defines what type of key that can be used with the certificate
#[derive(Debug, Clone, PartialEq)]
pub enum KeyType {
    /// RSA key with a 2048-bit length.
    RSA2048,
    /// RSA key with a 4096-bit length.
    RSA4096,
    /// Elliptic Curve key using the NIST P-224 curve (secp224r1).
    P224,
    /// Elliptic Curve key using the NIST P-256 curve (secp256r1). Also known as prime256v1.
    P256,
    /// Elliptic Curve key using the NIST P-384 curve (secp384r1).
    P384,
    /// Elliptic Curve key using the NIST P-521 curve (secp521r1).
    P521,
    /// Edwards-curve Digital Signature Algorithm using Ed25519.
    Ed25519,
}
/// Defines which hash algorithm to be used in certificate signing
#[derive(Debug, Clone)]
pub enum HashAlg {
    /// SHA-1 (Secure Hash Algorithm 1), now considered weak and generally discouraged for new certificates.
    SHA1,
    /// SHA-256 (part of SHA-2 family)
    SHA256,
    /// SHA-384 (SHA-2 family), offers stronger security and is often used with larger key sizes.
    SHA384,
    /// SHA-512 (SHA-2 family), provides the highest bit-length hash in the SHA-2 family.
    SHA512,
}
/// Represents the allowed usages for a certificate, used in KeyUsage and ExtendedKeyUsage extensions.
#[allow(non_camel_case_types)]
#[derive(Hash, Eq, PartialEq, Debug, Clone)]
pub enum Usage {
    /// Allows the certificate to sign other certificates (typically used for CA certificates).
    certsign,
    /// Allows the certificate to sign certificate revocation lists (CRLs).
    crlsign,
    /// Allows the certificate to be used for encrypting data (e.g., key encipherment).
    encipherment,
    /// Indicates the certificate can be used for client authentication in TLS.
    clientauth,
    /// Indicates the certificate can be used for server authentication in TLS.
    serverauth,
    /// Allows the certificate to be used for digital signatures.
    signature,
    /// Indicates the certificate can be used for content commitment (non-repudiation).
    contentcommitment,
}

/// Common functionality for extracting PEM-encoded data and private keys from X509-related types
pub trait X509Parts {
    /// Returns the PEM-encoded representation of the X.509 object (e.g., certificate or CSR).
    ///
    /// # Returns
    /// A `Vec<u8>` containing the PEM data, or an error if encoding fails.
    fn get_pem(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>>;
    /// Returns the PEM-encoded private key associated with the X.509 object.
    ///
    /// # Returns
    /// A `Vec<u8>` containing the PEM-encoded private key, or an error if retrieval fails.
    fn get_private_key(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>>;
    /// Returns the file extension typically used for the PEM output (e.g., `_cert.pem.`, `_csr.pem`, `_peky.pem`).
    ///
    /// # Returns
    /// A static string slice representing the file extension.
    fn pem_extension(&self) -> &'static str;
}

/// Provides a method to save the private key and X509 certificate or CSR data to files.
pub trait X509Common {
    /// Saves the X.509 object (e.g., certificate, CSR, or private key) to a file.
    ///
    /// # Arguments
    /// * `path` - The directory path where the file should be saved.
    /// * `filename` - The name of the file (without extension).
    ///
    /// The file extension is typically determined by the object's type (e.g., `.crt`, `.csr`, `.key`)
    /// and is provided by the [`X509Parts::pem_extension`] method if implemented.
    ///
    /// # Returns
    /// * `Ok(())` if the file was successfully written.
    /// * `Err` if an error occurred during file creation or writing.
    fn save<P: AsRef<Path>, F: AsRef<Path>>(
        &self,
        path: P,
        filename: F,
    ) -> Result<(), Box<dyn std::error::Error>>;
}

/// Implements `X509Common` for all types that implement `X509Parts`.
///
/// # Example
/// ```no_run
/// use cert_helper::certificate::{Certificate, X509Common};
/// let cert = Certificate::load_cert_and_key("cert.pem", "key.pem").expect("Failed to generate certificate");
/// cert.save("output", "mycert");
/// ```
impl<T: X509Parts> X509Common for T {
    /// Will save the cert/csr  and private key to pem file
    /// if path = /path/foo/bar and filename = mytest
    /// For example with certificate it will be:
    /// /path/foo/bar/mytest_cert.pem
    /// /path/foo/bar/mytest_pkey.pem
    /// and for certificate signing request:
    /// /path/foo/bar/mytest_csr.pem
    /// /path/foo/bar/mytest_pkey.pem
    ///
    /// If the path do not exist it will be created
    fn save<P: AsRef<Path>, F: AsRef<Path>>(
        &self,
        path: P,
        filename: F,
    ) -> Result<(), Box<dyn std::error::Error>> {
        create_dir_all(&path)?;

        let os_file = filename
            .as_ref()
            .file_name()
            .ok_or("Failed to extract file name")?;

        let write_file = |suffix: &str, content: &[u8]| -> Result<(), Box<dyn std::error::Error>> {
            let mut new_name = os_file.to_os_string();
            new_name.push(suffix);
            let full_path = path.as_ref().join(new_name);
            let mut file = File::create(full_path)?;
            file.write_all(content)?;
            Ok(())
        };
        match self.get_private_key() {
            Ok(ref key) => write_file("_pkey.pem", key)?,
            Err(_) => {}
        }
        write_file(&self.pem_extension(), &self.get_pem()?)?;
        Ok(())
    }
}
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
        let can_sign = can_sign_cert(&signer.x509)?;
        if !can_sign {
            let err = format!(
                "Trying to sign with non CA and/or no key usage that allow signing for signer certificate:{:?}",
                signer.x509.issuer_name()
            );
            return Err(err.into());
        }
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
                        }
                        if ku.key_encipherment() {
                            usage.key_encipherment();
                        }
                        if ku.key_cert_sign() {
                            cert_sign_added = true;
                            usage.key_cert_sign();
                        }
                        if ku.non_repudiation() {
                            usage.non_repudiation();
                        }
                        if ku.crl_sign() {
                            crl_sign_added = true;
                            usage.crl_sign();
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
        if options.ca {
            builder.append_extension(BasicConstraints::new().ca().build()?)?;
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
        let cert: X509;
        if signer.pkey.clone().unwrap().id() == Id::ED25519 {
            let builder_cert = builder.build();
            sign_certificate_ed25519(&builder_cert, signer.pkey.as_ref().unwrap())
                .map_err(|e| format!("Failed to sign certificate with ED25519: {}", e))?;
            cert = builder_cert;
        } else {
            builder.sign(signer.pkey.as_ref().unwrap(), MessageDigest::sha256())?;
            cert = builder.build();
        }

        Ok(Certificate {
            x509: cert,
            pkey: None,
        })
    }
}
/// Holds the generated X.509 certificate and its associated private key.
#[derive(Clone)]
pub struct Certificate {
    /// The X.509 certificate.
    pub x509: X509,
    /// The private key used to generate or sign the certificate.
    ///
    /// This is optional to allow for cases where the key is stored or managed separately.
    pub pkey: Option<PKey<Private>>,
}

impl X509Parts for Certificate {
    fn get_pem(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(self.x509.to_pem()?)
    }

    fn get_private_key(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        match self.pkey {
            Some(ref pkey) => Ok(pkey.private_key_to_pem_pkcs8()?),
            _ => Err("No private key found".into()),
        }
    }
    fn pem_extension(&self) -> &'static str {
        "_cert.pem"
    }
}

/// Helper trait to document that Certificate implements X509Common
pub trait CertificateX509Common: X509Common {}
impl CertificateX509Common for Certificate {}

impl Certificate {
    /// Loads a certificate and private key that are in PEM format from file
    /// and creates an X509 and PKey object.
    pub fn load_cert_and_key<C: AsRef<Path>, K: AsRef<Path>>(
        cert_pem_file: C,
        key_pem_file: K,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let cert_pem = std::fs::read(cert_pem_file)?;
        let key_pem = std::fs::read(key_pem_file)?;
        let cert = X509::from_pem(&cert_pem)?;
        let pkey = PKey::private_key_from_pem(&key_pem)?;
        Ok(Self {
            x509: cert,
            pkey: Some(pkey),
        })
    }
}

/// Defines a common interface for setting X509 certificate or CSR builder fields.
pub trait BuilderCommon {
    fn set_common_name(&mut self, name: &str);
    fn set_signer(&mut self, signer: &str);
    fn set_country_name(&mut self, name: &str);
    fn set_state_province(&mut self, name: &str);
    fn set_organization(&mut self, name: &str);
    fn set_organization_unit(&mut self, name: &str);
    fn set_alternative_names(&mut self, alternative_names: Vec<&str>);
    fn set_locality_time(&mut self, locality_time: &str);
    fn set_key_type(&mut self, key_type: KeyType);
    fn set_signature_alg(&mut self, signature_alg: HashAlg);
    fn set_key_usage(&mut self, key_usage: HashSet<Usage>);
}

/// Stores common configurable fields used during X509 certificate or CSR generation.
#[derive(Debug)]
pub struct BuilderFields {
    common_name: String,
    signer: Option<String>, //place holder for maybe future use??
    alternative_names: HashSet<String>,
    organization_unit: String,
    country_name: String,
    state_province: String,
    organization: String,
    locality_time: String,
    key_type: Option<KeyType>,
    signature_alg: Option<HashAlg>,
    usage: Option<HashSet<Usage>>,
}
impl BuilderCommon for BuilderFields {
    // Sets the common name, CN. This value will also be added to alternaitve_names
    fn set_common_name(&mut self, common_name: &str) {
        self.common_name = common_name.into();
        self.alternative_names.insert(String::from(common_name));
    }
    // A list of altrnative names(SAN) the Common Name(CN) is always included
    fn set_alternative_names(&mut self, alternative_names: Vec<&str>) {
        self.alternative_names
            .extend(vec_str_to_hs!(alternative_names));
    }
    // maybe
    fn set_signer(&mut self, signer: &str) {
        self.signer = Some(signer.into());
    }
    // Country, a valid two char value
    fn set_country_name(&mut self, country_name: &str) {
        self.country_name = country_name.into();
    }
    // State, province an utf-8 value
    fn set_state_province(&mut self, state_province: &str) {
        self.state_province = state_province.into();
    }
    // Org. an utf-8 value
    fn set_organization(&mut self, organization: &str) {
        self.organization = organization.into();
    }
    // Org. unit an utf-8 value
    fn set_organization_unit(&mut self, organization_unit: &str) {
        self.organization_unit = organization_unit.into();
    }
    // Locality, represents the city, town, or locality of the certificate subject
    fn set_locality_time(&mut self, locality_time: &str) {
        self.locality_time = locality_time.into();
    }
    // Selects what type of key to use RSA or elliptic
    fn set_key_type(&mut self, key_type: KeyType) {
        self.key_type = Some(key_type);
    }
    // Selects what alg to use for signature
    fn set_signature_alg(&mut self, signature_alg: HashAlg) {
        self.signature_alg = Some(signature_alg);
    }

    // Set what the certificate are allowed to do, KeyUsage and ExtendeKeyUsage
    fn set_key_usage(&mut self, key_usage: HashSet<Usage>) {
        match &mut self.usage {
            Some(existing_usage) => {
                existing_usage.extend(key_usage);
            }
            None => {
                self.usage = Some(key_usage);
            }
        };
    }
}

impl Default for BuilderFields {
    /// Returns default values for all fields
    fn default() -> Self {
        Self {
            common_name: Default::default(),
            signer: Default::default(),
            alternative_names: Default::default(),
            country_name: Default::default(),
            state_province: Default::default(),
            organization: Default::default(),
            organization_unit: Default::default(),
            locality_time: Default::default(),
            key_type: Default::default(),
            signature_alg: Default::default(),
            usage: Default::default(),
        }
    }
}
/// Provides a builder interface for configuring X509 certificate or CSR fields.
pub trait UseesBuilderFields: Sized {
    /// Returns a mutable reference to the internal `BuilderFields` structure.
    fn fields_mut(&mut self) -> &mut BuilderFields;

    /// Sets the Common Name (CN) of the certificate subject.
    ///
    /// This value will also be added to the list of Subject Alternative Names (SAN).
    fn common_name(mut self, common_name: &str) -> Self {
        self.fields_mut().set_common_name(common_name);
        self
    }
    /// Sets the signer name or identifier for the certificate.
    fn signer(mut self, signer: &str) -> Self {
        self.fields_mut().set_signer(signer);
        self
    }
    /// Sets the list of Subject Alternative Names (SAN).
    ///
    /// The Common Name (CN) is always included automatically.
    fn alternative_names(mut self, alternative_names: Vec<&str>) -> Self {
        self.fields_mut().set_alternative_names(alternative_names);
        self
    }
    /// Sets the country name (C), which must be a valid two-letter country code.
    fn country_name(mut self, country_name: &str) -> Self {
        self.fields_mut().set_country_name(country_name);
        self
    }
    /// Sets the state or province name (ST) as a UTF-8 string.
    fn state_province(mut self, state_province: &str) -> Self {
        self.fields_mut().set_state_province(state_province);
        self
    }
    /// Sets the organization name (O) as a UTF-8 string.
    fn organization(mut self, organization: &str) -> Self {
        self.fields_mut().set_organization(organization);
        self
    }
    /// Sets the locality name (L), typically representing the city or town.
    fn locality_time(mut self, locality_time: &str) -> Self {
        self.fields_mut().set_locality_time(locality_time);
        self
    }
    /// Sets the type of key to generate (e.g., RSA or Elliptic Curve).
    fn key_type(mut self, key_type: KeyType) -> Self {
        self.fields_mut().set_key_type(key_type);
        self
    }
    /// Sets the signature algorithm to use when signing the certificate.
    fn signature_alg(mut self, signature_alg: HashAlg) -> Self {
        self.fields_mut().set_signature_alg(signature_alg);
        self
    }

    /// Sets the allowed usages for the certificate (e.g., key signing, digital signature).
    ///
    /// This includes both `KeyUsage` and `ExtendedKeyUsage` extensions.
    fn key_usage(mut self, key_usage: HashSet<Usage>) -> Self {
        self.fields_mut().set_key_usage(key_usage);
        self
    }
}

/// Builder for creating a new certificate and private key
pub struct CertBuilder {
    fields: BuilderFields,
    valid_from: Asn1Time,
    valid_to: Asn1Time,
    ca: bool,
}

impl UseesBuilderFields for CertBuilder {
    fn fields_mut(&mut self) -> &mut BuilderFields {
        &mut self.fields
    }
}
impl CertBuilder {
    /// Create a new CertBuilder with defaults and one year from now as valid date
    pub fn new() -> Self {
        Self {
            fields: BuilderFields::default(),
            valid_from: Asn1Time::days_from_now(0).unwrap(), // today
            valid_to: Asn1Time::days_from_now(365).unwrap(), // one year from now
            ca: false,
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
        if ca {
            self.ca = ca;
            self.fields
                .set_key_usage(HashSet::from([Usage::certsign, Usage::crlsign]));
        }
        self
    }

    /// create a self signed x509 certificate and private key
    pub fn build_and_self_sign(&self) -> Result<Certificate, Box<dyn std::error::Error>> {
        let (mut builder, pkey) = self.prepare_x509_builder(None)?;
        let ca_cert: X509;
        if pkey.id() == Id::ED25519 {
            let build_cert = builder.build();
            sign_certificate_ed25519(&build_cert, &pkey)
                .map_err(|e| format!("Failed to sign certificate with ED25519: {}", e))?;
            ca_cert = build_cert;
        } else {
            builder.sign(&pkey, select_hash(&self.fields.signature_alg))?;
            ca_cert = builder.build();
        }

        Ok(Certificate {
            x509: ca_cert,
            pkey: Some(pkey),
        })
    }
    /// Create a signed certificate and private key
    pub fn build_and_sign(
        &self,
        signer: &Certificate,
    ) -> Result<Certificate, Box<dyn std::error::Error>> {
        let can_sign = can_sign_cert(&signer.x509)?;
        if !can_sign {
            let err = format!(
                "Trying to sign with non CA and/or no key usage that allow signing for signer certificate:{:?}",
                signer.x509.issuer_name()
            );
            return Err(err.into());
        }
        let (mut builder, pkey) = self.prepare_x509_builder(Some(&signer))?;
        let signer_key = signer.pkey.as_ref().unwrap();
        let cert: X509;
        if signer_key.id() == Id::ED25519 {
            let build_cert = builder.build();
            sign_certificate_ed25519(&build_cert, &signer_key)
                .map_err(|e| format!("Failed to sign certificate with ED25519: {}", e))?;
            cert = build_cert;
        } else {
            builder.sign(signer_key, select_hash(&self.fields.signature_alg))?;
            cert = builder.build();
        }
        Ok(Certificate {
            x509: cert,
            pkey: Some(pkey),
        })
    }

    fn prepare_x509_builder(
        &self,
        signer: Option<&Certificate>,
    ) -> Result<(X509Builder, PKey<Private>), Box<dyn std::error::Error>> {
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
        if !self.fields.organization_unit.trim().is_empty() {
            name_builder
                .append_entry_by_nid(Nid::ORGANIZATIONALUNITNAME, &self.fields.organization_unit)?;
        }

        let name = name_builder.build();

        let mut builder = X509::builder()?;
        builder.set_version(2)?;

        let serial_number = {
            let mut serial = BigNum::new()?;
            serial.rand(159, openssl::bn::MsbOption::MAYBE_ZERO, false)?;
            serial.to_asn1_integer()?
        };

        let pkey = select_key(&self.fields.key_type).unwrap();
        builder.set_serial_number(&serial_number)?;
        builder.set_subject_name(&name)?;
        builder.set_pubkey(&pkey)?;
        builder.set_not_before(&self.valid_from)?;
        builder.set_not_after(&self.valid_to)?;
        match signer {
            Some(signer) => builder.set_issuer_name(signer.x509.subject_name())?,
            None => builder.set_issuer_name(&name)?,
        }

        let key_usage = self.fields.usage.clone().unwrap_or_default();
        if self.ca {
            builder.append_extension(BasicConstraints::new().ca().build()?)?;
        } else {
            builder.append_extension(BasicConstraints::new().build()?)?;
        }

        let (tracked_key_usage, tracked_extended_key_usage) = get_key_usage(&Some(key_usage));
        if tracked_key_usage.is_used() {
            builder.append_extension(tracked_key_usage.into_inner().build()?)?;
        }
        if tracked_extended_key_usage.is_used() {
            builder.append_extension(tracked_extended_key_usage.into_inner().build()?)?;
        }

        let mut san = SubjectAlternativeName::new();
        for s in &self.fields.alternative_names {
            san.dns(s);
        }
        if let Some(signer_cert) = signer {
            builder.append_extension(
                san.build(&builder.x509v3_context(Some(&signer_cert.x509), None))?,
            )?;
            if signer_cert.x509.subject_key_id().is_some() {
                let aki = AuthorityKeyIdentifier::new()
                    .keyid(true)
                    .issuer(false)
                    .build(&builder.x509v3_context(Some(&signer_cert.x509), None))?;
                builder.append_extension(aki)?;
            }
        } else {
            // add aki that is the same as ski for self signed
            builder.append_extension(san.build(&builder.x509v3_context(None, None))?)?;
            let oid = Asn1Object::from_str("2.5.29.35")?; // OID för Authority Key Identifier (AKI)
            let pubkey_der = pkey.public_key_to_der()?;
            let aki_hash = hash(MessageDigest::sha1(), &pubkey_der)?;
            let der_encoded = yasna::construct_der(|writer| {
                writer.write_sequence(|writer| {
                    writer
                        .next()
                        .write_tagged_implicit(yasna::Tag::context(0), |writer| {
                            writer.write_bytes(aki_hash.as_ref());
                        })
                })
            });
            let aki_asn1 = Asn1OctetString::new_from_bytes(&der_encoded)?;
            let ext = X509Extension::new_from_der(oid.as_ref(), false, &aki_asn1)?;
            builder.append_extension(ext)?;
        }
        // tried
        // let ski = SubjectKeyIdentifier::new().build(&builder.x509v3_context(None, None))?;
        // but got miss/match in hash values so I calculate the ski explicitly with sha1
        // to verify with openssl cli
        // RSA:
        // openssl x509 -in mytestca_cert.pem -inform PEM -pubkey -noout | openssl rsa -pubin -outform DER | openssl dgst -c -sha1
        // EC:
        // openssl x509 -in mytestca_cert.pem -inform PEM -pubkey -noout| openssl pkey -pubin -outform DER| openssl dgst -c -sha1
        let oid = Asn1Object::from_str("2.5.29.14")?; // OID för Subject Key Identifier (SKI)
        let pubkey_der = pkey.public_key_to_der()?;
        let ski_hash = hash(MessageDigest::sha1(), &pubkey_der)?;
        let der_encoded = yasna::construct_der(|writer| {
            writer.write_bytes(ski_hash.as_ref());
        });
        let ski_asn1 = Asn1OctetString::new_from_bytes(&der_encoded)?;
        let ext = X509Extension::new_from_der(oid.as_ref(), false, &ski_asn1)?;
        builder.append_extension(ext)?;

        Ok((builder, pkey))
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
impl CsrBuilder {
    /// Create a new CsrBuilder with defaults
    pub fn new() -> Self {
        Self {
            fields: BuilderFields::default(),
        }
    }
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

        let mut extensions = Stack::new()?;

        let (tracked_key_usage, tracked_extended_key_usage) = get_key_usage(&Some(key_usage));
        if tracked_key_usage.is_used() {
            extensions.push(tracked_key_usage.inner.build()?)?;
        }
        if tracked_extended_key_usage.is_used() {
            extensions.push(tracked_extended_key_usage.inner.build()?)?;
        }

        let mut san = SubjectAlternativeName::new();
        for s in &self.fields.alternative_names {
            san.dns(s);
        }
        extensions.push(san.build(&builder.x509v3_context(None))?)?;

        builder.add_extensions(&extensions)?;
        let csr: X509Req;
        if pkey.id() == Id::ED25519 {
            let builder_csr = builder.build();
            sign_x509_req_ed25519(&builder_csr, &pkey)
                .map_err(|e| format!("Failed to sign certificate with ED25519: {}", e))?;
            csr = builder_csr;
        } else {
            builder.sign(&pkey, select_hash(&self.fields.signature_alg))?;
            csr = builder.build();
        }
        Ok(Csr {
            csr,
            pkey: Some(pkey),
        })
    }
}
struct TrackedExtendedKeyUsage {
    inner: ExtendedKeyUsage,
    used: bool,
}

impl TrackedExtendedKeyUsage {
    fn new() -> Self {
        Self {
            inner: ExtendedKeyUsage::new(),
            used: false,
        }
    }

    fn client_auth(&mut self) {
        self.inner.client_auth();
        self.used = true;
    }

    fn server_auth(&mut self) {
        self.inner.server_auth();
        self.used = true;
    }

    fn is_used(&self) -> bool {
        self.used
    }

    fn into_inner(self) -> ExtendedKeyUsage {
        self.inner
    }
}

struct TrackedKeyUsage {
    inner: KeyUsage,
    used: bool,
}

impl TrackedKeyUsage {
    fn new() -> Self {
        Self {
            inner: KeyUsage::new(),
            used: false,
        }
    }

    fn digital_signature(&mut self) {
        self.inner.digital_signature();
        self.used = true;
    }

    fn non_repudiation(&mut self) {
        self.inner.non_repudiation();
        self.used = true;
    }

    fn key_encipherment(&mut self) {
        self.inner.key_encipherment();
        self.used = true;
    }

    fn key_cert_sign(&mut self) {
        self.inner.key_cert_sign();
        self.used = true;
    }

    fn crl_sign(&mut self) {
        self.inner.crl_sign();
        self.used = true;
    }

    fn is_used(&self) -> bool {
        self.used
    }

    fn into_inner(self) -> KeyUsage {
        self.inner
    }
}

/// Verifies a certificate against a root certificate and the intermediate
/// chain leading up to it.
/// Note: The root certificate should not be included in the chain.
pub fn verify_cert(
    cert: &X509,
    ca: &X509,
    cert_chain: Vec<&X509>,
) -> Result<bool, Box<dyn std::error::Error>> {
    // Build a certificate store and add the issuer
    let mut store_builder = X509StoreBuilder::new()?;
    store_builder.add_cert(ca.clone())?;
    let store = store_builder.build();

    // Create a verification context
    let mut ctx = X509StoreContext::new()?;
    let mut chain = Stack::new()?; // create an empty chain
    cert_chain
        .iter()
        .try_for_each(|c| chain.push((*c).clone()))?;
    ctx.init(&store, &cert, &chain, |c| c.verify_cert())?;
    let verified = ctx.error() == openssl::x509::X509VerifyResult::OK;
    Ok(verified)
}

/// Takes a vector of certificates and returns a vector ordered
/// from the root to the leaf, with the leaf certificate as the last element.
///
/// For example, if the input list contains `ca2`, `leaf`, and `ca1`,
/// and the signing order is `ca1 -> ca2 -> leaf`,
/// the returned vector will be `[ca1, ca2, leaf]`.
///
/// If multiple valid chains are possible, the longest one is returned.
pub fn create_cert_chain_from_cert_list(
    certs: Vec<X509>,
) -> Result<Vec<X509>, Box<dyn std::error::Error>> {
    let mut subject_map: HashMap<Vec<u8>, X509> = HashMap::new();
    let mut issuer_map: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();

    for cert in &certs {
        let subject = cert.subject_name().to_der()?;
        let issuer = cert.issuer_name().to_der()?;
        subject_map.insert(subject.clone(), cert.clone());
        issuer_map.insert(subject, issuer);
    }

    // Find leaf certificates (those that are not issuers of any other cert)
    let all_issuers: Vec<Vec<u8>> = issuer_map.values().cloned().collect();
    let leaf_certs: Vec<X509> = subject_map
        .iter()
        .filter(|(subject, _)| !all_issuers.contains(subject))
        .map(|(_, cert)| cert.clone())
        .collect();

    // Try to build the longest chain from each leaf
    let mut longest_chain = Vec::new();

    for leaf in leaf_certs {
        let mut chain = vec![leaf.clone()];
        let mut current_cert = leaf;

        while let Ok(issuer_der) = current_cert.issuer_name().to_der() {
            if let Some(parent_cert) = subject_map.get(&issuer_der) {
                if parent_cert.subject_name().to_der()? == current_cert.subject_name().to_der()? {
                    break; // Self-signed, stop here
                }
                chain.push(parent_cert.clone());
                current_cert = parent_cert.clone();
            } else {
                break; // Issuer not found in the list
            }
        }

        if chain.len() > longest_chain.len() {
            longest_chain = chain;
        }
    }

    // Reverse to have root (or highest known CA) first
    longest_chain.reverse();
    Ok(longest_chain)
}

fn create_asn1_time_from_date(date_str: &str) -> Result<Asn1Time, Box<dyn std::error::Error>> {
    let date = NaiveDate::parse_from_str(date_str, "%Y-%m-%d")?;
    let datetime = NaiveDateTime::new(date, chrono::NaiveTime::from_hms_opt(0, 0, 0).unwrap());
    let utc_datetime = Utc.from_utc_datetime(&datetime);
    let asn1_time_str = utc_datetime.format("%Y%m%d%H%M%SZ").to_string();
    let asn1_time = Asn1Time::from_str(&asn1_time_str)?;
    Ok(asn1_time)
}

fn select_key(key_type: &Option<KeyType>) -> Result<PKey<Private>, ErrorStack> {
    match key_type {
        Some(KeyType::P224) => {
            let group = EcGroup::from_curve_name(Nid::SECP224R1)?;
            let ec_key = EcKey::generate(&group)?;
            PKey::from_ec_key(ec_key)
        }
        Some(KeyType::P256) => {
            let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
            let ec_key = EcKey::generate(&group)?;
            PKey::from_ec_key(ec_key)
        }
        Some(KeyType::P384) => {
            let group = EcGroup::from_curve_name(Nid::SECP384R1)?;
            let ec_key = EcKey::generate(&group)?;
            PKey::from_ec_key(ec_key)
        }
        Some(KeyType::P521) => {
            let group = EcGroup::from_curve_name(Nid::SECP521R1)?;
            let ec_key = EcKey::generate(&group)?;
            PKey::from_ec_key(ec_key)
        }
        Some(KeyType::Ed25519) => PKey::generate_ed25519(),
        Some(KeyType::RSA4096) => {
            let rsa = Rsa::generate(4096)?;
            PKey::from_rsa(rsa)
        }
        _ => {
            let rsa = Rsa::generate(2048)?;
            PKey::from_rsa(rsa)
        }
    }
}

fn select_hash(hash_type: &Option<HashAlg>) -> MessageDigest {
    match hash_type {
        Some(HashAlg::SHA1) => MessageDigest::sha1(),
        Some(HashAlg::SHA384) => MessageDigest::sha384(),
        Some(HashAlg::SHA512) => MessageDigest::sha512(),
        _ => MessageDigest::sha256(),
    }
}

fn get_key_usage(usage: &Option<HashSet<Usage>>) -> (TrackedKeyUsage, TrackedExtendedKeyUsage) {
    let mut ku = TrackedKeyUsage::new();
    let mut eku = TrackedExtendedKeyUsage::new();
    if let Some(usages) = usage {
        for u in usages {
            match u {
                Usage::contentcommitment => {
                    ku.non_repudiation();
                }
                Usage::encipherment => {
                    ku.key_encipherment();
                }
                Usage::certsign => {
                    ku.key_cert_sign();
                }
                Usage::clientauth => {
                    eku.client_auth();
                }
                Usage::signature => {
                    ku.digital_signature();
                }
                Usage::crlsign => {
                    ku.crl_sign();
                }
                Usage::serverauth => {
                    eku.server_auth();
                }
            }
        }
    }

    (ku, eku)
}

fn can_sign_cert(cert: &X509) -> Result<bool, Box<dyn std::error::Error>> {
    let der = cert.to_der()?;
    let (_, parsed_cert) = parse_x509_certificate(&der)?;

    let mut is_ca = false;
    let mut can_sign = false;

    for ext in parsed_cert.tbs_certificate.extensions().iter() {
        match &ext.parsed_extension() {
            ParsedExtension::BasicConstraints(bc) => {
                is_ca = bc.ca;
            }
            ParsedExtension::KeyUsage(ku) => {
                can_sign = ku.key_cert_sign();
            }
            _ => {}
        }
    }
    Ok(is_ca && can_sign)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::Path;
    use tempfile::NamedTempFile;

    #[test]
    fn save_certificate() {
        let ca = CertBuilder::new().common_name("My Test Ca").is_ca(true);
        match ca.build_and_self_sign() {
            Ok(cert) => {
                let output_file = NamedTempFile::new().unwrap();
                let full_path = output_file.path();
                let parent_dir: &Path = full_path.parent().unwrap();
                let file_name: &str = full_path.file_name().unwrap().to_str().unwrap();
                cert.save(parent_dir, file_name)
                    .expect("Failed to save certificate and key");
                let written_file_path = parent_dir.join(file_name);
                assert!(written_file_path.exists(), "File was not created");
            }
            Err(_) => panic!("Failed to creat certificate"),
        }
    }

    #[test]
    fn read_certificate_and_key_from_file() {
        let cert_pem = b"-----BEGIN CERTIFICATE-----
MIICiDCCAemgAwIBAgIUO3+y1WZPRRNs8dmZZTUHMj6TdiowCgYIKoZIzj0EAwQw
WzETMBEGA1UEAwwKTXkgVGVzdCBDYTELMAkGA1UEBhMCU0UxEjAQBgNVBAgMCVN0
b2NraG9sbTESMBAGA1UEBwwJU3RvY2tob2xtMQ8wDQYDVQQKDAZteSBvcmcwHhcN
MjUwNzA4MTExMzI2WhcNMjYwNzA4MTExMzI2WjBbMRMwEQYDVQQDDApNeSBUZXN0
IENhMQswCQYDVQQGEwJTRTESMBAGA1UECAwJU3RvY2tob2xtMRIwEAYDVQQHDAlT
dG9ja2hvbG0xDzANBgNVBAoMBm15IG9yZzCBmzAQBgcqhkjOPQIBBgUrgQQAIwOB
hgAEADZXcQK2ihgVTJeGx5FKm1x+R+ivygIvMnkv03faq1LpLU3doKX38DEO/cSW
Ev5u+kcjspXeeDPhqJFC8rRAz4awAMk+D0mXEms7xpFPh0HmI6NNcJc5eJ/8ZsEJ
GH1a34y0Yn6259gqlwAh2Eh9Nx1579BAanRr8lr+n1tZ09T/9AQho0gwRjAMBgNV
HRMEBTADAQH/MAsGA1UdDwQEAwIBBjApBgNVHREEIjAgggZjYS5jb22CCnd3dy5j
YS5jb22CCk15IFRlc3QgQ2EwCgYIKoZIzj0EAwQDgYwAMIGIAkIB8NVUgRIuNXmJ
cLCQ74Ub7Dqo71S0+iCrZF1YyJA8/q65aqMCT54k5Yx7HRBUUVHbCEpDXRqGPsIH
frfe5OmS3qICQgDBn07o0CcyfoSEd+Xoj2+/RBuU0vo9lUP7TKj7tssBxzEQFoxX
eE1qT98UIe78FZ+zqjwZTN9MCSsatuim6pXvOA==
-----END CERTIFICATE-----";

        let key_pem = b"-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIAgvZTeQgGysadAX0r
aZB5Lk4vjHy5iVuKdvcGdYt9NBvYx+Ib3Uk7vqMag7M1jyHL0Xf9uNtT2mxBmzBG
3CF+EgOhgYkDgYYABAA2V3ECtooYFUyXhseRSptcfkfor8oCLzJ5L9N32qtS6S1N
3aCl9/AxDv3ElhL+bvpHI7KV3ngz4aiRQvK0QM+GsADJPg9JlxJrO8aRT4dB5iOj
TXCXOXif/GbBCRh9Wt+MtGJ+tufYKpcAIdhIfTcdee/QQGp0a/Ja/p9bWdPU//QE
IQ==
-----END PRIVATE KEY-----";

        let mut cert_file = NamedTempFile::new().expect("Failed to create temp cert file");
        let mut key_file = NamedTempFile::new().expect("Failed to create temp key file");

        cert_file.write_all(cert_pem).expect("Failed to write cert");
        key_file.write_all(key_pem).expect("Failed to write key");

        let result = Certificate::load_cert_and_key(cert_file.path(), key_file.path());
        assert!(
            result.is_ok(),
            "Failed to load cert and key: {:?}",
            result.err()
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
