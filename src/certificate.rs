mod csr;
mod key;
mod policy;
mod usage;
use chrono::{NaiveDate, NaiveDateTime, TimeZone, Utc};
pub use csr::{Csr, CsrBuilder, CsrOptions, CsrX509Common};
pub use key::KeyType;
pub(crate) use key::is_digestless_key;
#[cfg(feature = "pqc")]
use key::reject_mlkem_signing;
use key::{select_key, sign_certificate_digestless};
use openssl::asn1::{Asn1Object, Asn1OctetString, Asn1Time};
use openssl::bn::BigNum;
use openssl::error::ErrorStack;
use openssl::hash::{MessageDigest, hash};
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::stack::Stack;
use openssl::x509::extension::{AuthorityKeyIdentifier, BasicConstraints, SubjectAlternativeName};
use openssl::x509::{
    X509, X509Builder, X509Extension, X509NameBuilder, X509StoreContext, store::X509StoreBuilder,
};
pub use policy::CertificatePolicy;
use policy::append_certificate_policies;
use std::collections::{HashMap, HashSet};
use std::fs::{File, create_dir_all};
use std::io::Write;
use std::marker::PhantomData;
use std::path::Path;
pub use usage::Usage; // keeps cert_helper::certificate::Usage
use usage::get_key_usage;
#[cfg(feature = "pqc")]
use usage::validate_pqc_key_usage;
use x509_parser::extensions::ParsedExtension;
use x509_parser::parse_x509_certificate;

pub struct PathLenUnset;
pub struct PathLenSet;

macro_rules! vec_str_to_hs {
    ($vec:expr) => {
        $vec.iter()
            .map(|s| s.to_string())
            .collect::<HashSet<String>>()
    };
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
        if let Ok(ref key) = self.get_private_key() {
            write_file("_pkey.pem", key)?;
        }
        write_file(self.pem_extension(), &self.get_pem()?)?;
        Ok(())
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
pub struct CertBuilder<P = PathLenUnset> {
    fields: BuilderFields,
    valid_from: Asn1Time,
    valid_to: Asn1Time,
    policies: Vec<CertificatePolicy>,
    ca: bool,
    path_len: Option<u32>,
    _marker: PhantomData<P>,
}

impl<P> UseesBuilderFields for CertBuilder<P> {
    fn fields_mut(&mut self) -> &mut BuilderFields {
        &mut self.fields
    }
}
impl Default for CertBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl<P> CertBuilder<P> {
    /// Add optional certificate policies
    ///
    /// # Arguments
    /// * `policies` - A list of certificate policies
    pub fn certificate_policies(mut self, policies: Vec<CertificatePolicy>) -> Self {
        self.policies = policies;
        self
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
    /// Add optional path length, it is the max number of **non-self-issued
    /// intermediate CA certs** that may follow this cert in a chain
    ///
    /// # Arguments
    /// * `path_len`- u32
    pub fn pathlen(self, path_len: u32) -> CertBuilder<PathLenSet> {
        CertBuilder {
            fields: self.fields,
            valid_from: self.valid_from,
            valid_to: self.valid_to,
            policies: self.policies,
            ca: self.ca,
            path_len: Some(path_len),
            _marker: PhantomData,
        }
    }

    /// create a self signed x509 certificate and private key
    pub fn build_and_self_sign(&self) -> Result<Certificate, Box<dyn std::error::Error>> {
        let (mut builder, pkey) = self.prepare_x509_builder(None)?;

        // ML-KEM keys cannot produce signatures, so a self-signed certificate is
        // impossible — issue via build_and_sign() with a separate signing CA.
        #[cfg(feature = "pqc")]
        reject_mlkem_signing(
            &pkey,
            "ML-KEM (FIPS 203) is a key-encapsulation key and cannot produce \
             signatures, so it cannot self-sign a certificate. Issue an ML-KEM \
             certificate with CertBuilder::build_and_sign() using a signing CA \
             (e.g. an ML-DSA or ECDSA CA) instead.",
        )?;

        let ca_cert: X509 = if is_digestless_key(&pkey) {
            let build_cert = builder.build();
            sign_certificate_digestless(&build_cert, &pkey)
                .map_err(|e| format!("Failed to sign certificate with digestless key: {}", e))?;
            build_cert
        } else {
            builder.sign(&pkey, select_hash(&self.fields.signature_alg))?;
            builder.build()
        };

        Ok(Certificate {
            x509: ca_cert,
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
        append_certificate_policies(&mut builder, &self.policies)?;
        // Enforce post-quantum KeyUsage rules (signature-only ML-DSA/SLH-DSA vs
        // keyEncipherment-only ML-KEM). See validate_pqc_key_usage.
        #[cfg(feature = "pqc")]
        validate_pqc_key_usage(&pkey, &key_usage)?;

        if self.ca {
            let result = ca_basic_constraints(self.path_len)?;
            builder.append_extension(result)?;
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

impl CertBuilder<PathLenUnset> {
    /// Create a new CertBuilder with defaults and one year from now as valid date
    pub fn new() -> Self {
        Self {
            fields: BuilderFields::default(),
            valid_from: Asn1Time::days_from_now(0).unwrap(), // today
            valid_to: Asn1Time::days_from_now(365).unwrap(), // one year from now
            ca: false,
            policies: Default::default(),
            path_len: None,
            _marker: PhantomData,
        }
    }
    /// Create a signed certificate and private key
    pub fn build_and_sign(
        &self,
        signer: &Certificate,
    ) -> Result<Certificate, Box<dyn std::error::Error>> {
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
        let (mut builder, pkey) = self.prepare_x509_builder(Some(signer))?;
        let signer_key = signer
            .pkey
            .as_ref()
            .ok_or("signer certificate has no associated private key; cannot sign")?;
        let cert: X509 = if is_digestless_key(signer_key) {
            let build_cert = builder.build();
            sign_certificate_digestless(&build_cert, signer_key)
                .map_err(|e| format!("Failed to sign certificate with digestless key: {}", e))?;
            build_cert
        } else {
            builder.sign(signer_key, select_hash(&self.fields.signature_alg))?;
            builder.build()
        };
        Ok(Certificate {
            x509: cert,
            pkey: Some(pkey),
        })
    }
}

impl CertBuilder<PathLenSet> {
    pub fn build_and_sign_with_chain(
        &self,
        signer: &Certificate,
        chain: &[&X509],
    ) -> Result<Certificate, Box<dyn std::error::Error>> {
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
        if self.ca {
            let budget = verify_cert_path(signer, chain)?; // Option<u32>
            if let (Some(b), Some(m)) = (budget, self.path_len)
                && m >= b
            {
                return Err("requested pathLen exceeds what the signer's chain permits".into());
            }
        }

        let (mut builder, pkey) = self.prepare_x509_builder(Some(signer))?;
        let signer_key = signer
            .pkey
            .as_ref()
            .ok_or("signer certificate has no associated private key; cannot sign")?;
        let cert: X509 = if is_digestless_key(signer_key) {
            let build_cert = builder.build();
            sign_certificate_digestless(&build_cert, signer_key)
                .map_err(|e| format!("Failed to sign certificate with digestless key: {}", e))?;
            build_cert
        } else {
            builder.sign(signer_key, select_hash(&self.fields.signature_alg))?;
            builder.build()
        };
        Ok(Certificate {
            x509: cert,
            pkey: Some(pkey),
        })
    }
}
fn ca_basic_constraints(path_len: Option<u32>) -> Result<X509Extension, ErrorStack> {
    let mut bc = BasicConstraints::new();
    bc.ca().critical();
    if let Some(len) = path_len {
        bc.pathlen(len);
    }
    bc.build()
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
    ctx.init(&store, cert, &chain, |c| c.verify_cert())?;
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
    let all_issuers: Vec<Vec<u8>> = issuer_map
        .iter()
        .filter(|(subject, issuer)| subject != issuer) // ignore the self-signed self-reference
        .map(|(_, issuer)| issuer.clone())
        .collect();
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

fn select_hash(hash_type: &Option<HashAlg>) -> MessageDigest {
    match hash_type {
        Some(HashAlg::SHA1) => MessageDigest::sha1(),
        Some(HashAlg::SHA384) => MessageDigest::sha384(),
        Some(HashAlg::SHA512) => MessageDigest::sha512(),
        _ => MessageDigest::sha256(),
    }
}

fn verify_cert_path(
    signer: &Certificate,
    chain: &[&X509],
) -> Result<Option<u32>, Box<dyn std::error::Error>> {
    let mut owned: Vec<X509> = chain.iter().map(|c| (*c).clone()).collect();
    owned.push(signer.x509.clone());
    let ordered = create_cert_chain_from_cert_list(owned)?;
    let root = ordered.first().unwrap();
    let pubkey = root.public_key()?;
    if !root.verify(&pubkey)? {
        let err = format!(
            "Could not find self signed root, found last ancestor {:?}",
            root.subject_name()
        );
        return Err(err.into());
    }
    let signer = ordered.last().unwrap();
    let intermediates: Vec<&X509> = ordered
        .get(1..ordered.len().saturating_sub(1)) // 1..0 → None for len==1
        .unwrap_or(&[])
        .iter()
        .collect();
    match verify_cert(signer, root, intermediates) {
        Ok(true) => {
            let mut budget: Option<i64> = None;
            for (d, ancestor) in ordered.iter().rev().enumerate() {
                if let Some(p) = ancestor.pathlen() {
                    // ancestor's declared pathLen
                    let candidate = p as i64 - d as i64; // can be negative — that's fine
                    budget = Some(budget.map_or(candidate, |b| b.min(candidate)));
                }
            }
            match budget {
                Some(b) if b < 1 => {
                    Err("signer's path length budget is exhausted; cannot issue a CA".into())
                }
                Some(b) => Ok(Some(b as u32)), // b >= 1 here, cast is safe
                None => Ok(None),              // no pathLen anywhere → unlimited
            }
        }
        _ => {
            let err = format!(
                "Cannot verify the crtificate chain for {:?}",
                signer.subject_name()
            );
            Err(err.into())
        }
    }
}

fn can_sign_cert(cert: &Certificate) -> Result<bool, Box<dyn std::error::Error>> {
    if cert.pkey.is_none() {
        return Ok(false);
    }

    let der = cert.x509.to_der()?;
    let (_, parsed_cert) = parse_x509_certificate(&der)?;

    let mut is_ca = false;
    let mut can_sign = false;
    let now = Asn1Time::days_from_now(0)?;
    let valid_time = cert.x509.not_before().compare(&now)? != std::cmp::Ordering::Greater
        && cert.x509.not_after().compare(&now)? == std::cmp::Ordering::Greater;

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
    Ok(is_ca && can_sign && valid_time)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Write;
    use std::path::Path;
    use tempfile::NamedTempFile;

    #[test]
    fn create_ca_with_path_len_set() {
        let ca = CertBuilder::new()
            .common_name("My Test Ca")
            .is_ca(true)
            .pathlen(0)
            .build_and_self_sign()
            .unwrap();
        assert_eq!(ca.x509.pathlen(), Some(0));
    }

    #[test]
    fn create_ca_with_no_path_len_set() {
        let ca = CertBuilder::new()
            .common_name("My Test Ca")
            .is_ca(true)
            .build_and_self_sign()
            .unwrap();
        assert_eq!(ca.x509.pathlen(), None);
    }

    #[test]
    fn incomplete_chain_without_root_is_rejected() {
        let ca = CertBuilder::new()
            .common_name("Root")
            .is_ca(true)
            .pathlen(2)
            .build_and_self_sign()
            .unwrap();
        let inter = CertBuilder::new()
            .common_name("Inter")
            .is_ca(true)
            .pathlen(1)
            .build_and_sign_with_chain(&ca, &[])
            .unwrap();

        // sign with `inter` but forget to pass its chain → top of chain is `inter`,
        // which is not self-signed → reject
        let err = CertBuilder::new()
            .common_name("Sub")
            .is_ca(true)
            .pathlen(0)
            .build_and_sign_with_chain(&inter, &[])
            .err()
            .expect("incomplete chain (missing root) must be rejected");
        assert!(
            err.to_string().contains("Could not find self signed root"),
            "got: {err}"
        );
    }

    #[test]
    fn unlimited_root_can_issue_ca() {
        let root = CertBuilder::new()
            .common_name("Unlimited Root")
            .is_ca(true) // note: no .pathlen() → None / unlimited
            .build_and_self_sign()
            .unwrap();
        assert_eq!(root.x509.pathlen(), None);

        // budget is None → no ceiling; even a large declared pathLen is fine
        let inter = CertBuilder::new()
            .common_name("Inter")
            .is_ca(true)
            .pathlen(5)
            .build_and_sign_with_chain(&root, &[])
            .unwrap();
        assert_eq!(inter.x509.pathlen(), Some(5));
    }

    #[test]
    fn create_cert_chain_and_verify() {
        let ca = CertBuilder::new()
            .common_name("My Test Ca")
            .is_ca(true)
            .pathlen(1)
            .build_and_self_sign()
            .unwrap();
        let chain: Vec<&X509> = Vec::new();
        let inter_ca = CertBuilder::new()
            .common_name("My Test inter Ca")
            .is_ca(true)
            .pathlen(0)
            .build_and_sign_with_chain(&ca, chain.as_slice())
            .unwrap();
        let leaf = CertBuilder::new()
            .common_name("My Test leaf")
            .build_and_sign(&inter_ca)
            .unwrap();
        assert_eq!(ca.x509.pathlen(), Some(1));
        assert_eq!(leaf.x509.pathlen(), None);
        assert!(verify_cert(&leaf.x509, &ca.x509, vec![&inter_ca.x509]).unwrap());
    }

    #[test]
    fn create_ca_cert_chain_and_verify() {
        let ca = CertBuilder::new()
            .common_name("My Test Ca")
            .is_ca(true)
            .pathlen(2)
            .build_and_self_sign()
            .unwrap();
        let chain: Vec<&X509> = Vec::new();
        let inter_ca = CertBuilder::new()
            .common_name("My Test inter Ca")
            .is_ca(true)
            .pathlen(1)
            .build_and_sign_with_chain(&ca, chain.as_slice())
            .unwrap();
        let leaf = CertBuilder::new()
            .common_name("leaf ca")
            .is_ca(true)
            .pathlen(0)
            .build_and_sign_with_chain(&inter_ca, &[&ca.x509])
            .unwrap();

        assert_eq!(leaf.x509.pathlen(), Some(0));
    }

    #[test]
    fn can_not_create_ca_cert_chain_with_wrong_intermediate_ca_path() {
        let ca = CertBuilder::new()
            .common_name("My Test Ca")
            .is_ca(true)
            .pathlen(2)
            .build_and_self_sign()
            .unwrap();
        let chain: Vec<&X509> = Vec::new();
        let inter_ca = CertBuilder::new()
            .common_name("My Test inter Ca")
            .is_ca(true)
            .pathlen(0)
            .build_and_sign_with_chain(&ca, chain.as_slice())
            .unwrap();
        let err = CertBuilder::new()
            .common_name("leaf ca")
            .is_ca(true)
            .pathlen(0)
            .build_and_sign_with_chain(&inter_ca, &[&ca.x509])
            .err()
            .expect("");

        assert!(
            err.to_string()
                .contains("signer's path length budget is exhausted; cannot issue a CA"),
            "signer's path length budget is exhausted; cannot issue a CA got: {err}"
        );
    }

    #[test]
    fn root_ca_have_one_path_length_and_can_not_sign_ca() {
        let ca = CertBuilder::new()
            .common_name("My Test Ca")
            .is_ca(true)
            .pathlen(1)
            .build_and_self_sign()
            .unwrap();

        let chain: Vec<&X509> = Vec::new();

        // A user mistake: an intermediate claiming pathlen(1) under a root that only
        // permits one CA below it. Must be rejected at issuance.
        let err = CertBuilder::new()
            .common_name("My Test inter Ca")
            .is_ca(true)
            .pathlen(1)
            .build_and_sign_with_chain(&ca, chain.as_slice())
            .err()
            .expect("inter CA with pathlen(1) under root pathlen(1) must be rejected");

        assert!(
            err.to_string()
                .contains("requested pathLen exceeds what the signer's chain permits"),
            "expected a pathLen-exceeds error, got: {err}"
        );
    }

    #[test]
    fn build_and_sign_without_signer_private_key_errors_not_panics() {
        let ca = CertBuilder::new()
            .common_name("My Test Ca")
            .is_ca(true)
            .build_and_self_sign()
            .unwrap();
        let keyless_ca = Certificate {
            x509: ca.x509.clone(),
            pkey: None,
        };

        let err = CertBuilder::new()
            .common_name("leaf")
            .build_and_sign(&keyless_ca)
            .err()
            .expect("signing with a key-less CA must return an error, not panic");
        assert!(
            err.to_string().contains("private key"),
            "expected a missing-private-key error, got: {err}"
        );
    }

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
}
