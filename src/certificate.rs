use chrono::{NaiveDate, NaiveDateTime, TimeZone, Utc};
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::stack::Stack;
use openssl::x509::extension::{
    BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
};
use openssl::x509::{
    X509, X509Builder, X509NameBuilder, X509StoreContext, store::X509StoreBuilder,
};
use std::collections::{HashMap, HashSet};
use std::fs::{File, create_dir_all};
use std::io::Write;
use std::path::Path;

use x509_parser::extensions::ParsedExtension;
use x509_parser::parse_x509_certificate;

macro_rules! vec_str_to_hs {
    ($vec:expr) => {
        $vec.iter()
            .map(|s| s.to_string())
            .collect::<HashSet<String>>()
    };
}
/// Defines what type of key that can be used with the certificate
pub enum KeyType {
    RSA2048,
    RSA4096,
    P224,
    P256,
    P384,
    P521,
}
/// Defines which hash algorithm to be used in certificate signing
pub enum HashAlg {
    SHA1,
    SHA256,
    SHA384,
    SHA512,
}
/// Which key usage and extended key usage values
/// are applicable when creating a certificate
#[allow(non_camel_case_types)]
#[derive(Hash, Eq, PartialEq, Debug, Clone)]
pub enum Usage {
    certsign,
    crlsign,
    encipherment,
    clientauth,
    serverauth,
    signature,
    contentcommitment,
}
/// Holds the generated certificate and private key
pub struct Certificate {
    pub x509: X509,
    pub pkey: PKey<Private>,
}

impl Certificate {
    /// Will save the certificate and private key to pem file
    /// if path = /path/foo/bar and filename = mytest
    /// the certificate will be saved as: /path/foo/bar/mytest_cert.pem
    /// the private key will be saved as: /path/foo/bar/mytest_pkey.pem
    /// If the path do not exist it will be created
    pub fn save<P: AsRef<Path>, F: AsRef<Path>>(
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

        write_file("_pkey.pem", &self.pkey.private_key_to_pem_pkcs8()?)?;
        write_file("_cert.pem", &self.x509.to_pem()?)?;

        Ok(())
    }

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
        Ok(Self { x509: cert, pkey })
    }
}
/// Builder for creating a new certificate and private key
pub struct CertBuilder {
    common_name: String,
    signer: Option<String>, //place holder for maybe future use??
    alternative_names: HashSet<String>,
    country_name: String,
    state_province: String,
    organization: String,
    locality_time: String,
    key_type: Option<KeyType>,
    signature_alg: Option<HashAlg>,
    ca: bool,
    valid_from: Asn1Time,
    valid_to: Asn1Time,
    usage: Option<HashSet<Usage>>,
}

impl Default for CertBuilder {
    /// Returns default values for all fields, except valid_from,
    /// which is set to the current time, and valid_to, which is
    /// set to one year from now.
    fn default() -> Self {
        Self {
            common_name: Default::default(),
            signer: Default::default(),
            alternative_names: Default::default(),
            country_name: Default::default(),
            state_province: Default::default(),
            organization: Default::default(),
            locality_time: Default::default(),
            key_type: Default::default(),
            signature_alg: Default::default(),
            ca: false,
            valid_from: Asn1Time::days_from_now(0).unwrap(), // today
            valid_to: Asn1Time::days_from_now(365).unwrap(), // one year from now
            usage: Default::default(),
        }
    }
}
impl CertBuilder {
    /// Create a new CertBuilder with defaults and one year from now as valid date
    pub fn new() -> Self {
        Self::default()
    }
    /// Sets the common name, CN. This value will also be added to alternaitve_names
    pub fn common_name(mut self, common_name: &str) -> Self {
        self.common_name = common_name.into();
        self.alternative_names.insert(String::from(common_name));
        self
    }
    pub fn signer(mut self, signer: &str) -> Self {
        self.signer = Some(signer.into());
        self
    }
    /// A list of altrnative names(SAN) the Common Name(CN) is always included
    pub fn alternative_names(mut self, alternative_names: Vec<&str>) -> Self {
        self.alternative_names
            .extend(vec_str_to_hs!(alternative_names));
        self
    }
    /// Country, a valid two char value
    pub fn country_name(mut self, country_name: &str) -> Self {
        self.country_name = country_name.into();
        self
    }
    /// State, province an utf-8 value
    pub fn state_province(mut self, state_province: &str) -> Self {
        self.state_province = state_province.into();
        self
    }
    /// Org. an utf-8 value
    pub fn organization(mut self, organization: &str) -> Self {
        self.organization = organization.into();
        self
    }
    /// Locality, represents the city, town, or locality of the certificate subject
    pub fn locality_time(mut self, locality_time: &str) -> Self {
        self.locality_time = locality_time.into();
        self
    }
    /// Selects what type of key to use RSA or elliptic
    pub fn key_type(mut self, key_type: KeyType) -> Self {
        self.key_type = Some(key_type);
        self
    }
    /// Selects what alg to use for signature
    pub fn signature_alg(mut self, signature_alg: HashAlg) -> Self {
        self.signature_alg = Some(signature_alg);
        self
    }
    /// if this certificate be a Certificate Authority (CN)
    pub fn is_ca(mut self, ca: bool) -> Self {
        self.ca = ca;
        self
    }
    /// start date that the certificate should be valid yyyy-mm-dd
    pub fn valid_from(mut self, valid_from: &str) -> Self {
        self.valid_from =
            create_asn1_time_from_date(valid_from).expect("Failed to parse valid_from date");
        self
    }
    /// end date that the certificate should no longer be valid yyyy-mm-dd
    pub fn valid_to(mut self, valid_to: &str) -> Self {
        self.valid_to =
            create_asn1_time_from_date(valid_to).expect("Failed to parse valid_to date");
        self
    }
    /// Set what the certificate are allowed to do, KeyUsage and ExtendeKeyUsage
    pub fn key_usage(mut self, key_usage: HashSet<Usage>) -> Self {
        self.usage = Some(key_usage);
        self
    }
    /// create a self signed x509 certificate and private key
    pub fn build_and_self_sign(&self) -> Result<Certificate, Box<dyn std::error::Error>> {
        let (mut builder, pkey) = self.prepare_x509_builder(None)?;
        builder.sign(&pkey, select_hash(&self.signature_alg))?;
        let ca_cert = builder.build();

        Ok(Certificate {
            x509: ca_cert,
            pkey: pkey,
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
        builder.sign(&signer.pkey, select_hash(&self.signature_alg))?;
        let cert = builder.build();
        Ok(Certificate { x509: cert, pkey })
    }

    fn prepare_x509_builder(
        &self,
        signer: Option<&Certificate>,
    ) -> Result<(X509Builder, PKey<Private>), Box<dyn std::error::Error>> {
        let mut name_builder = X509NameBuilder::new()?;
        name_builder.append_entry_by_nid(Nid::COMMONNAME, &self.common_name)?;
        if !self.country_name.trim().is_empty() {
            name_builder.append_entry_by_nid(Nid::COUNTRYNAME, &self.country_name)?;
        }
        if !self.state_province.trim().is_empty() {
            name_builder.append_entry_by_nid(Nid::STATEORPROVINCENAME, &self.state_province)?;
        }
        if !self.locality_time.trim().is_empty() {
            name_builder.append_entry_by_nid(Nid::LOCALITYNAME, &self.locality_time)?;
        }
        if !self.organization.trim().is_empty() {
            name_builder.append_entry_by_nid(Nid::ORGANIZATIONNAME, &self.organization)?;
        }
        let name = name_builder.build();

        let mut builder = X509::builder()?;
        builder.set_version(2)?;

        let serial_number = {
            let mut serial = BigNum::new()?;
            serial.rand(159, openssl::bn::MsbOption::MAYBE_ZERO, false)?;
            serial.to_asn1_integer()?
        };

        let pkey = select_key(&self.key_type).unwrap();
        builder.set_serial_number(&serial_number)?;
        builder.set_subject_name(&name)?;
        builder.set_pubkey(&pkey)?;
        builder.set_not_before(&self.valid_from)?;
        builder.set_not_after(&self.valid_to)?;
        match signer {
            Some(signer) => builder.set_issuer_name(signer.x509.subject_name())?,
            None => builder.set_issuer_name(&name)?,
        }

        let mut key_usage = self.usage.clone().unwrap_or_default();
        if self.ca {
            key_usage.insert(Usage::certsign);
            key_usage.insert(Usage::crlsign);
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
        for s in &self.alternative_names {
            san.dns(s);
        }
        if let Some(signer_cert) = signer {
            builder.append_extension(
                san.build(&builder.x509v3_context(Some(&signer_cert.x509), None))?,
            )?;
        } else {
            builder.append_extension(san.build(&builder.x509v3_context(None, None))?)?;
        }
        Ok((builder, pkey))
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
