use super::key::KeyType;
use super::usage::Usage;
use openssl::hash::MessageDigest;
use std::collections::HashSet;

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
    pub(crate) common_name: String,
    pub(crate) signer: Option<String>, //place holder for maybe future use??
    pub(crate) alternative_names: HashSet<String>,
    pub(crate) organization_unit: String,
    pub(crate) country_name: String,
    pub(crate) state_province: String,
    pub(crate) organization: String,
    pub(crate) locality_time: String,
    pub(crate) key_type: Option<KeyType>,
    pub(crate) signature_alg: Option<HashAlg>,
    pub(crate) usage: Option<HashSet<Usage>>,
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

pub(crate) fn select_hash(hash_type: &Option<HashAlg>) -> MessageDigest {
    match hash_type {
        Some(HashAlg::SHA1) => MessageDigest::sha1(),
        Some(HashAlg::SHA384) => MessageDigest::sha384(),
        Some(HashAlg::SHA512) => MessageDigest::sha512(),
        _ => MessageDigest::sha256(),
    }
}
