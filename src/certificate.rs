mod builder;
mod common;
mod csr;
mod key;
mod policy;
mod usage;
use builder::select_hash;
pub use builder::{BuilderCommon, BuilderFields, HashAlg, UseesBuilderFields};
use common::create_asn1_time_from_date;
pub use common::{X509Common, X509Parts};
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

use std::marker::PhantomData;
use std::path::Path;
pub use usage::Usage;
use usage::get_key_usage;
#[cfg(feature = "pqc")]
use usage::validate_pqc_key_usage;
use x509_parser::extensions::ParsedExtension;
use x509_parser::parse_x509_certificate;

pub struct PathLenUnset;
pub struct PathLenSet;

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
        chain: &[&Certificate],
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
        let chain_x509: Vec<&X509> = chain.iter().map(|c| &c.x509).collect();
        enforce_path_len(self.ca, self.path_len, signer, &chain_x509)?;

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

fn enforce_path_len(
    is_ca: bool,
    path_len: Option<u32>,
    signer: &Certificate,
    chain: &[&X509],
) -> Result<(), Box<dyn std::error::Error>> {
    // No pathLen set (or non-CA) → nothing to enforce, no chain required.
    // Matches CertBuilder: a no-pathLen / unlimited CA isn't budget-checked.
    if !is_ca || path_len.is_none() {
        return Ok(());
    }
    let budget = verify_cert_path(signer, chain)?;
    if let (Some(b), Some(m)) = (budget, path_len)
        && m >= b
    {
        return Err("requested pathLen exceeds what the signer's chain permits".into());
    }
    Ok(())
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
        let chain: Vec<&Certificate> = Vec::new();
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
        let chain: Vec<&Certificate> = Vec::new();
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
            .build_and_sign_with_chain(&inter_ca, &[&ca])
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
        let chain: Vec<&Certificate> = Vec::new();
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
            .build_and_sign_with_chain(&inter_ca, &[&ca])
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

        let chain: Vec<&Certificate> = Vec::new();

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
