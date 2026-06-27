use openssl::asn1::{Asn1Object, Asn1OctetString};
use openssl::x509::{X509Builder, X509Extension};
use yasna::models::ObjectIdentifier;
/// A certificate policy OID found in the `certificatePolicies` extension.
///
/// The named variants are the CA/Browser Forum reserved policy identifiers
/// (arc `2.23.140.1`) that signal the validation level a publicly-trusted CA
/// performed before issuance, plus the special `anyPolicy` OID from RFC 5280.
/// Anything outside that set is preserved verbatim in [`CertificatePolicy::Other`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificatePolicy {
    DomainValidated,       // 2.23.140.1.2.1
    OrganizationValidated, // 2.23.140.1.2.2
    IndividualValidated,   // 2.23.140.1.2.3
    ExtendedValidation,    // 2.23.140.1.1
    AnyPolicy,             // 2.5.29.32.0
    Other(String),         // private / arbitrary / test OID
}

impl CertificatePolicy {
    /// Returns the policy's OID in dotted-decimal notation.
    ///
    /// For named variants this is a fixed `&'static str`; for
    /// [`CertificatePolicy::Other`] it borrows the stored OID string.
    pub fn oid(&self) -> &str {
        match self {
            Self::DomainValidated => "2.23.140.1.2.1",
            Self::OrganizationValidated => "2.23.140.1.2.2",
            Self::IndividualValidated => "2.23.140.1.2.3",
            Self::ExtendedValidation => "2.23.140.1.1",
            Self::AnyPolicy => "2.5.29.32.0",
            Self::Other(oid) => oid,
        }
    }
}
/// Parse a dotted OID string into a yasna ObjectIdentifier.
fn parse_oid(dotted: &str) -> Result<ObjectIdentifier, Box<dyn std::error::Error>> {
    let components = dotted
        .split('.')
        .map(|c| c.parse::<u64>())
        .collect::<Result<Vec<u64>, _>>()
        .map_err(|_| format!("invalid policy OID: {dotted}"))?;
    Ok(ObjectIdentifier::new(components))
}

pub(crate) fn append_certificate_policies(
    builder: &mut X509Builder,
    policies: &[CertificatePolicy],
) -> Result<(), Box<dyn std::error::Error>> {
    if policies.is_empty() {
        return Ok(());
    }
    let oids = policies
        .iter()
        .map(|p| parse_oid(p.oid()))
        .collect::<Result<Vec<_>, _>>()?;
    let der = yasna::construct_der(|w| {
        w.write_sequence(|seq| {
            for oid in &oids {
                seq.next().write_sequence(|pi| pi.next().write_oid(oid));
            }
        });
    });
    let oid = Asn1Object::from_str("2.5.29.32")?;
    let value = Asn1OctetString::new_from_bytes(&der)?;
    builder.append_extension(X509Extension::new_from_der(oid.as_ref(), false, &value)?)?;
    Ok(())
}
