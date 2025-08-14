use crate::certificate::Certificate;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use num_bigint::BigUint;
use openssl::asn1::Asn1IntegerRef;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::Id;
use openssl::pkey::{PKey, Public};
use openssl::x509::{X509, X509Crl};
use std::fs::{File, create_dir_all};
use std::io::Write;
use std::path::Path;
use yasna::models::ObjectIdentifier;
use yasna::tags;
use yasna::tags::{TAG_BITSTRING, TAG_GENERALIZEDTIME, TAG_UTCTIME};
use yasna::{ASN1Error, ASN1ErrorKind, Tag};

/// Represents the reason why a certificate was revoked, as defined in RFC 5280.
#[derive(Debug, PartialEq)]
pub enum CrlReason {
    /// The reason for revocation is unspecified.
    Unspecified,
    /// The certificate's private key is suspected to be compromised.
    KeyCompromise,
    /// The certificate authority (CA) that issued the certificate is suspected to be compromised.
    CaCompromise,
    /// The subject's affiliation has changed (e.g., job change, department change).
    AffiliationChanged,
    /// The certificate has been superseded by a new one.
    Superseded,
    /// The certificate is no longer needed due to cessation of operation.
    CessationOfOperation,
    /// The certificate is temporarily on hold and may be reinstated later.
    CertificateHold,
    /// The certificate was previously on hold but is now removed from the CRL.
    RemoveFromCrl,
    /// The privileges granted to the certificate holder have been withdrawn.
    PrivilegeWithdrawn,
    /// The attribute authority associated with the certificate is suspected to be compromised.
    AaCompromise,
}

impl CrlReason {
    /// Returns the DER-encoded value for the reason
    pub fn value(&self) -> Vec<u8> {
        match self {
            CrlReason::Unspecified => vec![0x0A, 0x01, 0x00],
            CrlReason::KeyCompromise => vec![0x0A, 0x01, 0x01],
            CrlReason::CaCompromise => vec![0x0A, 0x01, 0x02],
            CrlReason::AffiliationChanged => vec![0x0A, 0x01, 0x03],
            CrlReason::Superseded => vec![0x0A, 0x01, 0x04],
            CrlReason::CessationOfOperation => vec![0x0A, 0x01, 0x05],
            CrlReason::CertificateHold => vec![0x0A, 0x01, 0x06],
            CrlReason::RemoveFromCrl => vec![0x0A, 0x01, 0x08],
            CrlReason::PrivilegeWithdrawn => vec![0x0A, 0x01, 0x09],
            CrlReason::AaCompromise => vec![0x0A, 0x01, 0x0A],
        }
    }

    /// Returns the full OID for the reason (e.g., 2.5.29.21)
    pub fn oid(&self) -> ObjectIdentifier {
        ObjectIdentifier::from_slice(&[2, 5, 29, 21])
    }

    /// Return `CrlReason` for the corresponding value
    pub fn from_oid_and_value(oid: &ObjectIdentifier, value: &[u8]) -> Option<Self> {
        // Check that the OID is 2.5.29.21
        if oid.components().as_slice() != [2, 5, 29, 21] {
            return None;
        }

        // Match the DER-encoded ENUMERATED value
        match value {
            [0x0A, 0x01, 0x00] => Some(CrlReason::Unspecified),
            [0x0A, 0x01, 0x01] => Some(CrlReason::KeyCompromise),
            [0x0A, 0x01, 0x02] => Some(CrlReason::CaCompromise),
            [0x0A, 0x01, 0x03] => Some(CrlReason::AffiliationChanged),
            [0x0A, 0x01, 0x04] => Some(CrlReason::Superseded),
            [0x0A, 0x01, 0x05] => Some(CrlReason::CessationOfOperation),
            [0x0A, 0x01, 0x06] => Some(CrlReason::CertificateHold),
            [0x0A, 0x01, 0x08] => Some(CrlReason::RemoveFromCrl),
            [0x0A, 0x01, 0x09] => Some(CrlReason::PrivilegeWithdrawn),
            [0x0A, 0x01, 0x0A] => Some(CrlReason::AaCompromise),
            _ => None,
        }
    }
}

pub struct X509CrlWrapper {
    crl: X509Crl,
}

impl X509CrlWrapper {
    pub fn from_der(crl_der: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        match X509Crl::from_der(crl_der) {
            Ok(data) => Ok(Self { crl: data }),
            Err(e) => Err(e.into()),
        }
    }
    pub fn verify_signature(
        &self,
        public_key: &PKey<Public>,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        match self.crl.verify(public_key) {
            Ok(result) => Ok(result),
            Err(e) => Err(e.into()),
        }
    }
    pub fn to_der(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        match self.crl.to_der() {
            Ok(data) => Ok(data),
            Err(e) => Err(e.into()),
        }
    }
    pub fn revoked(&self, serial: &Asn1IntegerRef) -> bool {
        if let Some(revoked) = self.crl.get_revoked() {
            revoked.into_iter().any(|r| r.serial_number() == serial)
        } else {
            false
        }
    }
    pub fn save_as_pem<P: AsRef<Path>, F: AsRef<Path>>(
        &self,
        path: P,
        filename: F,
    ) -> Result<(), Box<dyn std::error::Error>> {
        create_dir_all(&path)?;
        let os_file = filename
            .as_ref()
            .file_name()
            .ok_or("Failed to extract file name")?;
        let full_path = path.as_ref().join(os_file);
        let mut file = File::create(full_path)?;

        let pem_data = self.crl.to_pem()?;
        file.write_all(&pem_data)?;

        Ok(())
    }
    pub fn read_as_pem<F: AsRef<Path>>(
        crl_pem_file: F,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let crl_pem = std::fs::read(crl_pem_file)?;
        match X509Crl::from_pem(crl_pem.as_slice()) {
            Ok(crl) => Ok(Self { crl }),
            Err(e) => Err(e.into()),
        }
    }
}

/// Represents a builder for creating and signing X.509 Certificate Revocation Lists (CRLs).
///
/// The `X509CrlBuilder` allows you to construct a CRL by specifying a signer certificate,
/// adding revoked certificates, setting update times, and finally building and signing the CRL.
pub struct X509CrlBuilder {
    /// The certificate used to sign the CRL.
    signer: Certificate,
    /// A list of revoked certificates to include in the CRL.
    revoked: Vec<RevokedCert>,
    /// The timestamp indicating when the CRL was generated.
    this_update: DateTime<Utc>,
    /// The timestamp indicating when the next CRL will be issued.
    next_update: Option<DateTime<Utc>>,
}

/// Represents a single revoked certificate entry in a CRL.
#[derive(Debug)]
pub struct RevokedCert {
    /// The serial number of the revoked certificate.
    serial: BigUint,
    /// The date and time when the certificate was revoked.
    revocation_date: DateTime<Utc>,
    // CRL reason
    reasons: Vec<CrlReason>,
}

impl RevokedCert {
    /// Returns the serial number of the revoked certificate.
    pub fn serial(&self) -> &BigUint {
        &self.serial
    }

    /// Returns the date and time when the certificate was revoked.
    pub fn revocation_date(&self) -> &DateTime<Utc> {
        &self.revocation_date
    }

    /// Returns the list of revocation reasons associated with the certificate.
    pub fn reasons(&self) -> &[CrlReason] {
        &self.reasons
    }
}

impl X509CrlBuilder {
    /// Creates a new `X509CrlBuilder` with the given signer certificate.
    ///
    /// The `this_update` is set to the current time, and `next_update` is set to 30 days later.
    ///
    /// # Arguments
    ///
    /// * `signer` - The certificate that will be used to sign the CRL.
    pub fn new(signer: Certificate) -> Self {
        Self {
            signer,
            revoked: Vec::new(),
            this_update: Utc::now(),
            next_update: Some(Utc::now() + chrono::Duration::days(30)),
        }
    }

    /// Returns a read-only slice of the revoked certificates included in the CRL.
    ///
    /// This method provides access to the list of `RevokedCert` entries that have been
    /// added to the CRL builder. Each entry contains the serial number, revocation date,
    /// and associated revocation reasons for a certificate that has been revoked.
    ///
    pub fn revoked(&self) -> &[RevokedCert] {
        &self.revoked
    }

    /// Adds a revoked certificate to the CRL.
    ///
    /// # Arguments
    ///
    /// * `serial` - The serial number of the revoked certificate.
    /// * `revocation_date` - The date and time when the certificate was revoked.
    pub fn add_revoked_cert(&mut self, serial: BigUint, revocation_date: DateTime<Utc>) {
        self.revoked.push(RevokedCert {
            serial,
            revocation_date,
            reasons: Vec::new(),
        });
    }
    /// Adds a revoked certificate to the CRL.
    ///
    /// # Arguments
    ///
    /// * `serial` - The serial number of the revoked certificate.
    /// * `revocation_date` - The date and time when the certificate was revoked.
    /// * `crl_reasons` - A list of reasons explaining why the certificate was revoked.
    pub fn add_revoked_cert_with_reason(
        &mut self,
        serial: BigUint,
        revocation_date: DateTime<Utc>,
        crl_reasons: Vec<CrlReason>,
    ) {
        self.revoked.push(RevokedCert {
            serial,
            revocation_date,
            reasons: crl_reasons,
        });
    }
    /// Sets the `this_update` and `next_update` timestamps for the CRL.
    ///
    /// # Arguments
    ///
    /// * `this_update` - The time when the CRL is issued.
    /// * `next_update` - The time when the next CRL is expected to be issued.
    pub fn set_update_times(&mut self, this_update: DateTime<Utc>, next_update: DateTime<Utc>) {
        self.this_update = this_update;
        self.next_update = Some(next_update);
    }
    /// Builds and signs the CRL, returning the DER-encoded byte vector.
    ///
    /// This method constructs the CRL in ASN.1 DER format, signs it using the signer's private key,
    /// and returns the final encoded CRL.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing the DER-encoded CRL.
    pub fn build_and_sign(&self) -> Vec<u8> {
        let tbs = yasna::construct_der(|writer| {
            writer.write_sequence(|writer| {
                writer.next().write_u8(1); // Version v2

                // Signature Algorithm
                let sig_alg = self.signer.x509.signature_algorithm().object().to_string();
                let sig_oid = signature_algorithm_oid(&sig_alg).unwrap();
                writer.next().write_sequence(|writer| {
                    writer
                        .next()
                        .write_oid(&ObjectIdentifier::from_slice(&sig_oid));
                    writer.next().write_null();
                });

                // Issuer
                writer.next().write_sequence(|writer| {
                    writer.next().write_set(|writer| {
                        writer.next().write_sequence(|writer| {
                            writer
                                .next()
                                .write_oid(&ObjectIdentifier::from_slice(&[2, 5, 4, 3])); // CN
                            writer.next().write_utf8_string(
                                &get_clean_subject_name(&self.signer.x509).unwrap(),
                            );
                        });
                    });
                });

                // thisUpdate and nextUpdate
                write_generalized_time(writer.next(), &self.this_update);

                if let Some(ref next_update) = self.next_update {
                    write_generalized_time(writer.next(), next_update);
                }

                // Revoked Certificates
                writer.next().write_sequence_of(|writer| {
                    for revoked in &self.revoked {
                        writer.next().write_sequence(|writer| {
                            writer
                                .next()
                                .write_bigint_bytes(&revoked.serial.to_bytes_be(), true);
                            write_generalized_time(writer.next(), &revoked.revocation_date);

                            if revoked.reasons.len() > 0 {
                                writer.next().write_sequence_of(|writer| {
                                    for reason in &revoked.reasons {
                                        writer.next().write_sequence(|writer| {
                                            writer.next().write_oid(&reason.oid());
                                            writer.next().write_bytes(&reason.value());
                                        });
                                    }
                                });
                            }
                        });
                    }
                });
                if self.signer.x509.subject_key_id().is_some() {
                    let key_id = self.signer.x509.subject_key_id().unwrap();
                    let aki_oid = ObjectIdentifier::from_slice(&[2, 5, 29, 35]); // AKI

                    let aki_value_der = yasna::construct_der(|writer| {
                        writer.write_sequence(|writer| {
                            writer
                                .next()
                                .write_tagged_implicit(Tag::context(0), |writer| {
                                    writer.write_bytes(key_id.as_slice());
                                });
                        });
                    });

                    let extension_der = yasna::construct_der(|writer| {
                        writer.write_sequence(|writer| {
                            writer.next().write_oid(&aki_oid);
                            writer.next().write_bytes(&aki_value_der);
                        });
                    });

                    writer.next().write_tagged(Tag::context(0), |writer| {
                        writer.write_sequence_of(|writer| {
                            writer.next().write_der(&extension_der);
                        });
                    });
                }
            });
        });

        // Sign the TBS (To Be Signed)
        let signature: Vec<u8>;
        if self.signer.pkey.clone().unwrap().id() == Id::ED25519 {
            let mut signer =
                openssl::sign::Signer::new_without_digest(self.signer.pkey.as_ref().unwrap())
                    .unwrap();
            signature = signer.sign_oneshot_to_vec(&tbs).unwrap();
        } else {
            let mut signer = openssl::sign::Signer::new(
                MessageDigest::sha256(),
                self.signer.pkey.as_ref().unwrap(),
            )
            .unwrap();
            signer.update(&tbs).unwrap();
            signature = signer.sign_to_vec().unwrap();
        }

        // Final CRL
        yasna::construct_der(|writer| {
            writer.write_sequence(|writer| {
                writer.next().write_der(&tbs);

                // Signature Algorithm
                let sig_alg = self.signer.x509.signature_algorithm().object().to_string();
                let sig_oid = signature_algorithm_oid(&sig_alg).unwrap();
                writer.next().write_sequence(|writer| {
                    writer
                        .next()
                        .write_oid(&ObjectIdentifier::from_slice(&sig_oid));
                    writer.next().write_null();
                });

                // Signature Value
                writer
                    .next()
                    .write_tagged_implicit(TAG_BITSTRING, |writer| {
                        // First byte is the number of unused bits (0 in this case)
                        let mut bit_string = vec![0u8];
                        bit_string.extend_from_slice(&signature);
                        writer.write_bytes(&bit_string);
                    });
            });
        })
    }
    /// Parses a DER-encoded CRL and constructs an `X509CrlBuilder` from it.
    ///
    /// This method extracts the TBS (To Be Signed) portion, signature algorithm, and signature value,
    /// then parses the CRL fields including issuer, update times, and revoked certificates.
    ///
    /// # Arguments
    ///
    /// * `der` - A byte slice containing the DER-encoded CRL.
    /// * `signer` - The certificate that will be used to sign the CRL.
    ///
    /// # Returns
    ///
    /// A `Result` containing the reconstructed `X509CrlBuilder` or an error if parsing fails.
    pub fn from_der(der: &[u8], signer: Certificate) -> Result<Self, Box<dyn std::error::Error>> {
        let (tbs_der, _sig_algo_oid, _sig_value) = yasna::parse_der(der, |reader| {
            reader.read_sequence(|reader| {
                let tbs_der = reader.next().read_der()?;

                // Signature Algorithm
                let _sig_algo_oid = reader.next().read_sequence(|reader| {
                    let oid = reader.next().read_oid()?;
                    let _ = reader.next().read_null()?;
                    Ok(oid)
                })?;

                // Signature Value
                let _sig_value = reader.next().read_bitvec_bytes()?;

                Ok((tbs_der, _sig_algo_oid, _sig_value))
            })
        })
        .map_err(|e| format!("ASN.1 parse error: {}", e))?;

        let (_issuer_name, this_update, next_update, revoked) =
            yasna::parse_der(&tbs_der, |reader| {
                reader.read_sequence(|reader| {
                    let _version = reader.read_optional(|reader| reader.read_u8());

                    let _ = reader.next().read_sequence(|reader| {
                        let _ = reader.next().read_oid()?;
                        let _ = reader.next().read_null()?;
                        Ok(())
                    })?;

                    //       let issuer_name = reader.next().read_sequence(|reader| {
                    //           reader.next().read_set(|set_reader| {
                    //               set_reader.next(&[TAG_SEQUENCE])?.read_sequence(|reader| {
                    //                   let _ = reader.next().read_oid()?;
                    //                   reader.next().read_utf8string()
                    //               })
                    //           })
                    //       })?;
                    // skip all issuer data
                    let _issuer = reader.next().read_der()?;

                    let this_update = read_time(reader.next());

                    let next_update = reader.read_optional(|reader| {
                        read_time(reader)
                            .map_err(|_| yasna::ASN1Error::new(yasna::ASN1ErrorKind::Invalid))
                    });

                    let mut revoked: Vec<RevokedCert> = Vec::new();

                    // Handle optional revokedCertificates field
                    let revoked_reader = reader.next();
                    let _ = revoked_reader.read_sequence_of(|reader| {
                        let (serial, revocation_date, reasons) =
                            reader.read_sequence(|reader| {
                                let (serial_bytes, _is_negative) =
                                    reader.next().read_bigint_bytes()?;
                                let revocation_date = read_time(reader.next());

                                // Read optional extensions
                                let mut reasons: Vec<CrlReason> = Vec::new();
                                let _extensions = reader.read_optional(|reader| {
                                    reader.read_sequence_of(|reader| {
                                        reader.read_sequence(|reader| {
                                            let oid = reader.next().read_oid()?;
                                            let value = reader.next().read_bytes()?;
                                            if let Some(crl_reason) =
                                                CrlReason::from_oid_and_value(&oid, &value)
                                            {
                                                reasons.push(crl_reason);
                                            }
                                            Ok(())
                                        })
                                    })
                                })?;

                                Ok((serial_bytes, revocation_date, reasons))
                            })?;

                        revoked.push(RevokedCert {
                            serial: BigUint::from_bytes_be(&serial),
                            revocation_date: revocation_date.unwrap(),
                            reasons: reasons,
                        });
                        Ok(())
                    });

                    let _extensions = reader.read_optional(|reader| {
                        reader.read_tagged(Tag::context(0), |reader| {
                            reader.read_sequence_of(|reader| {
                                reader.read_sequence(|reader| {
                                    // Skip over the OID, critical flag (optional), and value
                                    let _oid = reader.next().read_oid();
                                    let _critical = reader.read_optional(|reader| match reader
                                        .lookahead_tag()?
                                    {
                                        tag if tag == Tag::from(tags::TAG_BOOLEAN) => {
                                            reader.read_bool().map(Some)
                                        }
                                        _ => Ok(None),
                                    })?;
                                    let _value = reader.next().read_bytes();
                                    Ok(())
                                })
                            })
                        })
                    })?;
                    Ok((_issuer, this_update, next_update, revoked))
                })
            })
            .map_err(|e| format!("ASN.1 parse error: {}", e))?;

        Ok(Self {
            signer,
            this_update: this_update.unwrap(),
            next_update: next_update.ok().unwrap(),
            revoked,
        })
    }
}
/// Writes a DER-encoded X.509 Certificate Revocation List (CRL) to a PEM-formatted file.
///
/// This function takes a byte slice containing DER-encoded CRL data, converts it to PEM format,
/// and writes it to a file at the specified path and filename. If the directory does not exist,
/// it will be created.
///
/// # Type Parameters
///
/// * `P` - A type that can be referenced as a `Path`, representing the directory path.
/// * `F` - A type that can be referenced as a `Path`, representing the filename.
///
/// # Arguments
///
/// * `der_data` - A byte slice containing the DER-encoded CRL.
/// * `path` - The directory path where the PEM file should be written.
/// * `filename` - The name of the PEM file to be created.
///
/// # Returns
///
/// * `Ok(())` if the file was successfully written.
/// * `Err` if any error occurred during directory creation, file creation, DER parsing, or writing.
///
/// # Errors
///
/// This function will return an error if:
/// - The directory cannot be created.
/// - The filename cannot be extracted.
/// - The file cannot be created.
/// - The DER data cannot be parsed into a CRL.
/// - The CRL cannot be converted to PEM format.
/// - The PEM data cannot be written to the file.
pub fn write_der_crl_as_pem<P: AsRef<Path>, F: AsRef<Path>>(
    der_data: &[u8],
    path: P,
    filename: F,
) -> Result<(), Box<dyn std::error::Error>> {
    create_dir_all(&path)?;
    let os_file = filename
        .as_ref()
        .file_name()
        .ok_or("Failed to extract file name")?;
    let full_path = path.as_ref().join(os_file);
    let mut file = File::create(full_path)?;

    let crl = X509Crl::from_der(der_data)?;
    let pem_data = crl.to_pem()?;
    file.write_all(&pem_data)?;

    Ok(())
}

fn write_generalized_time(writer: yasna::DERWriter, time: &chrono::DateTime<chrono::Utc>) {
    let time_str = time.format("%Y%m%d%H%M%SZ").to_string();
    writer.write_tagged_implicit(TAG_GENERALIZEDTIME, |writer| {
        writer.write_bytes(time_str.as_bytes());
    });
}

fn read_time(reader: yasna::BERReader) -> Result<DateTime<Utc>, Box<dyn std::error::Error>> {
    let parse_time = |reader: yasna::BERReader, format: &str| -> Result<DateTime<Utc>, ASN1Error> {
        let bytes = reader.read_bytes()?;
        let s = std::str::from_utf8(&bytes).map_err(|_| ASN1Error::new(ASN1ErrorKind::Invalid))?;
        let naive = NaiveDateTime::parse_from_str(s, format)
            .map_err(|_| ASN1Error::new(ASN1ErrorKind::Invalid))?;
        Ok(Utc.from_utc_datetime(&naive))
    };

    let tag = reader
        .lookahead_tag()
        .map_err(|e| format!("Failed to look ahead tag: {:?}", e))?;

    match tag {
        TAG_GENERALIZEDTIME => reader
            .read_tagged_implicit(TAG_GENERALIZEDTIME, |r| parse_time(r, "%Y%m%d%H%M%SZ"))
            .map_err(|e| format!("Failed to read GeneralizedTime: {:?}", e).into()),
        TAG_UTCTIME => reader
            .read_tagged_implicit(TAG_UTCTIME, |r| parse_time(r, "%y%m%d%H%M%SZ"))
            .map_err(|e| format!("Failed to read UTCTime: {:?}", e).into()),
        _ => Err("Invalid ASN.1 time format".into()),
    }
}

fn signature_algorithm_oid(name: &str) -> Option<&'static [u64]> {
    match name {
        "sha1WithRSAEncryption" => Some(&[1, 2, 840, 113549, 1, 1, 5]),
        "sha256WithRSAEncryption" => Some(&[1, 2, 840, 113549, 1, 1, 11]),
        "sha384WithRSAEncryption" => Some(&[1, 2, 840, 113549, 1, 1, 12]),
        "sha512WithRSAEncryption" => Some(&[1, 2, 840, 113549, 1, 1, 13]),
        "ecdsa-with-SHA1" => Some(&[1, 2, 840, 10045, 4, 1]),
        "ecdsa-with-SHA256" => Some(&[1, 2, 840, 10045, 4, 3, 2]),
        "ecdsa-with-SHA384" => Some(&[1, 2, 840, 10045, 4, 3, 3]),
        "ecdsa-with-SHA512" => Some(&[1, 2, 840, 10045, 4, 3, 4]),
        "ED25519" => Some(&[1, 3, 101, 112]),
        _ => None,
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificate::{CertBuilder, Certificate, UseesBuilderFields};
    use chrono::{Duration, Utc};
    use num_bigint::{BigUint, ToBigUint};
    use openssl::asn1::Asn1Integer;
    use std::fs;
    use tempfile::tempdir;

    fn dummy_certificate() -> Certificate {
        CertBuilder::new()
            .common_name("My Test Ca")
            .is_ca(true)
            .build_and_self_sign()
            .unwrap()
    }

    fn dummy_crl(cert: Certificate) -> X509CrlWrapper {
        let crl = X509CrlBuilder {
            signer: cert,
            this_update: Utc::now(),
            next_update: None,
            revoked: vec![RevokedCert {
                serial: BigUint::from(123u32),
                revocation_date: Utc::now(),
                reasons: vec![CrlReason::KeyCompromise],
            }],
        };
        let der = crl.build_and_sign();
        X509CrlWrapper::from_der(der.as_slice()).unwrap()
    }

    #[test]
    fn test_new_builder() {
        let cert = dummy_certificate();
        let builder = X509CrlBuilder::new(cert);
        assert_eq!(builder.revoked.len(), 0);
    }

    #[test]
    fn test_add_revoked_cert() {
        let cert = dummy_certificate();
        let mut builder = X509CrlBuilder::new(cert);
        let serial = BigUint::from(123u32);
        let date = Utc::now();
        builder.add_revoked_cert(serial.clone(), date);
        assert_eq!(builder.revoked.len(), 1);
        assert_eq!(builder.revoked[0].serial, serial);
    }

    #[test]
    fn test_set_update_times() {
        let cert = dummy_certificate();
        let mut builder = X509CrlBuilder::new(cert);
        let this_update = Utc::now();
        let next_update = this_update + Duration::days(10);
        builder.set_update_times(this_update, next_update);
        assert_eq!(builder.this_update, this_update);
        assert_eq!(builder.next_update, Some(next_update));
    }

    #[test]
    fn test_build_and_sign() {
        let cert = dummy_certificate();

        let builder = X509CrlBuilder::new(cert);
        let crl_der = builder.build_and_sign();
        assert!(!crl_der.is_empty());
    }

    #[test]
    fn test_from_der_valid_crl() {
        let cert = dummy_certificate();
        let mut builder = X509CrlBuilder::new(cert.clone());

        // Add a revoked certificate
        let serial = BigUint::from(456u32);
        let revocation_date = Utc::now();
        builder.add_revoked_cert(serial.clone(), revocation_date);

        // Build and sign the CRL
        let crl_der = builder.build_and_sign();

        // Parse the CRL back
        let parsed = X509CrlBuilder::from_der(&crl_der, cert).expect("Failed to parse DER");

        // Check that the parsed data matches
        assert_eq!(parsed.revoked.len(), 1);
        assert_eq!(parsed.revoked[0].serial, serial);
        assert_eq!(
            parsed.revoked[0].revocation_date.timestamp(),
            revocation_date.timestamp()
        );
    }

    #[test]
    fn test_from_der_invalid_data() {
        let cert = dummy_certificate();
        let invalid_der = b"not-a-valid-der";

        let result = X509CrlBuilder::from_der(invalid_der, cert);
        assert!(result.is_err());
    }

    #[test]
    fn test_write_der_crl_as_pem() {
        let ca = CertBuilder::new()
            .common_name("My Test Ca")
            .is_ca(true)
            .build_and_self_sign()
            .unwrap();
        let mut builder = X509CrlBuilder::new(ca);
        builder.add_revoked_cert(12345u32.to_biguint().unwrap(), Utc::now());

        let crl_der = builder.build_and_sign();

        let dir = tempdir().unwrap();
        let file_name = "test_crl.pem";
        let result = write_der_crl_as_pem(&crl_der, dir.path(), file_name);

        assert!(result.is_ok());
        let file_path = dir.path().join(file_name);
        let pem_contents = fs::read_to_string(file_path).unwrap();
        assert!(pem_contents.contains("-----BEGIN X509 CRL-----"));
    }

    #[test]
    fn test_handle_crl_without_next_update_time() {
        let crl = X509CrlBuilder {
            signer: dummy_certificate(), // You need to implement or mock this
            this_update: Utc::now(),
            next_update: None,
            revoked: vec![RevokedCert {
                serial: BigUint::from(123u32),
                revocation_date: Utc::now(),
                reasons: vec![CrlReason::KeyCompromise],
            }],
        };
        let der = crl.build_and_sign();
        assert!(der.len() > 0);
        let parsed =
            X509CrlBuilder::from_der(&der, dummy_certificate()).expect("Failed to parse DER");
        assert_eq!(parsed.next_update, None);
    }

    #[test]
    fn test_crl_contains_reason_code_extension() {
        // Setup: create a CRL with one revoked certificate and a reason
        let crl = X509CrlBuilder {
            signer: dummy_certificate(), // You need to implement or mock this
            this_update: Utc::now(),
            next_update: Some(Utc::now() + chrono::Duration::days(30)),
            revoked: vec![RevokedCert {
                serial: BigUint::from(123u32),
                revocation_date: Utc::now(),
                reasons: vec![CrlReason::KeyCompromise],
            }],
        };

        let der = crl.build_and_sign();

        // Decode the CRL and check it is valid
        let result = yasna::parse_der(&der, |reader| {
            reader.read_sequence(|reader| {
                let _tbs_der = reader.next().read_der()?;

                // Signature Algorithm
                let _sig_algo_oid = reader.next().read_sequence(|reader| {
                    let oid = reader.next().read_oid()?;
                    let _ = reader.next().read_null()?;
                    Ok(oid)
                })?;

                // Signature Value
                let _sig_value = reader.next().read_bitvec_bytes()?;
                Ok(())
            })
        });

        assert!(result.is_ok(), "CRL should be valid DER");

        // Parse the CRL back
        let parsed =
            X509CrlBuilder::from_der(&der, dummy_certificate()).expect("Failed to parse DER");
        assert_eq!(parsed.revoked[0].reasons[0], CrlReason::KeyCompromise);
    }

    #[test]
    fn test_from_der_and_to_der() {
        let cert = dummy_certificate();
        let crl_wrapper = dummy_crl(cert.clone());
        let der = crl_wrapper.to_der().expect("Failed to convert to DER");
        let parsed = X509CrlWrapper::from_der(&der).expect("Failed to parse DER");
        assert_eq!(parsed.to_der().unwrap(), der);
    }

    #[test]
    fn test_verify_signature() {
        let cert = dummy_certificate();
        let crl_wrapper = dummy_crl(cert.clone());
        let pub_key = cert.x509.public_key().expect("Failed to get public key");
        let verified = crl_wrapper
            .verify_signature(&pub_key)
            .expect("Verification failed");
        assert!(verified);
    }

    #[test]
    fn test_signature_with_wrong_signer() {
        let cert = dummy_certificate();
        let crl_wrapper = dummy_crl(cert.clone());
        let wrong_cert = dummy_certificate();
        let wrong_pub_key = wrong_cert
            .x509
            .public_key()
            .expect("Failed to get public key");
        let verified = crl_wrapper
            .verify_signature(&wrong_pub_key)
            .expect("Verification failed");
        assert!(!verified);
    }

    #[test]
    fn test_revoked_false() {
        let cert = dummy_certificate();
        let crl_wrapper = dummy_crl(cert.clone());
        let serial = Asn1Integer::from_bn(&openssl::bn::BigNum::from_u32(123456).unwrap()).unwrap();
        assert!(!crl_wrapper.revoked(&serial));
    }

    #[test]
    fn test_revoked_true() {
        let cert = dummy_certificate();
        let crl_wrapper = dummy_crl(cert.clone());
        let serial = Asn1Integer::from_bn(&openssl::bn::BigNum::from_u32(123).unwrap()).unwrap();
        assert!(crl_wrapper.revoked(&serial));
    }

    #[test]
    fn test_save_and_read_pem() {
        let cert = dummy_certificate();
        let crl_wrapper = dummy_crl(cert.clone());

        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path();
        let filename = "test_crl.pem";

        crl_wrapper
            .save_as_pem(path, filename)
            .expect("Failed to save PEM");

        let full_path = path.join(filename);
        let read_crl = X509CrlWrapper::read_as_pem(&full_path).expect("Failed to read PEM");

        assert_eq!(read_crl.to_der().unwrap(), crl_wrapper.to_der().unwrap());
    }
}
