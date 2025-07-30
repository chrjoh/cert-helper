use crate::certificate::Certificate;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use num_bigint::BigUint;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::x509::X509;
use yasna::models::ObjectIdentifier;
use yasna::tags::{TAG_BITSTRING, TAG_GENERALIZEDTIME, TAG_SEQUENCE};
use yasna::{ASN1Error, ASN1ErrorKind};

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
    next_update: DateTime<Utc>,
}

/// Represents a single revoked certificate entry in a CRL.
pub struct RevokedCert {
    /// The serial number of the revoked certificate.
    serial: BigUint,
    /// The date and time when the certificate was revoked.
    revocation_date: DateTime<Utc>,
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
            next_update: Utc::now() + chrono::Duration::days(30),
        }
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
        self.next_update = next_update;
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
                write_generalized_time(writer.next(), &self.next_update);

                // Revoked Certificates
                writer.next().write_sequence_of(|writer| {
                    for revoked in &self.revoked {
                        writer.next().write_sequence(|writer| {
                            writer
                                .next()
                                .write_bigint_bytes(&revoked.serial.to_bytes_be(), true);
                            write_generalized_time(writer.next(), &revoked.revocation_date);
                        });
                    }
                });
            });
        });

        // Sign the TBS
        let mut signer =
            openssl::sign::Signer::new(MessageDigest::sha256(), self.signer.pkey.as_ref().unwrap())
                .unwrap();
        signer.update(&tbs).unwrap();
        let signature = signer.sign_to_vec().unwrap();

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
    /// * `signer` - The certificate that signed the CRL.
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
                    let _version = reader.next().read_u8()?;

                    let _ = reader.next().read_sequence(|reader| {
                        let _ = reader.next().read_oid()?;
                        let _ = reader.next().read_null()?;
                        Ok(())
                    })?;

                    let issuer_name = reader.next().read_sequence(|reader| {
                        reader.next().read_set(|set_reader| {
                            set_reader.next(&[TAG_SEQUENCE])?.read_sequence(|reader| {
                                let _ = reader.next().read_oid()?;
                                reader.next().read_utf8string()
                            })
                        })
                    })?;

                    let this_update = read_generalized_time(reader.next());
                    let next_update = read_generalized_time(reader.next());

                    let mut revoked: Vec<RevokedCert> = Vec::new();

                    // Handle optional revokedCertificates field
                    let revoked_reader = reader.next();
                    let _ = revoked_reader.read_sequence_of(|reader| {
                        let (serial, revocation_date) = reader.read_sequence(|reader| {
                            let (serial_bytes, _is_negative) = reader.next().read_bigint_bytes()?;
                            let revocation_date = read_generalized_time(reader.next());
                            Ok((serial_bytes, revocation_date))
                        })?;

                        revoked.push(RevokedCert {
                            serial: BigUint::from_bytes_be(&serial),
                            revocation_date: revocation_date.unwrap(),
                        });
                        Ok(())
                    });

                    Ok((issuer_name, this_update, next_update, revoked))
                })
            })
            .map_err(|e| format!("ASN.1 parse error: {}", e))?;

        Ok(Self {
            signer,
            this_update: this_update.unwrap(),
            next_update: next_update.unwrap(),
            revoked,
        })
    }
}

fn write_generalized_time(writer: yasna::DERWriter, time: &chrono::DateTime<chrono::Utc>) {
    let time_str = time.format("%Y%m%d%H%M%SZ").to_string();
    writer.write_tagged_implicit(TAG_GENERALIZEDTIME, |writer| {
        writer.write_bytes(time_str.as_bytes());
    });
}

fn read_generalized_time(
    reader: yasna::BERReader,
) -> Result<DateTime<Utc>, Box<dyn std::error::Error>> {
    reader
        .read_tagged_implicit(TAG_GENERALIZEDTIME, |reader| {
            let bytes = reader.read_bytes()?;
            let s =
                std::str::from_utf8(&bytes).map_err(|_| ASN1Error::new(ASN1ErrorKind::Invalid))?;

            // Parse format like "20250729141655Z"

            //let s = s.trim_end_matches('Z');
            let naive = NaiveDateTime::parse_from_str(s, "%Y%m%d%H%M%SZ")
                .map_err(|_| ASN1Error::new(ASN1ErrorKind::Invalid))?;
            Ok(Utc.from_utc_datetime(&naive))
        })
        .map_err(|e| format!("Failed to read GeneralizedTime: {}", e).into())
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
    use num_bigint::BigUint;

    fn dummy_certificate() -> Certificate {
        CertBuilder::new()
            .common_name("My Test Ca")
            .is_ca(true)
            .build_and_self_sign()
            .unwrap()
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
        assert_eq!(builder.next_update, next_update);
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
}
