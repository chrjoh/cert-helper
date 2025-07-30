#![allow(unused_imports)]
use bit_vec::BitVec;
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use num_bigint::BigUint;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use std::error::Error;
use x509_parser::asn1_rs::AsTaggedImplicit;
use yasna::models::ObjectIdentifier;
use yasna::{ASN1Error, ASN1ErrorKind, BERReader, DERWriter, Tag, TagClass};

pub struct X509CrlBuilder {
    issuer_name: String,
    revoked: Vec<RevokedCert>,
    this_update: DateTime<Utc>,
    next_update: DateTime<Utc>,
}

pub struct RevokedCert {
    serial: BigUint,
    revocation_date: DateTime<Utc>,
}

impl X509CrlBuilder {
    pub fn new(issuer_cn: &str) -> Self {
        Self {
            issuer_name: issuer_cn.to_string(),
            revoked: Vec::new(),
            this_update: Utc::now(),
            next_update: Utc::now() + chrono::Duration::days(30),
        }
    }

    pub fn add_revoked_cert(&mut self, serial: BigUint, revocation_date: DateTime<Utc>) {
        self.revoked.push(RevokedCert {
            serial,
            revocation_date,
        });
    }

    pub fn set_update_times(&mut self, this_update: DateTime<Utc>, next_update: DateTime<Utc>) {
        self.this_update = this_update;
        self.next_update = next_update;
    }

    pub fn build_and_sign(&self, key: &PKey<openssl::pkey::Private>) -> Vec<u8> {
        let tbs = yasna::construct_der(|writer| {
            writer.write_sequence(|writer| {
                writer.next().write_u8(1); // Version v2

                // Signature Algorithm
                let sig_oid = signature_algorithm_oid("sha256WithRSAEncryption").unwrap();
                writer.next().write_sequence(|writer| {
                    writer
                        .next()
                        .write_oid(&ObjectIdentifier::from_slice(&sig_oid)); // sha256WithRSAEncryption
                    writer.next().write_null();
                });

                // Issuer
                writer.next().write_sequence(|writer| {
                    writer.next().write_set(|writer| {
                        writer.next().write_sequence(|writer| {
                            writer
                                .next()
                                .write_oid(&ObjectIdentifier::from_slice(&[2, 5, 4, 3])); // CN
                            writer.next().write_utf8_string(&self.issuer_name);
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
        let mut signer = openssl::sign::Signer::new(MessageDigest::sha256(), key).unwrap();
        signer.update(&tbs).unwrap();
        let signature = signer.sign_to_vec().unwrap();

        // Final CRL
        yasna::construct_der(|writer| {
            writer.write_sequence(|writer| {
                writer.next().write_der(&tbs);

                // Signature Algorithm
                let sig_oid = signature_algorithm_oid("sha256WithRSAEncryption").unwrap();
                writer.next().write_sequence(|writer| {
                    writer
                        .next()
                        .write_oid(&ObjectIdentifier::from_slice(&sig_oid));
                    writer.next().write_null();
                });

                // Signature Value
                writer
                    .next()
                    .write_tagged_implicit(TAG_BIT_STRING, |writer| {
                        // First byte is the number of unused bits (0 in this case)
                        let mut bit_string = vec![0u8];
                        bit_string.extend_from_slice(&signature);
                        writer.write_bytes(&bit_string);
                    });
            });
        })
    }

    pub fn from_der(der: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
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

        let (issuer_name, this_update, next_update, revoked) =
            yasna::parse_der(&tbs_der, |reader| {
                reader.read_sequence(|reader| {
                    let _version = reader.next().read_u8()?;

                    let _ = reader.next().read_sequence(|reader| {
                        let _ = reader.next().read_oid()?;
                        let _ = reader.next().read_null()?;
                        Ok(())
                    })?;

                    let tag_sequence = Tag {
                        tag_class: TagClass::Universal,
                        tag_number: 16,
                    };

                    let issuer_name = reader.next().read_sequence(|reader| {
                        reader.next().read_set(|set_reader| {
                            set_reader.next(&[tag_sequence])?.read_sequence(|reader| {
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
            issuer_name,
            this_update: this_update.unwrap(),
            next_update: next_update.unwrap(),
            revoked,
        })
    }
}

const TAG_BIT_STRING: yasna::Tag = yasna::Tag {
    tag_class: yasna::TagClass::Universal,
    tag_number: 3,
};

const TAG_GENERALIZED_TIME: Tag = Tag {
    tag_class: yasna::TagClass::Universal,
    tag_number: 24,
};

fn write_generalized_time(writer: yasna::DERWriter, time: &chrono::DateTime<chrono::Utc>) {
    let time_str = time.format("%Y%m%d%H%M%SZ").to_string();
    writer.write_tagged_implicit(TAG_GENERALIZED_TIME, |writer| {
        writer.write_bytes(time_str.as_bytes());
    });
}

fn read_generalized_time(
    reader: yasna::BERReader,
) -> Result<DateTime<Utc>, Box<dyn std::error::Error>> {
    reader
        .read_tagged_implicit(TAG_GENERALIZED_TIME, |reader| {
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
