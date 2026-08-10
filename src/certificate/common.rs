use chrono::{NaiveDate, NaiveDateTime, TimeZone, Utc};
use openssl::asn1::Asn1Time;
use std::fs;
use std::fs::{OpenOptions, create_dir_all};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
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

        let write_file =
            |suffix: &str, content: &[u8], mode: u32| -> Result<(), Box<dyn std::error::Error>> {
                let mut new_name = os_file.to_os_string();
                new_name.push(suffix);
                let full_path = path.as_ref().join(new_name);
                let mut opts = OpenOptions::new();
                opts.write(true).create(true).truncate(true);
                #[cfg(unix)]
                opts.mode(mode);
                #[cfg(not(unix))]
                let _ = mode;
                // `mode()` applies only at creation — an existing file keeps its old
                // permissions — so remove any previous file rather than truncating it.
                if full_path.exists() {
                    fs::remove_file(&full_path)?;
                }
                let mut file = opts.open(full_path)?;
                file.write_all(content)?;
                Ok(())
            };
        if let Ok(ref key) = self.get_private_key() {
            write_file("_pkey.pem", key, 0o600)?;
        }
        write_file(self.pem_extension(), &self.get_pem()?, 0o644)?;
        Ok(())
    }
}

/// Converts a `yyyy-mm-dd` date into an `Asn1Time` at midnight UTC.
///
/// The encoding is chosen by OpenSSL's `ASN1_TIME_set`, which applies RFC 5280
/// §4.1.2.5.1: dates through 2049 become `UTCTime`, 2050 and later become
/// `GeneralizedTime`.
///
/// Do **not** format the string here and hand it to `Asn1Time::from_str`
/// (`ASN1_TIME_set_string`): that infers the ASN.1 type from the string's length,
/// so a 4-digit year silently forces `GeneralizedTime` for every date — which
/// strict verifiers such as LibreSSL reject outright — and a 2-digit year
/// silently shifts anything from 2050 onwards back a century.
///
/// # Errors
/// If `date_str` is not a valid `yyyy-mm-dd` date, or OpenSSL cannot represent it.
pub(crate) fn create_asn1_time_from_date(
    date_str: &str,
) -> Result<Asn1Time, Box<dyn std::error::Error>> {
    let date = NaiveDate::parse_from_str(date_str, "%Y-%m-%d")?;
    let datetime = NaiveDateTime::new(date, chrono::NaiveTime::from_hms_opt(0, 0, 0).unwrap());
    Ok(Asn1Time::from_unix(
        Utc.from_utc_datetime(&datetime).timestamp(),
    )?)
}

#[cfg(test)]
mod asn1_time_encoding {
    use crate::certificate::{CertBuilder, CsrBuilder, CsrOptions, UseesBuilderFields};
    use crate::test_der::{TAG_GENERALIZEDTIME, TAG_UTCTIME, certificate_validity};

    /// A self-signed certificate with the given validity bounds, as DER.
    fn cert_der(valid_from: &str, valid_to: &str) -> Vec<u8> {
        CertBuilder::new()
            .common_name("asn1 time test")
            .valid_from(valid_from)
            .valid_to(valid_to)
            .build_and_self_sign()
            .unwrap()
            .x509
            .to_der()
            .unwrap()
    }

    #[test]
    fn explicit_date_before_2050_is_utctime() {
        let (not_before, not_after) = certificate_validity(&cert_der("2026-08-07", "2026-11-05"));

        assert_eq!(not_before.tag, TAG_UTCTIME, "notBefore: {not_before:?}");
        assert_eq!(not_after.tag, TAG_UTCTIME, "notAfter: {not_after:?}");
        assert_eq!(not_before.value, "260807000000Z");
        assert_eq!(not_after.value, "261105000000Z");
    }

    #[test]
    fn last_utctime_year_2049_is_utctime() {
        let (not_before, not_after) = certificate_validity(&cert_der("2049-12-30", "2049-12-31"));

        assert_eq!(not_before.tag, TAG_UTCTIME, "notBefore: {not_before:?}");
        assert_eq!(not_after.tag, TAG_UTCTIME, "notAfter: {not_after:?}");
        assert_eq!(not_after.value, "491231000000Z");
    }

    #[test]
    fn first_generalizedtime_year_2050_is_generalizedtime() {
        let (not_before, not_after) = certificate_validity(&cert_der("2050-01-01", "2050-01-02"));

        assert_eq!(
            not_before.tag, TAG_GENERALIZEDTIME,
            "notBefore: {not_before:?}"
        );
        assert_eq!(
            not_after.tag, TAG_GENERALIZEDTIME,
            "notAfter: {not_after:?}"
        );
        assert_eq!(not_before.value, "20500101000000Z");
    }

    #[test]
    fn the_two_encodings_may_be_mixed_across_the_boundary() {
        // A window that opens in 2049 and closes in 2050 is legal and must use a
        // different encoding for each bound.
        let (not_before, not_after) = certificate_validity(&cert_der("2049-12-31", "2050-01-01"));

        assert_eq!(not_before.tag, TAG_UTCTIME, "notBefore: {not_before:?}");
        assert_eq!(
            not_after.tag, TAG_GENERALIZEDTIME,
            "notAfter: {not_after:?}"
        );
    }

    #[test]
    fn a_far_future_date_keeps_its_century() {
        // The tempting "just use %y" fix encodes 2075 as UTCTime "75...", which
        // RFC 5280 §4.1.2.5.1 says means 1975.
        let (_, not_after) = certificate_validity(&cert_der("2026-01-01", "2075-06-01"));

        assert_eq!(
            not_after.tag, TAG_GENERALIZEDTIME,
            "notAfter: {not_after:?}"
        );
        assert_eq!(not_after.value, "20750601000000Z");
    }

    #[test]
    fn builder_default_dates_are_utctime() {
        // The defaults go through Asn1Time::days_from_now rather than
        // create_asn1_time_from_date, so they need their own guard.
        let der = CertBuilder::new()
            .common_name("asn1 default test")
            .build_and_self_sign()
            .unwrap()
            .x509
            .to_der()
            .unwrap();
        let (not_before, not_after) = certificate_validity(&der);

        assert_eq!(not_before.tag, TAG_UTCTIME, "notBefore: {not_before:?}");
        assert_eq!(not_after.tag, TAG_UTCTIME, "notAfter: {not_after:?}");
    }

    #[test]
    fn a_certificate_signed_from_a_csr_is_utctime() {
        // CsrOptions::valid_from/valid_to is a separate call site into the same
        // helper, and only stays fixed as long as it keeps sharing it.
        let ca = CertBuilder::new()
            .common_name("csr test ca")
            .is_ca(true)
            .build_and_self_sign()
            .unwrap();
        let csr = CsrBuilder::new()
            .common_name("csr subject")
            .certificate_signing_request()
            .unwrap();
        let signed = csr
            .build_signed_certificate(
                &ca,
                CsrOptions::new()
                    .valid_from("2026-08-07")
                    .valid_to("2026-11-05"),
            )
            .unwrap();
        let (not_before, not_after) = certificate_validity(&signed.x509.to_der().unwrap());

        assert_eq!(not_before.tag, TAG_UTCTIME, "notBefore: {not_before:?}");
        assert_eq!(not_after.tag, TAG_UTCTIME, "notAfter: {not_after:?}");
        assert_eq!(not_before.value, "260807000000Z");
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::certificate::{CertBuilder, UseesBuilderFields};
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    fn mode_of(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    fn a_certificate() -> impl X509Common {
        CertBuilder::new()
            .common_name("perm test")
            .build_and_self_sign()
            .unwrap()
    }

    #[test]
    fn private_key_is_not_readable_by_group_or_other() {
        let dir = tempdir().unwrap();
        a_certificate().save(dir.path(), "mytest").unwrap();

        let key = dir.path().join("mytest_pkey.pem");
        let mode = mode_of(&key);

        // The property that matters, and the one umask cannot weaken: umask only
        // ever clears bits, so if these are zero here they are zero everywhere.
        assert_eq!(
            mode & 0o077,
            0,
            "private key must not be group/world accessible, got {mode:o}"
        );
        assert_eq!(
            mode, 0o600,
            "private key should be exactly 0600, got {mode:o}"
        );
    }

    #[test]
    fn certificate_itself_is_left_readable() {
        let dir = tempdir().unwrap();
        a_certificate().save(dir.path(), "mytest").unwrap();

        let cert = dir.path().join("mytest_cert.pem");
        let mode = mode_of(&cert);

        // A certificate is public by definition; assert only that the owner can
        // read it. The exact bits depend on the ambient umask, so pinning 0644
        // here would make the test environment-dependent.
        assert_ne!(mode & 0o400, 0, "certificate should be owner-readable");
    }

    #[test]
    fn resaving_tightens_permissions_on_a_pre_existing_key_file() {
        let dir = tempdir().unwrap();
        let key = dir.path().join("mytest_pkey.pem");

        // Simulate a key written by an older version of this crate, when
        // `File::create` left it at the umask default.
        fs::write(&key, b"stale").unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(mode_of(&key), 0o644);

        a_certificate().save(dir.path(), "mytest").unwrap();

        // `OpenOptions::mode` applies only when a file is *created*, so writing
        // over the old file would silently keep 0644. save() must unlink first.
        assert_eq!(
            mode_of(&key),
            0o600,
            "re-saving must not inherit the old world-readable mode"
        );
    }
}
