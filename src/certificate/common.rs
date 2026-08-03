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

pub(crate) fn create_asn1_time_from_date(
    date_str: &str,
) -> Result<Asn1Time, Box<dyn std::error::Error>> {
    let date = NaiveDate::parse_from_str(date_str, "%Y-%m-%d")?;
    let datetime = NaiveDateTime::new(date, chrono::NaiveTime::from_hms_opt(0, 0, 0).unwrap());
    let utc_datetime = Utc.from_utc_datetime(&datetime);
    let asn1_time_str = utc_datetime.format("%Y%m%d%H%M%SZ").to_string();
    let asn1_time = Asn1Time::from_str(&asn1_time_str)?;
    Ok(asn1_time)
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
