use chrono::{NaiveDate, NaiveDateTime, TimeZone, Utc};
use openssl::asn1::Asn1Time;
use std::fs::{File, create_dir_all};
use std::io::Write;
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
