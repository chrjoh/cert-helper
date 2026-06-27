use openssl::x509::extension::{ExtendedKeyUsage, KeyUsage};
use std::collections::HashSet;
/// Represents the allowed usages for a certificate, used in KeyUsage and ExtendedKeyUsage extensions.
#[allow(non_camel_case_types)]
#[derive(Hash, Eq, PartialEq, Debug, Clone)]
pub enum Usage {
    /// Allows the certificate to sign other certificates (typically used for CA certificates).
    certsign,
    /// Allows the certificate to sign certificate revocation lists (CRLs).
    crlsign,
    /// Allows the certificate to be used for encrypting data (e.g., key encipherment).
    encipherment,
    /// Indicates the certificate can be used for client authentication in TLS.
    clientauth,
    /// Indicates the certificate can be used for server authentication in TLS.
    serverauth,
    /// Allows the certificate to be used for digital signatures.
    signature,
    /// Indicates the certificate can be used for content commitment (non-repudiation).
    contentcommitment,
}

pub(crate) struct TrackedKeyUsage {
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

    pub(crate) fn is_used(&self) -> bool {
        self.used
    }

    pub(crate) fn into_inner(self) -> KeyUsage {
        self.inner
    }
}

pub(crate) struct TrackedExtendedKeyUsage {
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

    pub(crate) fn is_used(&self) -> bool {
        self.used
    }

    pub(crate) fn into_inner(self) -> ExtendedKeyUsage {
        self.inner
    }
}

pub(crate) fn get_key_usage(
    usage: &Option<HashSet<Usage>>,
) -> (TrackedKeyUsage, TrackedExtendedKeyUsage) {
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
