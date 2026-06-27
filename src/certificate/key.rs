use foreign_types::ForeignType;
use openssl::ec::{EcGroup, EcKey};
use openssl::error::ErrorStack;
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::{X509, X509Req};

unsafe extern "C" {
    pub fn X509_sign(
        x: *mut openssl_sys::X509,
        pkey: *mut openssl_sys::EVP_PKEY,
        md: *const openssl_sys::EVP_MD,
    ) -> ::std::os::raw::c_int;
    pub fn X509_sign_ctx(
        x: *mut openssl_sys::X509,
        ctx: *mut openssl_sys::EVP_MD_CTX,
    ) -> ::std::os::raw::c_int;
}

unsafe extern "C" {
    pub fn X509_REQ_sign(
        req: *mut openssl_sys::X509_REQ,
        pkey: *mut openssl_sys::EVP_PKEY,
        md: *const openssl_sys::EVP_MD,
    ) -> ::std::os::raw::c_int;
    pub fn X509_REQ_sign_ctx(
        req: *mut openssl_sys::X509_REQ,
        ctx: *mut openssl_sys::EVP_MD_CTX,
    ) -> ::std::os::raw::c_int;
}
/// Sign a just-built `X509` in-place with a digest-less key (Ed25519 or PQC).
///
/// Ed25519 uses the plain `X509_sign(x, pkey, NULL)` path that has always
/// worked. PQC keys (ML-DSA / SLH-DSA) need a workaround on OpenSSL 3.5+:
/// `X509_sign(_, _, NULL)` triggers default-digest inference in
/// `do_sigver_init`, and the PQC providers then reject the inferred digest
/// with "Explicit digest not supported". We instead initialise an `EVP_MD_CTX`
/// with an *empty* C string as `mdname` — that bypasses the default-digest
/// lookup inside OpenSSL while still satisfying the provider's
/// `mdname[0] != '\0'` guard — and hand the ctx to `X509_sign_ctx`.
pub(crate) fn sign_certificate_digestless(
    cert: &X509,
    pkey: &PKey<openssl::pkey::Private>,
) -> Result<(), String> {
    if !is_digestless_key(pkey) {
        return Err("sign_certificate_digestless called with non-digestless key".to_string());
    }
    let cert_ptr = cert.as_ptr();
    let pkey_ptr = pkey.as_ptr();

    if pkey.id() == Id::ED25519 {
        let result = unsafe { X509_sign(cert_ptr, pkey_ptr, std::ptr::null()) };
        return if result > 0 {
            Ok(())
        } else {
            Err("Failed to sign certificate with Ed25519".to_string())
        };
    }

    // PQC path: EVP_DigestSignInit (non-ex) with NULL mdname + X509_sign_ctx.
    // `Signer::new_without_digest` in the openssl crate uses this exact call and
    // it works for ML-DSA/SLH-DSA whereas `EVP_DigestSignInit_ex` does not.
    // SAFETY: `ctx` is owned by `MdCtx` and freed on every path (early return or
    // scope exit). The internal EVP_PKEY_CTX created by EVP_DigestSignInit (NULL
    // pctx arg) is owned by `ctx` and released with it. `pkey_ptr`/`cert_ptr` are
    // borrows from live wrappers and are not freed here.
    let ctx = MdCtx(unsafe { openssl_sys::EVP_MD_CTX_new() });
    if ctx.0.is_null() {
        return Err("EVP_MD_CTX_new returned NULL".to_string());
    }
    let init = unsafe {
        openssl_sys::EVP_DigestSignInit(
            ctx.0,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null_mut(),
            pkey_ptr,
        )
    };
    if init <= 0 {
        return Err("EVP_DigestSignInit failed for PQC key".to_string());
    }
    let result = unsafe { X509_sign_ctx(cert_ptr, ctx.0) };

    if result > 0 {
        Ok(())
    } else {
        Err("X509_sign_ctx failed for PQC key".to_string())
    }
}

/// Same as `sign_certificate_digestless` but for `X509Req`. See the
/// `sign_certificate_digestless` docstring for why Ed25519 and PQC take
/// different OpenSSL paths.
pub(crate) fn sign_x509_req_digestless(req: &X509Req, pkey: &PKey<Private>) -> Result<(), String> {
    if !is_digestless_key(pkey) {
        return Err("sign_x509_req_digestless called with non-digestless key".to_string());
    }
    let req_ptr = req.as_ptr();
    let pkey_ptr = pkey.as_ptr();

    if pkey.id() == Id::ED25519 {
        let result = unsafe { X509_REQ_sign(req_ptr, pkey_ptr, std::ptr::null()) };
        return if result > 0 {
            Ok(())
        } else {
            Err("Failed to sign X509Req with Ed25519".to_string())
        };
    }

    // SAFETY: same invariants as in `sign_certificate_digestless` — `ctx` is
    // owned by `MdCtx` and freed on every path; `pkey_ptr`/`req_ptr` are borrows.
    let ctx = MdCtx(unsafe { openssl_sys::EVP_MD_CTX_new() });
    if ctx.0.is_null() {
        return Err("EVP_MD_CTX_new returned NULL".to_string());
    }
    let init = unsafe {
        openssl_sys::EVP_DigestSignInit(
            ctx.0,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null_mut(),
            pkey_ptr,
        )
    };
    if init <= 0 {
        return Err("EVP_DigestSignInit failed for PQC key".to_string());
    }
    let result = unsafe { X509_REQ_sign_ctx(req_ptr, ctx.0) };

    if result > 0 {
        Ok(())
    } else {
        Err("X509_REQ_sign_ctx failed for PQC key".to_string())
    }
}

/// FIPS 203 ML-KEM algorithm OIDs, arc `2.16.840.1.101.3.4.4.x`. These are the
/// `id-alg-ml-kem-*` identifiers from draft-ietf-lamps-kyber-certificates that
/// appear in an ML-KEM `SubjectPublicKeyInfo`. Detection in [`is_mlkem_pkey`] is
/// by OpenSSL EVP algorithm name (provider-agnostic, like [`is_pqc_pkey`]); the
/// OIDs are kept here for reference since `oid-registry` does not know them yet.
#[cfg(feature = "pqc")]
#[allow(dead_code)]
const ML_KEM_OIDS: [&str; 3] = [
    "2.16.840.1.101.3.4.4.1", // id-alg-ml-kem-512
    "2.16.840.1.101.3.4.4.2", // id-alg-ml-kem-768
    "2.16.840.1.101.3.4.4.3", // id-alg-ml-kem-1024
];

/// Sign a just-built `X509` in-place with a digest-less key (Ed25519 or PQC).
///
/// We avoid `X509_sign(x, pkey, NULL)` because OpenSSL 3.5+ infers a default
/// digest for ML-DSA/SLH-DSA in that path, which their providers then reject.
/// Instead we initialise an `EVP_MD_CTX` with an explicit NULL `mdname` and
/// hand it to `X509_sign_ctx`.
/// RAII guard that frees an `EVP_MD_CTX` on drop, including on early return and
/// unwind. Keeps the digest-less signing paths leak-free without manual
/// `EVP_MD_CTX_free` on every branch. Mirrors `pqc::PkeyCtx`.
struct MdCtx(*mut openssl_sys::EVP_MD_CTX);

impl Drop for MdCtx {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: freed exactly once (on every path including unwind);
            // EVP_MD_CTX_free is a no-op on NULL.
            unsafe { openssl_sys::EVP_MD_CTX_free(self.0) }
        }
    }
}

/// Defines what type of key that can be used with the certificate
#[derive(Debug, Clone, PartialEq)]
pub enum KeyType {
    /// RSA key with a 2048-bit length.
    RSA2048,
    /// RSA key with a 4096-bit length.
    RSA4096,
    /// Elliptic Curve key using the NIST P-224 curve (secp224r1).
    P224,
    /// Elliptic Curve key using the NIST P-256 curve (secp256r1). Also known as prime256v1.
    P256,
    /// Elliptic Curve key using the NIST P-384 curve (secp384r1).
    P384,
    /// Elliptic Curve key using the NIST P-521 curve (secp521r1).
    P521,
    /// Edwards-curve Digital Signature Algorithm using Ed25519.
    Ed25519,
    /// ML-DSA-44 (FIPS 204, formerly Dilithium2). Post-quantum lattice signature.
    #[cfg(feature = "pqc")]
    MlDsa44,
    /// ML-DSA-65 (FIPS 204, formerly Dilithium3). Post-quantum lattice signature.
    #[cfg(feature = "pqc")]
    MlDsa65,
    /// ML-DSA-87 (FIPS 204, formerly Dilithium5). Post-quantum lattice signature.
    #[cfg(feature = "pqc")]
    MlDsa87,
    /// SLH-DSA-SHA2-128s (FIPS 205, formerly SPHINCS+). Hash-based signature, small variant.
    #[cfg(feature = "pqc")]
    SlhDsaSha2_128s,
    /// SLH-DSA-SHA2-192s (FIPS 205). Hash-based signature, medium variant.
    #[cfg(feature = "pqc")]
    SlhDsaSha2_192s,
    /// SLH-DSA-SHA2-256s (FIPS 205). Hash-based signature, large variant.
    #[cfg(feature = "pqc")]
    SlhDsaSha2_256s,
    /// ML-KEM-512 (FIPS 203, formerly Kyber). Post-quantum key-encapsulation
    /// key. Encapsulation/encryption only — cannot sign. See [`KeyType`] notes
    /// on ML-KEM: only `keyEncipherment` is a valid KeyUsage and certificates
    /// must be issued by a separate signing CA, not self-signed.
    #[cfg(feature = "pqc")]
    MlKem512,
    /// ML-KEM-768 (FIPS 203). Post-quantum key-encapsulation key. See
    /// [`KeyType::MlKem512`].
    #[cfg(feature = "pqc")]
    MlKem768,
    /// ML-KEM-1024 (FIPS 203). Post-quantum key-encapsulation key. See
    /// [`KeyType::MlKem512`].
    #[cfg(feature = "pqc")]
    MlKem1024,
}

pub(crate) fn select_key(key_type: &Option<KeyType>) -> Result<PKey<Private>, ErrorStack> {
    match key_type {
        Some(KeyType::P224) => {
            let group = EcGroup::from_curve_name(Nid::SECP224R1)?;
            let ec_key = EcKey::generate(&group)?;
            PKey::from_ec_key(ec_key)
        }
        Some(KeyType::P256) => {
            let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
            let ec_key = EcKey::generate(&group)?;
            PKey::from_ec_key(ec_key)
        }
        Some(KeyType::P384) => {
            let group = EcGroup::from_curve_name(Nid::SECP384R1)?;
            let ec_key = EcKey::generate(&group)?;
            PKey::from_ec_key(ec_key)
        }
        Some(KeyType::P521) => {
            let group = EcGroup::from_curve_name(Nid::SECP521R1)?;
            let ec_key = EcKey::generate(&group)?;
            PKey::from_ec_key(ec_key)
        }
        Some(KeyType::Ed25519) => PKey::generate_ed25519(),
        #[cfg(feature = "pqc")]
        Some(KeyType::MlDsa44) => generate_pqc_key("ML-DSA-44"),
        #[cfg(feature = "pqc")]
        Some(KeyType::MlDsa65) => generate_pqc_key("ML-DSA-65"),
        #[cfg(feature = "pqc")]
        Some(KeyType::MlDsa87) => generate_pqc_key("ML-DSA-87"),
        #[cfg(feature = "pqc")]
        Some(KeyType::SlhDsaSha2_128s) => generate_pqc_key("SLH-DSA-SHA2-128s"),
        #[cfg(feature = "pqc")]
        Some(KeyType::SlhDsaSha2_192s) => generate_pqc_key("SLH-DSA-SHA2-192s"),
        #[cfg(feature = "pqc")]
        Some(KeyType::SlhDsaSha2_256s) => generate_pqc_key("SLH-DSA-SHA2-256s"),
        #[cfg(feature = "pqc")]
        Some(KeyType::MlKem512) => generate_pqc_key("ML-KEM-512"),
        #[cfg(feature = "pqc")]
        Some(KeyType::MlKem768) => generate_pqc_key("ML-KEM-768"),
        #[cfg(feature = "pqc")]
        Some(KeyType::MlKem1024) => generate_pqc_key("ML-KEM-1024"),
        Some(KeyType::RSA4096) => {
            let rsa = Rsa::generate(4096)?;
            PKey::from_rsa(rsa)
        }
        _ => {
            let rsa = Rsa::generate(2048)?;
            PKey::from_rsa(rsa)
        }
    }
}

#[cfg(feature = "pqc")]
mod pqc {
    use foreign_types::ForeignType;
    use openssl::error::ErrorStack;
    use openssl::pkey::{PKey, Private};
    use std::ffi::CString;

    unsafe extern "C" {
        fn EVP_PKEY_CTX_new_from_name(
            libctx: *mut std::ffi::c_void,
            name: *const std::os::raw::c_char,
            propquery: *const std::os::raw::c_char,
        ) -> *mut openssl_sys::EVP_PKEY_CTX;
        fn EVP_PKEY_keygen_init(ctx: *mut openssl_sys::EVP_PKEY_CTX) -> std::os::raw::c_int;
        fn EVP_PKEY_generate(
            ctx: *mut openssl_sys::EVP_PKEY_CTX,
            ppkey: *mut *mut openssl_sys::EVP_PKEY,
        ) -> std::os::raw::c_int;
        fn EVP_PKEY_CTX_free(ctx: *mut openssl_sys::EVP_PKEY_CTX);
        /// Returns 1 if `pkey` is of algorithm `name`, 0 otherwise.
        /// Use this instead of `EVP_PKEY_id` for provider-only algorithms
        /// (ML-DSA, SLH-DSA) whose legacy NID is -1.
        pub fn EVP_PKEY_is_a(
            pkey: *mut openssl_sys::EVP_PKEY,
            name: *const std::os::raw::c_char,
        ) -> std::os::raw::c_int;
    }

    /// RAII guard that frees an `EVP_PKEY_CTX` on drop, including unwinds.
    struct PkeyCtx(*mut openssl_sys::EVP_PKEY_CTX);

    impl Drop for PkeyCtx {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { EVP_PKEY_CTX_free(self.0) }
            }
        }
    }

    /// Generate a post-quantum signing key by OpenSSL EVP algorithm name.
    ///
    /// Accepts the FIPS 204 / FIPS 205 canonical names:
    /// `"ML-DSA-44"`, `"ML-DSA-65"`, `"ML-DSA-87"`,
    /// `"SLH-DSA-SHA2-128s"`, `"SLH-DSA-SHA2-192s"`, `"SLH-DSA-SHA2-256s"`.
    ///
    /// Returns `Err(ErrorStack)` if the algorithm is unknown to the linked
    /// OpenSSL, keygen init fails, or key generation fails. Never panics,
    /// never leaks the `EVP_PKEY_CTX`.
    pub(crate) fn generate_pqc_key(alg_name: &str) -> Result<PKey<Private>, ErrorStack> {
        let cname = CString::new(alg_name).expect("alg_name contains interior NUL");

        // SAFETY: NULL libctx => default library context. NULL propquery matches
        // every provider. The returned ctx is owned by PkeyCtx, freed on all paths.
        let ctx_ptr = unsafe {
            EVP_PKEY_CTX_new_from_name(std::ptr::null_mut(), cname.as_ptr(), std::ptr::null())
        };
        if ctx_ptr.is_null() {
            return Err(ErrorStack::get());
        }
        let ctx = PkeyCtx(ctx_ptr);

        if unsafe { EVP_PKEY_keygen_init(ctx.0) } <= 0 {
            return Err(ErrorStack::get());
        }

        let mut pkey_ptr: *mut openssl_sys::EVP_PKEY = std::ptr::null_mut();
        if unsafe { EVP_PKEY_generate(ctx.0, &mut pkey_ptr) } <= 0 {
            return Err(ErrorStack::get());
        }
        if pkey_ptr.is_null() {
            return Err(ErrorStack::get());
        }

        // SAFETY: EVP_PKEY_generate returned ownership of a freshly-allocated
        // EVP_PKEY. PKey::from_ptr takes ownership and frees on drop.
        Ok(unsafe { PKey::<Private>::from_ptr(pkey_ptr) })
    }
}
#[cfg(feature = "pqc")]
pub(crate) use pqc::generate_pqc_key;

#[cfg(feature = "pqc")]
pub(crate) fn is_pqc_pkey<T>(pkey: &PKey<T>) -> bool {
    use std::ffi::CString;
    use std::sync::OnceLock;

    // Cache the CStrings so we don't rebuild them per call.
    static NAMES: OnceLock<[CString; 6]> = OnceLock::new();
    let names = NAMES.get_or_init(|| {
        [
            CString::new("ML-DSA-44").unwrap(),
            CString::new("ML-DSA-65").unwrap(),
            CString::new("ML-DSA-87").unwrap(),
            CString::new("SLH-DSA-SHA2-128s").unwrap(),
            CString::new("SLH-DSA-SHA2-192s").unwrap(),
            CString::new("SLH-DSA-SHA2-256s").unwrap(),
        ]
    });
    use foreign_types::ForeignType;
    let ptr = pkey.as_ptr();
    names
        .iter()
        // SAFETY: EVP_PKEY_is_a accepts any NUL-terminated C string and a
        // valid EVP_PKEY*; returns 0 for mismatch, 1 for match — never UB.
        .any(|n| unsafe { pqc::EVP_PKEY_is_a(ptr, n.as_ptr()) } == 1)
}

/// Returns true if `pkey` is an ML-KEM (FIPS 203) key-encapsulation key.
///
/// This is deliberately separate from [`is_pqc_pkey`]: ML-KEM keys are *not*
/// signature keys. Per draft-ietf-lamps-kyber-certificates they may only assert
/// the `keyEncipherment` KeyUsage bit, and they cannot produce signatures — so
/// they can neither self-sign a certificate nor sign a CSR. Keeping them out of
/// `is_pqc_pkey` also keeps them out of [`is_digestless_key`], which gates the
/// signing path.
#[cfg(feature = "pqc")]
pub(crate) fn is_mlkem_pkey<T>(pkey: &PKey<T>) -> bool {
    use std::ffi::CString;
    use std::sync::OnceLock;

    // Cache the CStrings so we don't rebuild them per call.
    static NAMES: OnceLock<[CString; 3]> = OnceLock::new();
    let names = NAMES.get_or_init(|| {
        [
            CString::new("ML-KEM-512").unwrap(),
            CString::new("ML-KEM-768").unwrap(),
            CString::new("ML-KEM-1024").unwrap(),
        ]
    });
    use foreign_types::ForeignType;
    let ptr = pkey.as_ptr();
    names
        .iter()
        // SAFETY: EVP_PKEY_is_a accepts any NUL-terminated C string and a
        // valid EVP_PKEY*; returns 0 for mismatch, 1 for match — never UB.
        .any(|n| unsafe { pqc::EVP_PKEY_is_a(ptr, n.as_ptr()) } == 1)
}

/// Returns true for keys whose OpenSSL EVP signing path does not take an
/// external digest. Today: Ed25519 and (when the `pqc` feature is enabled)
/// the six FIPS 204 / 205 post-quantum variants.
pub(crate) fn is_digestless_key(pkey: &PKey<Private>) -> bool {
    if pkey.id() == Id::ED25519 {
        return true;
    }
    #[cfg(feature = "pqc")]
    {
        return is_pqc_pkey(pkey);
    }
    #[allow(unreachable_code)]
    false
}

/// Reject signing operations that an ML-KEM key cannot perform.
///
/// ML-KEM is a key-encapsulation mechanism and cannot produce signatures, so it
/// can neither self-sign a certificate nor sign a CSR. `message` lets the caller
/// supply the context-specific guidance. Returns `Ok(())` for any non-ML-KEM key.
#[cfg(feature = "pqc")]
pub(crate) fn reject_mlkem_signing(
    pkey: &PKey<Private>,
    message: &'static str,
) -> Result<(), Box<dyn std::error::Error>> {
    if is_mlkem_pkey(pkey) {
        return Err(message.into());
    }
    Ok(())
}
