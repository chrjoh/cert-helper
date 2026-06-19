# Changelog

All notable changes to this project will be documented in this file.

## [0.4.6] - 2026-06-19

### Added

- ML-KEM (FIPS 203, formerly Kyber) key-encapsulation support behind the `pqc`
  feature. New `KeyType` variants: `MlKem512`, `MlKem768`, `MlKem1024`
  (OIDs `2.16.840.1.101.3.4.4.{1,2,3}`). Keys are generated via the existing
  `openssl-sys` FFI path; requires OpenSSL ≥ 3.5 at build and runtime.
- KeyUsage lint for ML-KEM, per draft-ietf-lamps-kyber-certificates: when an
  ML-KEM key is used and a KeyUsage is present it must be exactly
  `keyEncipherment` (`Usage::encipherment`) and nothing else. Any other bit
  (`digitalSignature`, `keyAgreement`, `dataEncipherment`, `certsign`, `crlsign`)
  is rejected on both the certificate and CSR paths.
- Example `pqc_mlkem_issued_by_ca` showing the valid ML-KEM issuance flow.

### Notes

- ML-KEM is a key-encapsulation mechanism and cannot produce signatures, so an
  ML-KEM certificate cannot be self-signed (`build_and_self_sign`) nor requested
  via a CSR (`certificate_signing_request`) — both return an `Err`. Issue an
  ML-KEM certificate with `build_and_sign` using a separate signing CA.

### Changed

- Internal: the digest-less signing helpers (`sign_certificate_digestless` /
  `sign_x509_req_digestless`) now free the `EVP_MD_CTX` via an RAII guard
  (`MdCtx`) instead of manual `EVP_MD_CTX_free` on each branch, making cleanup
  panic- and refactor-safe. No public-API or behavioral change.

## [0.4.5] - 2026-06-18

### Added

- Reject `keyEncipherment` (`Usage::encipherment`) on post-quantum signature keys
  (ML-DSA / SLH-DSA). These algorithms are signature-only and cannot perform key
  encipherment, so `build_and_self_sign`, `build_and_sign`, and
  `certificate_signing_request` now return an `Err` for that combination instead of
  emitting a non-conformant certificate/CSR. (`pqc` feature only.)

## [0.4.4] - 2026-06-13

### Security

- Updated `openssl` 0.10.78 → 0.10.81 and `openssl-sys` 0.9.114 → 0.9.117 in the
  lock file to pick up upstream advisory fixes.

### Fixed

- Hardened CRL handling against malformed input — replaced panics (`unwrap`)
  with propagated `Result` errors:
  - `X509CrlBuilder::from_der` now returns an error instead of panicking when a
    CRL has a missing/invalid `thisUpdate`/`nextUpdate` or an unparseable
    revocation date.
  - `X509CrlBuilder::build_and_sign` now returns an error (instead of panicking)
    when the signer certificate uses a signature algorithm that is not mapped to
    a known OID. The algorithm OID is resolved once up front before DER encoding.
- Certificate/CRL signing validity checks (`can_sign_cert` / `can_sign_crl`) now
  use OpenSSL's native ASN.1 time comparison instead of formatting the times to
  strings and re-parsing them with `chrono`. This removes a panic on times that
  do not match the expected `"%b %e %H:%M:%S %Y GMT"` rendering (e.g. post-2049
  `GeneralizedTime`) and drops a locale/format dependency. Validity semantics
  (`not_before <= now < not_after`) are unchanged.

No public API or behavioral changes for valid input; affected functions already
returned `Result`, so previously-panicking inputs now surface as `Err`.

## [0.4.3] - 2026-04-23

### Added

- Experimental post-quantum key support behind the `pqc` Cargo feature.
  New `KeyType` variants: `MlDsa44`, `MlDsa65`, `MlDsa87`, `SlhDsaSha2_128s`,
  `SlhDsaSha2_192s`, `SlhDsaSha2_256s`. Keys are generated via direct
  `openssl-sys` FFI (`EVP_PKEY_CTX_new_from_name` / `EVP_PKEY_generate`);
  signing reuses the Ed25519 digest-less path (`X509_sign` / `X509_REQ_sign`
  with `md = NULL`). Requires OpenSSL ≥ 3.5 at build and runtime, enforced by
  `build.rs`. Non-breaking: builds without `--features pqc` are unchanged.

### Changed

- Internal: `sign_certificate_ed25519` / `sign_x509_req_ed25519` renamed to
  `sign_certificate_digestless` / `sign_x509_req_digestless`. New crate-visible
  helper `is_digestless_key` accepts Ed25519 and PQC keys. No public-API impact.

## [0.4.2] - 2026-04-23

Version bumps:

- bitflags 2.9.1 → 2.11.1
- bumpalo 3.19.0 → 3.20.2
- cc 1.2.30 → 1.2.60
- cfg-if 1.0.1 → 1.0.4
- chrono 0.4.41 → 0.4.44
- data-encoding 2.9.0 → 2.10.0
- errno 0.3.13 → 0.3.14
- fastrand 2.3.0 → 2.4.1
- getrandom 0.3.3 → 0.4.2
- iana-time-zone 0.1.63 → 0.1.65
- itoa 1.0.15 → 1.0.18
- js-sys 0.3.77 → 0.3.95
- libc 0.2.174 → 0.2.185
- linux-raw-sys 0.9.4 → 0.12.1
- log 0.4.27 → 0.4.29
- memchr 2.7.5 → 2.8.0
- once_cell 1.21.3 → 1.21.4
- openssl 0.10.73 → 0.10.78
- openssl-sys 0.9.109 → 0.9.114
- pkg-config 0.3.32 → 0.3.33
- proc-macro2 1.0.95 → 1.0.106
- quote 1.0.40 → 1.0.45
- r-efi 5.3.0 → 6.0.0
- rustix 1.0.8 → 1.1.4
- rustversion 1.0.21 → 1.0.22
- syn 2.0.104 → 2.0.117
- tempfile 3.20.0 → 3.27.0
- thiserror / thiserror-impl 2.0.12 → 2.0.18
- unicode-ident 1.0.18 → 1.0.24
- wasm-bindgen (+ macros/shared) 0.2.100 → 0.2.118
- windows-core 0.61.2 → 0.62.2, plus related windows-\* crates consolidated onto windows-link (dropping the old windows-targets split)

Added (new transitive deps):

- anyhow, equivalent, find-msvc-tools, foldhash, hashbrown (0.15 + 0.17), heck, id-arena, indexmap, leb128fmt, prettyplease, semver, serde, serde_json, unicode-xid, wasip2, wasip3, wasm-encoder, wasm-metadata, wasmparser, wit-bindgen (0.51 + 0.57),
  wit-bindgen-core, wit-bindgen-rust, wit-bindgen-rust-macro, wit-component, wit-parser, zmij

Removed: android-tzdata, old wit-bindgen-rt, the windows-targets/windows\*\*\*\* platform sub-crates

## [0.4.1] - 2026-04-17

- Security upgrade of time-core to 0.1.8

## [0.4.0] - 2025-08-17

- Add check that signer certificate is valid for signing crl
- Include check that time have valid to and from for signer certificate
- add to_builder method to X509CrlWrapper
- Breaking change:
  - X509CrlBuilder build_and_sign now returns Result<X509CrlWrapper, Box<dyn std::error::Error>>
    instead of Vec<u8>, the der vector can be retrived with to_der() method in X509CrlWrapper

---

## [0.3.14] - 2025-08-16

- Set basic constraint to critical if CA is true

---

## [0.3.13] - 2025-08-15

- Fix bug with adding revoked certificates and CRL

---

## [0.3.12] - 2025-08-15

- Fix so that if certificate serial is in the CRL list do not add duplicate

---

## [0.3.11] - 2025-08-14

- Add X509CrlWrapper to simplify working with CRL

---

## [0.3.10] - 2025-08-13

### Added

- Support for ED25519 keys in certificate and CSR generation.
- ED25519 signing for CRLs.
- Error handling for ED25519 signing.

---

## [0.3.9] - 2025-08-07

### Added

- Subject Key Identifier (SKI) and Authority Key Identifier (AKI) to certificate generation.
- SKI and AKI support for certificates created from CSRs.
- AKI support for CRLs.

---

## [0.3.8] - 2025-07-31

### Fixed

- Improved documentation.
- Fixed parsing of CRL DER with optional values.

---

## [0.3.6] - 2025-07-30

### Added

- CRL (Certificate Revocation List) generation capability.

---

## [0.3.0] - 2025-07-11

### Added

- Set basic constraints before generating certificates from CSRs.
- Enabled creation of CA certificates from CSRs.

---

## [0.2.0] - 2025-07-10

### Added

- Certificate Signing Request (CSR) builder.
- Support for creating signed certificates from CSRs.

### Fixed

- Issue with multiple calls to `key_usage`.
