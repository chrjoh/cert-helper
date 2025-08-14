# Changelog

All notable changes to this project will be documented in this file.

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
