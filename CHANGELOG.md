# Changelog

All notable changes to this project will be documented in this file.

## [0.5.2] - 2026-08-10

One fix, in two places, plus the reader half of the same rule. Nothing breaks.

### Fixed
- **Validity dates were encoded as `GeneralizedTime` regardless of year.** RFC 5280
  §4.1.2.5.1 requires `UTCTime` for dates through 2049 and `GeneralizedTime` for
  2050 and later; §5.1.2.4–5.1.2.6 impose the same rule on a CRL's `thisUpdate`,
  `nextUpdate` and each entry's `revocationDate`. Every certificate built with an
  explicit `valid_from`/`valid_to`, and every CRL this crate has produced, used
  `GeneralizedTime` throughout.

  OpenSSL accepts that, which is why it went unnoticed for nine releases — the
  crate's own tests, `verify_cert` and `openssl x509 -text` are all satisfied.
  Stricter verifiers are not: LibreSSL rejects the certificate outright with
  `format error in certificate's notBefore field`, so a certificate that verified
  in one toolchain failed in another for reasons nothing in the API surface hinted
  at. It also could not be seen in a log or an assertion, because `Asn1Time`'s
  `Display` renders both encodings identically — only the DER tag byte differs.

  Both encoders now follow the year boundary. The certificate path delegates to
  OpenSSL's `ASN1_TIME_set`, which implements the rule; the CRL path, which writes
  DER directly and has no `ASN1_TIME` to defer to, chooses the tag and the year
  width together.
- **The CRL parser read `UTCTime` with the wrong century for years 50–68.** RFC 5280
  fixes `UTCTime`'s two-digit year at 00–49 → 2000–2049 and 50–99 → 1950–1999.
  The parser used chrono's `%y`, which pivots at 68 instead, so a `thisUpdate` of
  `55…` was read as 2055 rather than 1955. Latent until now, since the writer never
  emitted `UTCTime`; reachable for CRLs from other implementations.

New certificates and CRLs are conforming from this release. **Artefacts already on
disk keep their old encoding** — a CA or leaf issued by an earlier version must be
reissued before a strict verifier will accept it.

## [0.5.1] - 2026-08-03

Two regressions from the SubjectAltName rework in 0.5.0. Both are fixes; nothing
breaks.

### Fixed
- **A signing request built with only a common name emitted an *empty*
  SubjectAltName extension.** Before 0.5.0 the CN was inserted into
  `alternative_names` as it was set, so the CSR path always had at least one
  name to write. 0.5.0 moved that decision to certificate build time and did not
  update the CSR path, which left it writing an extension with zero entries —
  forbidden by RFC 5280 §4.2.1.6 — and silently dropping the common name from
  the request. The CSR path now includes the CN and omits the extension entirely
  when there are no names.
- **A common name also listed in `alternative_names` was emitted twice.** The CN
  was appended to a list already collected from `alternative_names` with no
  check, so `common_name("example.com")` together with
  `alternative_names(["example.com"])` produced `DNS:example.com` twice. Harmless
  to verifiers, but wrong. The CN is now skipped when the caller already listed
  it.

Both paths now share one `san_names` helper, so certificate and CSR SAN
assembly cannot drift apart again — which is how these two arose.

## [0.5.0] - 2026-08-03

Released as `0.5.0` rather than `0.4.10` because of the breaking changes below.
Cargo treats the minor version as the compatibility unit for `0.y.z` releases,
so a `0.4.10` would have been picked up automatically by anyone depending on
`"0.4"` — including the new CSR error path. This way the upgrade is a choice.

### Breaking

- **`BuilderCommon::set_private_key` is a new required trait method.**
  `BuilderCommon` is publicly exported, so any implementation of it outside this
  crate must add the method to compile. Implementors of `UseesBuilderFields` are
  unaffected — the corresponding `private_key` builder method has a default body.
- **Signing a CSR now fails if it carries a subject alternative name this crate
  cannot reproduce** (`directoryName`, `otherName`, `x400Address`,
  `ediPartyName`), rather than silently dropping it. Previously such a CSR was
  signed and the requester received a certificate quietly missing an identity
  they had asked for. A malformed `iPAddress` — neither 4 nor 16 octets — is
  likewise rejected rather than skipped. Calls that previously succeeded may now
  return `Err`.
- **The `KeyUsage` extension is now marked critical**, as RFC 5280 §4.2.1.3 says
  conforming CAs SHOULD. This changes the meaning of every certificate the crate
  emits: a verifier must now enforce the key usage bits rather than being free to
  ignore them, so a certificate used outside its declared usage may start being
  rejected. `ExtendedKeyUsage` is deliberately left non-critical.
- **CA certificates no longer carry a SubjectAltName.** The common name used to
  be copied into `alternative_names` as the CN was set, so every certificate
  received a SAN whether or not it made sense — a root named `My Test Ca` was
  issued with `DNS:My Test Ca`, which is not a valid DNS name. The SAN list is
  now assembled when the certificate is built, and the CN is copied in only for
  end-entity certificates. CA certificates, root and intermediate alike, get no
  SAN at all: a CA is identified by its distinguished name and key identifier
  during path validation, and no verifier consults its SAN.

  Self-signed **leaf** certificates are unaffected and still receive the CN —
  `CertBuilder::new().common_name("localhost").build_and_self_sign()` continues
  to produce `DNS:localhost`, which matters because RFC 6125 verifiers ignore the
  CN and match only against the SAN.

  If a certificate would end up with no names at all, the extension is now
  omitted rather than emitted empty, which RFC 5280 §4.2.1.6 forbids.

  Code that inspects a CA's SAN will see `None` where it previously saw the CN.
  Nothing in certificate verification depends on it.

### Added
- `private_key` on the certificate and CSR builders — use a private key you
  already hold instead of generating a new one. Takes precedence over
  `key_type`, since the algorithm is a property of the key. Useful for
  re-issuing against an existing key, and for minting many certificates cheaply
  (key generation, not signing, dominates issuance cost).
- Subject alternative names now support `iPAddress`. An entry in
  `alternative_names` that parses as an IPv4 or IPv6 address is emitted as an
  `iPAddress` SAN instead of a `dNSName`, so certificates for IP literals are
  now accepted by clients that previously rejected them.
- When issuing from a CSR, `rfc822Name`, `uniformResourceIdentifier` and
  `registeredID` subject alternative names are carried across to the issued
  certificate. Previously only `dNSName` was.

### Fixed
- **Private keys are no longer written world-readable.** `save()` used
  `File::create`, leaving the key at the process umask default — typically
  `0644`. The key is now created with mode `0600` on Unix, applied at creation
  rather than afterwards so there is no window in which it is readable. Saving
  over an existing key file also tightens it, so a key written by an earlier
  version is corrected the next time it is saved. Note that a key never saved
  again keeps its old permissions — check any existing key directories.
- Key generation failures return an error instead of panicking. The two
  `select_key(..).unwrap()` call sites now propagate with `?`.

## [0.4.9] - 2026-07-28

### Added
- `Certificate::load_cert` — loads an X.509 certificate from a PEM file without a
  private key (`pkey: None`). Intended for chain entries passed to
  `CertBuilder::build_and_sign_with_chain` or `CsrOptions::pathlen`, which read
  the certificate but never the key.
- `Certificate` now derives `Debug`, so it (and types wrapping it) can be used
  with `assert!`/`unwrap_err` and logged. The `pkey` field prints opaquely and
  does not expose private key material.

### Changed
- Bumped `num-bigint` dependency from 0.4.6 to 0.5.1.

## [0.4.8] - 2026-06-27

### Added
- Path length constraint support: `CertBuilder::pathlen` and `CsrOptions::pathlen`
  set the BasicConstraints path length (max intermediate CAs below the cert).
- `CertBuilder::build_and_sign_with_chain` issues a CA and enforces the path
  length against the signer's chain — rejecting a CA that exceeds what its issuer
  permits. The same enforcement applies when issuing from a CSR.

### Changed
- Add validation that a certificate signing request with PQC key and 
  keyEncipherment key usage do not return a signed certificate
- Added so that the public key in the Certificate signing request is 
  validated before a certificate is generated

## [0.4.7] - 2026-06-20

### Added

- Certificate Policies (`id-ce-certificatePolicies`, OID `2.5.29.32`) support.
  New `CertificatePolicy` enum with named variants for the CA/Browser Forum
  reserved OIDs — `DomainValidated` (`2.23.140.1.2.1`), `OrganizationValidated`
  (`2.23.140.1.2.2`), `IndividualValidated` (`2.23.140.1.2.3`),
  `ExtendedValidation` (`2.23.140.1.1`), `AnyPolicy` (`2.5.29.32.0`) — plus an
  `Other(String)` escape hatch for private or arbitrary policy OIDs.
- `CertBuilder::certificate_policies(Vec<CertificatePolicy>)` — adds the
  certificatePolicies extension to directly-built certificates
  (`build_and_sign` / `build_and_self_sign`).
- `CsrOptions::certificate_policies(Vec<CertificatePolicy>)` — sets the policies
  when issuing a certificate from a CSR (`build_signed_certificate`). The policy
  is **issuer-set** at signing time, not taken from the requester's CSR.

### Notes

- Policies are opt-in: with none set, no certificatePolicies extension is
  emitted (unchanged output for existing callers).
- Only bare policy OIDs are encoded; policy qualifiers (CPS URI / user notice)
  are not yet supported. A malformed `Other(..)` OID fails at build time.

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
