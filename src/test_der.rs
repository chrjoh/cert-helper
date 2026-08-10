//! Test-only helpers for asserting on DER encodings.
//!
//! These exist for one reason: `Asn1Time`'s `Display` renders `UTCTime` and
//! `GeneralizedTime` identically (`Aug  7 00:00:00 2026 GMT`), and so does
//! `openssl x509 -text`. A test that asserts on either passes against both
//! encodings and proves nothing — which is how CH9 survived nine releases.
//! Only the DER tag byte distinguishes them.

/// ASN.1 universal tag for `UTCTime` (`YYMMDDHHMMSSZ`, 13 bytes).
pub(crate) const TAG_UTCTIME: u8 = 0x17;
/// ASN.1 universal tag for `GeneralizedTime` (`YYYYMMDDHHMMSSZ`, 15 bytes).
pub(crate) const TAG_GENERALIZEDTIME: u8 = 0x18;

/// One ASN.1 time value found in a DER blob: its tag and its textual value.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct DerTime {
    pub tag: u8,
    pub value: String,
}

impl DerTime {
    pub fn is_utc_time(&self) -> bool {
        self.tag == TAG_UTCTIME
    }
}

/// Every ASN.1 time value in `der`, in encounter order.
///
/// Scans rather than parses, but only accepts a candidate whose payload is the
/// exact length its tag requires *and* consists entirely of ASCII digits
/// followed by `Z`. Random signature or key bytes essentially cannot satisfy
/// that — twelve or fourteen digits at odds of 10/256 each — so the match is
/// reliable without teaching this helper the whole of X.509.
pub(crate) fn der_times(der: &[u8]) -> Vec<DerTime> {
    let mut out = Vec::new();
    for i in 0..der.len().saturating_sub(2) {
        let tag = der[i];
        let expected_len = match tag {
            TAG_UTCTIME => 13,
            TAG_GENERALIZEDTIME => 15,
            _ => continue,
        };
        if der[i + 1] as usize != expected_len {
            continue;
        }
        let Some(payload) = der.get(i + 2..i + 2 + expected_len) else {
            continue;
        };
        let (digits, zulu) = payload.split_at(expected_len - 1);
        if zulu != b"Z" || !digits.iter().all(|b| b.is_ascii_digit()) {
            continue;
        }
        out.push(DerTime {
            tag,
            value: String::from_utf8_lossy(payload).into_owned(),
        });
    }
    out
}

/// The `notBefore` and `notAfter` of a certificate, located structurally.
///
/// `Validity` is the only `SEQUENCE` in a certificate whose contents are exactly
/// two ASN.1 time values and nothing else, so that shape identifies it without
/// walking the whole TBSCertificate.
///
/// # Panics
/// If no such sequence is present — a certificate without a validity period is a
/// test failure, not a case to handle.
pub(crate) fn certificate_validity(der: &[u8]) -> (DerTime, DerTime) {
    for i in 0..der.len().saturating_sub(2) {
        if der[i] != 0x30 {
            continue;
        }
        let len = der[i + 1] as usize;
        let Some(body) = der.get(i + 2..i + 2 + len) else {
            continue;
        };
        let times = der_times(body);
        // Exactly two times, and they account for every byte of the sequence.
        let consumed: usize = times
            .iter()
            .map(|t| 2 + if t.is_utc_time() { 13 } else { 15 })
            .sum();
        if times.len() == 2 && consumed == body.len() {
            let mut it = times.into_iter();
            return (it.next().unwrap(), it.next().unwrap());
        }
    }
    panic!("no validity sequence found in certificate DER");
}
