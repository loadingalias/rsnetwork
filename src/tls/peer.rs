//! The authentication of a peer: the key algorithm of its end-entity certificate, which signed its
//! handshake.

use rustls::pki_types::alg_id;

use super::Authentication;

/// The key algorithm of the certificate `der`: the AlgorithmIdentifier of its
/// subjectPublicKeyInfo (RFC 5280, section 4.1), or `None` for another algorithm. The trust roots
/// verified the certificate, so its DER is well formed.
pub(super) fn authentication(der: &[u8]) -> Option<Authentication> {
    let (certificate, _) = element(der, SEQUENCE)?;
    let (mut tbs, _) = element(certificate, SEQUENCE)?;
    // The version is explicit and optional.
    if tbs.first() == Some(&VERSION) {
        tbs = element(tbs, VERSION)?.1;
    }
    // The serial number, the signature algorithm, the issuer, the validity, and the subject.
    for tag in [INTEGER, SEQUENCE, SEQUENCE, SEQUENCE, SEQUENCE] {
        tbs = element(tbs, tag)?.1;
    }
    let (key, _) = element(tbs, SEQUENCE)?;
    let (algorithm, _) = element(key, SEQUENCE)?;
    [
        (alg_id::ECDSA_P256, Authentication::EcdsaP256),
        (alg_id::ECDSA_P384, Authentication::EcdsaP384),
        (alg_id::ED25519, Authentication::Ed25519),
        (alg_id::RSA_ENCRYPTION, Authentication::Rsa),
    ]
    .into_iter()
    .find_map(|(id, authentication)| (id.as_ref() == algorithm).then_some(authentication))
}

const INTEGER: u8 = 0x02;
const SEQUENCE: u8 = 0x30;
/// The explicit tag 0 of the version of a certificate.
const VERSION: u8 = 0xa0;

/// Splits the DER element with `tag` at the start of `bytes`: its content, and the bytes after
/// it. A length takes at most 4 bytes.
fn element(bytes: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    let (&first, rest) = bytes.split_first()?;
    if first != tag {
        return None;
    }
    let (&len, rest) = rest.split_first()?;
    let (len, rest) = match len {
        0..=0x7f => (usize::from(len), rest),
        0x81..=0x84 => {
            let (digits, rest) = rest.split_at_checked(usize::from(len & 0x7f))?;
            let len = digits.iter().fold(0_u32, |len, &digit| (len << 8) | u32::from(digit));
            (usize::try_from(len).ok()?, rest)
        }
        _ => return None,
    };
    rest.split_at_checked(len)
}
