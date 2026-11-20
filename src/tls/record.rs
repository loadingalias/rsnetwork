//! The record protection of TLS 1.3 after the handshake (RFC 8446, section 5): the length check of
//! each record, its nonce, its open in place, and its seal into the output.
//!
//! rustls gives the traffic keys of each direction when the handshake completes, and after each
//! KeyUpdate. The ciphers of rscrypto keep them, and clear them when they drop.

use core::iter;
use core::ops::Range;

use rscrypto::aead::Nonce96;
use rscrypto::aead::expert::AeadWithNonce as _;
use rscrypto::{
    Aead, AeadGather, Aes128Gcm, Aes128GcmKey, Aes256Gcm, Aes256GcmKey, ChaCha20Poly1305, ChaCha20Poly1305Key,
};
use rustls::ConnectionTrafficSecrets;
use rustls::error::AlertDescription;

#[cfg(test)]
mod tests;

/// The bytes of a record header: the outer content type, the legacy version, and the length.
pub(super) const HEADER: usize = 5;

/// The bytes of the tag of each suite of the provider.
pub(super) const TAG: usize = 16;

/// The most bytes after the header of a protected record (RFC 8446, section 5.2).
pub(super) const PROTECTED_MAX: usize = (1 << 14) + 256;

/// The most content in one record (RFC 8446, section 5.1).
pub(super) const CONTENT_MAX: usize = 1 << 14;

/// The outer content type of each protected record, application data, and its legacy version.
const OUTER: [u8; 3] = [23, 3, 3];

/// The content type of a record (RFC 8446, section 5.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum Content {
    Alert = 21,
    Handshake = 22,
    Data = 23,
}

/// A record that breaks RFC 8446: the alert that this end sends, and the reason of its error.
#[derive(Clone, Copy, Debug)]
pub(super) struct Violation {
    pub(super) alert: AlertDescription,
    pub(super) reason: &'static str,
}

impl Violation {
    pub(super) const fn new(alert: AlertDescription, reason: &'static str) -> Self {
        Self { alert, reason }
    }
}

/// The bytes of the record that starts `pending`, from its header: `None` until the header is
/// complete. Refuses a header that RFC 8446 forbids after the handshake.
pub(super) fn length(pending: &[u8]) -> Result<Option<usize>, Violation> {
    let Some(header) = pending.first_chunk::<HEADER>() else {
        return Ok(None);
    };
    if header[0] != OUTER[0] {
        return Err(Violation::new(
            AlertDescription::UnexpectedMessage,
            "a TLS record after the handshake is not protected",
        ));
    }
    let protected = usize::from(u16::from_be_bytes([header[3], header[4]]));
    if protected > PROTECTED_MAX {
        return Err(Violation::new(
            AlertDescription::RecordOverflow,
            "a TLS record is longer than the protocol allows",
        ));
    }
    Ok(Some(HEADER + protected))
}

/// The content of a record that [`Protection::open`] opened.
#[derive(Debug)]
pub(super) struct Opened {
    pub(super) content: Content,
    /// The range of the content in the record.
    pub(super) range: Range<usize>,
}

/// The cipher of one direction, with its key.
enum Cipher {
    Aes128(Aes128Gcm),
    Aes256(Aes256Gcm),
    ChaCha(ChaCha20Poly1305),
}

/// The protection of one direction: its cipher, its IV, and the sequence number of its next
/// record.
pub(super) struct Protection {
    cipher: Cipher,
    iv: [u8; 12],
    seq: u64,
}

impl Protection {
    /// The protection of `secrets`, whose next record has the sequence number `seq`. Gives `None`
    /// for a suite that the provider does not have.
    pub(super) fn new(secrets: &ConnectionTrafficSecrets, seq: u64) -> Option<Self> {
        // Each key fills its rscrypto type in place, so no other copy of it stays.
        let (cipher, iv) = match secrets {
            ConnectionTrafficSecrets::Aes128Gcm { key, iv } => {
                let key: &[u8; 16] = key.as_ref().try_into().ok()?;
                let key = Aes128GcmKey::generate(|bytes| bytes.copy_from_slice(key));
                (Cipher::Aes128(Aes128Gcm::new(&key)), iv)
            }
            ConnectionTrafficSecrets::Aes256Gcm { key, iv } => {
                let key: &[u8; 32] = key.as_ref().try_into().ok()?;
                let key = Aes256GcmKey::generate(|bytes| bytes.copy_from_slice(key));
                (Cipher::Aes256(Aes256Gcm::new(&key)), iv)
            }
            ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv } => {
                let key: &[u8; 32] = key.as_ref().try_into().ok()?;
                let key = ChaCha20Poly1305Key::generate(|bytes| bytes.copy_from_slice(key));
                (Cipher::ChaCha(ChaCha20Poly1305::new(&key)), iv)
            }
            _ => return None,
        };
        Some(Self {
            cipher,
            iv: iv.as_ref().try_into().ok()?,
            seq,
        })
    }

    /// The sequence number of the next record.
    pub(super) fn seq(&self) -> u64 {
        self.seq
    }

    /// The nonce of the next record: the IV, with the sequence number in its last 8 bytes by
    /// exclusive or (RFC 8446, section 5.3).
    fn nonce(&self) -> Nonce96 {
        let mut nonce = self.iv;
        for (byte, seq) in nonce[4..].iter_mut().zip(self.seq.to_be_bytes()) {
            *byte ^= seq;
        }
        Nonce96::from_bytes(nonce)
    }

    /// Opens `record`, one complete record with its header, in place. Gives its content type and
    /// the range of its content. A refused record keeps no plaintext.
    pub(super) fn open(&mut self, record: &mut [u8]) -> Result<Opened, Violation> {
        const BAD_TAG: Violation =
            Violation::new(AlertDescription::BadRecordMac, "a TLS record failed its authentication");
        let Some((header, body)) = record.split_first_chunk_mut::<HEADER>() else {
            return Err(BAD_TAG);
        };
        let aad = *header;
        let Some((text, tag)) = body.split_last_chunk_mut::<TAG>() else {
            return Err(BAD_TAG);
        };
        let nonce = self.nonce();
        let opened = match &self.cipher {
            Cipher::Aes128(cipher) => open(cipher, &nonce, &aad, text, tag),
            Cipher::Aes256(cipher) => open(cipher, &nonce, &aad, text, tag),
            Cipher::ChaCha(cipher) => open(cipher, &nonce, &aad, text, tag),
        };
        opened.map_err(|()| BAD_TAG)?;
        self.seq = self.seq.checked_add(1).ok_or(Violation::new(
            AlertDescription::UnexpectedMessage,
            "the peer sent more TLS records under one key than a sequence number counts",
        ))?;
        if text.len() > CONTENT_MAX + 1 {
            return Err(Violation::new(
                AlertDescription::RecordOverflow,
                "a TLS record has more content than the protocol allows",
            ));
        }
        // The content type is the last byte that is not padding (RFC 8446, section 5.4).
        let Some(end) = text.iter().rposition(|&byte| byte != 0) else {
            return Err(Violation::new(
                AlertDescription::UnexpectedMessage,
                "a TLS record has no content type",
            ));
        };
        let content = match text[end] {
            21 => Content::Alert,
            22 => Content::Handshake,
            23 => Content::Data,
            _ => {
                return Err(Violation::new(
                    AlertDescription::UnexpectedMessage,
                    "a TLS record has an unknown content type",
                ));
            }
        };
        Ok(Opened {
            content,
            range: HEADER..HEADER + end,
        })
    }

    /// Seals one record of type `content` after the bytes of `out`: the parts of `plaintext` in
    /// their order, at most [`CONTENT_MAX`] bytes. The caller reserved the capacity of the
    /// record, so `out` does not grow. Refuses, and adds nothing, when the cipher refuses.
    pub(super) fn seal(&mut self, content: Content, plaintext: &[&[u8]], out: &mut Vec<u8>) -> Result<(), SealRefused> {
        let len: usize = plaintext.iter().map(|part| part.len()).sum();
        assert!(
            len <= CONTENT_MAX,
            "a sealed record holds at most one record of content"
        );
        // The content, its type, and the tag. The length fits in the 2 bytes of the header.
        let inner = len + 1;
        let [high, low] = u16::try_from(inner + TAG).map_err(|_| SealRefused)?.to_be_bytes();
        let header = [OUTER[0], OUTER[1], OUTER[2], high, low];
        let kind = [content as u8];
        let parts = plaintext.iter().copied().chain(iter::once(&kind[..]));
        let nonce = self.nonce();
        let start = out.len();
        out.extend_from_slice(&header);
        let sealed = match &self.cipher {
            Cipher::Aes128(cipher) => seal(cipher, &nonce, &header, parts, inner, out),
            Cipher::Aes256(cipher) => seal(cipher, &nonce, &header, parts, inner, out),
            Cipher::ChaCha(cipher) => seal(cipher, &nonce, &header, parts, inner, out),
        };
        if sealed.is_err() {
            out.truncate(start);
            return Err(SealRefused);
        }
        // The caller sends a KeyUpdate before the limit of the key, which is below the end of the
        // sequence numbers.
        self.seq = self.seq.checked_add(1).ok_or(SealRefused)?;
        Ok(())
    }
}

/// The cipher refused to seal a record.
#[derive(Clone, Copy, Debug)]
pub(super) struct SealRefused;

/// Opens `text` in place with `cipher`. The cipher clears `text` when the tag fails.
fn open<A: Aead<Nonce = Nonce96>>(
    cipher: &A,
    nonce: &Nonce96,
    aad: &[u8],
    text: &mut [u8],
    tag: &[u8; TAG],
) -> Result<(), ()> {
    let tag = A::tag_from_slice(tag).map_err(|_| ())?;
    cipher.decrypt_in_place(nonce, aad, text, &tag).map_err(|_| ())
}

/// Seals the parts of `plaintext`, `len` bytes, with `cipher` after the bytes of `out`, and then
/// its tag.
fn seal<'a, A: AeadGather<Nonce = Nonce96>>(
    cipher: &A,
    nonce: &Nonce96,
    aad: &[u8],
    plaintext: impl IntoIterator<Item = &'a [u8]>,
    len: usize,
    out: &mut Vec<u8>,
) -> Result<(), ()> {
    let tag = cipher
        .encrypt_gather_append(nonce, aad, plaintext, len, out)
        .map_err(|_| ())?;
    out.extend_from_slice(tag.as_ref());
    Ok(())
}
