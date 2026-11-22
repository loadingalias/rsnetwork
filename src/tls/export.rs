//! The exporter of an established connection (RFC 8446, section 7.5).

use core::fmt;

use super::{Phase, Tls};
use crate::host::{Connection, Engine};

/// The prefix of the exporter labels that the family reserves for its own channels, for example
/// the proofs and the keys of attached channels. Labels that start with `EXPERIMENTAL` are for
/// private use with no registration (RFC 5705, section 4). [`Tls::export`] refuses a label with
/// this prefix.
pub const RESERVED_LABEL_PREFIX: &[u8] = b"EXPERIMENTAL-rsnetwork-";

/// The longest label: the label of `HkdfLabel` holds at most 255 bytes with its prefix `tls13 `
/// (RFC 8446, section 7.1).
pub const EXPORT_LABEL_MAX: usize = 249;

/// The longest context. The exporter hashes the context, so this bounds its work.
pub const EXPORT_CONTEXT_MAX: usize = 1024;

/// The longest output: 255 blocks of SHA-256 (RFC 5869, section 2.3), the limit of the suite with
/// the shortest hash.
pub const EXPORT_OUTPUT_MAX: usize = 255 * 32;

/// Why a connection derives no exporter material.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportError {
    /// The handshake did not complete. Derive after it.
    Handshake,
    /// The connection has no TLS, so it has no exporter.
    Unavailable,
    /// The connection ended: this end closed or failed, or the input of the peer ended. Only a
    /// new connection gives new material.
    Closed,
    /// The request is outside the profile of the exporter: an empty label, a label longer than
    /// [`EXPORT_LABEL_MAX`] or under [`RESERVED_LABEL_PREFIX`], a context longer than
    /// [`EXPORT_CONTEXT_MAX`], or an output of 0 bytes or of more than [`EXPORT_OUTPUT_MAX`].
    Profile,
}

impl fmt::Display for ExportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Handshake => "the TLS handshake did not complete",
            Self::Unavailable => "the connection has no TLS exporter",
            Self::Closed => "the connection ended",
            Self::Profile => "the label, the context, or the length is outside the exporter profile",
        })
    }
}

impl core::error::Error for ExportError {}

impl<E> Tls<E> {
    /// Derives `output.len()` bytes of keying material with `label` and `context` from the
    /// regular exporter of the established connection (RFC 8446, section 7.5), never from the
    /// early exporter. Both ends of one connection derive the same bytes, and another connection,
    /// label, or context gives other bytes.
    ///
    /// The material is a secret for as long as `output` holds it: wipe it at the end of its use.
    /// The exporter secret stays in rustls. A derivation is not authorization, and not freshness:
    /// bind a fresh context, for example an authentication instance, into each proof.
    ///
    /// Refuses with the [`ExportError`] of each case, and then writes zeros to `output`.
    pub fn export(&self, label: &[u8], context: &[u8], output: &mut [u8]) -> Result<(), ExportError> {
        let derived = self.derive(label, context, output);
        if derived.is_err() {
            output.fill(0);
        }
        derived
    }

    /// The checks and the derivation of [`export`](Self::export).
    fn derive(&self, label: &[u8], context: &[u8], output: &mut [u8]) -> Result<(), ExportError> {
        if label.is_empty()
            || label.len() > EXPORT_LABEL_MAX
            || label.starts_with(RESERVED_LABEL_PREFIX)
            || context.len() > EXPORT_CONTEXT_MAX
            || output.is_empty()
            || output.len() > EXPORT_OUTPUT_MAX
        {
            return Err(ExportError::Profile);
        }
        let records = match &self.phase {
            Phase::Handshake(_) => return Err(ExportError::Handshake),
            Phase::Failed => return Err(ExportError::Closed),
            Phase::Records(records) => records,
        };
        if self.end.is_some() || self.closure.is_some() {
            return Err(ExportError::Closed);
        }
        let derived = records.exporter.derive(label, Some(context), &mut *output);
        assert!(
            derived.is_ok(),
            "rustls derives each request within the limits of the profile"
        );
        Ok(())
    }
}

impl<E: Engine> Connection<Tls<E>> {
    /// Derives exporter material, as [`Tls::export`] does. A connection whose transport failed
    /// refuses with [`ExportError::Closed`] at once, also before the drive that ends its engine.
    pub(crate) fn export(&self, label: &[u8], context: &[u8], output: &mut [u8]) -> Result<(), ExportError> {
        if self.is_reset() {
            output.fill(0);
            return Err(ExportError::Closed);
        }
        self.engine().export(label, context, output)
    }
}
