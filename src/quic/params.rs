//! The transport parameters of version 1 (RFC 9000, section 18, and RFC 9221, section 3): the
//! limits that each end declares in its handshake, and their checks.

use core::fmt;
use core::time::Duration;

use super::frame::STREAMS_MAX;
use super::{ConnectionId, Reader, VARINT_MAX, Writer, varint_len};

/// Whether the peer can move the connection to a new address (RFC 9000, section 9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Migration {
    /// The peer can migrate.
    Allowed,
    /// The peer must not start a migration: `disable_active_migration`.
    Disabled,
}

/// The address that a server prefers after the handshake (RFC 9000, section 18.2).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PreferredAddress {
    /// The IPv4 address and port, or all zero bytes when the server gives none.
    pub ipv4: ([u8; 4], u16),
    /// The IPv6 address and port, or all zero bytes when the server gives none.
    pub ipv6: ([u8; 16], u16),
    /// The connection ID to use at the address. It is not empty.
    pub connection_id: ConnectionId,
    /// The stateless reset token of that connection ID.
    pub reset_token: [u8; 16],
}

impl fmt::Debug for PreferredAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreferredAddress")
            .field("ipv4", &self.ipv4)
            .field("ipv6", &self.ipv6)
            .field("connection_id", &self.connection_id)
            .finish_non_exhaustive()
    }
}

/// The transport parameters of one end. [`Parameters::default`] has the default value of each
/// parameter, which the encoding then omits.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Parameters {
    /// The destination connection ID of the first Initial packet of the client. Only a server
    /// sends it.
    pub original_destination_cid: Option<ConnectionId>,
    /// The time with no activity after which the connection closes, or `None` for no limit.
    pub idle_timeout: Option<Duration>,
    /// The stateless reset token of the connection ID of the handshake. Only a server sends it.
    pub stateless_reset_token: Option<[u8; 16]>,
    /// The largest UDP payload that this end receives: 1,200 to 65,527 bytes.
    pub udp_payload_bytes_max: u64,
    /// The initial flow-control limit of the connection, in bytes.
    pub data_bytes_initial: u64,
    /// The initial limit of each bidirectional stream that this end opens, in bytes.
    pub stream_bytes_bidi_local_initial: u64,
    /// The initial limit of each bidirectional stream that the peer opens, in bytes.
    pub stream_bytes_bidi_remote_initial: u64,
    /// The initial limit of each unidirectional stream that the peer opens, in bytes.
    pub stream_bytes_uni_initial: u64,
    /// The bidirectional streams that the peer can open at first, at most 2^60.
    pub streams_bidi_initial: u64,
    /// The unidirectional streams that the peer can open at first, at most 2^60.
    pub streams_uni_initial: u64,
    /// The exponent of the ACK delay field: at most 20.
    pub ack_delay_exponent: u8,
    /// The longest time that this end delays an acknowledgement: below 2^14 ms.
    pub ack_delay_max: Duration,
    /// Whether the peer can migrate the connection.
    pub migration: Migration,
    /// The address that a server prefers. Only a server sends it.
    pub preferred_address: Option<PreferredAddress>,
    /// The connection IDs of the peer that this end stores: at least 2.
    pub connection_ids_active_max: u64,
    /// The source connection ID of the first packets of this end.
    pub initial_source_cid: Option<ConnectionId>,
    /// The source connection ID of the Retry packet of a server. Only a server sends it.
    pub retry_source_cid: Option<ConnectionId>,
    /// The largest DATAGRAM frame that this end receives, or `None` when it receives none
    /// (RFC 9221).
    pub datagram_bytes_max: Option<u64>,
}

impl fmt::Debug for Parameters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Parameters")
            .field("original_destination_cid", &self.original_destination_cid)
            .field("idle_timeout", &self.idle_timeout)
            .field("has_reset_token", &self.stateless_reset_token.is_some())
            .field("udp_payload_bytes_max", &self.udp_payload_bytes_max)
            .field("data_bytes_initial", &self.data_bytes_initial)
            .field("stream_bytes_bidi_local_initial", &self.stream_bytes_bidi_local_initial)
            .field(
                "stream_bytes_bidi_remote_initial",
                &self.stream_bytes_bidi_remote_initial,
            )
            .field("stream_bytes_uni_initial", &self.stream_bytes_uni_initial)
            .field("streams_bidi_initial", &self.streams_bidi_initial)
            .field("streams_uni_initial", &self.streams_uni_initial)
            .field("ack_delay_exponent", &self.ack_delay_exponent)
            .field("ack_delay_max", &self.ack_delay_max)
            .field("migration", &self.migration)
            .field("preferred_address", &self.preferred_address)
            .field("connection_ids_active_max", &self.connection_ids_active_max)
            .field("initial_source_cid", &self.initial_source_cid)
            .field("retry_source_cid", &self.retry_source_cid)
            .field("datagram_bytes_max", &self.datagram_bytes_max)
            .finish_non_exhaustive()
    }
}

impl Default for Parameters {
    fn default() -> Self {
        Self {
            original_destination_cid: None,
            idle_timeout: None,
            stateless_reset_token: None,
            udp_payload_bytes_max: UDP_PAYLOAD_MAX,
            data_bytes_initial: 0,
            stream_bytes_bidi_local_initial: 0,
            stream_bytes_bidi_remote_initial: 0,
            stream_bytes_uni_initial: 0,
            streams_bidi_initial: 0,
            streams_uni_initial: 0,
            ack_delay_exponent: 3,
            ack_delay_max: Duration::from_millis(25),
            migration: Migration::Allowed,
            preferred_address: None,
            connection_ids_active_max: 2,
            initial_source_cid: None,
            retry_source_cid: None,
            datagram_bytes_max: None,
        }
    }
}

/// The largest UDP payload of IPv4 and IPv6 (RFC 9000, section 18.2).
const UDP_PAYLOAD_MAX: u64 = 65_527;
/// The smallest UDP payload that an end of version 1 receives (RFC 9000, section 14).
const UDP_PAYLOAD_MIN: u64 = 1_200;
/// The longest ACK delay that the parameter can declare, in milliseconds (RFC 9000, section 18.2).
const ACK_DELAY_MAX_MS: u64 = 1 << 14;

/// The identifier of each parameter (RFC 9000, section 18.2, and RFC 9221, section 3).
mod id {
    pub(super) const ORIGINAL_DESTINATION_CID: u64 = 0x00;
    pub(super) const IDLE_TIMEOUT: u64 = 0x01;
    pub(super) const STATELESS_RESET_TOKEN: u64 = 0x02;
    pub(super) const UDP_PAYLOAD_MAX: u64 = 0x03;
    pub(super) const DATA: u64 = 0x04;
    pub(super) const STREAM_BIDI_LOCAL: u64 = 0x05;
    pub(super) const STREAM_BIDI_REMOTE: u64 = 0x06;
    pub(super) const STREAM_UNI: u64 = 0x07;
    pub(super) const STREAMS_BIDI: u64 = 0x08;
    pub(super) const STREAMS_UNI: u64 = 0x09;
    pub(super) const ACK_DELAY_EXPONENT: u64 = 0x0a;
    pub(super) const ACK_DELAY_MAX: u64 = 0x0b;
    pub(super) const DISABLE_MIGRATION: u64 = 0x0c;
    pub(super) const PREFERRED_ADDRESS: u64 = 0x0d;
    pub(super) const CONNECTION_IDS: u64 = 0x0e;
    pub(super) const INITIAL_SOURCE_CID: u64 = 0x0f;
    pub(super) const RETRY_SOURCE_CID: u64 = 0x10;
    pub(super) const DATAGRAM_MAX: u64 = 0x20;
}

/// The end that sent a set of parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sender {
    /// The client.
    Client,
    /// The server.
    Server,
}

/// Transport parameters that are not valid: close the connection with
/// `TRANSPORT_PARAMETER_ERROR` (RFC 9000, section 7.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParameterError {
    /// The identifier of the parameter that broke a rule, or `None` when the encoding ended in a
    /// parameter.
    pub id: Option<u64>,
}

impl fmt::Display for ParameterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.id {
            Some(id) => write!(f, "the QUIC transport parameter {id:#x} is not valid"),
            None => f.write_str("the QUIC transport parameters end inside a parameter"),
        }
    }
}

impl core::error::Error for ParameterError {}

impl Parameters {
    /// Parses the parameters that `sender` sent. Refuses a parameter that appears two times, a
    /// value outside its range, and a parameter that only a server sends in the parameters of a
    /// client. A parameter that this end does not know is ignored (RFC 9000, section 7.4.2).
    pub fn parse(bytes: &[u8], sender: Sender) -> Result<Self, ParameterError> {
        let mut parameters = Self::default();
        // A bit for each known identifier: 0x00 to 0x10, and 0x20 as bit 17.
        let mut seen = 0_u32;
        let mut reader = Reader::new(bytes);
        while !reader.rest().is_empty() {
            let id = reader.varint().ok_or(ParameterError { id: None })?;
            let len = reader
                .varint()
                .and_then(|len| usize::try_from(len).ok())
                .ok_or(ParameterError { id: Some(id) })?;
            let value = reader.take(len).ok_or(ParameterError { id: Some(id) })?;
            let bit = match id {
                0x00..=0x10 => Some(id),
                id::DATAGRAM_MAX => Some(17),
                _ => None,
            };
            let Some(bit) = bit else {
                continue;
            };
            let error = ParameterError { id: Some(id) };
            if seen & (1 << bit) != 0 {
                return Err(error);
            }
            seen |= 1 << bit;
            parameters.set(id, value, sender).ok_or(error)?;
        }
        Ok(parameters)
    }

    /// Sets the parameter `id` from its encoded `value`, or gives `None` when it is not valid.
    fn set(&mut self, id: u64, value: &[u8], sender: Sender) -> Option<()> {
        let server = sender == Sender::Server;
        let integer = || {
            let mut reader = Reader::new(value);
            let integer = reader.varint()?;
            reader.rest().is_empty().then_some(integer)
        };
        let cid = || ConnectionId::new(value);
        match id {
            id::ORIGINAL_DESTINATION_CID if server => self.original_destination_cid = Some(cid()?),
            id::IDLE_TIMEOUT => self.idle_timeout = Some(Duration::from_millis(integer()?)).filter(|t| !t.is_zero()),
            id::STATELESS_RESET_TOKEN if server => self.stateless_reset_token = Some(value.try_into().ok()?),
            id::UDP_PAYLOAD_MAX => {
                self.udp_payload_bytes_max = Some(integer()?).filter(|&size| size >= UDP_PAYLOAD_MIN)?;
            }
            id::DATA => self.data_bytes_initial = integer()?,
            id::STREAM_BIDI_LOCAL => self.stream_bytes_bidi_local_initial = integer()?,
            id::STREAM_BIDI_REMOTE => self.stream_bytes_bidi_remote_initial = integer()?,
            id::STREAM_UNI => self.stream_bytes_uni_initial = integer()?,
            id::STREAMS_BIDI => self.streams_bidi_initial = Some(integer()?).filter(|&n| n <= STREAMS_MAX)?,
            id::STREAMS_UNI => self.streams_uni_initial = Some(integer()?).filter(|&n| n <= STREAMS_MAX)?,
            id::ACK_DELAY_EXPONENT => self.ack_delay_exponent = u8::try_from(integer()?).ok().filter(|&e| e <= 20)?,
            id::ACK_DELAY_MAX => {
                self.ack_delay_max = Duration::from_millis(Some(integer()?).filter(|&ms| ms < ACK_DELAY_MAX_MS)?);
            }
            id::DISABLE_MIGRATION if value.is_empty() => self.migration = Migration::Disabled,
            id::PREFERRED_ADDRESS if server => self.preferred_address = Some(preferred(value)?),
            id::CONNECTION_IDS => self.connection_ids_active_max = Some(integer()?).filter(|&n| n >= 2)?,
            id::INITIAL_SOURCE_CID => self.initial_source_cid = Some(cid()?),
            id::RETRY_SOURCE_CID if server => self.retry_source_cid = Some(cid()?),
            id::DATAGRAM_MAX => self.datagram_bytes_max = Some(integer()?),
            _ => return None,
        }
        Some(())
    }

    /// The bytes of the encoding of the parameters that differ from their defaults, or `None`
    /// when a value does not fit its field: a value above 2^62 - 1, an ACK delay of 2^14 ms or
    /// more, or a UDP payload size below 1,200 bytes.
    pub fn encoded_len(&self) -> Option<usize> {
        let mut len = 0_usize;
        self.each(|id, value| {
            len = len.checked_add(varint_len(id)? + varint_len(value.len() as u64)? + value.len())?;
            Some(())
        })?;
        Some(len)
    }

    /// Writes the encoding of the parameters that differ from their defaults at the start of
    /// `out`, which has [`encoded_len`](Self::encoded_len) bytes or more. Gives the bytes written, or `None` when a
    /// value does not fit or `out` has no room.
    pub fn write(&self, out: &mut [u8]) -> Option<usize> {
        let mut writer = Writer::new(out);
        self.each(|id, value| {
            writer.varint(id)?;
            writer.varint(value.len() as u64)?;
            writer.bytes(value.bytes())
        })?;
        Some(writer.len())
    }

    /// Calls `f` with each parameter that differs from its default, and its encoded value.
    fn each(&self, mut f: impl FnMut(u64, &Value) -> Option<()>) -> Option<()> {
        let default = Self::default();
        let ack_delay_ms = u64::try_from(self.ack_delay_max.as_millis()).ok()?;
        if ack_delay_ms >= ACK_DELAY_MAX_MS || self.udp_payload_bytes_max < UDP_PAYLOAD_MIN {
            return None;
        }
        let mut parameter = |id: u64, value: Option<Value>| match value {
            Some(value) => f(id, &value),
            None => Some(()),
        };
        // The encoding of an integer that differs from `default`, `Some(None)` when it does not,
        // and `None` when it does not fit.
        let changed = |value: u64, default: u64| {
            if value == default {
                Some(None)
            } else {
                Value::integer(value).map(Some)
            }
        };
        let cid = |cid: Option<ConnectionId>| cid.map(|cid| Value::of(cid.as_bytes()));
        parameter(id::ORIGINAL_DESTINATION_CID, cid(self.original_destination_cid))?;
        let idle_ms = match self.idle_timeout {
            Some(timeout) => u64::try_from(timeout.as_millis()).ok()?,
            None => 0,
        };
        parameter(id::IDLE_TIMEOUT, changed(idle_ms, 0)?)?;
        parameter(
            id::STATELESS_RESET_TOKEN,
            self.stateless_reset_token.map(|t| Value::of(&t)),
        )?;
        parameter(
            id::UDP_PAYLOAD_MAX,
            changed(self.udp_payload_bytes_max, default.udp_payload_bytes_max)?,
        )?;
        parameter(id::DATA, changed(self.data_bytes_initial, 0)?)?;
        parameter(id::STREAM_BIDI_LOCAL, changed(self.stream_bytes_bidi_local_initial, 0)?)?;
        parameter(
            id::STREAM_BIDI_REMOTE,
            changed(self.stream_bytes_bidi_remote_initial, 0)?,
        )?;
        parameter(id::STREAM_UNI, changed(self.stream_bytes_uni_initial, 0)?)?;
        parameter(id::STREAMS_BIDI, changed(self.streams_bidi_initial, 0)?)?;
        parameter(id::STREAMS_UNI, changed(self.streams_uni_initial, 0)?)?;
        parameter(
            id::ACK_DELAY_EXPONENT,
            changed(
                u64::from(self.ack_delay_exponent),
                u64::from(default.ack_delay_exponent),
            )?,
        )?;
        parameter(id::ACK_DELAY_MAX, changed(ack_delay_ms, 25)?)?;
        parameter(
            id::DISABLE_MIGRATION,
            (self.migration == Migration::Disabled).then(|| Value::of(&[])),
        )?;
        parameter(
            id::PREFERRED_ADDRESS,
            self.preferred_address.map(|a| encode_preferred(&a)),
        )?;
        parameter(id::CONNECTION_IDS, changed(self.connection_ids_active_max, 2)?)?;
        parameter(id::INITIAL_SOURCE_CID, cid(self.initial_source_cid))?;
        parameter(id::RETRY_SOURCE_CID, cid(self.retry_source_cid))?;
        let datagram = match self.datagram_bytes_max {
            Some(size) => Some(Value::integer(size)?),
            None => None,
        };
        parameter(id::DATAGRAM_MAX, datagram)
    }
}

/// The encoded value of one parameter: at most a preferred address of 61 bytes.
struct Value {
    bytes: [u8; 61],
    len: usize,
}

impl Value {
    fn of(bytes: &[u8]) -> Self {
        let mut value = Self { bytes: [0; 61], len: 0 };
        value.bytes[..bytes.len()].copy_from_slice(bytes);
        value.len = bytes.len();
        value
    }

    fn integer(integer: u64) -> Option<Self> {
        if integer > VARINT_MAX {
            return None;
        }
        let mut value = Self { bytes: [0; 61], len: 0 };
        let mut writer = Writer::new(&mut value.bytes);
        writer.varint(integer)?;
        value.len = writer.len();
        Some(value)
    }

    const fn len(&self) -> usize {
        self.len
    }

    fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// Parses a preferred address: IPv4, its port, IPv6, its port, a connection ID that is not empty
/// with its length, and a stateless reset token.
fn preferred(value: &[u8]) -> Option<PreferredAddress> {
    let mut reader = Reader::new(value);
    let ipv4 = (reader.array()?, u16::from_be_bytes(reader.array()?));
    let ipv6 = (reader.array()?, u16::from_be_bytes(reader.array()?));
    let len = usize::from(reader.u8()?);
    let connection_id = ConnectionId::new(reader.take(len)?).filter(|cid| !cid.as_bytes().is_empty())?;
    let reset_token = reader.array()?;
    reader.rest().is_empty().then_some(PreferredAddress {
        ipv4,
        ipv6,
        connection_id,
        reset_token,
    })
}

fn encode_preferred(address: &PreferredAddress) -> Value {
    let mut value = Value { bytes: [0; 61], len: 0 };
    let cid = address.connection_id.as_bytes();
    let mut writer = Writer::new(&mut value.bytes);
    let written = (|| {
        writer.bytes(&address.ipv4.0)?;
        writer.bytes(&address.ipv4.1.to_be_bytes())?;
        writer.bytes(&address.ipv6.0)?;
        writer.bytes(&address.ipv6.1.to_be_bytes())?;
        writer.u8(u8::try_from(cid.len()).ok()?)?;
        writer.bytes(cid)?;
        writer.bytes(&address.reset_token)
    })();
    assert!(written.is_some(), "a preferred address takes at most 61 bytes");
    value.len = writer.len();
    value
}
