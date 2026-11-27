//! Admission and ordered output for the three critical streams and each request.

use std::collections::VecDeque;

use super::connection::{Code, Connection, Error, Limits, MethodKind, Phase, ROOM, Scratch, empty, misuse};
use super::frame::{Header, Kind};
use crate::buffer::{Buffer as _, Lease, WriteLoan};
use crate::capacity::{Budget, Permit};
use crate::drive::{Error as HostError, Kind as HostKind};
use crate::h2::message;
use crate::qpack::FieldLine;
use crate::quic::{self, StreamId, frame::Direction, packet::Side};
use crate::varint;

pub(super) const CONTROL: usize = 0;
pub(super) const ENCODER: usize = 1;
pub(super) const DECODER: usize = 2;
const PREFIX_ROOM: usize = 16 + 22;
pub(super) const REQUEST_PRIORITY: quic::Priority = quic::Priority {
    urgency: 3,
    incremental: false,
};

struct Critical {
    id: Option<StreamId>,
    bytes: Scratch,
    busy: bool,
    staged: u64,
    acknowledged: u64,
}
impl Critical {
    fn new(cap: usize, budget: &Budget) -> Result<Self, Error> {
        Ok(Self {
            id: None,
            bytes: Scratch::new(cap, budget)?,
            busy: false,
            staged: 0,
            acknowledged: 0,
        })
    }
}
struct Write {
    id: StreamId,
    first: Lease,
    second: Option<Lease>,
    fin: bool,
}
impl Write {
    fn len(&self) -> usize {
        self.first.initialized() + self.second.as_ref().map_or(0, crate::buffer::Buffer::initialized)
    }
}

pub(super) struct Output {
    critical: [Critical; 3],
    writes: VecDeque<Write>,
    _places: Permit,
    attempts: usize,
    app_bytes: usize,
    app_max: usize,
    reserve: usize,
}
impl Output {
    pub(super) fn new(limits: Limits, budget: &Budget) -> Result<Self, Error> {
        let count = limits.requests.checked_add(3).ok_or(ROOM)?;
        let layout = core::alloc::Layout::array::<Write>(count).map_err(|_| ROOM)?;
        let places = budget.reserve(layout.size() as u64).map_err(|_| ROOM)?;
        let mut writes = VecDeque::new();
        writes.try_reserve_exact(count).map_err(|_| ROOM)?;
        Ok(Self {
            critical: [
                Critical::new(limits.control_bytes, budget)?,
                Critical::new(limits.control_bytes, budget)?,
                Critical::new(limits.control_bytes, budget)?,
            ],
            writes,
            _places: places,
            attempts: 0,
            app_bytes: 0,
            app_max: 0,
            reserve: 0,
        })
    }
    pub(super) fn started(&self) -> bool {
        self.critical[DECODER].id.is_some()
    }
    pub(super) fn critical(&self, id: StreamId) -> Option<usize> {
        self.critical.iter().position(|c| c.id == Some(id))
    }
    pub(super) fn loan(&mut self, k: usize) -> &mut WriteLoan<Vec<u8>> {
        &mut self.critical[k].bytes.loan
    }
    pub(super) fn ack(&mut self, id: StreamId, offset: u64) {
        if let Some(k) = self.critical(id) {
            self.critical[k].acknowledged = offset;
        }
    }
    pub(super) fn wake(&mut self) {
        self.attempts = self.writes.len();
    }
    pub(super) fn more(&self) -> bool {
        self.attempts > 0
            || self
                .critical
                .iter()
                .any(|c| !c.busy && !c.bytes.loan.filled().is_empty())
    }
    fn check(&self, n: usize) -> Result<(), Error> {
        if n > self.app_max - self.app_bytes {
            return Err(HostError::new(HostKind::Overload, "the HTTP/3 send byte limit is full").into());
        }
        Ok(())
    }
    fn push(&mut self, w: Write) {
        if self.critical(w.id).is_none() {
            self.app_bytes += w.len();
        }
        assert!(self.writes.len() < self.writes.capacity());
        self.writes.push_back(w);
        self.wake();
    }
    pub(super) fn discard(&mut self, id: StreamId) {
        if let Some(i) = self.writes.iter().position(|w| w.id == id)
            && let Some(w) = self.writes.remove(i)
        {
            self.app_bytes -= w.len();
        }
        self.wake();
    }
}

impl Connection {
    pub(super) fn start(&mut self, q: &mut quic::Connection) -> Result<(), Error> {
        if q.negotiated().and_then(|n| n.protocol) != Some(b"h3") {
            return Err(misuse("HTTP/3 requires the negotiated ALPN name h3"));
        }
        if q.peer_parameters().is_none_or(|p| p.streams_uni_initial < 3) {
            return Err(Code::StreamCreation.into());
        }
        let limit = usize::try_from(q.local_limits().send_bytes_max).unwrap_or(usize::MAX);
        self.out.app_max = limit;
        self.out.reserve = (limit / 4).min(self.limits.control_bytes);
        for (k, prefix) in [(CONTROL, 0), (ENCODER, 2), (DECODER, 3)] {
            let stream = q.open(Direction::Unidirectional)?.ok_or(Code::StreamCreation)?;
            q.set_priority(
                stream,
                quic::Priority {
                    urgency: 0,
                    incremental: true,
                },
            )?;
            self.out.critical[k].id = Some(stream);
            assert_eq!(self.out.loan(k).fill_from(&[prefix]), 1);
        }
        let d = self.limits.decoder;
        let mut payload = [0; 48];
        let mut len = 0;
        for (id, v) in [(1, d.table_bytes), (6, d.list_bytes), (7, d.blocked_streams)] {
            len += integer(&mut payload[len..], id);
            len += integer(&mut payload[len..], v as u64);
        }
        self.control_frame(Kind::SETTINGS, &payload[..len])?;
        Ok(())
    }
    fn control_frame(&mut self, kind: Kind, payload: &[u8]) -> Result<(), Error> {
        let out = self.out.loan(CONTROL);
        let mut header = [0; 16];
        let n = Header {
            kind,
            len: payload.len() as u64,
        }
        .write(&mut header)
        .expect("a control header fits");
        if out.capacity() - out.filled().len() < n + payload.len() {
            return Err(ROOM.into());
        }
        out.fill_from(&header[..n]);
        out.fill_from(payload);
        Ok(())
    }

    /// Opens a client request after the critical streams start. A limit or GOAWAY gives `None`.
    pub fn open(&mut self, q: &mut quic::Connection) -> Result<Option<StreamId>, Error> {
        self.live()?;
        if self.side != Side::Client {
            return Err(misuse("only an HTTP/3 client opens requests"));
        }
        if !self.out.started()
            || self.peer_goaway.is_some()
            || self.local_goaway.is_some()
            || self.requests.len() == self.limits.requests
        {
            return Ok(None);
        }
        if let Some(id) = q.open(Direction::Bidirectional)? {
            if let Err(error) = q.set_priority(id, REQUEST_PRIORITY) {
                q.abort_stream(id, Code::RequestCancelled as u64)?;
                q.close_stream(id)?;
                return Err(error.into());
            }
            self.insert(id, self.requests.len());
            return Ok(Some(id));
        }
        Ok(None)
    }

    /// Queues request or response fields, an informational response, or trailers in message order.
    /// A refusal leaves the message and QPACK encoder unchanged. A queued frame must advance before the next write.
    pub fn headers(&mut self, id: StreamId, fields: &[FieldLine<'_>], end: bool) -> Result<(), Error> {
        let lines = fields.iter().copied();
        self.live()?;
        let i = self.index(id)?;
        let r = &self.requests[i];
        if r.queued {
            return Err(ROOM.into());
        }
        let peer = self.peer.and_then(|s| s.field_section_bytes).unwrap_or(u64::MAX);
        let max = peer.min(self.limits.decoder.list_bytes as u64);
        let mut size = 0;
        for line in lines.clone() {
            size = u64::saturating_add(size, 32)
                .saturating_add(line.name.len() as u64)
                .saturating_add(line.value.len() as u64);
            if size > max {
                return Err(ROOM.into());
            }
        }
        let bad = || misuse("invalid HTTP/3 fields or message sequence");
        let mut method = r.method;
        let next = match r.send {
            Phase::Head if self.side == Side::Client => {
                let h = message::request_fields(lines.clone()).map_err(|_| bad())?;
                method = MethodKind::of(h.method);
                Phase::Body(h.length())
            }
            Phase::Head => {
                if r.recv == Phase::Head {
                    return Err(bad());
                }
                let h = message::ResponseFields::check(lines.clone()).map_err(|_| bad())?;
                let status = h.status.code();
                if (status < 200
                    || status == 204
                    || matches!(method, MethodKind::Connect) && (200..300).contains(&status))
                    && fields.iter().any(|line| line.name == b"content-length")
                {
                    return Err(bad());
                }
                if status < 200 {
                    Phase::Head
                } else {
                    Phase::Body(method.length(h.status.code(), h.length))
                }
            }
            Phase::Body(None | Some(0)) => {
                message::check_trailers(lines.clone()).map_err(|_| bad())?;
                Phase::Trailers
            }
            _ => return Err(bad()),
        };
        if end {
            next.finish().map_err(|_| bad())?;
        }
        let needed = self.encoder.needed(lines.clone());
        let cap = PREFIX_ROOM.checked_add(needed).ok_or(ROOM)?;
        self.out.check(cap)?;
        let (mut bytes, charge) = message::region(cap, &self.budget).ok_or(ROOM)?;
        bytes.resize(PREFIX_ROOM, 0);
        let mut section = WriteLoan::new(bytes);
        let prefix = self
            .encoder
            .encode(id.get(), lines, &mut section, self.out.loan(ENCODER))
            .expect("the field section has the encoder's required capacity");
        let mut bytes = section.into_inner();
        let field_bytes = bytes.len() - PREFIX_ROOM + prefix.bytes().len();
        let mut header = [0; 16];
        let n = Header {
            kind: Kind::HEADERS,
            len: field_bytes as u64,
        }
        .write(&mut header)
        .expect("a bounded field section fits");
        let prefix_at = PREFIX_ROOM - prefix.bytes().len();
        let start = prefix_at - n;
        bytes[start..prefix_at].copy_from_slice(&header[..n]);
        bytes[prefix_at..PREFIX_ROOM].copy_from_slice(prefix.bytes());
        let first = message::charged(bytes, charge)
            .view(start..)
            .expect("the encoded header and fields share a region");
        self.out.push(Write {
            id,
            first,
            second: None,
            fin: end,
        });
        let r = &mut self.requests[i];
        r.queued = true;
        r.method = method;
        r.send = if end { Phase::End } else { next };
        Ok(())
    }

    /// Queues one DATA frame. Its payload keeps its original backing until QUIC releases it.
    pub fn data(&mut self, id: StreamId, data: &Lease, end: bool) -> Result<(), Error> {
        self.live()?;
        let i = self.index(id)?;
        let r = &self.requests[i];
        if r.queued {
            return Err(ROOM.into());
        }
        let len = data.initialized();
        let next = r
            .send
            .data(len as u64)
            .map_err(|_| misuse("DATA exceeds the declared length or is out of sequence"))?;
        if end {
            next.finish()
                .map_err(|_| misuse("the body does not match its content-length"))?;
        }
        let mut header = [0; 16];
        let n = Header {
            kind: Kind::DATA,
            len: len as u64,
        }
        .write(&mut header)
        .map_err(|_| ROOM)?;
        self.out.check(len.checked_add(n).ok_or(ROOM)?)?;
        let (mut bytes, charge) = message::region(n, &self.budget).ok_or(ROOM)?;
        bytes.extend_from_slice(&header[..n]);
        self.out.push(Write {
            id,
            first: message::charged(bytes, charge),
            second: (len != 0).then(|| data.clone()),
            fin: end,
        });
        self.requests[i].queued = true;
        self.requests[i].send = if end { Phase::End } else { next };
        Ok(())
    }

    /// Sends a FIN after the last complete frame.
    pub fn finish(&mut self, id: StreamId) -> Result<(), Error> {
        self.live()?;
        let i = self.index(id)?;
        let r = &self.requests[i];
        if r.queued {
            return Err(ROOM.into());
        }
        r.send
            .finish()
            .map_err(|_| misuse("the HTTP/3 message is incomplete or already ended"))?;
        self.out.push(Write {
            id,
            first: empty(),
            second: None,
            fin: true,
        });
        self.requests[i].queued = true;
        self.requests[i].send = Phase::End;
        Ok(())
    }
    /// Starts graceful shutdown. Admitted requests can finish. The return value is the first excluded identifier.
    pub fn goaway(&mut self) -> Result<u64, Error> {
        self.live()?;
        if let Some(id) = self.local_goaway {
            return Ok(id);
        }
        if !self.out.started() {
            return Err(misuse("start the critical streams before GOAWAY"));
        }
        let id = if self.side == Side::Server {
            match self.highest {
                None => 0,
                Some(s) => s
                    .get()
                    .checked_add(4)
                    .filter(|id| *id <= varint::MAX)
                    .ok_or_else(|| misuse("the last request identifier has no GOAWAY successor"))?,
            }
        } else {
            0
        };
        let mut bytes = [0; 8];
        let n = integer(&mut bytes, id);
        self.control_frame(Kind::GOAWAY, &bytes[..n])?;
        self.local_goaway = Some(id);
        Ok(id)
    }
    /// Whether all requests retired and the peer acknowledged the last critical-stream bytes, including GOAWAY.
    pub fn drained(&self) -> bool {
        self.local_goaway.is_some()
            && self.requests.is_empty()
            && self
                .out
                .critical
                .iter()
                .all(|c| c.bytes.loan.filled().is_empty() && !c.busy && c.acknowledged >= c.staged)
    }

    pub(super) fn flush(&mut self, q: &mut quic::Connection) -> Result<(), Error> {
        for k in [CONTROL, DECODER, ENCODER] {
            let c = &mut self.out.critical[k];
            if c.busy || c.bytes.loan.filled().is_empty() {
                continue;
            }
            let id = c.id.expect("the critical streams started");
            let first = c.bytes.drain(&self.budget)?;
            c.staged = c
                .staged
                .checked_add(first.initialized() as u64)
                .ok_or(Code::ExcessiveLoad)?;
            c.busy = true;
            self.out.push(Write {
                id,
                first,
                second: None,
                fin: false,
            });
        }
        if self.out.attempts == 0 {
            return Ok(());
        }
        let Some(mut w) = self.out.writes.pop_front() else {
            return Ok(());
        };
        self.out.attempts -= 1;
        let critical = self.out.critical(w.id);
        let Some(room) = q.send_room(w.id, if critical.is_some() { 0 } else { self.out.reserve })? else {
            // QUIC has stopped this direction. Its STOP_SENDING event discards this write.
            self.out.writes.push_back(w);
            return Ok(());
        };
        let len = w.first.initialized();
        let n = len.min(room);
        if n == 0 && len != 0 {
            self.out.writes.push_back(w);
            return Ok(());
        }
        let all = n == len && w.second.is_none();
        let data = w.first.view(..n).expect("a send prefix lies within its region");
        q.send(w.id, data, all && w.fin)?;
        if critical.is_none() {
            self.out.app_bytes -= n;
        }
        if all {
            if let Some(k) = critical {
                self.out.critical[k].busy = false;
            } else if let Ok(i) = self.at(w.id) {
                self.requests[i].queued = false;
            }
        } else {
            w.first = if n == len {
                w.second.take().expect("the frame has another region")
            } else {
                w.first.view(n..).expect("the unsent suffix lies in its region")
            };
            self.out.writes.push_back(w);
        }
        self.out.wake();
        Ok(())
    }
}
fn integer(out: &mut [u8], value: u64) -> usize {
    let n = varint::len(value).expect("a checked HTTP/3 setting or stream ID fits");
    varint::write(out, value, n).expect("the integer has room");
    n
}
