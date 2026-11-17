//! The stream layer of the HTTP/2 engine: the stream states of RFC 9113, section 5.1, the stream
//! identifiers and the concurrency limit (sections 5.1.1 and 5.1.2), flow control at the stream
//! level and at the connection level (sections 5.2 and 6.9), the parts of a message (section
//! 8.1), and the drain after a GOAWAY (section 6.8).
//!
//! The table holds each stream that is open or half-closed. Push is off, so only a client opens
//! streams, with odd identifiers. A stream with no entry is idle when its identifier is even or
//! above the highest identifier that the client used, and closed otherwise. A closed stream
//! keeps no state, and each frame on it gets the minimal processing of section 5.1: its header
//! block decodes and is discarded, its DATA counts toward the connection window and is
//! discarded, and other frames change nothing.
//!
//! A stream that a reset closed keeps only its identifier, which holds its slot: the open and the
//! held streams together stay within the endpoint's `SETTINGS_MAX_CONCURRENT_STREAMS`. The slot is
//! free when the application closes the stream, after its handler ended. Thus the handlers in
//! flight never pass the limit, however fast the peer opens and resets streams.

use core::alloc::Layout;

use rstypes::capacity::{Budget, Permit};

use super::connection::Fault;
use super::frame::{ErrorCode, MAX_STREAM};
use super::{Role, Settings};
use crate::drive::{Error, Kind};
use crate::hpack::FieldLine;

/// The initial flow-control window of RFC 9113, section 6.9.2: of the connection, and of each
/// stream until the peer applies another `SETTINGS_INITIAL_WINDOW_SIZE`.
pub(super) const INITIAL_WINDOW: u32 = 65_535;

/// The largest flow-control window: 2^31 - 1.
const MAX: i64 = MAX_STREAM as i64;

/// The part of a message that one side of a stream sends next (RFC 9113, section 8.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Part {
    /// The header section, after zero or more interim responses.
    Head,
    /// DATA frames, or the trailer section.
    Body,
    /// Nothing: the side sent END_STREAM.
    Done,
}

/// The receive credit of one level: the stream or the connection. The three counts, with the data
/// bytes of a DATA frame that did not go up yet, sum to the capacity that the consumer admitted,
/// so no grant passes it.
#[derive(Clone, Copy, Debug)]
struct Credit {
    /// The DATA bytes that the peer can still send, as this endpoint counts them.
    window: i64,
    /// The bytes that went up to the consumer, which it did not release yet.
    held: i64,
    /// The bytes that are free again, which no WINDOW_UPDATE gave back yet.
    free: i64,
}

impl Credit {
    const fn new(capacity: i64) -> Self {
        Self {
            window: capacity,
            held: 0,
            free: 0,
        }
    }

    /// Counts a DATA frame of `flow` bytes, of which `data` bytes go up later. The rest, such as
    /// the padding, is free at once.
    const fn take(&mut self, flow: i64, data: i64) {
        self.window -= flow;
        self.free += flow - data;
    }

    /// Counts `bytes` bytes that the consumer released.
    const fn release(&mut self, bytes: i64) {
        self.held -= bytes;
        self.free += bytes;
    }

    /// The increment of the next WINDOW_UPDATE: the free bytes, once they reach the credit that
    /// the peer still has. This is the rule of nghttp2, so no small increment goes out.
    fn due(&self) -> Option<u32> {
        if self.free > 0 && self.free >= self.window {
            u32::try_from(self.free).ok()
        } else {
            None
        }
    }

    /// Counts the WINDOW_UPDATE of `increment` that went out.
    fn grant(&mut self, increment: u32) {
        self.window += i64::from(increment);
        self.free -= i64::from(increment);
        assert!(
            self.free >= 0 && self.window <= MAX,
            "a grant gives back only free bytes, within 2^31 - 1"
        );
    }
}

/// One stream that is open or half-closed.
#[derive(Debug)]
struct Stream {
    id: u32,
    sending: Part,
    receiving: Part,
    /// The DATA bytes that the endpoint can send. It is negative after the peer makes its
    /// `SETTINGS_INITIAL_WINDOW_SIZE` smaller (section 6.9.2).
    window: i64,
    credit: Credit,
}

/// The shutdown of the endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Drain {
    /// The endpoint sent no GOAWAY.
    Open,
    /// A server sent a GOAWAY with the last stream 2^31 - 1 and a PING. At the PING's
    /// acknowledgement, it sends the GOAWAY with its last stream (section 6.8).
    Notice,
    /// The endpoint sent its GOAWAY with this last stream.
    Sent(u32),
}

/// What the engine does with a decoded header block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Section {
    /// It goes up as a header section.
    Head,
    /// It goes up as the trailer section, which ends the body.
    Trailers,
    /// It is discarded: its stream is closed, or the endpoint ignores it after its GOAWAY.
    Discard,
    /// The engine refuses the new stream with this code before it goes up.
    Refuse(ErrorCode),
    /// The engine resets the stream with this code, a stream error (section 5.4.2).
    Reset(ErrorCode),
}

/// What the engine does with a DATA frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Flow {
    /// Its data goes up.
    Deliver,
    /// It is discarded: its stream is closed.
    Discard,
    /// It is discarded, and the engine resets the stream with this code.
    Reset(ErrorCode),
}

/// The streams of one connection, and its flow-control windows.
pub(super) struct Streams {
    role: Role,
    /// The open and half-closed streams, in the order of their identifiers.
    table: Vec<Stream>,
    /// The streams that a reset ended, whose handlers did not end. Each keeps its slot until the
    /// application closes it, so a peer that resets streams starts no more handlers than the
    /// limit (CVE-2023-44487), also when it makes the endpoint reset them (CVE-2025-8671).
    held: Vec<u32>,
    /// The most streams of the table and of `held` together: the endpoint's
    /// `SETTINGS_MAX_CONCURRENT_STREAMS`.
    limit: usize,
    _charge: Permit,
    /// The highest stream identifier that the client used. Each client stream at or below it
    /// with no entry is closed.
    highest: u32,
    /// The highest stream of the peer whose header section went up: the last stream of each
    /// GOAWAY of the endpoint.
    pub(super) last_stream: u32,
    /// The DATA bytes that the endpoint can send on the connection.
    window: i64,
    credit: Credit,
    /// The peer's `SETTINGS_INITIAL_WINDOW_SIZE`: the send window of each new stream.
    send_initial: i64,
    /// The receive window of each new stream: 65,535 until the peer acknowledges the endpoint's
    /// settings, and then the endpoint's `SETTINGS_INITIAL_WINDOW_SIZE`.
    recv_initial: i64,
    local_initial: i64,
    /// The last stream of the peer's last GOAWAY.
    peer_goaway: Option<u32>,
    pub(super) drain: Drain,
}

impl Streams {
    /// Makes the streams of a connection of `role` with the endpoint's settings `local` and a
    /// connection receive window of `connection_window`. It charges a table of
    /// `max_concurrent_streams` entries, and as many held identifiers, to `budget` before it
    /// allocates them.
    pub(super) fn new(role: Role, local: &Settings, connection_window: u32, budget: &Budget) -> Result<Self, Error> {
        let limit = usize::try_from(local.max_concurrent_streams).unwrap_or(usize::MAX);
        let too_large = Error::new(Kind::Overload, "the stream table is too large");
        let bytes = Layout::array::<Stream>(limit)
            .and_then(|table| Ok(table.extend(Layout::array::<u32>(limit)?)?.0.size()))
            .map_err(|_| too_large)?;
        let charge = budget
            .reserve(u64::try_from(bytes).map_err(|_| too_large)?)
            .map_err(|_| Error::new(Kind::Overload, "the budget refused the stream table"))?;
        let (mut table, mut held) = (Vec::new(), Vec::new());
        table
            .try_reserve_exact(limit)
            .and_then(|()| held.try_reserve_exact(limit))
            .map_err(|_| Error::new(Kind::Overload, "the memory for the stream table is not available"))?;
        Ok(Self {
            role,
            table,
            held,
            limit,
            _charge: charge,
            highest: 0,
            last_stream: 0,
            window: i64::from(INITIAL_WINDOW),
            credit: Credit::new(i64::from(connection_window)),
            send_initial: i64::from(INITIAL_WINDOW),
            recv_initial: i64::from(INITIAL_WINDOW),
            local_initial: i64::from(local.initial_window_size),
            peer_goaway: None,
            drain: Drain::Open,
        })
    }

    /// The increment of the WINDOW_UPDATE on stream 0 that raises the connection window from
    /// 65,535 to the capacity that the caller admitted, at the start.
    pub(super) fn initial_grant(&self) -> Option<u32> {
        u32::try_from(self.credit.window - i64::from(INITIAL_WINDOW))
            .ok()
            .filter(|&increment| increment > 0)
    }

    fn find(&self, id: u32) -> Option<usize> {
        self.table.binary_search_by_key(&id, |stream| stream.id).ok()
    }

    /// Whether a stream with no entry is idle: no side can have used it. Push is off, so each
    /// even stream is idle.
    const fn idle(&self, id: u32) -> bool {
        id.is_multiple_of(2) || id > self.highest
    }

    /// Removes the stream at `index` when both of its sides sent END_STREAM.
    fn close_done(&mut self, index: usize) {
        let stream = &self.table[index];
        if stream.sending == Part::Done && stream.receiving == Part::Done {
            self.table.remove(index);
        }
    }

    /// Ends the stream at `index` with a reset of the peer or of the endpoint. The stream is
    /// closed, and its slot stays held until the application closes it.
    fn hold(&mut self, index: usize) {
        let stream = self.table.remove(index);
        assert!(
            self.table.len() + self.held.len() < self.limit,
            "the open and the held streams together fit in the limit"
        );
        self.held.push(stream.id);
    }

    /// Frees the slot of stream `id`, which a reset ended, when its handler ended.
    pub(super) fn free(&mut self, id: u32) -> Result<(), Error> {
        let index = self.held.iter().position(|&held| held == id).ok_or(Error::new(
            Kind::Misuse,
            "the stream holds no slot: no reset ended it, or it was closed",
        ))?;
        self.held.swap_remove(index);
        Ok(())
    }

    /// Acts on a decoded header block on stream `id`, whose first line is `first`. `acknowledged`
    /// tells whether the peer acknowledged the endpoint's settings, so that it knows the
    /// concurrency limit.
    pub(super) fn headers(
        &mut self,
        id: u32,
        end_stream: bool,
        first: Option<FieldLine<'_>>,
        acknowledged: bool,
    ) -> Result<Section, Fault> {
        let Some(index) = self.find(id) else {
            return self.open_remote(id, end_stream, acknowledged);
        };
        let stream = &mut self.table[index];
        let interim = stream.receiving == Part::Head && interim(first);
        let (section, next) = match stream.receiving {
            // Section 5.1: half-closed (remote).
            Part::Done => (Section::Reset(ErrorCode::STREAM_CLOSED), None),
            // Section 8.1: the trailer section ends the stream.
            Part::Body if end_stream => (Section::Trailers, Some(Part::Done)),
            Part::Body => (Section::Reset(ErrorCode::PROTOCOL_ERROR), None),
            // Section 8.1: an interim response cannot end the stream, and the final response
            // comes after it.
            Part::Head if interim && end_stream => (Section::Reset(ErrorCode::PROTOCOL_ERROR), None),
            Part::Head if interim => (Section::Head, Some(Part::Head)),
            Part::Head => (Section::Head, Some(if end_stream { Part::Done } else { Part::Body })),
        };
        match next {
            Some(part) => {
                stream.receiving = part;
                self.close_done(index);
            }
            None => self.hold(index),
        }
        Ok(section)
    }

    /// Whether a HEADERS frame on stream `id` opens a new stream of the peer that must wait for
    /// a free slot: the peer is within its limit, and streams that a reset ended hold the other
    /// slots. A stream that the endpoint discards after its GOAWAY needs no slot.
    pub(super) fn waits(&self, id: u32) -> bool {
        let discarded = matches!(self.drain, Drain::Sent(last) if id > last);
        self.role == Role::Server
            && !id.is_multiple_of(2)
            && id > self.highest
            && !discarded
            && self.table.len() < self.limit
            && self.table.len() + self.held.len() >= self.limit
    }

    /// Acts on a header block on a stream with no entry: a new stream of the client on a server,
    /// a closed stream, or an idle stream that the peer cannot open.
    fn open_remote(&mut self, id: u32, end_stream: bool, acknowledged: bool) -> Result<Section, Fault> {
        if self.role == Role::Client || !self.idle(id) || id.is_multiple_of(2) {
            return if self.idle(id) {
                Err(Fault::peer(
                    ErrorCode::PROTOCOL_ERROR,
                    "a header block came on an idle stream that the peer cannot open",
                ))
            } else {
                Ok(Section::Discard)
            };
        }
        // Section 5.1.1: each client stream below it that is still idle is now closed.
        self.highest = id;
        if let Drain::Sent(last) = self.drain
            && id > last
        {
            return Ok(Section::Discard);
        }
        // Section 5.1.2: a peer that knows the limit gets PROTOCOL_ERROR, and a peer that cannot
        // know it yet gets REFUSED_STREAM, which permits a retry. The rule of nghttp2 and Go.
        if self.table.len() >= self.limit {
            return Ok(Section::Refuse(if acknowledged {
                ErrorCode::PROTOCOL_ERROR
            } else {
                ErrorCode::REFUSED_STREAM
            }));
        }
        assert!(
            self.table.len() + self.held.len() < self.limit,
            "a new stream waits at its HEADERS frame until a slot is free"
        );
        self.table.push(Stream {
            id,
            sending: Part::Head,
            receiving: if end_stream { Part::Done } else { Part::Body },
            window: self.send_initial,
            credit: Credit::new(self.recv_initial),
        });
        self.last_stream = id;
        Ok(Section::Head)
    }

    /// Acts on the header of a DATA frame of `flow` bytes, with its padding, on stream `id`,
    /// whose data is `data` bytes. Each DATA frame counts toward the connection window (section
    /// 6.9), and its bytes that do not go up are free at once. Gives the increment of a
    /// WINDOW_UPDATE on the stream that is due: none for a frame with `end_stream`, after which
    /// the peer sends no DATA.
    pub(super) fn data(
        &mut self,
        id: u32,
        flow: u32,
        data: u32,
        end_stream: bool,
    ) -> Result<(Flow, Option<u32>), Fault> {
        let (flow, data) = (i64::from(flow), i64::from(data));
        if self.idle(id) {
            return Err(Fault::peer(ErrorCode::PROTOCOL_ERROR, "DATA came on an idle stream"));
        }
        if flow > self.credit.window {
            return Err(Fault::peer(
                ErrorCode::FLOW_CONTROL_ERROR,
                "DATA is past the connection window",
            ));
        }
        let mut grant = None;
        let verdict = match self.find(id) {
            None => Flow::Discard,
            Some(index) => {
                let stream = &mut self.table[index];
                let code = match stream.receiving {
                    Part::Body if flow > stream.credit.window => Some(ErrorCode::FLOW_CONTROL_ERROR),
                    Part::Body => None,
                    // Section 8.1.1: DATA before the header section is malformed.
                    Part::Head => Some(ErrorCode::PROTOCOL_ERROR),
                    // Section 5.1: half-closed (remote).
                    Part::Done => Some(ErrorCode::STREAM_CLOSED),
                };
                match code {
                    Some(code) => {
                        self.hold(index);
                        Flow::Reset(code)
                    }
                    None => {
                        stream.credit.take(flow, data);
                        grant = stream.credit.due().filter(|_| !end_stream);
                        if let Some(increment) = grant {
                            stream.credit.grant(increment);
                        }
                        Flow::Deliver
                    }
                }
            }
        };
        self.credit.take(flow, if verdict == Flow::Deliver { data } else { 0 });
        Ok((verdict, grant))
    }

    /// Counts `bytes` data bytes of a DATA frame on stream `id` whose header [`data`](Self::data)
    /// delivered, and gives whether they go up. The consumer holds them from now on. They are free
    /// at once when the stream no longer receives: the application reset it inside the frame.
    pub(super) fn receive(&mut self, id: u32, bytes: u32) -> bool {
        let bytes = i64::from(bytes);
        match self.find(id).filter(|&index| self.table[index].receiving == Part::Body) {
            Some(index) => {
                self.table[index].credit.held += bytes;
                self.credit.held += bytes;
                true
            }
            None => {
                self.credit.free += bytes;
                false
            }
        }
    }

    /// Records the END_STREAM of a DATA frame on stream `id`.
    pub(super) fn end(&mut self, id: u32) {
        if let Some(index) = self.find(id) {
            self.table[index].receiving = Part::Done;
            self.close_done(index);
        }
    }

    /// Acts on a RST_STREAM on stream `id`, and gives whether it ended a stream (section 6.4).
    pub(super) fn reset(&mut self, id: u32) -> Result<bool, Fault> {
        if self.idle(id) {
            return Err(Fault::peer(
                ErrorCode::PROTOCOL_ERROR,
                "RST_STREAM came on an idle stream",
            ));
        }
        Ok(self.find(id).map(|index| self.hold(index)).is_some())
    }

    /// Acts on a WINDOW_UPDATE of `increment` on stream `id`, or on the connection for 0
    /// (section 6.9). Gives `Ok(None)` when it changed no window that the endpoint uses, and the
    /// code of a stream error.
    pub(super) fn window(&mut self, id: u32, increment: u32) -> Result<Option<Result<(), ErrorCode>>, Fault> {
        let increment = i64::from(increment);
        if id == 0 {
            if self.window + increment > MAX {
                return Err(Fault::peer(
                    ErrorCode::FLOW_CONTROL_ERROR,
                    "a WINDOW_UPDATE takes the connection window past 2^31 - 1",
                ));
            }
            self.window += increment;
            return Ok(Some(Ok(())));
        }
        if self.idle(id) {
            return Err(Fault::peer(
                ErrorCode::PROTOCOL_ERROR,
                "WINDOW_UPDATE came on an idle stream",
            ));
        }
        // Section 5.1: a stream that sent its end can ignore the frame.
        let Some(index) = self.find(id).filter(|&index| self.table[index].sending != Part::Done) else {
            return Ok(None);
        };
        let stream = &mut self.table[index];
        if stream.window + increment > MAX {
            self.hold(index);
            return Ok(Some(Err(ErrorCode::FLOW_CONTROL_ERROR)));
        }
        stream.window += increment;
        Ok(Some(Ok(())))
    }

    /// Acts on a WINDOW_UPDATE of 0 on stream `id`, and gives whether it ended a stream with a
    /// stream error (section 6.9).
    pub(super) fn zero_window(&mut self, id: u32) -> Result<bool, Fault> {
        if self.idle(id) {
            return Err(Fault::peer(
                ErrorCode::PROTOCOL_ERROR,
                "WINDOW_UPDATE came on an idle stream",
            ));
        }
        Ok(self.find(id).map(|index| self.hold(index)).is_some())
    }

    /// Applies the peer's `SETTINGS_INITIAL_WINDOW_SIZE` of `initial` at the end of a SETTINGS
    /// frame, in which its largest value was `peak`. Each send window changes by the difference
    /// (section 6.9.2), and a window past 2^31 - 1 at any value is a connection error.
    pub(super) fn settings(&mut self, peak: u32, initial: u32) -> Result<(), Fault> {
        let (peak, initial) = (i64::from(peak), i64::from(initial));
        if peak == self.send_initial && initial == self.send_initial {
            return Ok(());
        }
        let mut sending = self.table.iter_mut().filter(|stream| stream.sending != Part::Done);
        if sending.any(|stream| stream.window + peak - self.send_initial > MAX) {
            return Err(Fault::peer(
                ErrorCode::FLOW_CONTROL_ERROR,
                "SETTINGS_INITIAL_WINDOW_SIZE takes a stream window past 2^31 - 1",
            ));
        }
        for stream in self.table.iter_mut().filter(|stream| stream.sending != Part::Done) {
            stream.window += initial - self.send_initial;
        }
        self.send_initial = initial;
        Ok(())
    }

    /// Applies the endpoint's `SETTINGS_INITIAL_WINDOW_SIZE` at the peer's acknowledgement:
    /// the peer applied it to each stream before it sent the acknowledgement.
    pub(super) fn acknowledged(&mut self) {
        let difference = self.local_initial - self.recv_initial;
        for stream in &mut self.table {
            stream.credit.window += difference;
        }
        self.recv_initial = self.local_initial;
    }

    /// Acts on a GOAWAY of the peer with `last` as its last stream (section 6.8). Each stream of
    /// a client above it ends, and the client can retry it on a new connection.
    pub(super) fn goaway(&mut self, last: u32) -> Result<(), Fault> {
        if self.peer_goaway.is_some_and(|earlier| last > earlier) {
            return Err(Fault::peer(
                ErrorCode::PROTOCOL_ERROR,
                "a GOAWAY has a larger last stream than the GOAWAY before it",
            ));
        }
        self.peer_goaway = Some(last);
        if self.role == Role::Client {
            self.table.retain(|stream| stream.id <= last);
        }
        Ok(())
    }

    /// Whether the connection ends: a GOAWAY went or came, and no stream is open.
    pub(super) fn drained(&self) -> bool {
        self.table.is_empty() && (self.peer_goaway.is_some() || matches!(self.drain, Drain::Sent(_)))
    }

    /// Whether a stream is open or half-closed.
    pub(super) fn active(&self) -> bool {
        !self.table.is_empty()
    }

    /// The identifier of the next stream of a client that can send at most `peer_limit`
    /// concurrent streams.
    pub(super) fn next(&self, peer_limit: u32) -> Result<u32, Error> {
        if self.role == Role::Server {
            return Err(Error::new(Kind::Misuse, "a server opens no stream: push is off"));
        }
        if self.peer_goaway.is_some() || self.drain != Drain::Open {
            return Err(Error::new(
                Kind::Overload,
                "the connection takes no new stream after a GOAWAY: use a new connection",
            ));
        }
        if self.table.len() >= self.limit.min(usize::try_from(peer_limit).unwrap_or(usize::MAX)) {
            return Err(Error::new(Kind::Overload, "the connection has its most streams open"));
        }
        if self.table.len() + self.held.len() >= self.limit {
            return Err(Error::new(
                Kind::Overload,
                "each free stream is held by a reset stream: close it when its handler ends",
            ));
        }
        let id = if self.highest == 0 { 1 } else { self.highest + 2 };
        if id > MAX_STREAM {
            return Err(Error::new(
                Kind::Overload,
                "the connection has no free stream identifier: use a new connection",
            ));
        }
        Ok(id)
    }

    /// Records the stream `id` that the endpoint opened with a header block.
    pub(super) fn opened(&mut self, id: u32, end_stream: bool) {
        assert!(id > self.highest, "a stream opens above each earlier stream");
        self.highest = id;
        self.table.push(Stream {
            id,
            sending: if end_stream { Part::Done } else { Part::Body },
            receiving: Part::Head,
            window: self.send_initial,
            credit: Credit::new(self.recv_initial),
        });
    }

    /// Checks that the endpoint can send a header section on stream `id`: an interim response
    /// (`interim`), the header section, or the trailer section, which ends the stream.
    pub(super) fn sendable(&self, id: u32, interim: bool, end_stream: bool) -> Result<(), Error> {
        let index = self.open_index(id)?;
        match (self.table[index].sending, interim, end_stream) {
            (Part::Head, true, true) => Err(Error::new(Kind::Misuse, "an interim response cannot end the stream")),
            (Part::Head, ..) | (Part::Body, _, true) => Ok(()),
            (Part::Body, ..) => Err(Error::new(Kind::Misuse, "a trailer section must end the stream")),
            (Part::Done, ..) => Err(Error::new(Kind::Misuse, "the stream sent its end")),
        }
    }

    /// Records a header section that the endpoint sent on stream `id`.
    pub(super) fn sent(&mut self, id: u32, interim: bool, end_stream: bool) {
        if let Some(index) = self.find(id) {
            let stream = &mut self.table[index];
            stream.sending = match (end_stream, interim) {
                (true, _) => Part::Done,
                (false, true) => Part::Head,
                (false, false) => Part::Body,
            };
            self.close_done(index);
        }
    }

    /// The DATA bytes of `len` that the endpoint can send on stream `id` now, in a frame of at
    /// most `max_frame` bytes: the smaller of the two windows.
    pub(super) fn credit(&self, id: u32, len: usize, max_frame: u32) -> Result<usize, Error> {
        let stream = &self.table[self.open_index(id)?];
        match stream.sending {
            Part::Head => Err(Error::new(Kind::Misuse, "send the header section first")),
            Part::Done => Err(Error::new(Kind::Misuse, "the stream sent its end")),
            Part::Body => {
                let credit = self.window.min(stream.window).clamp(0, i64::from(max_frame));
                Ok(len.min(usize::try_from(credit).unwrap_or(usize::MAX)))
            }
        }
    }

    /// Records `len` DATA bytes that the endpoint sent on stream `id`.
    pub(super) fn sent_data(&mut self, id: u32, len: u32, end_stream: bool) {
        let len = i64::from(len);
        self.window -= len;
        if let Some(index) = self.find(id) {
            let stream = &mut self.table[index];
            stream.window -= len;
            if end_stream {
                stream.sending = Part::Done;
                self.close_done(index);
            }
        }
    }

    /// Checks that the endpoint can reset stream `id` with `code`.
    pub(super) fn resettable(&self, id: u32, code: ErrorCode) -> Result<(), Error> {
        self.open_index(id)?;
        // Section 8.7: each stream of a server's table went up, so it cannot be refused.
        if self.role == Role::Server && code == ErrorCode::REFUSED_STREAM {
            return Err(Error::new(
                Kind::Misuse,
                "a stream whose header section went up cannot be refused",
            ));
        }
        Ok(())
    }

    /// Ends stream `id`, which the endpoint reset.
    pub(super) fn close(&mut self, id: u32) {
        if let Some(index) = self.find(id) {
            self.table.remove(index);
        }
    }

    /// Releases `bytes` bytes of stream `id` that the consumer held, and gives the WINDOW_UPDATE
    /// frames that return their credit: at most `room` of them. Refuses, and changes nothing,
    /// when the consumer holds fewer bytes or the frames need more room.
    pub(super) fn release(&mut self, id: u32, bytes: u32, room: usize) -> Result<[Option<(u32, u32)>; 2], Error> {
        let bytes = i64::from(bytes);
        let more = Error::new(Kind::Misuse, "the consumer released more bytes than it holds");
        if bytes > self.credit.held {
            return Err(more);
        }
        let mut connection = self.credit;
        connection.release(bytes);
        let mut stream = None;
        if let Some(index) = self.find(id) {
            let mut credit = self.table[index].credit;
            if bytes > credit.held {
                return Err(more);
            }
            credit.release(bytes);
            stream = Some((index, credit));
        }
        // A stream whose peer sent its end needs no credit.
        let stream_grant = stream
            .filter(|&(index, _)| self.table[index].receiving == Part::Body)
            .and_then(|(_, credit)| credit.due());
        let grants = [
            stream_grant.map(|increment| (id, increment)),
            connection.due().map(|increment| (0, increment)),
        ];
        if grants.iter().flatten().count() > room {
            return Err(Error::new(Kind::Overload, "the output queue or the frame pool is full"));
        }
        if let Some((index, mut credit)) = stream {
            if let Some(increment) = stream_grant {
                credit.grant(increment);
            }
            self.table[index].credit = credit;
        }
        if let Some((_, increment)) = grants[1] {
            connection.grant(increment);
        }
        self.credit = connection;
        Ok(grants)
    }

    /// The increment of a WINDOW_UPDATE that returns the free credit of the connection, when it
    /// is due.
    pub(super) fn connection_due(&self) -> Option<u32> {
        self.credit.due()
    }

    /// Counts the WINDOW_UPDATE of `increment` on the connection that went out.
    pub(super) fn connection_granted(&mut self, increment: u32) {
        self.credit.grant(increment);
    }

    fn open_index(&self, id: u32) -> Result<usize, Error> {
        self.find(id).ok_or(Error::new(Kind::Misuse, "the stream is not open"))
    }
}

/// Whether a header section with the first line `first` is an interim response: a status of 1xx
/// (RFC 9110, section 15.2). Its pseudo-header fields come first (RFC 9113, section 8.3), and a
/// response has one: `:status`.
pub(super) fn interim(first: Option<FieldLine<'_>>) -> bool {
    first.is_some_and(|line| line.name == b":status" && line.value.len() == 3 && line.value[0] == b'1')
}
