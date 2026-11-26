//! The calls that take the work of the peer and of time: `receive` and `drive`, the packets
//! and the frames that arrive, the timers, and the recovery of the packets that left.

use super::*;

impl Connection {
    /// Opens the packets of `datagrams`, the received region, which arrived on `path`. Runs the
    /// handshake on their CRYPTO data, and reads the frames of the streams. A packet that this end
    /// cannot open is discarded. Gives the next event, and stops there: call again with the same
    /// region and path while the call gives an event or [`Progress::Pending`].
    ///
    /// A server takes the packets of each path, and follows its peer to the path of its newest
    /// packet. A client takes only the packets of its path, and of the path that it left.
    pub fn receive(&mut self, datagrams: &mut Datagrams, path: Path, now: Instant) -> (Option<Event>, Turn) {
        let mut work = Work::default();
        self.more = false;
        if let Err(error) = self.timers(now, &mut work) {
            self.outcome = Some(Err(error));
        }
        loop {
            if let Some(event) = self.next_event(&mut work, now) {
                return (Some(event), self.turn());
            }
            if self.outcome.is_some() {
                break;
            }
            if work.reached(&self.limits.turn) {
                self.more = true;
                break;
            }
            let ecn = datagrams.ecn;
            let suffix = datagrams.next_datagram().and_then(endpoint::reset_suffix).copied();
            let Some(next) = datagrams.next_packet() else {
                break;
            };
            match next {
                Ok(packet) if self.ending.is_some() => self.heard(&packet, path, &mut work),
                Ok(packet) => {
                    if let Err(failure) = self.packet(packet, path, &mut work, now, ecn) {
                        self.fail(failure, now);
                    }
                }
                Err(_) => work.add(1, 1),
            }
            if self.reading.is_none()
                && suffix.is_some_and(|tail| self.matches_reset(&tail, path.peer))
                && let Err(error) = self.stateless_reset(now)
            {
                self.outcome = Some(Err(error));
            }
        }
        (None, self.turn())
    }

    /// Counts a datagram of the peer for a closing end, which reads no packet. A copy of the
    /// CONNECTION_CLOSE frame answers datagram 1, 2, 4, 8, and so on (RFC 9000, section 10.2.1).
    /// The datagram also pays for the frame on a path with no validation, so a server that waits
    /// for its credit sends the frame (RFC 9000, section 10.2.3).
    fn heard(&mut self, packet: &packet::Protected<'_>, path: Path, work: &mut Work) {
        work.add(packet.header().end(), 0);
        let (bytes, first) = packet.datagram();
        let Header::Protected { kind, dcid, .. } = *packet.header() else {
            return;
        };
        if !first || !self.ours(kind, dcid) {
            return;
        }
        // A client path has no amplification limit, so this counts only for a server.
        if path == self.paths.active.addresses {
            self.paths.received(path, bytes as u64);
        }
        if let Some(ending) = &mut self.ending {
            ending.heard = ending.heard.saturating_add(1);
            ending.send |= ending.close.is_some() && ending.heard.is_power_of_two();
        }
    }

    /// Whether a packet of `kind` to `dcid` is for this connection: its destination is a
    /// connection ID that this end issued, or the first destination of the client while the
    /// server has its Initial keys.
    fn ours(&self, kind: PacketKind, dcid: ConnectionId) -> bool {
        self.ids.issued().contains(&Some(dcid))
            || (matches!(self.end, End::Server { .. })
                && kind == PacketKind::Initial
                && dcid == self.retry_cid.unwrap_or(self.original_cid)
                && !self.spaces[0].discarded)
    }

    /// Runs the timers at `now`, and the work that waits: the events of the streams, the frames
    /// after an event, and the handshake work that a limit of a turn or the budget stopped. Gives
    /// the next event. Call it at the deadline of the last turn, when capacity is free, after the
    /// last [`transmit`](Self::transmit), and again while it gives an event or
    /// [`Progress::Pending`].
    pub fn drive(&mut self, now: Instant) -> (Option<Event>, Turn) {
        let mut work = Work::default();
        self.more = false;
        if let Err(error) = self.timers(now, &mut work) {
            self.outcome = Some(Err(error));
        }
        let event = self.next_event(&mut work, now);
        // A scan that a limit of the turn stopped goes on in the next turn.
        self.more |= work.reached(&self.limits.turn);
        (event, self.turn())
    }

    /// Gives the next event: the end of the connection, then the events of the streams that wait,
    /// and then the events of the frames of the packet that the engine reads. Else runs the
    /// handshake.
    fn next_event(&mut self, work: &mut Work, now: Instant) -> Option<Event> {
        for _ in 0..2 {
            if let Some(ending) = &mut self.ending
                && self.outcome.is_none()
                && core::mem::take(&mut ending.notify)
            {
                self.more = true;
                return Some(Event::Closed(ending.outcome));
            }
            if self.outcome.is_some() || self.ending.is_some() {
                return None;
            }
            if let Some(flow) = self.sides.notify_probe.take() {
                self.more = true;
                return Some(Event::SideProbe(flow));
            }
            let event = self
                .streams
                .event(work, &self.limits.turn)
                .map_or_else(|| self.frames(work), |event| Ok(Some(event)));
            match event {
                Ok(Some(event)) => {
                    self.more = true;
                    return Some(event);
                }
                Ok(None) => {}
                Err(failure) => self.fail(failure, now),
            }
        }
        if self.outcome.is_none()
            && self.ending.is_none()
            && let Err(failure) = self.advance(work)
        {
            self.fail(failure, now);
        }
        None
    }

    /// The result of a call.
    fn turn(&mut self) -> Turn {
        let deadline = match self.deadline() {
            Ok(at) => at.map(Deadline::at),
            Err(error) => {
                self.outcome = Some(Err(error));
                None
            }
        };
        let progress = match (self.outcome, self.wait) {
            (Some(outcome), _) => Progress::Terminal(outcome),
            (None, Some(units)) => Progress::Blocked(Blocked::Capacity(units)),
            (None, None) if self.more => Progress::Pending,
            (None, None) => Progress::Blocked(Blocked::Input),
        };
        Turn { progress, deadline }
    }

    /// The earliest timer of the connection.
    fn deadline(&self) -> Result<Option<Instant>, Error> {
        if self.outcome.is_some() {
            return Ok(None);
        }
        if let Some(ending) = &self.ending {
            return Ok(ending.until.or(self.handshake_deadline));
        }
        let previous = self
            .one_rtt
            .as_ref()
            .and_then(|keys| keys.previous.as_ref().map(|(_, until)| *until));
        let handshake = if self.confirmed { None } else { self.handshake_deadline };
        let validation = self.paths.validation.as_ref().map(|validation| validation.until);
        let probe = self
            .paths
            .probe
            .as_ref()
            .map(|probe| earlier(Some(probe.next), Some(probe.until)));
        Ok(earlier(
            earlier(
                earlier(self.idle_deadline()?, handshake),
                earlier(validation, probe.flatten()),
            ),
            earlier(
                earlier(previous, self.recovery_timer().map(|(at, _)| at)),
                self.paths.active.pacing_wait,
            ),
        ))
    }

    fn idle_deadline(&self) -> Result<Option<Instant>, Error> {
        self.idle
            .map(|idle| after(self.last_activity, idle.max(3 * self.pto())))
            .transpose()
    }

    /// The loss timer takes priority over a probe in any space (RFC 9002, section 6).
    fn recovery_timer(&self) -> Option<(Instant, Alarm)> {
        let loss = Level::ALL
            .into_iter()
            .filter_map(|l| self.spaces[l as usize].history.loss_time.map(|at| (at, Alarm::Loss(l))))
            .chain(self.sides.deadline().map(|at| (at, Alarm::SideLoss)))
            .min_by_key(|(at, _)| at.as_nanos());
        if loss.is_some()
            || self.paths.active.amplification_credit == Some(0)
            || self.paths.active.amplification_blocked
            || self.spaces.iter().any(|space| space.probe)
        {
            return loss;
        }
        let delay = |base: Instant, pto: Duration| {
            let nanos = pto
                .as_nanos()
                .checked_mul(1u128.checked_shl(self.paths.active.backoff)?)?
                .try_into()
                .ok()?;
            base.checked_add(Duration::from_nanos(nanos)).ok()
        };
        let parent = |base, level| {
            let pto = if level == Level::Data {
                self.pto()
            } else {
                self.paths.active.pto(Duration::ZERO)
            };
            delay(base, pto).map(|at| (at, Alarm::Probe(level)))
        };
        Level::ALL
            .into_iter()
            .filter_map(|level| {
                self.spaces[level as usize]
                    .history
                    .pto_start()
                    .filter(|_| level != Level::Data || self.confirmed)
                    .and_then(|base| parent(base, level))
            })
            .chain(
                self.sides
                    .probe_start()
                    .and_then(|(base, flow)| delay(base, self.pto()).map(|at| (at, Alarm::SideProbe(flow)))),
            )
            .min_by_key(|(at, _)| at.as_nanos())
            .or_else(|| {
                if self.validated() {
                    return None;
                }
                let level = if self.spaces[Level::Handshake as usize].keys.is_some() {
                    Level::Handshake
                } else {
                    Level::Initial
                };
                parent(self.validation_at, level)
            })
    }

    fn validated(&self) -> bool {
        self.confirmed
            || matches!(self.end, End::Server { .. })
            || self.spaces[Level::Handshake as usize].history.largest.is_some()
    }

    /// Ends the connection at its idle or handshake deadline, with no packet (RFC 9000, section
    /// 10.1), and at the end of its closing or draining period. Drops the old key of the peer at
    /// its deadline, and leaves a path that gave no answer in the time of its validation. When the
    /// peer gave no connection ID for the path before that one, the connection ends there.
    fn timers(&mut self, now: Instant, work: &mut Work) -> Result<(), Error> {
        if self.outcome.is_some() {
            return Ok(());
        }
        self.check_clock(now)?;
        if let Some(ending) = self.ending {
            // An end with no period ends when its frame is out, and at the handshake deadline at
            // the latest.
            if reached(ending.until.or(self.handshake_deadline), now)? {
                self.outcome = Some(ending.outcome);
            }
            return Ok(());
        }
        if reached(self.paths.active.pacing_wait, now)? {
            self.paths.active.pacing_wait = None;
        }
        if reached(self.idle_deadline()?, now)? {
            return Err(IDLE);
        }
        if !self.confirmed && reached(self.handshake_deadline, now)? {
            return Err(HANDSHAKE_LATE);
        }
        if let Some(keys) = &mut self.one_rtt
            && reached(keys.previous.as_ref().map(|(_, until)| *until), now)?
        {
            keys.previous = None;
        }
        // The connection returns to its last validated path, with the delivery state of that path
        // (RFC 9000, sections 8.2.4 and 9.3.2). A connection that cannot return has no path.
        let validation = self.paths.validation.as_ref();
        let ended = validation.filter(|validation| validation.until.as_nanos() <= now.as_nanos());
        if let Some(fallback) = ended.map(|validation| validation.fallback.addresses)
            && !self.moved(fallback, now)?
        {
            return Err(NO_PATH);
        }
        self.probe_ended(now)?;
        if let Some((at, alarm)) = self.recovery_timer()
            && reached(Some(at), now)?
        {
            match alarm {
                Alarm::Loss(level) => {
                    self.detect_loss(level, now, work)?;
                }
                Alarm::SideLoss => self.sides.timers(&mut self.paths, now, (work, &self.limits.turn))?,
                Alarm::Probe(level) => self.probe(level),
                Alarm::SideProbe(flow) => {
                    self.sides.probe(flow, now);
                    self.probe(Level::Data);
                }
            }
        }
        Ok(())
    }

    /// A probe timeout of `level` ended: its next packet is a probe (RFC 9002, section 6.2.4).
    fn probe(&mut self, level: Level) {
        self.spaces[level as usize].probe = true;
        let path = &mut self.paths.active;
        path.backoff = path.backoff.saturating_add(1);
        path.mtu.timed_out();
        // The probe also carries the challenge of a path that waits for its validation.
        if let Some(validation) = &mut self.paths.validation {
            validation.send = true;
        }
    }

    pub(super) fn limited(&self) -> bool {
        self.paths.active.room() < self.datagram_bytes() as u64
            || self.sides.waiting()
            || Level::ALL.into_iter().any(|l| self.has_data(l))
    }

    pub(super) fn ack_delay(&self, encoded: u64) -> Duration {
        self.peer.map_or(Duration::ZERO, |peer| {
            let delay = Duration::from_micros(encoded.saturating_mul(1 << peer.ack_delay_exponent));
            if self.confirmed {
                delay.min(peer.ack_delay_max)
            } else {
                delay
            }
        })
    }

    /// Takes an ACK frame of `level`. Gives `false` when a limit of the turn stopped its walk: give
    /// the same frame in the next turn.
    fn acknowledge(&mut self, level: Level, ack: &Ack<'_>, now: Instant, work: &mut Work) -> Result<bool, Failure> {
        let space = &self.spaces[level as usize];
        if ack.largest >= space.next {
            return Err(Failure::transport(
                ErrorCode::PROTOCOL_VIOLATION,
                if ack.ecn.is_some() { 3 } else { 2 },
                VIOLATION,
            ));
        }
        let mut delay = Duration::ZERO;
        if level == Level::Data {
            if let Some(keys) = &mut self.one_rtt
                && keys.first_sent.is_some_and(|first| ack.largest >= first)
            {
                keys.acknowledged = true;
            }
            delay = self.ack_delay(ack.delay);
        }
        let limited = self.limited();
        self.paths.active.controller.limited(now, limited);
        let space = &mut self.spaces[level as usize];
        let turn = (&mut *work, &self.limits.turn);
        let Some(acked) = space
            .history
            .ack(ack, &mut self.paths, now, delay, turn, |record| match record {
                Record::Range(DataRange::Crypto { offset, len }) => {
                    let refunded = self.output.refund(space.send.acknowledged(offset, len));
                    assert!(refunded.is_ok(), "the output charge holds each CRYPTO message");
                }
                record @ (Record::RetireId(_) | Record::NewToken) => self.ids.acknowledged(record),
                other => self.streams.acknowledged(other),
            })?
        else {
            return Ok(false);
        };
        if acked.eliciting {
            space.probe = false;
            self.validation_at = now;
            if self.validated() {
                self.paths.active.backoff = 0;
            }
        }
        let congestion = self.detect_loss(level, now, work)?;
        self.paths.active.acknowledged(acked, now, limited && !congestion);
        Ok(true)
    }

    fn detect_loss(&mut self, level: Level, now: Instant, work: &mut Work) -> Result<bool, Error> {
        let space = &mut self.spaces[level as usize];
        space
            .history
            .detect(&mut self.paths, now, (work, &self.limits.turn), |record| {
                match record {
                    record @ (Record::IssueId(_) | Record::RetireId(_) | Record::NewToken) => self.ids.lost(record),
                    // The recovery layer takes these records.
                    Record::Mtu(_) | Record::Challenge => {}
                    Record::HandshakeDone => self.handshake_done = true,
                    Record::Limit(_) | Record::Control(_, _) => self.streams.lost_control(record),
                    Record::Range(range) => {
                        let retry = &mut space.retry;
                        super::super::reassembly::grow(
                            (retry.len(), retry.capacity(), size_of::<DataRange>()),
                            &mut space.credit,
                            |n| retry.try_reserve_exact(n).is_ok(),
                        )
                        .map_err(|_| recovery::NO_ROOM)?;
                        retry.push_back(range);
                    }
                }
                Ok(())
            })
    }

    /// Opens one packet, which arrived on `path`, and reads its frames.
    fn packet(
        &mut self,
        packet: packet::Protected<'_>,
        path: Path,
        work: &mut Work,
        now: Instant,
        ecn: Ecn,
    ) -> Result<(), Failure> {
        work.add(packet.header().end(), 0);
        let active = path == self.paths.active.addresses;
        let Header::Protected { kind, dcid, scid, .. } = *packet.header() else {
            if !active {
                return Ok(());
            }
            if matches!(self.end, End::Client { .. })
                && matches!(packet.header(), Header::Negotiation { .. })
                && packet::Negotiation::of(
                    (packet.bytes(), packet.header()),
                    (&self.original_cid, &self.local_cid, super::super::Version::V1),
                    self.initial_peer.is_some() || self.retry_cid.is_some(),
                ) == packet::Negotiation::Abandon
            {
                self.outcome = Some(Err(Error::new(
                    Kind::Unsupported,
                    "the peer offered no supported QUIC version",
                )));
                return Ok(());
            }
            if let Header::Retry { dcid, scid, token, .. } = packet.header()
                && matches!(self.end, End::Client { .. })
                && self.retry_cid.is_none()
                && self.initial_peer.is_none()
                && self.local_cid == *dcid
                && *scid != self.original_cid
                && !token.is_empty()
                && token.len() <= CLIENT_TOKEN_MAX
                && packet::retry_is_valid(packet.bytes(), &self.original_cid)
            {
                let token = self.copy_token(&packet.bytes()[token.clone()])?;
                let space = &mut self.spaces[0];
                space.history.discard(&mut self.paths);
                space.retry.clear();
                space.keys = Some(packet::initial_keys(scid, Side::Client));
                space.sealed = 0;
                space.send.rewind();
                space.probe = false;
                // The connection starts again, with the connection ID of the Retry packet.
                self.paths.switch(PathState::new(
                    path,
                    *scid,
                    self.limits.datagram_bytes_max,
                    self.limits.congestion_control,
                ))?;
                self.initial_token = Some(token);
                self.retry_cid = Some(*scid);
                self.validation_at = now;
            }
            return Ok(());
        };
        let server = matches!(self.end, End::Server { .. });
        let ours = self.ours(kind, dcid);
        let (bytes, first) = packet.datagram();
        // Each datagram counts one time, for the address that it came from. The active path counts
        // each datagram of the connection, also one that this end then discards (RFC 9000, section
        // 8.1).
        if server && first && ours && active {
            self.paths.received(path, bytes as u64);
        }
        if server && kind == PacketKind::Initial && bytes < DATAGRAM_MIN {
            return Ok(());
        }
        let Some(level) = Level::of(kind).filter(|_| ours) else {
            return Ok(());
        };
        // Another path carries only 1-RTT packets, after the handshake is confirmed. A server takes
        // each path. A client takes only the path that it left, the path to the preferred address
        // of the server, and after its move there, the path of the handshake, where the server
        // sends until it validates its preferred address. It takes no other address of the server
        // (RFC 9000, sections 9 and 9.6).
        let known = self
            .paths
            .validation
            .as_ref()
            .is_some_and(|validation| validation.fallback.addresses == path)
            || self.paths.probe.as_ref().is_some_and(|probe| probe.path == path)
            || matches!(self.end, End::Client { left: Some(left), .. } if left == path);
        if !active && !(level == Level::Data && self.confirmed && (server || known)) {
            return Ok(());
        }
        // A client takes the connection ID of the server from its first Initial packet, and drops
        // each later packet with another one (RFC 9000, section 7.2).
        if level != Level::Data && self.initial_peer.is_some_and(|first| first != scid) {
            return Ok(());
        }
        let space = &self.spaces[level as usize];
        let expected = space.ranges.largest().map_or(0, |largest| largest + 1);
        let opened = match level {
            Level::Data => {
                // No 1-RTT packet is read before the handshake completes (RFC 9001, section
                // 5.7): the parameters of the peer, which the frames need, come with it.
                let Some(keys) = self.one_rtt.as_mut().filter(|_| self.peer.is_some()) else {
                    return Ok(());
                };
                let unmasked = match packet.unmask(&*keys.remote.header, expected) {
                    Ok(unmasked) => unmasked,
                    Err(_) => return Ok(()),
                };
                // A packet of the other phase is of the previous phase while the old key stays and
                // its number is below each packet of this phase, and else of the next phase (RFC
                // 9001, section 6.3). The next phase starts only above each packet of this phase.
                let number = unmasked.number();
                let (old, forward) = keys
                    .received
                    .map_or((true, true), |(low, high)| (number < low, number > high));
                match (unmasked.key_phase() == keys.phase, &keys.previous) {
                    (true, _) => unmasked.open(&*keys.remote.packet).map(|packet| (packet, false, true)),
                    (false, Some((previous, _))) if old => {
                        unmasked.open(&**previous).map(|packet| (packet, false, true))
                    }
                    (false, _) => unmasked.open(&*keys.next.remote).map(|packet| (packet, true, forward)),
                }
            }
            _ => {
                let Some(keys) = &space.keys else {
                    return Ok(());
                };
                packet
                    .unmask(&*keys.remote.header, expected)
                    .and_then(|unmasked| unmasked.open(&*keys.remote.packet))
                    .map(|packet| (packet, false, true))
            }
        };
        let (packet, updated, forward) = match opened {
            Ok(opened) => opened,
            Err(OpenError::Authentication) => return self.authentication_failed(level),
            Err(OpenError::Short) => return Ok(()),
            Err(OpenError::Violation) => return Err(Failure::transport(ErrorCode::PROTOCOL_VIOLATION, 0, VIOLATION)),
        };
        // The newer keys protect a packet below one of the older keys (RFC 9001, section 6.4).
        if !forward {
            return Err(Failure::transport(
                ErrorCode::KEY_UPDATE_ERROR,
                0,
                Error::new(
                    Kind::Malformed,
                    "the QUIC peer protected a lower packet number with newer keys",
                ),
            ));
        }
        let number = packet.number();
        if self.spaces[level as usize].ranges.seen(number) {
            return Ok(());
        }
        // After its move to its preferred address, a server drops each newer packet that arrives
        // at the address that it left, and reads a delayed one (RFC 9000, section 9.6.2).
        if let End::Server {
            left: Some((local, largest)),
            ..
        } = self.end
            && level == Level::Data
            && path.local == local
            && number > largest
        {
            return Ok(());
        }
        // Another address counts only a datagram whose first packet opens, so no forged datagram
        // changes its credit.
        if server && first && !active {
            self.paths.received(path, bytes as u64);
        }
        if updated {
            // The peer updated its keys: this end follows in its next packet (RFC 9001, section
            // 6.2).
            let until = after(now, 3 * self.pto())?;
            if let Some(keys) = &mut self.one_rtt {
                keys.update(until);
            }
        }
        if level == Level::Data
            && let Some(keys) = &mut self.one_rtt
            && keys.phase == packet.key_phase()
        {
            keys.received = Some(
                keys.received
                    .map_or((number, number), |(low, high)| (low.min(number), high.max(number))),
            );
        }
        if !server && level == Level::Initial && self.initial_peer.is_none() {
            self.paths.active.remote_cid = scid;
            self.initial_peer = Some(scid);
        }
        // A server drops the Initial keys when a Handshake packet of the client opens (RFC 9001,
        // section 4.9.1).
        if server && level == Level::Handshake && !self.spaces[0].discarded {
            self.paths.active.amplification_credit = None;
            self.paths.active.amplification_blocked = false;
            self.discard(Level::Initial);
        }
        self.received = true;
        self.last_activity = now;
        self.reading = Some(Reading {
            destination: dcid,
            path,
            probing: true,
            level,
            payload: packet.payload(),
            at: 0,
            number,
            received_at: now,
            ecn,
            eliciting: false,
            first_datagram: None,
            accepted: false,
        });
        Ok(())
    }

    /// Counts a packet of `level` that failed authentication. The packets of each level that
    /// failed count together, and the connection ends past the integrity limit of the suite of
    /// `level` (RFC 9001, section 6.6).
    fn authentication_failed(&mut self, level: Level) -> Result<(), Failure> {
        self.failures = self.failures.saturating_add(1);
        let limit = match level {
            Level::Data => self.one_rtt.as_ref().map(|keys| &keys.remote),
            _ => self.spaces[level as usize].keys.as_ref().map(|keys| &keys.remote),
        }
        .map_or(u64::MAX, |remote| remote.packet.integrity_limit());
        if self.failures > limit {
            return Err(Failure::transport(
                ErrorCode::AEAD_LIMIT_REACHED,
                0,
                Error::new(
                    Kind::Malformed,
                    "the QUIC packets that failed authentication reached their limit",
                ),
            ));
        }
        Ok(())
    }

    /// Reads the frames of the opened packet, up to a frame that gives an event: the rest waits
    /// for the next call. A frame whose stream data or state finds no room ends the packet, which
    /// is then not received.
    fn frames(&mut self, work: &mut Work) -> Result<Option<Event>, Failure> {
        let Some(mut reading) = self.reading.take() else {
            return Ok(None);
        };
        let server = matches!(self.end, End::Server { .. });
        let (level, handshake_level) = (reading.level, reading.level != Level::Data);
        loop {
            let bytes = reading.payload.bytes().get(reading.at..).unwrap_or_default();
            if bytes.is_empty() {
                if !reading.accepted && !self.spaces[level as usize].discarded {
                    let ranges = &mut self.spaces[level as usize].ranges;
                    ranges.accept(reading.number, reading.received_at, reading.eliciting, reading.ecn)?;
                    // The peer moved: its newest packet that is not a probe came on another path.
                    // A probe with a higher number can arrive before it (RFC 9000, section 9.3).
                    if level == Level::Data
                        && !reading.probing
                        && self.non_probing.is_none_or(|largest| reading.number > largest)
                    {
                        self.non_probing = Some(reading.number);
                        if server && reading.path != self.paths.active.addresses {
                            // A server validates the path from its preferred address before it
                            // sends there (RFC 9000, section 9.6.2).
                            if self.to_preferred(reading.path) {
                                self.probe_preferred(reading.path, reading.received_at)
                                    .map_err(Failure::local)?;
                            } else {
                                self.moved(reading.path, reading.received_at)?;
                            }
                        }
                    }
                    if let Some(at) = reading.first_datagram {
                        reading.at = at;
                        reading.accepted = true;
                        continue;
                    }
                }
                return Ok(None);
            }
            if work.reached(&self.limits.turn) {
                self.more = true;
                self.reading = Some(reading);
                return Ok(None);
            }
            let start = reading.at;
            let (frame, len) =
                Frame::parse(bytes).map_err(|error| Failure::transport(error.code, error.frame_type, VIOLATION))?;
            reading.at += len;
            work.add(0, 1);
            // The data of a STREAM or DATAGRAM frame is the end of its frame.
            let data = |data: &[u8]| reading.at - data.len()..reading.at;
            if reading.accepted && !matches!(frame, Frame::Datagram { .. }) {
                continue;
            }
            reading.eliciting |= !matches!(
                frame,
                Frame::Padding { .. } | Frame::Ack(_) | Frame::ConnectionClose { .. }
            );
            reading.probing &= matches!(
                frame,
                Frame::Padding { .. }
                    | Frame::PathChallenge { .. }
                    | Frame::PathResponse { .. }
                    | Frame::NewConnectionId { .. }
            );
            let taken = match frame {
                Frame::Padding { .. } | Frame::Ping => Ok(None),
                Frame::Ack(ack) => {
                    if !self.acknowledge(level, &ack, reading.received_at, work)? {
                        // A limit of the turn stopped the walk of the frame: the next turn reads
                        // the frame again, and the walk goes on.
                        reading.at = start;
                        self.reading = Some(reading);
                        self.more = true;
                        return Ok(None);
                    }
                    Ok(None)
                }
                Frame::Crypto { offset, data } => {
                    self.crypto(level, offset, data)?;
                    Ok(None)
                }
                // A close of the application is only in 1-RTT packets (RFC 9000, section 12.4).
                Frame::ConnectionClose { frame_type: None, .. } if handshake_level => {
                    return Err(Failure::transport(ErrorCode::PROTOCOL_VIOLATION, 0x1d, VIOLATION));
                }
                Frame::ConnectionClose { code, frame_type, .. } => {
                    let close = match frame_type {
                        Some(frame_type) => PeerClose::Transport {
                            code: ErrorCode(code),
                            frame_type,
                        },
                        None => PeerClose::Application(code),
                    };
                    self.peer_close = Some(close);
                    self.end_with(close.outcome(), None, reading.received_at);
                    return Ok(None);
                }
                Frame::HandshakeDone if !server && !handshake_level => {
                    self.confirm();
                    self.prefer(reading.received_at).map_err(Failure::local)?;
                    Ok(None)
                }
                Frame::HandshakeDone => {
                    return Err(Failure::transport(ErrorCode::PROTOCOL_VIOLATION, 0x1e, VIOLATION));
                }
                Frame::NewToken { token } => {
                    if server || handshake_level {
                        return Err(Failure::transport(ErrorCode::PROTOCOL_VIOLATION, 7, VIOLATION));
                    }
                    if token.len() <= CLIENT_TOKEN_MAX
                        && let Ok(token) = self.copy_token(token)
                    {
                        self.future_token = Some(token);
                    }
                    Ok(None)
                }
                // Only PADDING, PING, ACK, CRYPTO, and CONNECTION_CLOSE are in Initial and
                // Handshake packets (RFC 9000, section 12.4).
                _ if handshake_level => {
                    return Err(Failure::transport(ErrorCode::PROTOCOL_VIOLATION, 0, VIOLATION));
                }
                Frame::Stream {
                    stream,
                    offset,
                    data: bytes,
                    fin,
                } => self
                    .streams
                    .stream_in(stream, (offset, fin), data(bytes), &reading.payload),
                Frame::ResetStream {
                    stream,
                    code,
                    final_size,
                } => self.streams.reset_in(stream, code, final_size).map(|()| None),
                Frame::StopSending { stream, code } => self.streams.stop_in(stream, code).map(|()| None),
                Frame::MaxData { max } => {
                    self.streams.max_data_in(max);
                    Ok(None)
                }
                Frame::MaxStreamData { stream, max } => self.streams.max_stream_data_in(stream, max).map(|()| None),
                Frame::MaxStreams { direction, max } => {
                    self.streams.max_streams_in(direction, max);
                    Ok(None)
                }
                Frame::StreamDataBlocked { stream, .. } => self.streams.blocked_in(stream).map(|()| None),
                Frame::Datagram { data: bytes } => {
                    self.streams
                        .unreliable_in(len, data(bytes), &reading.payload)
                        .map(|event| {
                            if reading.accepted {
                                event
                            } else {
                                reading.first_datagram.get_or_insert(start);
                                None
                            }
                        })
                }
                Frame::NewConnectionId {
                    sequence,
                    retire_prior_to,
                    id,
                    reset_token,
                } => {
                    let id = Id {
                        sequence,
                        id,
                        reset: Some(reset_token),
                    };
                    let active = self.paths.active.remote_cid;
                    let kept = self
                        .ids
                        .receive(id, retire_prior_to, active)
                        .map_err(|code| Failure::transport(code, 0x18, VIOLATION))?;
                    // A path keeps its connection ID while the peer did not retire it. Else it
                    // takes one that no path uses, when the peer gave one (RFC 9000, section 9.5).
                    if kept != active {
                        self.paths.active.remote_cid = self.spare().map_or(kept, |spare| spare.id);
                    }
                    let left = self.paths.validation.as_ref();
                    let fallback = left.map(|validation| validation.fallback.addresses);
                    if let Some(cid) = fallback.and_then(|path| self.cid_for(path))
                        && let Some(validation) = &mut self.paths.validation
                    {
                        validation.fallback.remote_cid = cid;
                    }
                    Ok(None)
                }
                Frame::RetireConnectionId { sequence } => {
                    if self.local_cid.as_bytes().is_empty() {
                        return Err(Failure::transport(ErrorCode::PROTOCOL_VIOLATION, 0x19, VIOLATION));
                    }
                    if self
                        .ids
                        .retire_local(sequence, reading.destination)
                        .map_err(|code| Failure::transport(code, 0x19, VIOLATION))?
                    {
                        self.issue_id()?;
                        if !self.ids.issued().contains(&Some(self.local_cid)) {
                            self.local_cid = reading.destination;
                        }
                    }
                    Ok(None)
                }
                Frame::PathChallenge { data } => {
                    let active = &self.paths.active;
                    let on_active = reading.path == active.addresses;
                    let fallback = self.paths.validation.as_ref().map(|validation| &validation.fallback);
                    let validated = if on_active {
                        active.amplification_credit.is_none()
                    } else {
                        fallback.is_some_and(|fallback| fallback.addresses == reading.path)
                    };
                    self.answers[usize::from(!on_active)] = Some(Answer {
                        path: reading.path,
                        data,
                        validated,
                    });
                    // The answer on the active path goes in a packet that is not a probe, so a
                    // peer that did not move brings the connection back (RFC 9000, section 9.3.3).
                    self.ping |= on_active;
                    Ok(None)
                }
                Frame::PathResponse { data } => {
                    self.responded(data, reading.received_at)?;
                    Ok(None)
                }
                // The credit of the peer follows the consumer of this end: these frames change
                // nothing.
                Frame::DataBlocked { .. } | Frame::StreamsBlocked { .. } => Ok(None),
            };
            match taken {
                Ok(None) => {}
                Ok(Some(event)) => {
                    self.reading = Some(reading);
                    return Ok(Some(event));
                }
                Err(Stop::Violation(code, frame_type)) => {
                    return Err(Failure::transport(code, frame_type, VIOLATION));
                }
                Err(Stop::Refused(_)) => {
                    self.refused = self.refused.saturating_add(1);
                    return Ok(None);
                }
            }
        }
    }

    /// Takes the CRYPTO data of a frame of `level`. Data at a level below the one that rustls
    /// reads must not pass the data that arrived there (RFC 9001, section 4.1.3).
    fn crypto(&mut self, level: Level, offset: u64, data: &[u8]) -> Result<(), Failure> {
        let end = offset.saturating_add(data.len() as u64);
        let space = &mut self.spaces[level as usize];
        if (level as usize) < (self.read as usize) && end > space.received {
            return Err(Failure::transport(ErrorCode::PROTOCOL_VIOLATION, 0x06, VIOLATION));
        }
        space.received = space.received.max(end);
        space.receive.insert(offset, data).map_err(|refused| {
            Failure::transport(
                refused.code(),
                0x06,
                match refused {
                    Refused::Bound => Error::new(
                        Kind::Overload,
                        "the CRYPTO data of the peer passed the buffer bound of its level",
                    ),
                    Refused::Budget => Error::new(Kind::Overload, "the budget refused the CRYPTO data of the peer"),
                },
            )
        })
    }

    /// Confirms the handshake: the handshake keys and the handshake deadline go.
    pub(super) fn confirm(&mut self) {
        if self.confirmed {
            return;
        }
        self.confirmed = true;
        self.handshake_deadline = None;
        self.discard(Level::Handshake);
    }

    pub(super) fn discard(&mut self, level: Level) {
        if level == Level::Initial {
            self.initial_token = None;
        }
        let space = &mut self.spaces[level as usize];
        space.history.discard(&mut self.paths);
        self.paths.active.backoff = 0;
        let refunded = self.output.refund(space.send.bytes());
        assert!(refunded.is_ok(), "the output charge holds each CRYPTO message");
        space.discard(&self.budget, self.window);
    }

    /// The longest time that the peer delays an acknowledgement, after the handshake is confirmed.
    pub(super) fn ack_delay_max(&self) -> Duration {
        self.peer
            .filter(|_| self.confirmed)
            .map_or(Duration::ZERO, |peer| peer.ack_delay_max)
    }

    /// The probe timeout of the data space, including the peer's maximum ACK delay.
    pub(super) fn pto(&self) -> Duration {
        self.paths.active.pto(self.ack_delay_max())
    }
}
