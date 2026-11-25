//! The calls that send: `transmit` and `transmit_ecn`, the batches for segmentation offload,
//! and the building and the sealing of each packet.

use super::*;

impl Connection {
    /// Builds a batch of at most `segments` unmarked datagrams at the start of `out`. Gives the
    /// batch, or `None` when no datagram can leave now. Call it until it gives `None`. A host with
    /// no segmentation offload asks for one segment. Each datagram has at most
    /// [`Limits::datagram_bytes_max`] bytes. A client Initial or an ack-eliciting server Initial
    /// needs at least 1,200. A batch holds what the window and the pacer allow now: about 1 ms of
    /// the rate of the path. It also ends where `out` has no room for one more datagram.
    ///
    /// Refuses with [`Kind::Misuse`] when `out` has fewer bytes than
    /// [`Limits::datagram_bytes_max`].
    pub fn transmit(
        &mut self,
        out: &mut [u8],
        segments: NonZeroUsize,
        now: Instant,
    ) -> Result<Option<Transmission>, Error> {
        self.transmit_mark(out, segments.get(), now, Ecn::NotEct)
    }

    /// Builds a batch for a host that can set its IP ECN codepoint. Apply the returned mark to
    /// each datagram of the batch. Supply the received mark with [`Datagrams::with_ecn`]. A host
    /// without send metadata uses [`transmit`](Self::transmit). After `None`, call
    /// [`drive`](Self::drive) to get the next deadline.
    pub fn transmit_ecn(
        &mut self,
        out: &mut [u8],
        segments: NonZeroUsize,
        now: Instant,
    ) -> Result<Option<Transmission>, Error> {
        self.check_clock(now)?;
        let (ecn, marks) = self.paths.active.mark(now);
        let sent = self.transmit_mark(out, segments.get().min(marks), now, ecn)?;
        if let Some(sent) = sent {
            let datagrams = sent.len.div_ceil(sent.segment_bytes);
            self.paths.active.marked(sent.ecn, datagrams, now);
        }
        Ok(sent)
    }

    fn transmit_mark(
        &mut self,
        out: &mut [u8],
        segments: usize,
        now: Instant,
        mark: Ecn,
    ) -> Result<Option<Transmission>, Error> {
        self.check_clock(now)?;
        if out.len() < self.limits.datagram_bytes_max {
            return Err(Error::new(
                Kind::Misuse,
                "a QUIC datagram needs an output of the bytes of its limit",
            ));
        }
        if self.outcome.is_some() {
            return Ok(None);
        }
        let send = SendAt {
            now,
            mark,
            admitted: false,
        };
        if self.ending.is_none() {
            self.fit();
            match self.build(out, segments, send) {
                Ok(sent) => return Ok(sent),
                Err(failure) => self.fail(failure, now),
            }
        }
        Ok(self.closing(out, send))
    }

    /// Builds the next batch of a live connection, of at most `segments` datagrams. A datagram for
    /// a path that does not carry the connection, and then a probe of the datagram size, go
    /// alone. Then the datagrams of the packets that wait follow each other: each one except the
    /// last has the datagram size of the active path.
    fn build(&mut self, out: &mut [u8], segments: usize, send: SendAt) -> Result<Option<Transmission>, Failure> {
        if let Some((len, path)) = self.off_path(out, send)? {
            return Ok(Some(Transmission::one(len, Ecn::NotEct, path)));
        }
        let (path, ecn) = (self.paths.active.addresses, send.mark);
        if let Some(len) = self.size_probe(out, send)? {
            return Ok(Some(Transmission::one(len, ecn, path)));
        }
        let segment = self.room();
        let mut at = 0;
        for _ in 0..segments {
            let Some(rest) = out.get_mut(at..at + segment) else {
                break;
            };
            let Some(len) = self.next(rest, send)? else {
                break;
            };
            at += len;
            if len < segment {
                break;
            }
        }
        Ok((at > 0).then_some(Transmission {
            len: at,
            segment_bytes: at.min(segment),
            ecn,
            path,
        }))
    }

    /// Builds one datagram of the packets that wait into `out`, and charges it to the active path.
    fn next(&mut self, out: &mut [u8], send: SendAt) -> Result<Option<usize>, Failure> {
        let room = self.room().min(out.len());
        let pad = self.spaces[0].keys.is_some() && (self.spaces[0].probe || self.has_data(Level::Initial));
        if self.paths.active.amplification_credit.is_some() && (room == 0 || (pad && room < DATAGRAM_MIN)) {
            self.amplification_blocked();
            return Ok(None);
        }
        let Some(len) = self.datagram(&mut out[..room], send.now, send.mark)? else {
            let active = &self.paths.active;
            if room < DATAGRAM_MIN && active.pacing_wait.is_none() && active.room() >= room as u64 {
                self.amplification_blocked();
            }
            return Ok(None);
        };
        self.paths.active.charge(len as u64);
        Ok(Some(len))
    }

    /// The bytes of the next datagram to the active path: its datagram size, and what the
    /// amplification limit leaves. After a probe timeout, at most 1,200 bytes, so a path that now
    /// drops larger datagrams still carries the probe.
    fn room(&self) -> usize {
        let path = &self.paths.active;
        let size = if self.spaces.iter().any(|space| space.probe) {
            DATAGRAM_MIN
        } else {
            path.mtu.size()
        };
        path.amplification_credit
            .map_or(size, |credit| size.min(usize::try_from(credit).unwrap_or(usize::MAX)))
    }

    fn amplification_blocked(&mut self) {
        let pending = self.ending.is_some() || Level::ALL.into_iter().any(|level| self.wants(level, true));
        let path = &mut self.paths.active;
        if pending && !path.amplification_blocked {
            path.amplification_blocked = true;
            path.amplification_rounds = path.amplification_rounds.saturating_add(1);
        }
    }

    /// The bytes of the largest datagram that this end sends now: the datagram size of the
    /// active path.
    pub(super) fn datagram_bytes(&self) -> usize {
        self.paths.active.mtu.size()
    }

    /// The top of the search for the datagram size of a path: the limit of this end, and the
    /// limit of the peer.
    pub(super) fn datagram_top(&self) -> usize {
        let peer = self.peer.map_or(usize::MAX, |peer| {
            usize::try_from(peer.udp_payload_bytes_max).unwrap_or(usize::MAX)
        });
        self.limits.datagram_bytes_max.min(peer)
    }

    /// Whether a PATH_RESPONSE or a PATH_CHALLENGE frame waits for the active path.
    pub(super) fn path_frames(&self) -> bool {
        let active = self.paths.active.addresses;
        self.answers.iter().flatten().any(|answer| answer.path == active)
            || self.paths.validation.as_ref().is_some_and(|validation| validation.send)
    }

    /// Whether an ack-eliciting frame waits at this level.
    pub(super) fn has_data(&self, level: Level) -> bool {
        let space = &self.spaces[level as usize];
        space.send.pending()
            || !space.retry.is_empty()
            || (level == Level::Data
                && (self.handshake_done
                    || self.ping
                    || self.path_frames()
                    || self.ids.pending()
                    || self.streams.pending()))
    }

    fn wants(&self, level: Level, admitted: bool) -> bool {
        let space = &self.spaces[level as usize];
        let keyed = if level == Level::Data {
            self.one_rtt.is_some()
        } else {
            space.keys.is_some()
        };
        keyed && (space.ranges.due || space.probe || (self.has_data(level) && admitted))
    }

    /// Builds a datagram of the packets that wait, at most one for each level.
    fn datagram(&mut self, out: &mut [u8], now: Instant, mark: Ecn) -> Result<Option<usize>, Failure> {
        // Only an ACK settles a bare ACK, so bare ACKs that waited one probe timeout send a PING,
        // which brings one (RFC 9000, section 13.2.4).
        if self.one_rtt.is_some() && self.spaces[Level::Data as usize].history.stale(&self.paths, now) {
            self.ping = true;
        }
        let data = Level::ALL.into_iter().any(|level| self.has_data(level));
        let path = &mut self.paths.active;
        let admitted = data && path.paced(out.len() as u64, now)?;
        let limited = data || self.sides.waiting() || path.room() < out.len() as u64;
        path.controller.limited(now, limited);
        let send = SendAt { now, mark, admitted };
        let wanted = Level::ALL.map(|level| self.wants(level, admitted));
        let Some(last) = wanted.iter().rposition(|&wanted| wanted) else {
            return Ok(None);
        };
        let initial = wanted[0]
            && (matches!(self.end, End::Client { .. }) || self.has_data(Level::Initial) || self.spaces[0].probe);
        let mut at = 0;
        let mut handshake_sent = false;
        for level in Level::ALL {
            if !wanted[level as usize] {
                continue;
            }
            let pad = initial.then_some((DATAGRAM_MIN.saturating_sub(at), Level::ALL[last]));
            let Some(len) = self.packet_out(level, &mut out[at..], pad, None, send)? else {
                break;
            };
            at += len;
            handshake_sent |= level == Level::Handshake;
        }
        if at == 0 {
            return Ok(None);
        }
        // A client drops its Initial keys when it first sends a Handshake packet (RFC 9001,
        // section 4.9.1).
        if handshake_sent && matches!(self.end, End::Client { .. }) && !self.spaces[0].discarded {
            self.discard(Level::Initial);
        }
        Ok(Some(at))
    }

    /// Builds the datagram of a closing end when a copy of its CONNECTION_CLOSE frame is due, with
    /// the frame in each level that has keys (RFC 9000, section 10.2.1). Each copy after the first
    /// one is the same protected datagram, so the copies use no packet key. An end with no closing
    /// period ends when its frame is out.
    fn closing(&mut self, out: &mut [u8], SendAt { now, mark, .. }: SendAt) -> Option<Transmission> {
        let ending = self.ending?;
        let close = ending.close.filter(|_| ending.send)?;
        let room = self.room();
        let len = if let Some((sealed, len)) = ending.sealed {
            if room < len {
                self.amplification_blocked();
                return None;
            }
            out[..len].copy_from_slice(&sealed[..len]);
            len
        } else {
            let keyed = Level::ALL.map(|level| match level {
                Level::Data => self.one_rtt.is_some(),
                _ => self.spaces[level as usize].keys.is_some(),
            });
            // A datagram with an Initial packet has 1,200 bytes, so the frame waits for that credit.
            if room < if keyed[0] { DATAGRAM_MIN } else { 1 } {
                self.amplification_blocked();
                return None;
            }
            let last = keyed.iter().rposition(|&keyed| keyed);
            let mut at = 0;
            for level in Level::ALL {
                if !keyed[level as usize] {
                    continue;
                }
                let pad = last
                    .filter(|_| keyed[0])
                    .map(|i| (DATAGRAM_MIN.saturating_sub(at), Level::ALL[i]));
                let send = SendAt {
                    now,
                    mark,
                    admitted: false,
                };
                // The frame goes in one datagram with each level, or it waits: for the credit of
                // that datagram, and at most to the deadline.
                let Ok(Some(len)) = self.packet_out(level, &mut out[at..room], pad, Some(close), send) else {
                    if self.paths.active.amplification_credit.is_some() {
                        self.amplification_blocked();
                    }
                    return None;
                };
                at += len;
            }
            at
        };
        if let Some(ending) = &mut self.ending {
            ending.send = false;
            let mut sealed = [0; CLOSE_BYTES_MAX];
            if ending.sealed.is_none()
                && len > 0
                && let Some(copy) = sealed.get_mut(..len)
            {
                copy.copy_from_slice(&out[..len]);
                ending.sealed = Some((sealed, len));
            }
        }
        if ending.until.is_none() {
            self.ending = None;
            self.outcome = Some(ending.outcome);
        }
        let path = &mut self.paths.active;
        path.charge(len as u64);
        (len > 0).then_some(Transmission::one(len, mark, path.addresses))
    }

    /// The number of the next packet of `level`, and the bytes of its encoding.
    fn number(&self, level: Level) -> Result<(u64, usize), Failure> {
        let space = &self.spaces[level as usize];
        let number = space.next;
        let number_len = packet::number_len(number, space.history.largest)
            .filter(|_| number <= VARINT_MAX)
            .ok_or(Failure::local(Error::new(
                Kind::Overload,
                "the packet numbers of a QUIC space passed their limit",
            )))?;
        Ok((
            number,
            if level == Level::Data {
                number_len.max(packet::number_len(self.window - 1, None).unwrap_or(4))
            } else {
                number_len
            },
        ))
    }

    /// The packets that the keys of `level` sealed, and the most that they seal: for 1-RTT keys
    /// the limit of [`OneRtt`], and for the keys of the handshake the confidentiality limit of
    /// their suite (RFC 9001, section 6.6).
    fn key_use(&self, level: Level) -> Option<(u64, u64)> {
        match level {
            Level::Data => self.one_rtt.as_ref().map(|keys| (keys.sealed, keys.limit)),
            _ => {
                let space = &self.spaces[level as usize];
                let keys = space.keys.as_ref()?;
                Some((space.sealed, keys.local.packet.confidentiality_limit()))
            }
        }
    }

    /// Seals the packet of `builder`, which has the number `number` of `level`. Gives its bytes.
    /// Refuses a packet past the limit of its key: this end then sends no packet more with it
    /// (RFC 9001, section 6.6).
    fn seal(&mut self, level: Level, builder: Builder<'_>, number: u64) -> Result<usize, Failure> {
        if self.key_use(level).is_some_and(|(sealed, limit)| sealed >= limit) {
            return Err(Failure::transport(
                ErrorCode::AEAD_LIMIT_REACHED,
                0,
                Error::new(Kind::Overload, "the QUIC packet key sealed each packet of its limit"),
            ));
        }
        let keys = match level {
            Level::Data => self.one_rtt.as_ref().map(|keys| &keys.local),
            _ => self.spaces[level as usize].keys.as_ref().map(|keys| &keys.local),
        };
        let keys = keys.ok_or(Failure::local(Error::new(
            Kind::Unsupported,
            "a QUIC level has no keys for its packet",
        )))?;
        let len = builder.seal(keys).map_err(|_| {
            Failure::local(Error::new(
                Kind::Unsupported,
                "the packet key refused to seal a QUIC packet",
            ))
        })?;
        let space = &mut self.spaces[level as usize];
        space.next = number + 1;
        if level != Level::Data {
            space.sealed += 1;
        } else if let Some(keys) = &mut self.one_rtt {
            keys.sealed += 1;
            keys.first_sent.get_or_insert(number);
        }
        Ok(len)
    }

    /// Builds a datagram with one 1-RTT packet: `frame`, to the address `peer` with the connection
    /// ID `dcid`. An output of 1,200 bytes or more gives a datagram of its size, with padding. A
    /// smaller output gives a datagram with no padding. A datagram with a frame of the paths has
    /// 1,200 bytes or no expansion (RFC 9000, sections 8.2.1 and 8.2.2). With `record`, the packet
    /// counts on the active path, and the record tells its delivery or its loss. Else the packet
    /// goes to another path, and no delivery state of the active path follows it.
    fn single(
        &mut self,
        out: &mut [u8],
        (peer, dcid): (SocketAddr, ConnectionId),
        frame: &Frame<'_>,
        record: Option<Record>,
        SendAt { now, mark, .. }: SendAt,
    ) -> Result<Option<usize>, Failure> {
        let (number, number_len) = self.number(Level::Data)?;
        self.key_limit(Level::Data, now)?;
        let header = Outgoing::OneRtt {
            dcid: &dcid,
            spin: false,
            key_phase: self.one_rtt.as_ref().is_some_and(|keys| keys.phase),
        };
        let size = if out.len() < DATAGRAM_MIN { 0 } else { out.len() };
        let Ok(builder) = Builder::new(out, header, number, number_len) else {
            return Ok(None);
        };
        let mut output = Output::new(builder, &self.budget);
        let written = match record {
            Some(record) => output.track(frame, record),
            None => output.builder.frame(frame),
        };
        if written.is_err() || output.builder.pad_to(size).is_err() {
            return Ok(None);
        }
        if output.refused {
            return Err(Failure::local(recovery::NO_ROOM));
        }
        let Output { builder, records, .. } = output;
        let len = self.seal(Level::Data, builder, number)?;
        self.sent_to(peer, dcid);
        if record.is_none() {
            return Ok(Some(len));
        }
        let space = &mut self.spaces[Level::Data as usize];
        space.history.ect_sent += u64::from(mark == Ecn::Ect0);
        space.history.insert(
            &mut self.paths,
            Sent {
                mark,
                number,
                time: now,
                bytes: len as u64,
                eliciting: true,
                records,
            },
        )?;
        Ok(Some(len))
    }

    /// Builds a datagram for a path that does not carry the connection: the PATH_RESPONSE for a
    /// path that the peer probes, or the PATH_CHALLENGE for the path that the peer left (RFC
    /// 9000, sections 8.2.2 and 9.3.3). The datagram has 1,200 bytes. When the credit of a path
    /// with no validation does not allow them, the answer has no padding. The answer takes its
    /// bytes from that credit. A path that the peer gave no connection ID for gets no datagram.
    fn off_path(&mut self, out: &mut [u8], send: SendAt) -> Result<Option<(usize, Path)>, Failure> {
        let active = self.paths.active.addresses;
        if let Some(slot) = self
            .answers
            .iter_mut()
            .find(|slot| slot.is_some_and(|answer| answer.path != active))
            && let Some(answer) = slot.take()
        {
            let Some(dcid) = self.cid_for(answer.path) else {
                return Ok(None);
            };
            let frame = Frame::PathResponse { data: answer.data };
            let room = if answer.validated {
                DATAGRAM_MIN
            } else {
                self.paths.off_path_room(answer.path)
            };
            let sent = self.single(&mut out[..room], (answer.path.peer, dcid), &frame, None, send)?;
            if let Some(len) = sent.filter(|_| !answer.validated) {
                self.paths.off_path_sent(answer.path, len as u64);
            }
            return Ok(sent.map(|len| (len, answer.path)));
        }
        let left = self.paths.validation.as_ref().filter(|validation| validation.left);
        if let Some(path) = left.map(|validation| validation.fallback.addresses)
            && let Some(dcid) = self.cid_for(path)
            && let Some(validation) = &mut self.paths.validation
        {
            validation.left = false;
            let frame = Frame::PathChallenge {
                data: challenge(self.stream.as_ref(), self.random)?,
            };
            let sent = self.single(&mut out[..DATAGRAM_MIN], (path.peer, dcid), &frame, None, send)?;
            return Ok(sent.map(|len| (len, path)));
        }
        Ok(None)
    }

    /// Builds a probe of the next datagram size of the active path: a PING frame and its padding
    /// (RFC 8899, and RFC 9000, section 14.4). The probe counts in the window. Only a validated
    /// path of a confirmed connection searches.
    fn size_probe(&mut self, out: &mut [u8], send: SendAt) -> Result<Option<usize>, Failure> {
        let searches = self.confirmed && self.paths.validation.is_none();
        let path = &mut self.paths.active;
        let Some(size) = path
            .mtu
            .next()
            .filter(|_| searches && path.amplification_credit.is_none())
        else {
            return Ok(None);
        };
        if !path.paced(size as u64, send.now)? {
            return Ok(None);
        }
        let to = (path.addresses.peer, path.remote_cid);
        let sent = self.single(&mut out[..size], to, &Frame::Ping, Some(Record::Mtu(size)), send)?;
        if sent.is_some() {
            self.paths.active.mtu.sent(size);
        }
        Ok(sent)
    }

    /// Builds one packet of `level` at the start of `out`: a CONNECTION_CLOSE frame for `close`,
    /// or the HANDSHAKE_DONE and CRYPTO frames and the frames of the streams that wait. Pads it
    /// to `pad` bytes. Gives its length, or `None` when `out` has no room for a packet with a
    /// frame.
    fn packet_out(
        &mut self,
        level: Level,
        out: &mut [u8],
        mut pad: Option<(usize, Level)>,
        close: Option<Close>,
        SendAt { now, mark, admitted }: SendAt,
    ) -> Result<Option<usize>, Failure> {
        let (number, number_len) = self.number(level)?;
        let space = &self.spaces[level as usize];
        let admitted = space.probe || (admitted && self.paths.active.room() >= out.len() as u64);
        if close.is_none() {
            self.key_limit(level, now)?;
        }
        let (dcid, scid) = (self.paths.active.remote_cid, self.initial_local);
        let header = match level {
            Level::Initial => Outgoing::Initial {
                dcid: &dcid,
                scid: &scid,
                token: self.initial_token.as_ref().map_or(&[], |t| t.bytes.as_slice()),
            },
            Level::Handshake => Outgoing::Handshake {
                dcid: &dcid,
                scid: &scid,
            },
            Level::Data => Outgoing::OneRtt {
                dcid: &dcid,
                spin: false,
                key_phase: self.one_rtt.as_ref().is_some_and(|keys| keys.phase),
            },
        };
        // A datagram with a frame of the paths has 1,200 bytes where the limit of the path allows
        // them (RFC 9000, sections 8.2.1 and 8.2.2).
        let full = out.len() >= DATAGRAM_MIN;
        let full_pad = full.then_some((DATAGRAM_MIN, level));
        let Ok(builder) = Builder::new(out, header, number, number_len) else {
            return Ok(None);
        };
        let overflow = |_: packet::BuildError| {
            Failure::local(Error::new(Kind::Unsupported, "a QUIC frame did not fit its packet"))
        };
        let mut output = Output::new(builder, &self.budget);
        let room = output.room();
        let mut eliciting = false;
        if let Some(close) = close {
            if output.builder.frame(&close.frame(level)).is_err() {
                return Ok(None);
            }
        } else {
            let space = &mut self.spaces[level as usize];
            space.ranges.write(&mut output.builder, now)?;
            let after_ack = output.room();
            if admitted {
                if level == Level::Data {
                    let active = self.paths.active.addresses;
                    if let Some(slot) = self
                        .answers
                        .iter_mut()
                        .find(|slot| slot.is_some_and(|answer| answer.path == active))
                        && let Some(answer) = *slot
                        && output.builder.frame(&Frame::PathResponse { data: answer.data }).is_ok()
                    {
                        *slot = None;
                        pad = pad.or(full_pad);
                    }
                    if let Some(validation) = self.paths.validation.as_mut().filter(|validation| validation.send) {
                        let data = challenge(self.stream.as_ref(), self.random)?;
                        if output.track(&Frame::PathChallenge { data }, Record::Challenge).is_ok() {
                            validation.sent(data, full);
                            pad = pad.or(full_pad);
                        }
                    }
                }
                if level == Level::Data
                    && self.handshake_done
                    && output.track(&Frame::HandshakeDone, Record::HandshakeDone).is_ok()
                {
                    self.handshake_done = false;
                }
                if level == Level::Data && self.ping && output.builder.frame(&Frame::Ping).is_ok() {
                    self.ping = false;
                }
                space.resend(&self.streams, &mut output);
                let send = &mut space.send;
                while output.room() > CRYPTO_FRAME_HEAD
                    && let Some((offset, data)) = send.next(output.room() - CRYPTO_FRAME_HEAD)
                {
                    let len = data.len();
                    output
                        .track(
                            &Frame::Crypto { offset, data },
                            Record::Range(DataRange::Crypto { offset, len }),
                        )
                        .map_err(overflow)?;
                    send.sent(len);
                }
                if level == Level::Data {
                    self.ids.write(&mut output);
                    self.streams.write(&mut output);
                }
                if space.probe && output.room() == after_ack {
                    let _fits = output.builder.frame(&Frame::Ping);
                }
            }
            eliciting = after_ack != output.room();
            if output.refused {
                return Err(Failure::local(recovery::NO_ROOM));
            }
            // A packet that took no frame, because none fits, waits for the next datagram.
            if output.room() == room && pad.is_none_or(|(min, last)| min == 0 || level != last) {
                return Ok(None);
            }
        }
        let Output {
            mut builder, records, ..
        } = output;
        let before_pad = builder.room();
        if let Some((minimum, last)) = pad
            && (level == last || before_pad < COALESCED_ROOM)
        {
            builder.pad_to(minimum).map_err(overflow)?;
        }
        let in_flight = eliciting || builder.room() < before_pad;
        let len = self.seal(level, builder, number)?;
        self.sent_to(self.paths.active.addresses.peer, dcid);
        self.spaces[level as usize].history.ect_sent += u64::from(mark == Ecn::Ect0);
        // A bare ACK has a record of no bytes too: a later ACK of its space that covers it shows
        // that the path delivered between the packets around it, so a loss run across it breaks
        // only then (RFC 9002, section 7.6.2). It can also be the largest number in an ACK that
        // covers a live elicitor. Bare ACKs back to back share one record, and a record that
        // waits too long gets a PING into the next packet of its space.
        let space = &mut self.spaces[level as usize];
        if close.is_none() && (in_flight || !space.history.extend(&mut self.paths, number, now, mark)) {
            let bytes = if in_flight { len as u64 } else { 0 };
            space.history.insert(
                &mut self.paths,
                Sent {
                    mark,
                    number,
                    time: now,
                    bytes,
                    eliciting,
                    records,
                },
            )?;
            if eliciting {
                if core::mem::take(&mut space.probe) {
                    self.paths.active.probes = self.paths.active.probes.saturating_add(1);
                }
                if core::mem::take(&mut self.received) {
                    self.last_activity = now;
                }
            }
        }
        Ok(Some(len))
    }

    /// Updates the 1-RTT keys of this end before the key seals the last packet of its limit
    /// (RFC 9001, sections 6 and 6.6). A key update needs a confirmed handshake. After the first
    /// one, it also needs an acknowledgement of a packet of the current phase. Without them, and
    /// for the keys of the handshake, which do not update, the connection ends with
    /// AEAD_LIMIT_REACHED, and the last packet of the key carries that close.
    fn key_limit(&mut self, level: Level, now: Instant) -> Result<(), Failure> {
        if self
            .key_use(level)
            .is_none_or(|(sealed, limit)| sealed < limit.saturating_sub(1))
        {
            return Ok(());
        }
        let keys = self.one_rtt.as_ref().filter(|_| level == Level::Data);
        if let Some(keys) = keys
            && self.confirmed
            && (!keys.updated || keys.acknowledged)
        {
            let until = after(now, 3 * self.pto())?;
            self.one_rtt.as_mut().expect("this space has 1-RTT keys").update(until);
            return Ok(());
        }
        let reason = if level == Level::Data {
            "the QUIC packet key reached its limit, and the peer did not acknowledge the last key update"
        } else {
            "the QUIC packet key of the handshake reached its limit"
        };
        Err(Failure::transport(
            ErrorCode::AEAD_LIMIT_REACHED,
            0,
            Error::new(Kind::Overload, reason),
        ))
    }
}
