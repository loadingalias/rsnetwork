//! The TLS handshake on rustls's QUIC API: each call of rustls, its charges, and the end of the
//! handshake.

use super::*;

impl Connection {
    /// Runs rustls on the CRYPTO data in order, one level at a time, until it needs more, a limit
    /// of the turn stops it, or the budget cannot pay for the next call.
    pub(super) fn advance(&mut self, work: &mut Work) -> Result<(), Failure> {
        self.wait = None;
        loop {
            if matches!(self.tls, Tls::Failed) || self.ending.is_some() || self.outcome.is_some() {
                return Ok(());
            }
            let level = self.read;
            let visible = self.spaces[level as usize].receive.ordered();
            let ready = self.tls.ready();
            if !ready && (visible == 0 || self.stall == Some((level, visible, true))) {
                return Ok(());
            }
            if work.reached(&self.limits.turn) {
                self.more = true;
                return Ok(());
            }
            let own = self.own.get();
            // A call in a state that holds a message works on that message too.
            let bytes = if ready { visible.max(self.message) } else { visible };
            if let Err(units) = self.held.charge(own.work(self.cost.read, bytes)) {
                self.wait = Some(units);
                return Ok(());
            }
            if let Err(units) = self.output.charge(output(&own)).map_err(|_| output(&own)) {
                self.held.after(0, &own);
                self.wait = Some(units);
                return Ok(());
            }
            work.add(visible, 1);
            let consumed = self.spaces[level as usize].receive.consumed();
            let ticket = self.ticket(level, visible);
            let tls = core::mem::replace(&mut self.tls, Tls::Failed);
            let input = &mut self.spaces[level as usize].receive;
            let config = match &mut self.end {
                End::Server { config, parameters, .. } => Some((Arc::clone(config), parameters)),
                End::Client { .. } => None,
            };
            let step = Self::step(tls, input, config, &mut self.events);
            let (held, output, stream) = (&mut self.held, &mut self.output, self.stream.as_ref());
            // A read that can give a session ticket runs with the charge of the ticket; each other
            // call with the charges of the handshake. One call context runs at a time.
            let next = match ticket {
                Some(ticket) => memory::ticket(ticket, || tls::scoped(stream, step)),
                None => memory::handshake(held, output, || tls::scoped(stream, step)),
            };
            // Each part of the call that stays takes its charge from the reservations of the call,
            // or had it before: the keys from the start, the messages from the output charge, and
            // the transport parameters of the peer from the working memory. So no charge can fail
            // after rustls ran.
            let events = self.events.len();
            let taken = self.take_events();
            self.settle_output()?;
            if let Ok(tls) = &next {
                self.held.keep_parameters(tls.parameters_bytes());
                self.message = if tls.ready() { bytes } else { 0 };
            }
            self.held.after(bytes, &own);
            self.tls = next.map_err(|error| Failure::tls(&error))?;
            taken?;
            self.completed()?;
            // rustls reports what a call consumed by the next call at the latest, so a stall is two
            // calls in a row on the same data that consume nothing, give no event, and keep the
            // level: then the engine waits for the rest of a message. A limit of the turn can come
            // between the two calls.
            let progress =
                ready || events > 0 || self.read != level || self.spaces[level as usize].receive.consumed() != consumed;
            if progress {
                self.stall = None;
            } else {
                let again = self.stall.is_some_and(|(at, bytes, _)| (at, bytes) == (level, visible));
                self.stall = Some((level, visible, again));
                if again {
                    return Ok(());
                }
            }
            // A level that rustls left must hold no more data (RFC 9001, section 4.1.3).
            for lower in Level::ALL.iter().take(self.read as usize) {
                if self.spaces[*lower as usize].receive.ordered() > 0 {
                    return Err(Failure::transport(ErrorCode::PROTOCOL_VIOLATION, 0x06, VIOLATION));
                }
            }
        }
    }

    /// The charge of a session ticket that a client can read in `visible` bytes of the data
    /// space, for the store of its configuration, or `None`.
    fn ticket(&self, level: Level, visible: usize) -> Option<memory::Ticket> {
        let (
            End::Client {
                tickets: Some(store), ..
            },
            Level::Data,
        ) = (&self.end, level)
        else {
            return None;
        };
        let chain = match &self.tls {
            Tls::ClientDone(connection) => memory::chain_bytes(connection.peer_identity()),
            _ => 0,
        };
        store.charge(visible, chain)
    }

    /// One rustls call on `input` in the state `tls`, which gives the next state.
    fn step<'a>(
        tls: Tls,
        input: &'a mut crypto::Receive,
        config: Option<(Arc<rustls::ServerConfig>, &'a mut Option<Vec<u8>>)>,
        events: &'a mut Vec<QuicEvent>,
    ) -> impl FnOnce() -> Result<Tls, rustls::Error> + 'a {
        move || match tls {
            Tls::Client(ClientHandshake::NeedsInput(needs)) => needs.process(input, events).map(client),
            Tls::Client(ClientHandshake::VerifyServerIdentity(verify)) => verify.with_config(events).map(client),
            Tls::Server(ServerHandshake::NeedsInput(needs)) => needs.process(input, events).map(server),
            Tls::Server(ServerHandshake::Accepted(accepted)) => {
                let (config, parameters) = config.expect("a server has its configuration");
                let parameters = parameters.take().unwrap_or_default();
                accepted.choose_config(config, parameters, events).map(server)
            }
            Tls::Server(ServerHandshake::VerifyClientIdentity(verify)) => verify.with_config(events).map(server),
            Tls::ClientDone(mut connection) => {
                let read = connection.read_hs(input);
                events.extend(connection.events());
                read.map(|()| Tls::ClientDone(connection))
            }
            Tls::ServerDone(mut connection) => {
                let read = connection.read_hs(input);
                events.extend(connection.events());
                read.map(|()| Tls::ServerDone(connection))
            }
            // A completed state and a failed one wait for no call; the others are not in this
            // version of rustls.
            other => Ok(other),
        }
    }

    /// Runs `f`, the first rustls call of a client, under the charges of the connection.
    pub(super) fn call(
        &mut self,
        f: impl FnOnce(&mut Vec<QuicEvent>) -> Result<Tls, rustls::Error>,
    ) -> Result<Tls, Failure> {
        let own = self.own.get();
        self.output
            .charge(output(&own))
            .map_err(|_| Failure::local(OUTPUT_REFUSED))?;
        let (held, output, stream, events) = (&mut self.held, &mut self.output, self.stream.as_ref(), &mut self.events);
        let started = memory::handshake(held, output, || tls::scoped(stream, || f(events)));
        let taken = self.take_events();
        self.settle_output()?;
        self.held.after(0, &own);
        let started = started.map_err(|error| Failure::tls(&error))?;
        taken.map(|()| started)
    }

    /// Settles the output charge after a call: it keeps the room of the events and each CRYPTO
    /// message that waits, and gives back the rest of the reservation of the call.
    fn settle_output(&mut self) -> Result<(), Failure> {
        let kept =
            (EVENTS * size_of::<QuicEvent>()) as u64 + self.spaces.iter().map(|space| space.send.bytes()).sum::<u64>();
        let charged = self.output.charged();
        if let Some(rest) = charged.checked_sub(kept) {
            let refunded = self.output.refund(rest);
            assert!(refunded.is_ok(), "a credit refunds at most its charged units");
        } else {
            // Only a call that wrote past the bound of its reservation gets here.
            self.output
                .charge(kept - charged)
                .map_err(|_| Failure::local(OUTPUT_REFUSED))?;
        }
        if self.events.capacity() > EVENTS {
            return Err(Failure::local(Error::new(
                Kind::Unsupported,
                "rustls gave more QUIC events in one call than the engine keeps room for",
            )));
        }
        Ok(())
    }

    /// Takes the events of the last rustls call: each message goes to the CRYPTO stream of its
    /// level, and each key change installs its keys.
    fn take_events(&mut self) -> Result<(), Failure> {
        for event in self.events.drain(..) {
            match event {
                QuicEvent::Message(message) => self.spaces[self.write as usize]
                    .send
                    .push(message)
                    .map_err(|_| Failure::local(OUTPUT_REFUSED))?,
                QuicEvent::KeyChange(KeyChange::Handshake { keys }) => {
                    self.spaces[Level::Handshake as usize].install(keys);
                    self.write = Level::Handshake;
                    self.read = Level::Handshake;
                }
                QuicEvent::KeyChange(KeyChange::OneRtt { keys, next }) => {
                    self.one_rtt = Some(OneRtt::new(keys, next, self.limits.key_packets_max));
                    self.write = Level::Data;
                }
                _ => {
                    return Err(Failure::local(Error::new(
                        Kind::Unsupported,
                        "rustls gave a QUIC event that the engine does not know",
                    )));
                }
            }
        }
        Ok(())
    }

    /// When rustls completed the handshake: the facts, the parameters of the peer, and on a
    /// server the confirmation and its HANDSHAKE_DONE.
    fn completed(&mut self) -> Result<(), Failure> {
        self.tls = match core::mem::replace(&mut self.tls, Tls::Failed) {
            Tls::Client(ClientHandshake::Complete(connection)) => Tls::ClientDone(connection),
            Tls::Server(ServerHandshake::Complete(connection)) => Tls::ServerDone(connection),
            other => other,
        };
        if self.facts.is_some() {
            return Ok(());
        }
        let (common, parameters, sender): (&rustls::CommonState, _, _) = match &self.tls {
            Tls::ClientDone(connection) => (&**connection, connection.quic_transport_parameters(), Sender::Server),
            Tls::ServerDone(connection) => (&**connection, connection.quic_transport_parameters(), Sender::Client),
            _ => return Ok(()),
        };
        let invalid = || Failure::transport(ErrorCode::TRANSPORT_PARAMETER_ERROR, 0, PARAMETERS);
        let parameters = Parameters::parse(parameters.ok_or_else(invalid)?, sender).map_err(|_| invalid())?;
        let identity = common.peer_identity();
        let (peer, evidence) = (memory::chain_bytes(identity), memory::end_entity_bytes(identity));
        let facts = Facts::of(common, self.if_classical)
            .map_err(Failure::local)?
            .ok_or(Failure::local(Error::new(
                Kind::Unsupported,
                "rustls did not give the facts of the QUIC handshake",
            )))?;
        self.facts = Some(facts);
        self.held.finished(peer, evidence, &self.own.get());
        self.validate(&parameters)?;
        self.ids
            .first_peer(self.paths.active.remote_cid, parameters.stateless_reset_token);
        if let Some(preferred) = parameters.preferred_address {
            self.ids
                .preferred_peer(preferred.connection_id, preferred.reset_token)
                .map_err(|code| Failure::transport(code, 0, PARAMETERS))?;
            let chosen = self.server_address(&preferred);
            if let End::Client { preferred: slot, .. } = &mut self.end {
                *slot = chosen;
            }
        }
        self.peer = Some(parameters);
        self.streams.peer(&parameters);
        self.paths.active.ack_delay_max = parameters.ack_delay_max;
        self.paths.active.mtu.limit(parameters.udp_payload_bytes_max);
        self.idle = match (self.limits.idle_timeout, parameters.idle_timeout) {
            (Some(local), Some(remote)) => Some(local.min(remote)),
            (local, remote) => local.or(remote),
        };
        self.read = Level::Data;
        // The connection ID of a preferred address is the second ID of its server.
        if !self.local_cid.as_bytes().is_empty()
            && (self.issuer.is_some() || parameters.stateless_reset_token.is_some())
            && self.ids.has_room()
        {
            self.issue_id()?;
        }
        if sender == Sender::Client {
            self.handshake_done = true;
            if let (Some(issuer), End::Server { config, .. }) = (&self.issuer, &self.end) {
                let now = config.time_provider.current_time().ok_or(endpoint::TIME)?.as_secs();
                self.ids.token = Some(tls::scoped(self.stream.as_ref(), || {
                    issuer.repeat(now, self.random, &self.budget)
                })?);
                self.ids.send_token = true;
            }
            self.confirm();
        }
        Ok(())
    }

    /// The preferred address of the server that the client validates after the handshake: the
    /// address of the family of the handshake path, because the client sends from the local
    /// address of that path. Gives `None` when the limits keep the handshake address, and when
    /// the server gives no other address of that family. An address of zero bytes, or with the
    /// port zero, is no address (RFC 9000, section 18.2).
    fn server_address(&self, preferred: &PreferredAddress) -> Option<SocketAddr> {
        if self.limits.server_address == ServerAddress::Handshake {
            return None;
        }
        let handshake = self.paths.active.addresses.peer;
        let address = match handshake {
            SocketAddr::V4(_) => SocketAddr::from((preferred.ipv4.0, preferred.ipv4.1)),
            SocketAddr::V6(_) => SocketAddr::from((preferred.ipv6.0, preferred.ipv6.1)),
        };
        (!address.ip().is_unspecified() && address.port() != 0 && address != handshake).then_some(address)
    }

    /// Checks the connection IDs that the peer names in its parameters against the ones of its
    /// packets (RFC 9000, section 7.3).
    fn validate(&self, parameters: &Parameters) -> Result<(), Failure> {
        let invalid = || Failure::transport(ErrorCode::TRANSPORT_PARAMETER_ERROR, 0, PARAMETERS);
        // A server with a connection ID of no bytes gives no reset token and no preferred address
        // (RFC 9000, section 18.2).
        let empty = self.paths.active.remote_cid.as_bytes().is_empty();
        if parameters.initial_source_cid != self.initial_peer
            || (empty && (parameters.stateless_reset_token.is_some() || parameters.preferred_address.is_some()))
        {
            return Err(invalid());
        }
        if matches!(self.end, End::Client { .. })
            && (parameters.original_destination_cid != Some(self.original_cid)
                || parameters.retry_source_cid != self.retry_cid)
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// Ends the connection with `failure`: its CONNECTION_CLOSE waits for
    /// [`transmit`](Self::transmit) when this end has keys to send it.
    pub(super) fn fail(&mut self, failure: Failure, now: Instant) {
        if self.outcome.is_some() || self.ending.is_some() {
            return;
        }
        self.reading = None;
        let keys = self.spaces.iter().any(|space| space.keys.is_some()) || self.one_rtt.is_some();
        match failure.code {
            Some((code, frame_type)) if keys => {
                let close = Close {
                    code,
                    frame_type: Some(frame_type),
                };
                self.end_with(Err(failure.error), Some(close), now);
            }
            _ => self.outcome = Some(Err(failure.error)),
        }
    }
}
