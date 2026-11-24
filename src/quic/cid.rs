//! The two active connection IDs in each direction and the control frames that keep them in sync.

use super::endpoint::Token;
use super::frame::Frame;
use super::recovery::{Output, Record};
use super::{ConnectionId, ErrorCode};

#[derive(Clone, Copy)]
pub(super) struct Id {
    pub(super) sequence: u64,
    pub(super) id: ConnectionId,
    pub(super) reset: Option<[u8; 16]>,
}

#[derive(Clone, Copy)]
struct Local {
    id: Id,
    send: bool,
}

#[derive(Clone, Copy)]
struct Retire {
    sequence: u64,
    send: bool,
}

pub(super) struct Ids {
    local: [Option<Local>; 2],
    remote: [Option<Id>; 2],
    /// The largest retire_prior_to received, including on reordered frames.
    prior: u64,
    next: u64,
    /// RFC 9000 section 5.1.1 permits bounding outstanding retirements.
    retire: [Option<Retire>; 8],
    pub(super) token: Option<Token>,
    pub(super) send_token: bool,
}

impl Ids {
    pub(super) fn new(local: ConnectionId) -> Self {
        let first = Id {
            sequence: 0,
            id: local,
            reset: None,
        };
        Self {
            local: [Some(Local { id: first, send: false }), None],
            remote: [None; 2],
            prior: 0,
            next: 1,
            retire: [None; 8],
            token: None,
            send_token: false,
        }
    }

    pub(super) fn issued(&self) -> [Option<ConnectionId>; 2] {
        self.local.map(|slot| slot.map(|l| l.id.id))
    }

    pub(super) fn first_peer(&mut self, id: ConnectionId, reset: Option<[u8; 16]>) {
        self.remote[0] = Some(Id { sequence: 0, id, reset });
    }

    pub(super) fn peer(&self, cid: ConnectionId) -> Option<Id> {
        self.remote.iter().flatten().find(|p| p.id == cid).copied()
    }

    /// A connection ID of the peer that no path uses. `used` has the ID of each path.
    pub(super) fn spare(&self, used: [ConnectionId; 2]) -> Option<Id> {
        self.remote.iter().flatten().find(|p| !used.contains(&p.id)).copied()
    }

    pub(super) fn rotate(&mut self, old: u64) -> Result<(), ErrorCode> {
        self.retire_peer(old)?;
        self.prior = self.prior.max(old + 1);
        Ok(())
    }

    pub(super) fn issue(&mut self, id: ConnectionId, reset: [u8; 16]) -> Result<(), ErrorCode> {
        let slot = self
            .local
            .iter_mut()
            .find(|s| s.is_none())
            .ok_or(ErrorCode::CONNECTION_ID_LIMIT_ERROR)?;
        let sequence = self.next;
        self.next = sequence
            .checked_add(1)
            .filter(|_| sequence <= super::VARINT_MAX)
            .ok_or(ErrorCode::INTERNAL_ERROR)?;
        *slot = Some(Local {
            id: Id {
                sequence,
                id,
                reset: Some(reset),
            },
            send: true,
        });
        Ok(())
    }

    pub(super) fn retire_local(&mut self, sequence: u64, destination: ConnectionId) -> Result<bool, ErrorCode> {
        if sequence >= self.next {
            return Err(ErrorCode::PROTOCOL_VIOLATION);
        }
        let Some(slot) = self
            .local
            .iter_mut()
            .find(|s| s.is_some_and(|l| l.id.sequence == sequence))
        else {
            return Ok(false);
        };
        if slot.is_some_and(|l| l.id.id == destination) {
            return Err(ErrorCode::PROTOCOL_VIOLATION);
        }
        *slot = None;
        Ok(true)
    }

    fn owe_retirement(&mut self, sequence: u64) -> Result<(), ErrorCode> {
        if self.retire.iter().flatten().any(|r| r.sequence == sequence) {
            return Ok(());
        }
        let slot = self
            .retire
            .iter_mut()
            .find(|s| s.is_none())
            .ok_or(ErrorCode::CONNECTION_ID_LIMIT_ERROR)?;
        *slot = Some(Retire { sequence, send: true });
        Ok(())
    }

    pub(super) fn retire_peer(&mut self, sequence: u64) -> Result<(), ErrorCode> {
        self.owe_retirement(sequence)?;
        if let Some(slot) = self
            .remote
            .iter_mut()
            .find(|p| p.is_some_and(|p| p.sequence == sequence))
        {
            *slot = None;
        }
        Ok(())
    }

    pub(super) fn receive(&mut self, new: Id, prior: u64, current: ConnectionId) -> Result<ConnectionId, ErrorCode> {
        if current.as_bytes().is_empty() {
            return Err(ErrorCode::PROTOCOL_VIOLATION);
        }
        self.prior = self.prior.max(prior);
        let mut duplicate = false;
        for old in self.remote.into_iter().flatten() {
            if old.sequence == new.sequence {
                if old.id != new.id || old.reset != new.reset {
                    return Err(ErrorCode::PROTOCOL_VIOLATION);
                }
                duplicate = true;
            } else if old.id == new.id || old.reset == new.reset {
                return Err(ErrorCode::PROTOCOL_VIOLATION);
            }
            if old.sequence < self.prior {
                self.retire_peer(old.sequence)?;
            }
        }
        if new.sequence < self.prior || self.retire.iter().flatten().any(|r| r.sequence == new.sequence) {
            self.owe_retirement(new.sequence)?;
        } else if !duplicate {
            let slot = self
                .remote
                .iter_mut()
                .find(|p| p.is_none())
                .ok_or(ErrorCode::CONNECTION_ID_LIMIT_ERROR)?;
            *slot = Some(new);
        }
        Ok(self
            .peer(current)
            .or_else(|| self.remote.iter().flatten().next().copied())
            .ok_or(ErrorCode::PROTOCOL_VIOLATION)?
            .id)
    }

    pub(super) fn pending(&self) -> bool {
        self.send_token || self.local.iter().flatten().any(|l| l.send) || self.retire.iter().flatten().any(|r| r.send)
    }

    pub(super) fn write(&mut self, out: &mut Output<'_, '_>) {
        for local in self.local.iter_mut().flatten().filter(|l| l.send) {
            let Id { sequence, id, reset } = local.id;
            let frame = Frame::NewConnectionId {
                sequence,
                retire_prior_to: 0,
                id,
                reset_token: reset.expect("an issued ID has a token"),
            };
            if out.track(&frame, Record::IssueId(sequence)).is_err() {
                return;
            }
            local.send = false;
        }
        for r in self.retire.iter_mut().flatten().filter(|r| r.send) {
            if out
                .track(
                    &Frame::RetireConnectionId { sequence: r.sequence },
                    Record::RetireId(r.sequence),
                )
                .is_err()
            {
                return;
            }
            r.send = false;
        }
        if self.send_token
            && let Some(token) = &self.token
            && out
                .track(&Frame::NewToken { token: token.bytes() }, Record::NewToken)
                .is_ok()
        {
            self.send_token = false;
        }
    }

    pub(super) fn lost(&mut self, record: Record) {
        match record {
            Record::IssueId(n) => {
                if let Some(l) = self.local.iter_mut().flatten().find(|l| l.id.sequence == n) {
                    l.send = true;
                }
            }
            Record::RetireId(n) => {
                if let Some(r) = self.retire.iter_mut().flatten().find(|r| r.sequence == n) {
                    r.send = true;
                }
            }
            Record::NewToken => self.send_token = self.token.is_some(),
            _ => {}
        }
    }

    pub(super) fn acknowledged(&mut self, record: Record) {
        match record {
            Record::RetireId(n) => {
                if let Some(r) = self.retire.iter_mut().find(|r| r.is_some_and(|r| r.sequence == n)) {
                    *r = None;
                }
            }
            Record::NewToken => {
                self.token = None;
                self.send_token = false;
            }
            _ => {}
        }
    }
}
