//! The paths of a connection: their addresses, the validation of a new path, and the search for
//! the datagram size of each path (RFC 9000, sections 8.2, 9, and 14, and RFC 8899).

use core::net::SocketAddr;

use rstypes::time::Instant;

use super::connection::DATAGRAM_MIN;
use super::recovery::PathState;

/// A network path: the address of this end and the address of the peer.
///
/// The host gives the path of each received region, and each transmission names the path that
/// it goes out on. The connection only compares the addresses. A host with no local address for
/// its datagrams gives one fixed value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Path {
    /// The local address: the destination of a received datagram, and the source of a sent one.
    pub local: SocketAddr,
    /// The address of the peer.
    pub peer: SocketAddr,
}

/// The PATH_CHALLENGE frames of one validation whose answer the connection still takes. A
/// validation sends about seven of them before its period ends, each at a probe timeout.
const CHALLENGES_MAX: usize = 8;

/// The validation of the active path (RFC 9000, section 8.2), and the path that the connection
/// returns to when the validation fails.
pub(super) struct Validation {
    /// The last validated path, with its delivery state.
    pub(super) fallback: PathState,
    /// The PATH_CHALLENGE frames of the active path that wait for their answer, the newest
    /// first. Each frame has its own data (RFC 9000, section 8.2.1). The flag tells whether the
    /// datagram of the frame had at least 1,200 bytes. The answer to such a frame also shows that
    /// the path carries them.
    challenges: [Option<([u8; 8], bool)>; CHALLENGES_MAX],
    /// A PATH_CHALLENGE frame waits to go out.
    pub(super) send: bool,
    /// The validation fails at this time.
    pub(super) until: Instant,
    /// One PATH_CHALLENGE frame waits to go out on the fallback path, after the peer moved
    /// (RFC 9000, section 9.3.3).
    pub(super) left: bool,
}

impl Validation {
    /// The validation of a path that the connection moved to from `fallback`, which ends at
    /// `until`. With `left`, the connection also asks the fallback path one time.
    pub(super) fn new(fallback: PathState, until: Instant, left: bool) -> Self {
        Self {
            fallback,
            challenges: [None; CHALLENGES_MAX],
            send: true,
            until,
            left,
        }
    }

    /// Starts the validation again, with a period to `until`: for another path, or for a
    /// challenge of 1,200 bytes. No answer to an earlier challenge counts.
    pub(super) fn restart(&mut self, until: Instant) {
        self.challenges = [None; CHALLENGES_MAX];
        self.send = true;
        self.until = until;
    }

    /// A PATH_CHALLENGE frame with `data` went out. `padded` tells whether its datagram had at
    /// least 1,200 bytes. The oldest frame leaves when the list is full.
    pub(super) fn sent(&mut self, data: [u8; 8], padded: bool) {
        self.challenges.rotate_right(1);
        self.challenges[0] = Some((data, padded));
        self.send = false;
    }

    /// Whether the datagram of the challenge with `data` had at least 1,200 bytes, or `None` for
    /// data of no challenge that waits.
    pub(super) fn answered(&self, data: [u8; 8]) -> Option<bool> {
        let challenge = self.challenges.iter().flatten().find(|(sent, _)| *sent == data);
        challenge.map(|(_, padded)| *padded)
    }
}

/// The probes of one size that the search loses before it takes the size as too large
/// (MAX_PROBES of RFC 8899, section 5.1.2).
const PROBES_MAX: u8 = 3;
/// The search ends when it can raise the datagram size by fewer bytes than this.
const STEP: usize = 20;
/// The probe timeouts in a row that lose only datagrams above 1,200 bytes before the path
/// returns to 1,200 bytes.
const BLACK_HOLE_TIMEOUTS: u8 = 3;

/// The datagram size of one path, and the search above it (RFC 8899). A path starts at 1,200
/// bytes. One search runs for each path: it sends at most [`PROBES_MAX`] probes for each size.
/// The search doubles the size while its probes arrive. After a size failed, it takes the middle
/// of the sizes that remain.
#[derive(Clone, Copy, Debug)]
pub(super) struct Mtu {
    /// The largest datagram that the path carried.
    size: usize,
    /// The largest size that the search can still find.
    top: usize,
    /// A size failed, so the search takes the middle of the sizes that remain.
    halving: bool,
    /// The size of the probe that waits for its acknowledgement.
    probe: Option<usize>,
    /// The probes of the next size that were lost.
    lost: u8,
    /// A probe timeout ended, and no loss or large datagram followed it.
    timeout: bool,
    /// The probe timeouts in a row that lost only datagrams above 1,200 bytes.
    black_hole: u8,
}

impl Mtu {
    /// A path that searches up to `top` bytes.
    pub(super) fn new(top: usize) -> Self {
        Self {
            size: DATAGRAM_MIN,
            top: top.max(DATAGRAM_MIN),
            halving: false,
            probe: None,
            lost: 0,
            timeout: false,
            black_hole: 0,
        }
    }

    /// The search of a path that follows this one with only a new peer port.
    pub(super) fn carried(self) -> Self {
        Self {
            probe: None,
            timeout: false,
            black_hole: 0,
            ..self
        }
    }

    /// The bytes of the largest datagram that the path carries.
    pub(super) const fn size(&self) -> usize {
        self.size
    }

    /// Lowers the top of the search to `top`, the largest datagram that the peer takes.
    pub(super) fn limit(&mut self, top: u64) {
        self.top = self.top.min(usize::try_from(top).unwrap_or(usize::MAX)).max(self.size);
    }

    /// The size of the next probe: the top, or two datagrams of the size that the path carries
    /// when the top is above them. A congestion window always holds two datagrams (RFC 9002,
    /// section 7.2), so it holds each probe. After a size failed, the middle of the sizes that
    /// remain. `None` while a probe is out, and when the search is complete.
    pub(super) fn next(&self) -> Option<usize> {
        let range = self.top - self.size;
        if self.probe.is_some() || range < STEP {
            return None;
        }
        Some(if self.halving {
            self.size + range.div_ceil(2)
        } else {
            self.top.min(2 * self.size)
        })
    }

    pub(super) fn sent(&mut self, size: usize) {
        self.probe = Some(size);
    }

    pub(super) fn probe_acknowledged(&mut self, size: usize) {
        if self.probe == Some(size) {
            self.probe = None;
            self.size = self.size.max(size);
            self.lost = 0;
        }
    }

    pub(super) fn probe_lost(&mut self, size: usize) {
        if self.probe == Some(size) {
            self.probe = None;
            self.lost += 1;
            if self.lost == PROBES_MAX {
                self.top = size - 1;
                self.halving = true;
                self.lost = 0;
            }
        }
    }

    /// A probe timeout ended. The probe that follows has at most 1,200 bytes, so a path that
    /// drops larger datagrams still carries it.
    pub(super) fn timed_out(&mut self) {
        self.timeout = true;
    }

    /// The peer acknowledged a datagram above 1,200 bytes: the path carries them.
    pub(super) fn large_acknowledged(&mut self) {
        self.black_hole = 0;
        self.timeout = false;
    }

    /// One loss detection lost datagrams of the path, and `large` tells whether each of them
    /// had more than 1,200 bytes. After a probe timeout, a loss of only such datagrams is the
    /// sign of a path that now drops them (RFC 8899, section 4.3). At [`BLACK_HOLE_TIMEOUTS`]
    /// in a row, the path returns to 1,200 bytes and its search ends. A timeout that also lost a
    /// datagram of 1,200 bytes or fewer ends the row: that loss is no sign of the size.
    pub(super) fn lost(&mut self, large: bool) {
        if !core::mem::take(&mut self.timeout) || self.size == DATAGRAM_MIN {
            return;
        }
        if !large {
            self.black_hole = 0;
            return;
        }
        self.black_hole += 1;
        if self.black_hole == BLACK_HOLE_TIMEOUTS {
            *self = Self::new(DATAGRAM_MIN);
        }
    }
}
