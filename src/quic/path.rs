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

/// The validation of the active path (RFC 9000, section 8.2), and the path that the connection
/// returns to when the validation fails.
pub(super) struct Validation {
    /// The last validated path, with its delivery state.
    pub(super) fallback: PathState,
    /// The data of the PATH_CHALLENGE frames of the active path.
    pub(super) data: [u8; 8],
    /// A PATH_CHALLENGE frame waits to go out.
    pub(super) send: bool,
    /// Whether each copy of `data` went out in a datagram of at least 1,200 bytes, so that its
    /// answer also shows that the path carries them. `None` before the first copy.
    pub(super) padded: Option<bool>,
    /// The validation fails at this time.
    pub(super) until: Instant,
    /// The data of one PATH_CHALLENGE frame that waits to go out on the fallback path, after
    /// the peer moved (RFC 9000, section 9.3.3).
    pub(super) left: Option<[u8; 8]>,
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

    /// The size of the next probe: the top first, and then the middle of the sizes that remain.
    /// `None` while a probe is out, and when the search is complete.
    pub(super) fn next(&self) -> Option<usize> {
        let range = self.top - self.size;
        if self.probe.is_some() || range < STEP {
            return None;
        }
        Some(if self.halving {
            self.size + range.div_ceil(2)
        } else {
            self.top
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
    /// in a row, the path returns to 1,200 bytes and its search ends.
    pub(super) fn lost(&mut self, large: bool) {
        if core::mem::take(&mut self.timeout) && large && self.size > DATAGRAM_MIN {
            self.black_hole += 1;
            if self.black_hole == BLACK_HOLE_TIMEOUTS {
                *self = Self::new(DATAGRAM_MIN);
            }
        }
    }
}
