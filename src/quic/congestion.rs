//! Congestion windows for one QUIC path (RFC 9002, RFC 9406, and RFC 9438).

use core::time::Duration;

use rstypes::time::Instant;

/// The congestion controller for a QUIC path.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CongestionControl {
    /// CUBIC with HyStart++, fast convergence, and Reno-friendly growth.
    #[default]
    Cubic,
    /// NewReno (RFC 9002, section 7).
    NewReno,
}

#[derive(Clone)]
pub(super) struct Controller {
    pub(super) datagram: u64,
    pub(super) window: u64,
    threshold: u64,
    recovery: Option<Instant>,
    growth: Growth,
}

#[derive(Clone)]
enum Growth {
    NewReno { credit: u64 },
    Cubic(Cubic),
}

impl Controller {
    pub(super) fn new(datagram: u64, algorithm: CongestionControl) -> Self {
        Self {
            datagram,
            window: (10 * datagram).min((2 * datagram).max(14_720)),
            threshold: u64::MAX,
            recovery: None,
            growth: match algorithm {
                CongestionControl::Cubic => Growth::Cubic(Cubic::default()),
                CongestionControl::NewReno => Growth::NewReno { credit: 0 },
            },
        }
    }

    /// Follows the datagram size of the path. A smaller size keeps the number of datagrams in the
    /// window: the peer can take a smaller datagram, or the path now drops the larger ones. A
    /// larger size keeps the bytes of the window.
    pub(super) fn datagram_limit(&mut self, bytes: u64) {
        if bytes < self.datagram {
            let scale = |n| {
                u64::try_from(u128::from(n) * u128::from(bytes) / u128::from(self.datagram))
                    .expect("the datagram size decreases")
            };
            self.window = scale(self.window).max(2 * bytes);
            if self.threshold != u64::MAX {
                self.threshold = scale(self.threshold);
            }
            match &mut self.growth {
                Growth::NewReno { credit } => *credit = scale(*credit),
                Growth::Cubic(cubic) => {
                    cubic.maximum = scale(cubic.maximum);
                    cubic.prior = scale(cubic.prior);
                    cubic.epoch = None;
                }
            }
        }
        self.datagram = bytes;
    }

    pub(super) fn can_grow(&self, sent: Instant) -> bool {
        self.recovery.is_none_or(|start| sent.as_nanos() > start.as_nanos())
    }

    pub(super) fn congestion(&mut self, sent: Instant, now: Instant) -> bool {
        if !self.can_grow(sent) {
            return false;
        }
        self.recovery = Some(now);
        self.threshold = match &mut self.growth {
            Growth::NewReno { credit } => {
                *credit = 0;
                self.window / 2
            }
            Growth::Cubic(cubic) => cubic.reduce(self.window),
        }
        .max(2 * self.datagram);
        self.window = self.threshold;
        true
    }

    pub(super) fn persistent(&mut self) {
        self.window = 2 * self.datagram;
        match &mut self.growth {
            Growth::NewReno { credit } => *credit = 0,
            Growth::Cubic(cubic) => *cubic = Cubic::default(),
        }
    }

    /// Packets sent before a round ends retain that round across reordering and number spaces.
    pub(super) fn round(&self) -> u64 {
        match &self.growth {
            Growth::Cubic(cubic) => cubic.startup.round,
            Growth::NewReno { .. } => 0,
        }
    }

    pub(super) fn round_sample(&mut self, round: u64, rtt: Duration) {
        if self.threshold == u64::MAX
            && let Growth::Cubic(cubic) = &mut self.growth
            && cubic.startup.sample(round, rtt)
        {
            self.threshold = self.window;
            cubic.prior = self.window;
        }
    }

    pub(super) fn acknowledged(&mut self, bytes: u64, now: Instant, rtt: Duration) {
        if self.window < self.threshold {
            let growth = match &self.growth {
                Growth::Cubic(cubic) if self.threshold == u64::MAX && cubic.startup.rounds_left > 0 => bytes / 4,
                _ => bytes,
            };
            self.window = self.window.saturating_add(growth);
            return;
        }
        match &mut self.growth {
            Growth::NewReno { credit } => {
                *credit = credit.saturating_add(bytes);
                if *credit >= self.window {
                    *credit -= self.window;
                    self.window = self.window.saturating_add(self.datagram);
                }
            }
            Growth::Cubic(cubic) => {
                self.window = cubic.increase(self.window, self.datagram, bytes, now, rtt);
            }
        }
    }

    pub(super) fn limited(&mut self, now: Instant, limited: bool) {
        if let Growth::Cubic(cubic) = &mut self.growth
            && let Some(epoch) = &mut cubic.epoch
        {
            if !limited {
                epoch.idle.get_or_insert(now.as_nanos());
            } else if let Some(idle) = epoch.idle.take() {
                epoch.start = epoch.start.saturating_add(now.as_nanos().saturating_sub(idle));
            }
        }
    }
}

#[derive(Clone, Default)]
struct Cubic {
    maximum: u64,
    prior: u64,
    epoch: Option<Epoch>,
    startup: Startup,
}

/// HyStart++ samples one round of sent packets at a time (RFC 9406, section 4).
#[derive(Clone, Default)]
struct Startup {
    round: u64,
    previous: Option<Duration>,
    minimum: Option<Duration>,
    baseline: Duration,
    samples: u8,
    rounds_left: u8,
}

impl Startup {
    fn sample(&mut self, round: u64, rtt: Duration) -> bool {
        let minimum = self.minimum.map_or(rtt, |old| old.min(rtt));
        self.minimum = Some(minimum);
        self.samples = self.samples.saturating_add(1);
        if self.samples >= 8 {
            if self.rounds_left != 0 {
                if minimum < self.baseline {
                    self.rounds_left = 0;
                }
            } else if let Some(previous) = self.previous {
                let threshold = (previous / 8).clamp(Duration::from_millis(4), Duration::from_millis(16));
                if minimum >= previous.saturating_add(threshold) {
                    self.baseline = minimum;
                    self.rounds_left = 5;
                }
            }
        }
        if round == self.round {
            self.round = self.round.saturating_add(1);
            self.previous = self.minimum.take();
            self.samples = 0;
            if self.rounds_left > 0 {
                self.rounds_left -= 1;
                return self.rounds_left == 0;
            }
        }
        false
    }
}

#[derive(Clone)]
struct Epoch {
    start: u64,
    idle: Option<u64>,
    k_ms: u64,
    estimate: u64,
    reno_credit: u128,
    cubic_credit: u128,
}

// C = 0.4 segments/s³. The controller measures time in ms and windows in bytes.
const CUBIC_SCALE: u128 = 2_500_000_000;

impl Cubic {
    fn reduce(&mut self, window: u64) -> u64 {
        let fraction = |a: u64, b: u64| window / b * a + window % b * a / b;
        self.maximum = if window < self.maximum {
            fraction(17, 20)
        } else {
            window
        };
        self.prior = window;
        self.epoch = None;
        fraction(7, 10)
    }

    fn increase(&mut self, window: u64, datagram: u64, bytes: u64, now: Instant, rtt: Duration) -> u64 {
        let epoch = self.epoch.get_or_insert_with(|| {
            self.maximum = self.maximum.max(window);
            let cube = u128::from(self.maximum - window) * CUBIC_SCALE / u128::from(datagram);
            // The starting power of two bounds the cube root. Each Newton step decreases it.
            let mut root = 1u128 << (u128::BITS - cube.leading_zeros()).div_ceil(3);
            for _ in 0..u128::BITS {
                let next = (2 * root + cube / (root * root)) / 3;
                if next >= root || next == 0 {
                    root = root.min(next);
                    break;
                }
                root = next;
            }
            Epoch {
                start: now.as_nanos(),
                idle: None,
                k_ms: u64::try_from(root).expect("the cube root fits u64"),
                estimate: window,
                reno_credit: 0,
                cubic_credit: 0,
            }
        });
        let elapsed = u128::from(now.as_nanos().saturating_sub(epoch.start) / 1_000_000);
        let cubic = |time: u128| {
            let k = u128::from(epoch.k_ms);
            let offset = time.abs_diff(k).saturating_pow(3).saturating_mul(u128::from(datagram)) / CUBIC_SCALE;
            let offset = u64::try_from(offset).unwrap_or(u64::MAX);
            if time < k {
                self.maximum.saturating_sub(offset)
            } else {
                self.maximum.saturating_add(offset)
            }
        };
        let alpha = if epoch.estimate < self.prior { 9 } else { 17 };
        epoch.reno_credit += alpha * u128::from(bytes) * u128::from(datagram);
        let divisor = 17 * u128::from(window);
        let increase = u64::try_from(epoch.reno_credit / divisor).unwrap_or(u64::MAX);
        epoch.reno_credit %= divisor;
        epoch.estimate = epoch.estimate.saturating_add(increase);
        if cubic(elapsed) < epoch.estimate {
            return window.max(epoch.estimate);
        }
        let delta = cubic(elapsed + rtt.as_millis()).saturating_sub(window).min(window / 2);
        epoch.cubic_credit += u128::from(delta) * u128::from(datagram);
        let increase = u64::try_from(epoch.cubic_credit / u128::from(window)).unwrap_or(u64::MAX);
        epoch.cubic_credit %= u128::from(window);
        window.saturating_add(increase)
    }
}
