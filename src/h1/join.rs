//! The join of a head or a trailer section that continues across received regions.

use rstypes::buffer::{Buffer as _, Lease};
use rstypes::capacity::{Budget, Permit};

use super::head::ParseError;
use crate::drive::Inbound;

/// The joined bytes of one head or trailer section, and the charge that pays for them.
///
/// A received region is frozen, so the bytes of a head that continue in the next region cannot
/// grow in place. The join copies them into one buffer of at most the limit of the section. Each
/// region adds only its new bytes, so the copy is linear in the section, also when the bytes
/// arrive one at a time.
pub(super) struct Join {
    bytes: Vec<u8>,
    permit: Permit,
}

/// The owner of the bytes of a complete join, inside its lease. The last view of the lease drops
/// it, which frees the bytes and releases their charge.
struct Joined {
    bytes: Vec<u8>,
    _permit: Permit,
}

impl AsRef<[u8]> for Joined {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// What a step of a join found.
pub(super) enum Step {
    /// The section is complete: the joined region, which holds exactly the section.
    Complete(Lease),
    /// The section continues after the queued regions.
    Wait,
    /// The budget cannot pay for a join of this many bytes now.
    Capacity(u64),
}

/// Copies the bytes of the front regions of `inbound` into the join in `slot`, until `end` finds
/// the end of the section in the joined bytes.
///
/// `end` reads the joined bytes from the start of the section, and gives the length of the
/// section when they hold all of it. The join consumes from `inbound` only the bytes of the
/// section, so the bytes after it keep their owner. It starts in `slot` when it has no join yet:
/// it reserves `limit` units of `budget` before it allocates.
pub(super) fn join(
    slot: &mut Option<Join>,
    budget: &Budget,
    limit: usize,
    inbound: &mut Inbound,
    mut end: impl FnMut(&[u8]) -> Result<Option<usize>, ParseError>,
) -> Result<Step, ParseError> {
    loop {
        let Some(front) = inbound.front() else {
            return Ok(Step::Wait);
        };
        let join = match slot {
            Some(join) => join,
            None => {
                let units = limit as u64;
                let Ok(permit) = budget.reserve(units) else {
                    return Ok(Step::Capacity(units));
                };
                let mut bytes = Vec::new();
                if bytes.try_reserve_exact(limit).is_err() {
                    return Ok(Step::Capacity(units));
                }
                slot.insert(Join { bytes, permit })
            }
        };
        let before = join.bytes.len();
        let take = front.region.initialized().min(limit - before);
        join.bytes.extend_from_slice(&front.region.bytes()[..take]);
        match end(&join.bytes)? {
            Some(len) => {
                let used = len.checked_sub(before).ok_or(ParseError::Malformed)?;
                inbound.consume(used).map_err(|_| ParseError::Malformed)?;
                let Some(Join { mut bytes, permit }) = slot.take() else {
                    return Ok(Step::Wait);
                };
                bytes.truncate(len);
                let size = bytes.capacity();
                return Ok(Step::Complete(Lease::from_owner(
                    Joined { bytes, _permit: permit },
                    size,
                )));
            }
            // A full join with no end is over the limit of the section.
            None if take == 0 => return Err(ParseError::HeadTooLarge),
            None => inbound.consume(take).map_err(|_| ParseError::Malformed)?,
        }
    }
}
