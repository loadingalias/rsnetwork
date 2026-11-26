//! The priority of a response (RFC 9218): its urgency, and whether the client uses its bytes as
//! they arrive.
//!
//! A client sends the priority of a request in the `priority` field, and HTTP/2 can change it
//! later with a PRIORITY_UPDATE frame. The value of both is a Structured Field Dictionary
//! (RFC 9651) with the parameters `u` and `i`. The send scheduler of a server sends the responses
//! of a higher urgency first. Of one urgency, it shares the connection between the incremental
//! responses, and it sends the other ones one at a time, in the order of their streams.
//!
//! ```
//! use rsnetwork::priority::{Priority, Urgency};
//!
//! // A request for an image that the client shows as its bytes arrive.
//! let image = Priority { urgency: Urgency::new(5)?, incremental: true };
//! let field = image.field();
//! assert_eq!((field.name(), field.value()), (&b"priority"[..], &b"u=5, i"[..]));
//!
//! // A receiver reads the value, and ignores the parameters that it does not know.
//! assert_eq!(Priority::parse(b"u=5, i, x=?1"), Some(image));
//! // A parameter out of its range keeps its default, and a value that is not a dictionary is
//! // ignored as a whole.
//! assert_eq!(Priority::parse(b"u=9"), Some(Priority::DEFAULT));
//! assert_eq!(Priority::parse(b"u=1,"), None);
//! # Ok::<(), rsnetwork::value::InvalidValue>(())
//! ```

use crate::structured::{self, Value};
use crate::value::{Field, InvalidValue};

/// The urgency of a response, from 0, the highest, to 7, the lowest (RFC 9218, section 4.1). The
/// order of the type is the order of the numbers: a smaller urgency goes first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Urgency(u8);

impl Urgency {
    /// Urgency 0, the highest.
    pub const HIGHEST: Self = Self(0);
    /// Urgency 3, of a request with no signal.
    pub const DEFAULT: Self = Self(3);
    /// Urgency 7, the lowest: for example a background download.
    pub const LOWEST: Self = Self(7);

    /// Checks an urgency, or refuses it.
    pub const fn new(value: u8) -> Result<Self, InvalidValue> {
        if value <= Self::LOWEST.0 {
            Ok(Self(value))
        } else {
            Err(InvalidValue::Urgency)
        }
    }

    /// The number of the urgency.
    pub const fn get(self) -> u8 {
        self.0
    }
}

/// The priority of a response (RFC 9218, section 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Priority {
    /// How soon the client needs the response.
    pub urgency: Urgency,
    /// The client uses the bytes of the response as they arrive, so the response can share the
    /// connection with the other incremental responses of its urgency. A response that is not
    /// incremental is of use only when it is complete.
    pub incremental: bool,
}

/// The values of each `priority` field, by urgency and then by the incremental flag.
const FIELDS: [[&[u8]; 2]; 8] = [
    [b"u=0", b"u=0, i"],
    [b"u=1", b"u=1, i"],
    [b"u=2", b"u=2, i"],
    [b"u=3", b"u=3, i"],
    [b"u=4", b"u=4, i"],
    [b"u=5", b"u=5, i"],
    [b"u=6", b"u=6, i"],
    [b"u=7", b"u=7, i"],
];

impl Priority {
    /// The priority of a request with no signal: urgency 3, not incremental (RFC 9218, section 4).
    pub const DEFAULT: Self = Self {
        urgency: Urgency::DEFAULT,
        incremental: false,
    };

    /// Reads the value of a `priority` field, or of a PRIORITY_UPDATE frame: the parameters `u`
    /// and `i` of a Structured Field Dictionary. A parameter that the value does not hold, holds
    /// out of its range, or holds as another type keeps its default, and a receiver ignores the
    /// other parameters (section 4). Gives `None` when the value is not a dictionary: ignore it as
    /// a whole (RFC 9651, section 4.2).
    pub fn parse(value: &[u8]) -> Option<Self> {
        let mut parameters = Parameters::default();
        structured::dictionary(value, |key, value| parameters.take(key, value)).ok()?;
        Some(parameters.priority())
    }

    /// Reads the values of the field lines of a `priority` field, in their order, as one value
    /// whose lines a comma joins (RFC 9651, section 4.2): for example the lines of a request
    /// head. Gives the default with no line, and when the joined value is not a dictionary.
    /// Joined, a line with no member makes an empty member, so it is not a dictionary either, and
    /// it gives the default as one line too.
    pub fn of_lines<'a>(lines: impl IntoIterator<Item = &'a [u8]>) -> Self {
        let mut parameters = Parameters::default();
        for line in lines {
            let mut members = 0_usize;
            let parsed = structured::dictionary(line, |key, value| {
                members = members.saturating_add(1);
                parameters.take(key, value);
            });
            if parsed.is_err() || members == 0 {
                return Self::DEFAULT;
            }
        }
        parameters.priority()
    }

    /// The field line `priority` that sends this priority, for the fields of a request.
    pub fn field(self) -> Field<'static> {
        Field {
            name: b"priority",
            value: FIELDS[usize::from(self.urgency.0)][usize::from(self.incremental)],
        }
    }
}

/// The parameters of a dictionary so far: the last value of each member wins, also a value that
/// the receiver ignores.
#[derive(Default)]
struct Parameters {
    urgency: Option<Urgency>,
    incremental: Option<bool>,
}

impl Parameters {
    fn take(&mut self, key: &[u8], value: Value) {
        match key {
            b"u" => {
                self.urgency = match value {
                    Value::Integer(value) => u8::try_from(value).ok().and_then(|value| Urgency::new(value).ok()),
                    Value::Boolean(_) | Value::Other => None,
                };
            }
            b"i" => {
                self.incremental = match value {
                    Value::Boolean(value) => Some(value),
                    Value::Integer(_) | Value::Other => None,
                };
            }
            _ => {}
        }
    }

    fn priority(self) -> Priority {
        Priority {
            urgency: self.urgency.unwrap_or(Urgency::DEFAULT),
            incremental: self.incremental.unwrap_or(false),
        }
    }
}
