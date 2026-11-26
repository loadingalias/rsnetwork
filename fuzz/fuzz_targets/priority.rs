//! The priority of RFC 9218 reads fuzzed field values (N212). The input is the field lines of one
//! `priority` field, which a 0 byte separates: a field value has no 0 byte.
//!
//! - No read allocates.
//! - The lines give what their join with a comma and a space gives (RFC 9651, section 4.2): the
//!   priority of the joined value, or the default when it is not a dictionary.
//! - The field of each priority that a value gives reads back as the same priority.

#![no_main]

use rsnetwork::priority::Priority;
use rsnetwork_fuzz::allocated;

libfuzzer_sys::fuzz_target!(|input: &[u8]| {
    let lines: Vec<&[u8]> = input.split(|&byte| byte == 0).collect();
    let joined = lines.join(&b", "[..]);
    let ((by_lines, parsed), bytes) =
        allocated(|| (Priority::of_lines(lines.iter().copied()), Priority::parse(&joined)));
    assert_eq!(bytes, 0, "a read allocated");
    assert_eq!(by_lines, parsed.unwrap_or(Priority::DEFAULT), "{lines:?}");
    if let Some(priority) = Priority::parse(input) {
        assert_eq!(Priority::parse(priority.field().value()), Some(priority));
    }
});
