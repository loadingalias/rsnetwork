//! rsnetwork and `httparse` read a request head and the chunked body after it. The input is the
//! bytes of the peer.
//!
//! The module `differential` of `tests/` gives the two readings: each part that a parser
//! accepted, and the end. Each head that rsnetwork accepts must have the same method, target,
//! version, field lines, and length for `httparse`, and each chunked body the same data, trailer
//! section, and length. A refusal by rsnetwork is permitted, and so is an input that ends before
//! rsnetwork accepts the next part, because rsnetwork then gives the bytes no meaning.

#![no_main]

#[path = "../../tests/differential/mod.rs"]
mod differential;

use core::assert_matches;

use differential::Verdict;

libfuzzer_sys::fuzz_target!(|input: &[u8]| {
    let (rsnetwork, httparse) = differential::heads_and_chunks(input);
    let verdict = differential::judge(&rsnetwork, &httparse);
    assert_matches!(
        verdict,
        Verdict::Same | Verdict::RsnetworkRefuses,
        "rsnetwork {rsnetwork:?}, httparse {httparse:?}"
    );
});
