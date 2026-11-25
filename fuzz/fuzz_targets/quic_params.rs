//! The QUIC transport parameters read a fuzzed encoding. The low bit of the first byte selects the
//! sender: 0 for the client and 1 for the server. The rest is the encoding.
//!
//! Each accepted set writes in the bytes that `encoded_len` gives, and its encoding parses back to
//! the same set from the same sender.

#![no_main]

use rsnetwork::quic::params::{Parameters, Sender};

libfuzzer_sys::fuzz_target!(|input: &[u8]| {
    let Some((&control, encoding)) = input.split_first() else {
        return;
    };
    let sender = if control & 1 == 0 {
        Sender::Client
    } else {
        Sender::Server
    };
    let Ok(parameters) = Parameters::parse(encoding, sender) else {
        return;
    };
    let len = parameters.encoded_len().expect("a parsed set has an encoding");
    let mut out = vec![0; len];
    assert_eq!(parameters.write(&mut out), Some(len), "{parameters:?}");
    assert_eq!(Parameters::parse(&out, sender), Ok(parameters), "{parameters:?}");
});
