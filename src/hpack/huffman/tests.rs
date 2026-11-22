use super::{CODES, decode, encode, encoded_len};

/// RFC 7541, Appendix B, gives a canonical code: in the order of length and then symbol, each
/// code is the code before it plus one, shifted left by the change of length. The code is
/// complete, and EOS is 30 one bits. A wrong row of `CODES` breaks one of these facts, and the
/// decoder, which uses only the lengths, then disagrees with the encoder.
#[test]
fn the_code_table_is_the_canonical_complete_code_of_appendix_b() {
    let mut order: Vec<usize> = (0..CODES.len()).collect();
    order.sort_by_key(|&symbol| (CODES[symbol].1, symbol));
    let mut expected = 0_u64;
    let mut previous = CODES[order[0]].1;
    for (position, &symbol) in order.iter().enumerate() {
        let (code, len) = CODES[symbol];
        if position > 0 {
            expected = (expected + 1) << (len - previous);
        }
        previous = len;
        assert_eq!(u64::from(code), expected, "the code of symbol {symbol}");
    }
    let kraft: u64 = CODES.iter().map(|&(_, len)| 1_u64 << (30 - len)).sum();
    assert_eq!(kraft, 1 << 30, "the code is not complete");
    assert_eq!(CODES[256], (0x3fff_ffff, 30), "EOS");
}

/// Each byte value has a code of a different length, up to 30 bits. A decode table that is wrong
/// for a rare length decodes the bytes of real peers wrongly.
#[test]
fn each_byte_value_survives_a_round_trip() {
    let all: Vec<u8> = (0..=255).collect();
    let mut strings: Vec<Vec<u8>> = all.iter().map(|&byte| vec![byte]).collect();
    strings.push(all.clone());
    strings.push(all.iter().rev().copied().collect());
    for string in strings {
        let mut code = Vec::new();
        encode(string.iter().copied(), |piece| code.extend_from_slice(piece));
        assert_eq!(code.len(), encoded_len(string.iter().copied()));
        let mut out = Vec::new();
        assert_eq!(decode(&code, &mut out, usize::MAX), Ok(string.len()));
        assert_eq!(out, string);
    }
}
