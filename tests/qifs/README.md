# qifs

This directory is test data from <https://github.com/qpackers/qifs>, at commit
`da52cd936b3e34dac7ac12aa8066fc57676af106`, under the MIT license in `LICENSE.md`. The files are
not changed.

`qifs/` holds the field sections that each encoder read, in the QIF text format. `encoded/`
holds the output of six independent encoders in the format of the QPACK offline interop: a
sequence of records, each a stream ID of 8 bytes, a length of 4 bytes, both big-endian, and the
bytes. Stream 0 is the encoder stream. A file name ends with the table capacity, the limit of
blocked streams, and the mode of acknowledgement.

Subset rule: `netbsd.qif`, `netbsd-hq.qif`, `fb-req.qif`, and `fb-resp.qif`. Each output of
`netbsd` and `netbsd-hq` of the six encoders `f5`, `ls-qpack`, `nghttp3`, `proxygen`,
`qthingey`, and `quinn`. The outputs `fb-req.out.256.100.1` and `fb-resp.out.256.100.1` of the
same six encoders. The other files are not here. `tests/qpack.rs` decodes each output here, and
encodes each QIF here.

The outputs follow draft 06 of QPACK, in which the dynamic table starts at its maximum capacity.
In RFC 9204, the table starts at zero, and an insertion before a Set Dynamic Table Capacity
instruction is an error. Thus the test gives the decoder that instruction, with the capacity of
the file name, before the first record. The other wire formats of the draft are the formats of
RFC 9204.
