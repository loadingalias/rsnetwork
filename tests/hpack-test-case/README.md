# hpack-test-case

This directory is test data from <https://github.com/http2jp/hpack-test-case>, at commit
`8a1406e7d14bfcb6c046021f13cc15cfb162726d`, under the MIT license in `LICENSE`. The files are
not changed.

Subset rule: `story_00.json` to `story_19.json` of each of the 14 encoder directories. The
`raw-data` directory and stories 20 to 31 are not here. `tests/hpack.rs` decodes each file here.
