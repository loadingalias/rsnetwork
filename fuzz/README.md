# Fuzz targets

This directory holds the fuzz targets of rsnetwork. It is a cargo-fuzz package with its own
workspace and lock file. No library depends on it, so libFuzzer and its C++ build never enter the
closure of rsnetwork.

Each target drives production code. `src/lib.rs` is the shared harness: a counting allocator, the
limits of the conformance suite, and a transport that drives one H1 engine over cut input and short
writes. The module documentation of each target gives its input format and its checks.

| Target | Production code | Checks |
| --- | --- | --- |
| `request` | `h1::Server` | A cut input gives the result of the whole input. Each complete body has the length of its framing. No response follows a refusal. The bounds of the transport hold. |
| `response` | `h1::Client` | A cut input gives the result of the whole input. Each complete body has the length of its framing. The bounds of the transport hold. |
| `chunked` | `h1::ChunkDecoder` | Pieces give the result of the whole input. No step allocates. The data and the trailers stay in their limits. |
| `values` | The constructors of `value`, `write_request`, `write_head`, `RequestParser`, and `ResponseParser` | No constructor allocates. A host name obeys its rules. Each accepted value passes through a writer and a parser with no change. |
| `hpack` | `hpack::Decoder` and `hpack::Encoder` | No decode allocates or changes the charge. The lines of a block stay in the list limit. A decoder that fails gives the same error for each later block. The encoder sends each decoded block to a second decoder, which reads the same lines and marks. |
| `h2` | `h2::Connection`, with its stream layer, `hpack::Decoder`, and the frame codec | A cut input gives the events, the output, and the end of the whole input. No drive allocates past the work limit. Each charge returns when the connection drops. No frame follows a GOAWAY, and a connection error ends with one. A body goes up only on a stream after its header section and before its end, and no event follows a reset. No frame follows a reset of the endpoint, and no reset goes on an idle stream. The WINDOW_UPDATE frames of each stream and of the connection give back at most the DATA bytes of the input. The last stream of a GOAWAY never increases. A server has at most 4 handlers in flight: a stream that a reset ended keeps its slot until the target closes it, at the wait for a free slot. |
| `differential` | `RequestParser` and `ChunkDecoder`, against `httparse` | Each head that rsnetwork accepts has the same method, target, version, field lines, and length for `httparse`. Each chunked body after it has the same data, trailer section, and length. |

The transport checks the bounds of [Bound the memory and the work of a connection](../docs/content/limits.md)
on each drive: the engine holds at most one charged join of a head or a trailer section, no drive
allocates more than one section, each charge returns when the engine drops, and each round makes
progress. The allocation bound also permits 256 bytes (`RECORD` in `src/lib.rs`) for the record
that `Lease::from_owner` allocates with a join. This is a stated tolerance, not a value measured
from the code.

`differential` and `tests/h1_differential.rs` share the module `tests/differential/mod.rs`, which
gives the two readings and their class. The test also compares the server engine with llhttp, the
parser of Node.js, through a record of its readings. Its module documentation tells how to make
the record again.

The host-name check of `values` applies the "ends in a number" rule of the WHATWG URL Standard,
which `Authority` documents, to the name that `host()` gives. It is a consistency check between
`Authority::new` and `host()`: it finds a name that the two split in different ways.

The application makes a call that waits for the peer, such as the next request of a client, only
in a quiet round: a round in which the transport and the engine do nothing else. The peer closes
its side only in a quiet round too. Thus a cut changes no order of calls, bytes, and the close,
and the result of the whole input stays the only permitted result. In `response`, the peer sends
the bytes for each request only after that request, as a server does. Thus `response` never has
bytes that arrived with a response before the next request. The client test
`bytes_after_a_response_never_become_the_next_response` and the conformance vector of those bytes
cover that case, because there the bytes are in the queue at the end of the response.

## Run a target

1. Install cargo-fuzz 0.13.2. On a maintainer Mac, `machine update all` installs it.
2. Make the working corpus directory: `mkdir -p fuzz/corpus/<target>`. It stays out of Git.
3. From the repository root, run the target with its seeds:

   ```bash
   cargo fuzz run --fuzz-dir fuzz <target> fuzz/corpus/<target> fuzz/seeds/<target> -- -max_len=4096
   ```

4. On an Apple silicon Mac whose cargo-fuzz is an x86_64 binary, add `--target aarch64-apple-darwin`
   after `run`.
5. A failure writes its input to `fuzz/artifacts/<target>/`. To reproduce it, give that file in
   place of the directories: `cargo fuzz run --fuzz-dir fuzz <target> fuzz/artifacts/<target>/<file>`.

A failure is a defect of the task that owns the code. Report it with the input, the target, and the
cause. The fix adds a regression test to `tests/`.

## Seeds

`seeds/<target>/` holds the seed inputs. Each file starts with the control bytes of its target. The
name of a file gives its source: an RFC and its section, or `n010-` for the input of an N010
conformance vector in `tests/conformance/mod.rs`, taken at `b43defd`.

The seeds of `hpack` are the blocks of RFC 7541, Appendix C (`rfc7541-c2` to `rfc7541-c6`), and
the first 12 blocks of `story_02.json` of four encoders of `tests/hpack-test-case`, each after the
two control bytes of the target.

The seeds of `h2` are frame sequences that follow the figures of RFC 9113, section 6, with the
blocks of RFC 7541, C.3.1 and C.4. Each name gives the RFC section that it exercises. The seeds of
sections 5.1, 5.1.2, 6.8, 6.9, and 8.1 pass the stream states, the stream limit, GOAWAY, the
windows, and the parts of a message. The seeds of section 10.5 are floods: streams that open and
reset at line rate, past the 4 slots, and empty CONTINUATION frames past a work limit of 64 bytes.

`differential` has no control bytes and no seeds of its own. Its corpus starts from the seeds of
`request` and `chunked`, with their control bytes removed and a chunked request head before each
chunked body:

```bash
mkdir -p fuzz/corpus/differential
for f in fuzz/seeds/request/*; do tail -c +3 "$f" >"fuzz/corpus/differential/request-${f##*/}"; done
for f in fuzz/seeds/chunked/*; do
  { printf 'POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n'; tail -c +2 "$f"; } \
    >"fuzz/corpus/differential/chunked-${f##*/}"
done
```

## Add a target

1. Add a `[[bin]]` to `Cargo.toml` and a file in `fuzz_targets/`.
2. Drive the production code through `src/lib.rs` when the code is an engine.
3. Write the input format and each check in the module documentation, and add a row to the table.
4. Add seeds, and write the campaign in [Campaigns](#campaigns) before it starts.

## Campaigns

Each campaign writes its named risk, budget, and stop condition here before it starts. It adds its
result when it ends.

### N009: the H1 parsers and the value constructors

- Risk: request smuggling, which is a framing that depends on how the input is cut, or a body whose
  length is not its framing. Unbounded retained state, which is a charge or an allocation past one
  section, a charge that does not return, a leak, or unbounded work in one input.
- Code: the commit of N009, on the toolchain of `rust-toolchain.toml`. cargo-fuzz 0.13.2 and
  `libfuzzer-sys` 0.4.13 are approved for this package (2026-11-05). The closure of
  `libfuzzer-sys` is `arbitrary` 1.5.0, `cc` 1.10.0, `find-msvc-tools` 0.1.15, `jobserver`
  0.1.35, `getrandom` 0.4.3, `cfg-if` 1.0.5, `r-efi` 6.0.0, `libc` 0.2.191, and `shlex` 2.0.1.
  On 2026-11-14 the youngest of them, `cc`, was 21 days old. The only native code is the libFuzzer
  C++ that `libfuzzer-sys` builds.
- Host: one `aws-linux-arm64-ubuntu2604` host (c8g.4xlarge, 16 cores), with `dev-machine run
  --ephemeral`. The run installs cargo-fuzz on the host, which the run then discards.
- Budget: the four targets at the same time, each with
  `-fork=4 -max_total_time=3600 -timeout=5 -rss_limit_mb=2048` and AddressSanitizer. That is four
  CPU hours for each target. `-max_len` is 4096, and 1024 for `values`. Each target has a wall limit
  of 90 minutes, and the host has a lease of 120 minutes.
- Stop condition: a target stops at its time budget, or at its first crash, leak, timeout, or
  out-of-memory error. The run prints each artifact in base64, so the run record keeps it.
- Command, from the root of the checkout:

  ```bash
  DEV_MACHINE_MAX_LEASE_MINUTES=120 ~/dev-machines/dev-machine run rsnetwork \
    aws-linux-arm64-ubuntu2604 --ephemeral --execute bash -c '
    set -u; uname -srm; rustc -V
    cargo install cargo-fuzz --version 0.13.2 --locked --quiet && cargo fuzz --version || exit 1
    cargo fuzz build --fuzz-dir fuzz || exit 1
    for t in request response chunked values; do
      len=4096; [ $t = values ] && len=1024; mkdir -p fuzz/corpus/$t
      timeout 5400 cargo fuzz run --fuzz-dir fuzz $t fuzz/corpus/$t fuzz/seeds/$t -- -fork=4 \
        -max_total_time=3600 -timeout=5 -rss_limit_mb=2048 -max_len=$len >fuzz/$t.log 2>&1 &
    done
    status=0; for job in $(jobs -p); do wait $job || status=1; done
    for t in request response chunked values; do
      echo "== $t"; grep -m1 -A60 -E "panicked|ERROR:" fuzz/$t.log; tail -n 4 fuzz/$t.log
    done
    for f in fuzz/artifacts/*/*; do [ -f "$f" ] && { echo "== $f"; base64 -w0 "$f"; echo; }; done
    exit $status'
  ```

- Result (2026-11-14): pass. Run `20261114T071355Z-29146` at the N009 commit, on c8g.4xlarge,
  `ami-06b1a03fa3561aefb`, Linux `7.0.0-1016-aws` aarch64, `rustc 1.101.0-nightly (3e92e1a2d
  2026-11-01)`, and cargo-fuzz 0.13.2. Each target ran its full budget, from 3619 to 3628 seconds in
  167 jobs, with 0 crashes, 0 timeouts, and 0 out-of-memory errors. A leak also counts as a crash.
  The run printed no artifact. The host ran for 63 minutes, and `dev-machine status rsnetwork`
  then showed no instance and no volume.

  | Target | Runs | Coverage (`cov`) | Features (`ft`) | Corpus |
  | --- | --- | --- | --- | --- |
  | `request` | 136,104,549 | 1752 | 9529 | 1987 |
  | `response` | 123,649,985 | 1607 | 8348 | 1742 |
  | `chunked` | 1,413,102,426 | 516 | 2571 | 1116 |
  | `values` | 1,503,721,494 | 1020 | 2959 | 956 |

  Before the campaign, the smoke runs of a few seconds on a Mac found two defects of N005. They
  were fixed at their root, each with regression tests: bytes after a response that became the
  response to the next request (`5a1d3bd`), and Upgrade and Expect facts of an HTTP/1.0 request
  (`a0c7728`). Limits: the working corpus stayed on the discarded host. The time of each drive is
  constant, so the head timer never expires. `response` never has bytes that arrive with a
  response before the next request, which the regression tests of `5a1d3bd` cover.
- Next campaign: bring the minimized corpus back from the host into the evidence directory of the
  run, so that the next campaign starts from it.

### N011: differential parsing against `httparse`

- Risk: request smuggling between two parsers. That is a head or a chunked body that rsnetwork
  accepts and `httparse` reads with another meaning: another method, target, version, field line,
  head length, chunk data, trailer section, or body length.
- Code: the commit of N011, on the toolchain of `rust-toolchain.toml`. `httparse` 1.10.1 is
  approved as a dev-dependency (2026-11-15). It has no dependency and no native code. Its build
  script only selects its SIMD code.
- Host: the maintainer Mac (Apple silicon, macOS, aarch64), with cargo-fuzz 0.13.2. The run starts
  only when the load average of `uptime` is below 16.
- Budget: `-fork=4 -max_total_time=1800 -timeout=5 -rss_limit_mb=2048 -max_len=4096` and
  AddressSanitizer. That is 30 minutes with 4 workers, and a wall limit of 35 minutes.
- Stop condition: the time budget, or the first disagreement, crash, leak, timeout, or
  out-of-memory error. A disagreement fails the assertion of the target, and libFuzzer writes its
  input to `fuzz/artifacts/differential/`.
- Command, from the root of the checkout, after the corpus of [Seeds](#seeds):

  ```bash
  timeout 2100 cargo fuzz run --target aarch64-apple-darwin --fuzz-dir fuzz differential \
    fuzz/corpus/differential -- -fork=4 -max_total_time=1800 -timeout=5 -rss_limit_mb=2048 \
    -max_len=4096
  ```

- After the run: minimize the corpus with `cargo fuzz cmin`. Then llhttp reads each input of the
  minimized corpus, and `llhttp_gives_each_accepted_request_stream_the_same_meaning` compares the
  server engine with it. The test reads the corpora and the record under `CARGO_MANIFEST_DIR`, so
  a copy of the root with the corpus in `fuzz/seeds/request/` serves it. Each input there starts
  with two control bytes.
- Result (2026-11-15): pass. The run was at `f63a048`, on an Apple M1 Pro with macOS 27.2.1
  (`Darwin 27.2.0 arm64`), `rustc 1.101.0-nightly (3e92e1a2d 2026-11-01)`, and cargo-fuzz 0.13.2.
  The load average was 7.31 at the start. The target ran its full budget: 1821 seconds in 117
  jobs, 201,787,657 runs, `cov` 1440, `ft` 5218, and a corpus of 1823. It had 0 disagreements,
  crashes, timeouts, and out-of-memory errors, and it wrote no artifact. The later refusal of a
  framing field in a trailer section only refuses more inputs. Thus each input that the final code
  accepts has the reading that the run checked.
- llhttp after the run: `cargo fuzz cmin` kept 1721 inputs. llhttp and the server engine read them
  and the 64 seeds: 1368 the same, 374 refusals by rsnetwork, and 43 refusals by llhttp, with no
  input that has two meanings. 40 of the refusals by llhttp are methods that are not in its table
  (`HPE_INVALID_METHOD`), and 3 are whitespace before a chunk extension. The seed
  `request/rfc3253-7.1-update` keeps the first class in the record of `tests/h1_differential.rs`.
  The minimized corpus is in `~/.local/state/fuzz-evidence/rsnetwork/N011/` on the maintainer Mac.

### N201: the HPACK decoder

- Risk: a header block that makes the decoder allocate, keep state past its limits, or do work
  past its work limit, such as an expansion through references to a large entry. A table that
  falls out of step with the encoder, so that a later block decodes to other lines. A panic on
  malformed input.
- Code: the commit of N201, on the toolchain of `rust-toolchain.toml`, with cargo-fuzz 0.13.2 and
  the `libfuzzer-sys` closure of N009. The target adds no dependency.
- Host: one `aws-linux-arm64-ubuntu2604` host (c8g.4xlarge, 16 cores), with `dev-machine run
  --ephemeral`. The run installs cargo-fuzz on the host, which the run then discards.
- Budget: `-fork=14 -max_total_time=1200 -timeout=5 -rss_limit_mb=2048 -max_len=4096` and
  AddressSanitizer. That is 20 minutes with 14 workers, a wall limit of 25 minutes for the target,
  and a lease of 35 minutes for the host.
- Stop condition: the time budget, or the first crash, failed assertion, leak, timeout, or
  out-of-memory error. The run prints each artifact in base64, so the run record keeps it.
- Command, from the root of the checkout:

  ```bash
  DEV_MACHINE_MAX_LEASE_MINUTES=35 ~/dev-machines/dev-machine run rsnetwork \
    aws-linux-arm64-ubuntu2604 --ephemeral --execute bash -c '
    set -u; uname -srm; rustc -V
    cargo install cargo-fuzz --version 0.13.2 --locked --quiet && cargo fuzz --version || exit 1
    mkdir -p fuzz/corpus/hpack
    timeout 1500 cargo fuzz run --fuzz-dir fuzz hpack fuzz/corpus/hpack fuzz/seeds/hpack -- \
      -fork=14 -max_total_time=1200 -timeout=5 -rss_limit_mb=2048 -max_len=4096 >fuzz/hpack.log 2>&1
    status=$?
    grep -m1 -A60 -E "panicked|ERROR:" fuzz/hpack.log; tail -n 4 fuzz/hpack.log
    for f in fuzz/artifacts/hpack/*; do [ -f "$f" ] && { echo "== $f"; base64 -w0 "$f"; echo; }; done
    exit $status'
  ```
- Result (2026-11-15): pass. Run `20261115T075158Z-72714` at `c766996`, on c8g.4xlarge,
  `ami-06b1a03fa3561aefb`, Linux `7.0.0-1016-aws` aarch64, `rustc 1.101.0-nightly (3e92e1a2d
  2026-11-01)`, and cargo-fuzz 0.13.2. The target ran its full budget: 1210 seconds in 176 jobs,
  33,185,549 runs, `cov` 494, `ft` 2684, and a corpus of 562. It had 0 crashes, failed
  assertions, leaks, timeouts, and out-of-memory errors, and it wrote no artifact. The host ran
  for about 23 minutes, and `dev-machine status rsnetwork` then showed no instance and no volume.
  Limit: the working corpus stayed on the discarded host. After the run, the decoder writes into
  the `Lines` that the caller lends to each decode, not into a buffer of its own. The target
  changed only its calls, and the decode code that it reaches is the same.

### N202: the HTTP/2 frame and connection layer

- Risk: a frame sequence that makes the connection allocate past one header-block join, keep a
  charge, or read a frame differently when it crosses regions: a lost or doubled DATA byte, another
  flow count, another decoded block, or another connection error. A frame after a GOAWAY, a
  connection error with no GOAWAY, or a panic on hostile input.
- Code: the commit of N202, on the toolchain of `rust-toolchain.toml`, with cargo-fuzz 0.13.2 and
  the `libfuzzer-sys` closure of N009. The target adds no dependency.
- Host: one `aws-linux-arm64-ubuntu2604` host (c8g.4xlarge, 16 cores), with `dev-machine run
  --ephemeral`. The run installs cargo-fuzz on the host, which the run then discards.
- Budget: `-fork=14 -max_total_time=1200 -timeout=5 -rss_limit_mb=2048 -max_len=4096` and
  AddressSanitizer. That is 20 minutes with 14 workers, a wall limit of 25 minutes for the target,
  and a lease of 35 minutes for the host.
- Stop condition: the time budget, or the first crash, failed assertion, leak, timeout, or
  out-of-memory error. The run prints each artifact in base64, so the run record keeps it.
- Command, from the root of the checkout:

  ```bash
  DEV_MACHINE_MAX_LEASE_MINUTES=35 ~/dev-machines/dev-machine run rsnetwork \
    aws-linux-arm64-ubuntu2604 --ephemeral --execute bash -c '
    set -u; uname -srm; rustc -V
    cargo install cargo-fuzz --version 0.13.2 --locked --quiet && cargo fuzz --version || exit 1
    mkdir -p fuzz/corpus/h2
    timeout 1500 cargo fuzz run --fuzz-dir fuzz h2 fuzz/corpus/h2 fuzz/seeds/h2 -- \
      -fork=14 -max_total_time=1200 -timeout=5 -rss_limit_mb=2048 -max_len=4096 >fuzz/h2.log 2>&1
    status=$?
    grep -m1 -A60 -E "panicked|ERROR:" fuzz/h2.log; tail -n 4 fuzz/h2.log
    for f in fuzz/artifacts/h2/*; do [ -f "$f" ] && { echo "== $f"; base64 -w0 "$f"; echo; }; done
    exit $status'
  ```

- Result (2026-11-17): pass. Run `20261117T022531Z-33481` at `3862742`, whose code is the code of
  the N202 commit, on c8g.4xlarge, `ami-06b1a03fa3561aefb`, Linux `7.0.0-1016-aws` aarch64,
  `rustc 1.101.0-nightly (3e92e1a2d 2026-11-01)`, and cargo-fuzz 0.13.2. The target ran its full
  budget: 1211 seconds in 176 jobs, 25,826,886 runs, `cov` 1178, `ft` 4834, and a corpus of 571.
  It had 0 crashes, failed assertions, leaks, timeouts, and out-of-memory errors, and it wrote no
  artifact. `dev-machine status rsnetwork` then showed no instance and no volume. Limits: the
  working corpus stayed on the discarded host. The time of each drive is constant, so the settings
  timeout never ends a run.

### N210: the HTTP/2 stream layer

- Risk: a frame sequence that makes the stream layer give a body on an idle or closed stream, send
  a frame on a stream after its reset or a reset on an idle stream, grant more credit than the DATA
  bytes that arrived, raise the last stream of a GOAWAY, or read differently when frames cross
  regions. A header block of a refused or closed stream that puts the HPACK state out of step. A
  panic on hostile input.
- Code: the commit of N210, on the toolchain of `rust-toolchain.toml`, with the `libfuzzer-sys`
  closure of N009. The target adds no dependency. Each stream admits 1024 bytes and a server
  takes 4 streams, so an input of at most 4096 bytes can pass a window and the stream limit.
- Host: one `aws-linux-arm64-ubuntu2604` host (c8g.4xlarge, 16 cores), with `dev-machine run
  --ephemeral`. The host has no cargo-fuzz, and the run installs nothing. Plain cargo builds the
  target with the flags that `cargo fuzz build -v` (cargo-fuzz 0.13.2) gave on the maintainer Mac,
  and the run gives libFuzzer the arguments that `cargo fuzz run` gives.
- Budget: `-fork=14 -max_total_time=1200 -timeout=5 -rss_limit_mb=2048 -max_len=4096` and
  AddressSanitizer. That is 20 minutes with 14 workers, a wall limit of 25 minutes for the target,
  and a lease of 45 minutes for the host, with the build.
- Stop condition: the time budget, or the first crash, failed assertion, leak, timeout, or
  out-of-memory error. The run prints each artifact in base64, so the run record keeps it.
- Command, from the root of the checkout:

  ```bash
  DEV_MACHINE_MAX_LEASE_MINUTES=45 ~/dev-machines/dev-machine run rsnetwork \
    aws-linux-arm64-ubuntu2604 --ephemeral --execute bash -c '
    set -u; uname -srm; rustc -V
    export RUSTFLAGS="-Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=4 \
      -Cllvm-args=-sanitizer-coverage-inline-8bit-counters -Cllvm-args=-sanitizer-coverage-pc-table \
      -Cllvm-args=-sanitizer-coverage-trace-compares --cfg fuzzing \
      -Cllvm-args=-simplifycfg-branch-fold-threshold=0 -Zsanitizer=address -Cdebug-assertions \
      -Ccodegen-units=1"
    CARGO_PROFILE_RELEASE_DEBUG=line-tables-only cargo build --manifest-path fuzz/Cargo.toml --locked \
      --release --target aarch64-unknown-linux-gnu --bin h2 || exit 1
    mkdir -p fuzz/corpus/h2 fuzz/artifacts/h2
    ASAN_OPTIONS=detect_odr_violation=0 timeout 1500 fuzz/target/aarch64-unknown-linux-gnu/release/h2 \
      -artifact_prefix=fuzz/artifacts/h2/ fuzz/corpus/h2 fuzz/seeds/h2 \
      -fork=14 -max_total_time=1200 -timeout=5 -rss_limit_mb=2048 -max_len=4096 >fuzz/h2.log 2>&1
    status=$?
    grep -m1 -A60 -E "panicked|ERROR:" fuzz/h2.log; tail -n 4 fuzz/h2.log
    for f in fuzz/artifacts/h2/*; do [ -f "$f" ] && { echo "== $f"; base64 -w0 "$f"; echo; }; done
    exit $status'
  ```

- Result (2026-11-17): pass. Run `20261117T045047Z-90354` at `9f86d1d`, whose code is the code of
  the N210 commit, on c8g.4xlarge, `ami-06b1a03fa3561aefb`, Linux `7.0.0-1016-aws` aarch64, and
  `rustc 1.101.0-nightly (3e92e1a2d 2026-11-01)`. The target ran its full budget: 1212 seconds in
  176 jobs, 20,583,384 runs, `cov` 1898, `ft` 6846, and a corpus of 815. It had 0 crashes, failed
  assertions, leaks, timeouts, and out-of-memory errors, and it wrote no artifact. `dev-machine
  status rsnetwork` then showed no instance and no volume. A first run, `20261117T044352Z-63320`,
  stopped after 2 seconds at an assertion of the target, not of rsnetwork: the input ended inside
  a padded DATA frame, and the target did not count that frame, which the connection counts at its
  header (RFC 9113, section 6.9.1). The target now counts it, and the input is the seed
  `rfc9113-6.9.1-padding-of-a-cut-frame`. Limit: the working corpus stayed on the discarded host.

### N203: HTTP/2 floods

- Risk: a frame sequence that starts more handlers than the stream limit, because a reset frees a
  slot before the consumer closes it or a new stream takes a held slot. A wait for a slot that no
  reset holds, or a wait at another frame in a cut input. A panic, an allocation past the work
  limit, or a charge that does not return, on the paths of held slots and of CONTINUATION frames
  that count toward the block bound.
- Code: the commit of N203, on the toolchain of `rust-toolchain.toml`, with the `libfuzzer-sys`
  closure of N009. The target adds no dependency. A server takes 4 streams, so a short input can
  reset more streams than the slots.
- Host, budget, stop condition, and command: as for N210, on one `aws-linux-arm64-ubuntu2604`
  host. That is `-fork=14 -max_total_time=1200` with AddressSanitizer, 20 minutes, and a lease of
  45 minutes. Stop at the time budget, or at the first crash, failed assertion, leak, timeout, or
  out-of-memory error.
- Result (2026-11-17): pass. Run `20261117T055844Z-70390` at `be9ecce`, whose code is the code of
  the N203 commit, on c8g.4xlarge, `ami-06b1a03fa3561aefb`, Linux `7.0.0-1016-aws` aarch64, and
  `rustc 1.101.0-nightly (3e92e1a2d 2026-11-01)`. The target ran its full budget: 1211 seconds in
  176 jobs, 20,182,778 runs, `cov` 1925, `ft` 7013, and a corpus of 831. It had 0 crashes, failed
  assertions, leaks, timeouts, and out-of-memory errors, and it wrote no artifact. `dev-machine
  status rsnetwork` then showed no instance and no volume. Limit: the working corpus stayed on the
  discarded host.
