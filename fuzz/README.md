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

The transport checks the bounds of [Bound the memory and the work of a connection](../docs/content/limits.md)
on each drive: the engine holds at most one charged join of a head or a trailer section, no drive
allocates more than one section, each charge returns when the engine drops, and each round makes
progress. The allocation bound also permits 256 bytes (`RECORD` in `src/lib.rs`) for the record
that `Lease::from_owner` allocates with a join. This is a stated tolerance, not a value measured
from the code.

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
