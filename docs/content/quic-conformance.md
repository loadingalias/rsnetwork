# The QUIC conformance suite

The QUIC conformance suite checks the QUIC engines under the faults of a network: loss,
reordering, delay, a path that drops large datagrams, cleared ECN marks, a shared bottleneck, and
a flood of new handshakes. It runs the client and server engines of the core in memory, with no
socket and no runtime. The test gives each call its time, so a run takes no wall-clock time to
wait.

rsnetwork is in development and has no release.

## Run the suite

```sh
cargo xtask test -E 'binary(quic_conformance) | binary(quic_streams) | binary(quic_handshake) | binary(quic_rogue)'
```

`cargo xtask test` with no argument also runs these tests. A failure names the cell and its
expected result.

## Run the QUIC tests on WebAssembly

The QUIC core and its tests build for `wasm32-wasip1`, and the tests run in Wasmtime. This is a
compile and test target only: no browser run and no other WebAssembly host has a claim.
`wasm32-unknown-unknown` does not build yet, because rustls with `std` needs a JavaScript clock
on that target.

Prerequisites: `wasmtime` on the `PATH`. `rust-toolchain.toml` installs the `wasm32-wasip1`
target, and `.cargo/config.toml` makes Wasmtime the test runner of that target.

```sh
cargo xtask test -p rsnetwork --target wasm32-wasip1 --cargo-profile release \
  -E 'binary(/^quic/) | (kind(lib) & test(/^quic::/))'
```

The command runs the QUIC unit tests and the QUIC test binaries. The release profile keeps the
overflow checks and runs about four times faster than the test profile in Wasmtime. A test that
needs a thread, a socket, or a process cannot run on `wasm32-wasip1`. `cargo xtask check` builds and lints the core and all of its tests for this target, so a change
that cannot build there fails the check.

## Replay a run

A seeded run gives each end its own child of the seed as its entropy, and the faults of the path
another child. The test gives the time of each call. Thus two runs with the same seed send the same
datagrams, with the same bytes, at the same times. The replay cell compares each datagram of two
runs of one seed, and a second seed must change the bytes. An engine whose bytes or times depend
on the system clock fails this cell.

## The cells

Each expected result comes from the RFC that the cell names, or from a run of the same engines
with the fault off. It never comes from the code under test.

| Cell | Tests | Expected result |
| --- | --- | --- |
| Replay | `quic_conformance`: `a_seeded_run_replays_each_byte_and_time_and_another_seed_changes_them` | An upload through delay, jitter, loss, late datagrams, and cleared ECN marks, then over a path that drops datagrams above 1,200 bytes: two runs of one seed send the same datagrams at the same times. Another seed sends other bytes. |
| Loss and reordering | `quic_conformance`: `a_transfer_through_seeded_loss_and_reordering_delivers_each_byte_once_in_order`; `quic_streams`: `the_declared_reordering_interval_preserves_goodput_and_delivers_each_datagram_once`, `newreno_grows_on_delivery_and_halves_once_for_packet_and_time_threshold_losses` | A 1 MiB upload through 3% loss and 10% of datagrams 20 ms late gives each byte once and in order, and no end closes. Loss detection and the window follow RFC 9002, sections 6 and 7. |
| Anti-amplification | `quic_handshake`: `an_unvalidated_server_counts_udp_bytes_and_stops_its_probe_timer_at_the_limit`; `quic_streams`: `data_to_a_new_peer_address_stays_within_three_times_its_received_bytes_until_validation`; `quic_rogue`: `a_datagram_from_a_new_address_pays_for_three_times_its_bytes_one_time` | Before an address is valid, an end sends at most three times the bytes that came from it (RFC 9000, sections 8.1 and 9.3.1). |
| Address validation and migration | `quic_handshake`: `retry_validates_the_first_address_and_new_token_validates_a_repeat_connection_on_a_new_port`, `a_client_moves_to_a_new_local_address_with_new_connection_ids_and_the_listener_follows`; `quic_streams`: `a_rebound_client_keeps_its_connection_after_path_validation`, `the_validation_of_an_address_that_never_answers_ends_at_its_timer_and_the_old_path_keeps_its_window` | RFC 9000, sections 8 and 9. |
| MTU black holes | `quic_streams`: `the_search_finds_the_datagram_size_of_the_path_and_a_lost_probe_is_no_congestion`, `a_path_that_starts_to_drop_large_datagrams_returns_to_1200_bytes_in_three_probe_timeouts` | RFC 8899, and RFC 9000, section 14. |
| ECN and pacing | `quic_streams`: `a_valid_ce_mark_reduces_cubic_once_and_a_cleared_mark_disables_ecn`, `each_datagram_in_a_full_window_leaves_at_its_pacing_deadline`, `a_batch_holds_one_millisecond_of_the_pacing_rate_and_the_next_waits_for_its_departure` | RFC 9000, section 13.4, and RFC 9002, sections 7.1 and 7.7. |
| Idle ends | `quic_handshake`: `an_idle_connection_reaches_its_idle_deadline_with_no_peer_traffic`; `quic_conformance`: `an_idle_end_takes_the_deadline_of_new_work_at_once_and_acts_at_it` | With no traffic, the next deadline is the idle timeout, and the end ends at it (RFC 9000, section 10.1). Work from the application gives an earlier deadline at once. The probe leaves at that deadline and not before it (RFC 9002, section 6.2). |
| Fairness under overload | `quic_conformance`: `connections_that_share_a_bottleneck_each_get_their_fair_share_within_25_percent` | Four connections share a bottleneck of 600 KB/s with a 24 KB drop-tail queue, on a 40 ms round trip. After the first 5 s, each connection gets its fair share within 25% for 20 s. |
| Flood of new handshakes | `quic_conformance`: `a_flood_of_new_handshakes_leaves_an_established_upload_within_1_percent`; `quic_handshake`: `full_handshake_admission_still_routes_an_established_connection_and_releases_removed_slots` | 1,000 handshakes in each second, each from a new address, pass the Retry threshold of the listener. An established upload on an uplink of 1 MB/s keeps its bytes within 1% of a run with no flood. |

The handshake work of a flood costs CPU time, which a simulated clock does not show. The cells
check the state of the protocol: routes, tables, and admission.

The fuzz targets `quic_packet`, `quic_frame`, and `quic_params` drive the packet layer, the frame
codec, and the transport parameters with coverage-guided input. The [fuzz README](../../fuzz/README.md)
gives their checks.

## The path of a pair

`tests/quic_path/mod.rs` holds the path. A `Pair` is a client and a server after their handshake,
with one `Link` in each direction. The handshake runs on a path with no delay and no fault, and
then the links of its `Setup` apply.

| Field | Effect |
| --- | --- |
| `Link::delay` | The time from the entry of a datagram, or from its exit from the bottleneck, to its arrival |
| `Link::jitter` | An extra delay of each datagram, up to this value |
| `Link::loss_per_mille` | The datagrams of each 1,000 that the link drops |
| `Link::late_per_mille`, `Link::late` | The datagrams of each 1,000 that arrive `late` after their time, so that later datagrams pass them |
| `Link::marks` | `Marks::Clear` delivers each datagram as Not-ECT |
| `Link::bottleneck` | A queue with a fixed rate and a drop-tail limit. The clones of a link share one queue |
| `Pair::path_bytes` | The link drops each datagram above this size |
| `Pair::seen` | The client address that the server sees, for a rebinding |

Each fault that is on draws from the seed for each datagram. A link with no fault draws nothing.
`run_together` moves several pairs on one clock. Each pair moves only at its own deadlines and
arrivals, as a host of its own does.

## Use the suite in a binding

A binding test includes the module as the [Tokio binding](tokio.md) includes the HTTP/1.1 suite:

```rust
#[path = "../../tests/quic_path/mod.rs"]
mod quic_path;
```

The module drives the engines of the core and delivers each datagram in memory, at the arrival
time that its link gives. A binding that runs a cell over its sockets sends each datagram through
its own socket at that step, and gives the receiving end what the socket received. Its expected
result does not change.
