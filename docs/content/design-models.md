# Check the design models

rsnetwork has two TLA+ design models. They check the design, not the Rust code. Change a model
when you change one of its rules or the wire format that the rules constrain.

- [`models/attached-datagram/`](../../models/attached-datagram/README.md) checks the datagram
  form of attached channels. It checks that the consumer reads only the bytes that the sender
  sent, that an acknowledgement means that the receiver holds the bytes, that the receiver's
  replay state stays bounded, and that the channel ends under the declared loss budget when the
  consumer reads and the path eventually stays stable. It checks lossy ordinary ACKs, delayed
  final-size arrival, independent endpoint outcomes, and repeated migration attempts. Each
  validation must end even if attempts continue.
- [`models/backing-release/`](../../models/backing-release/README.md) checks charged
  backings across protocol acceptance, retransmission, peer acknowledgement, and kernel release.
  One output can gather views of two backings, such as a frame header and its payload. It
  checks that each retained view and each kernel use keeps its backing alive and charged once,
  and that the release of each backing runs once, when its last obligation ends. It also checks
  that a partial acceptance keeps the suffix of each backing with its writer, and that a
  repeated or unknown acknowledgement changes no ownership. The
  [boundary assumptions](#backing-release-boundary-assumptions) below state what it takes from
  the runtime.

## Checker requirements

The model command uses the pinned Rust toolchain and the checkers under `~/.local/opt/`:
`temurin-jre`, `tla2tools`, and `apalache`. `~/machine` owns their versions through
`machine update all`; installation or updates need maintainer approval. The command installs
nothing. If a checker is missing, or more than one version is present, it stops and names the
directory. Each evidence record keeps the checker versions and file identities.

## Run the model

From the repository root:

```sh
cargo xtask model attached-datagram                                  # every profile
cargo xtask model attached-datagram/AttachedDatagram.NoTagSquat_bad.cfg # one profile
cargo xtask model backing-release                                    # every profile
```

You can give several selections to one command. The command freezes the selected model files
before it starts a checker, and each checker reads its retained source copy. One model run at a
time holds the host lock; another run waits for it.

By default, the command uses the JVM and TLC memory defaults. To set memory for a larger TLC
search, give both sizes in MiB. For example, on a 32 GiB host:

```sh
cargo xtask model --tlc-heap-mib=20480 --tlc-fp-mib=4096 \
  attached-datagram/AttachedDatagram.FaultySender.cfg
```

The first size sets the Java heap with `-Xmx`; the second sets separate fingerprint storage with
`-XX:MaxDirectMemorySize`. The pair selects the pinned TLC `OffHeapDiskFPSet`, as defined by its
[memory configuration](https://raw.githubusercontent.com/tlaplus/tlaplus/bc1b506bdcad/tlatools/org.lamport.tlatools/src/tlc2/tool/fp/FPSetConfiguration.java).
Choose sizes that leave memory for the OS, file cache, and other native allocations. Each size
must be a positive whole number of MiB, at most 4294967295. A missing member of the pair,
duplicate option, or invalid value fails before a checker starts. The options apply to TLC;
a selection that contains only Apalache profiles rejects them.

With the pair, each TLC run also retains `gc.log` beside `run.txt`. The GC log has time stamps
and no file rotation, so it keeps the whole run. The manifest records the exact JVM options.
Without the pair, the command keeps the default memory policy and adds no GC log. These options
change resources only; every selected profile still needs its complete check.

Every TLC command also sets `-XX:+ExitOnOutOfMemoryError`. The pinned
[liveness index](https://raw.githubusercontent.com/tlaplus/tlaplus/bc1b506bdcad/tlatools/org.lamport.tlatools/src/tlc2/tool/liveness/NodePtrTable.java)
can retry with mismatched arrays after a heap allocation fails. The selected JDK exits with
status 3 before that Java handler can recover. Such a run is incomplete, never a pass.

The command prints the digest of the model files, then one result for each profile:

```text
files of .../target/model/inputs/<run>/attached-datagram: sha256:<digest> (<count> files)
── tlc attached-datagram/AttachedDatagram.NoTagSquat_bad.cfg
   `AckMeansHeld` is violated: as the known-bad variant requires, in 0.63s (exit status: 12)
```

- A main profile passes with `ok` and exit status 0: a complete search with no violation. The
  command reads the checker's own summary: TLC must report a completed search with 0 states left on the queue, and
  Apalache the outcome `NoError` with no timed-out query. A search that stopped early fails as
  inconclusive, also when the checker exits with 0. The command removes the JVM option variables
  (`JAVA_TOOL_OPTIONS`, `JDK_JAVA_OPTIONS`, `_JAVA_OPTIONS`, `JVM_ARGS`) from each checker run.
- A `_bad` profile is a known-bad variant. It passes only when the checker reports a violation
  of its one property.
- A `_reach` profile is a reachability witness. It passes only when the checker reaches its
  target.

The command exits 0 when every selected profile passes. The output of each profile goes to
`target/model/<model>/<profile>/<run>/`: the input closure in `source/`,
`run.txt` with commands and identities, `checker.log`, `stderr.log`, and `trace.json` for a violation.
Runs have separate directories; a later run does not replace an earlier result.

## Large profiles

The 2026-11-12 matrix of the attached-datagram model completed all 43 declared profiles on one 16-vCPU host. All 33 known-bad
and reachability profiles gave their required violations. Each of the ten positive profiles
completed safety and final liveness within its original one-hour cap; native times ranged from
208.432595 to 3195.420733 seconds. These results cover the exact source, bounds, and assumptions
in the [evidence record](../../models/attached-datagram/README.md#current-evidence).

The model uses an exact
[retired payload view](../../models/attached-datagram/README.md#retired-payloads). It keeps sent
offsets where old payload distinctions cannot affect a later step, and retains full payload
evidence in the forgery variants. The [retired ACK view](../../models/attached-datagram/README.md#retired-ack-history)
also omits obsolete acceptance identities while it keeps live loss/ACK membership and the
passed-window observation. Four identity-sensitive variants keep full ACK sets. Ordinary
actions, fairness, properties, and bounds stay unchanged. The evidence retains the exact inputs,
commands, verdicts, traces, earlier incomplete attempts, and completed host cleanup.

An edit that lets omitted payload or ACK history affect a guard, receive result, checked
observation, or fair action requires a new view correspondence argument and all profile checks. The original
invariants still run; an assumed safety result cannot justify a smaller view.

Each profile must finish within one hour on a 16-vCPU host, so that a run of every profile after a
change stays short. Use the first 10 minutes of a capped run to estimate its full size from the
growth of the distinct states and the queue. If it can finish within the cap, continue that run;
do not restart it only to repeat the sample. A profile that does not finish within its cap gives
no result, and a larger host does not change the limit. Make the model smaller
only in a way that keeps the result sound: symmetry over identical processes, a bound that the
model proves, or an inductive proof. Each such change needs a known-bad variant that still fails
under it. A smaller bound must still reach each failure that the model names, and it needs a
profile with that bound raised by one.

On a smaller host, select the profiles that your change touches, and run the whole model before
you record evidence.

## Backing-release boundary assumptions

The backing-release model composes two ownership contracts. The protocol keeps output until
exact acceptance and peer acknowledgement. The rsasync driver keeps each accepted submission
until its terminal event. The model takes the driver side from rsasync's terminal-release
contract, which the rsasync model `models/operation-ownership/` checks. It owns no driver. These
facts are its boundary:

- An accepted submission gives the driver a view of each backing of its regions until its
  terminal event. A refused submission returns the views to the caller.
- A zero-copy send has a send result and, when the kernel armed one, a later notice. Without a
  notice, the result is terminal. A copying send is that second case.
- Notices, send results, and the peer's acknowledgements come in any order.
- Cancellation, a request deadline, and close prove no kernel release. Each kernel use keeps its
  view until its own terminal event.
- The model checks safety only. The rsasync model checks that each terminal event comes.

The model checks one writer region of two slices, in each layout of those slices in one or two
backings, and two datagram copies of each slice. One datagram can gather slices of two backings.
The `Slices3` and `Copies3` profiles raise each of the two argued bounds by one. `Slices3` has
25,161,615 distinct states and took 335 seconds on one 16-vCPU host, so run it on such a host.
If a protocol or runtime change breaks one of these facts, change the model first, and run all
of its profiles.

## When a profile fails

- A main profile reports a violation. The trace in `trace.json` starts at an initial state.
  Compare each step with the design's transitions. If the model follows the design, the trace is
  a counterexample to a design rule: the design changes first, and then the model. If the model
  does not follow the design, correct the model.
- A `_bad` profile reports "no violation". The variant no longer breaks its property, so the
  property or the module changed. Find which one changed before you change the profile.
- A profile reports a violation of a property other than its own. The variant fails for another
  reason, so it shows nothing about its own property.

After a change, run every profile and update the evidence record in the model's README with the
digest that the command prints.
