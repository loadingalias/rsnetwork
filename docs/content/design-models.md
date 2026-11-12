# Check the design models

rsnetwork has a TLA+ model of the datagram form of attached channels:
[`models/attached-datagram/`](../../models/attached-datagram/README.md). It checks that the
consumer reads only the bytes that the sender sent, that an acknowledgement means that the
receiver holds the bytes, that the receiver's replay state stays bounded, and that the channel
ends under the declared loss budget when the consumer reads and the path eventually stays
stable. It checks lossy ordinary ACKs, delayed final-size arrival, independent endpoint outcomes,
and repeated migration attempts. Each validation must end even if attempts continue. The model
checks the design, not the Rust code. Change the model when you change one of these rules or the
wire format that they constrain.

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
[memory configuration](https://raw.githubusercontent.com/tlaplus/tlaplus/d8fb231de4e4/tlatools/org.lamport.tlatools/src/tlc2/tool/fp/FPSetConfiguration.java).
Choose sizes that leave memory for the OS, file cache, and other native allocations. Each size
must be a positive whole number of MiB, at most 4294967295. A missing member of the pair,
duplicate option, or invalid value fails before a checker starts. The options apply to TLC;
a selection that contains only Apalache profiles rejects them.

With the pair, each TLC run also retains `gc.log` beside `run.txt`. The GC log has time stamps
and no file rotation, so it keeps the whole run. The manifest records the exact JVM options.
Without the pair, the command keeps the default memory policy and adds no GC log. These options
change resources only; every selected profile still needs its complete check.

Every TLC command also sets `-XX:+ExitOnOutOfMemoryError`. The pinned
[liveness index](https://raw.githubusercontent.com/tlaplus/tlaplus/d8fb231de4e4/tlatools/org.lamport.tlatools/src/tlc2/tool/liveness/NodePtrTable.java)
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
`target/model/attached-datagram/<profile>/<run>/`: the input closure in `source/`,
`run.txt` with commands and identities, `checker.log`, `stderr.log`, and `trace.json` for a violation.
Runs have separate directories; a later run does not replace an earlier result.

In an Apalache induction matrix, a Step profile can use
`--tuning-options=search.invariantFilter=1->.*` when its initializer already includes `IndInv`.
This checks every invariant clause at the successor state and omits the redundant initial-state
check. Init and Safety stay unfiltered; the matrix rejects narrower filters and transition filters.

## Large profiles

The 2026-11-09 model took about 25 minutes on its 16-vCPU evidence host. Those timings do not
size the revised model. Its README records the current results and any unfinished boundary.

The current gate remains blocked after an exact
[state view](../../models/attached-datagram/README.md#state-view) removed unused packet mappings
and terminal data histories. The declared actions, properties, and bounds stay unchanged.
All 33 known-bad and reachability profiles passed on the final source. `FaultySender` reached
the one-hour cap on the 16-vCPU, 32 GiB host with a 20 GiB heap and 4 GiB fingerprint storage;
3,260,892 states remained queued. The other nine positives did not start, so all ten positive
obligations remain open. The [evidence record](../../models/attached-datagram/README.md#current-evidence)
keeps the exact inputs, failed attempts, cap, and completed host cleanup. Dependent implementation
must wait for the complete-search gate.

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
