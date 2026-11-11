# Attached channel: datagram form

This is the design model of task N000. It checks the rules of attached datagram channels in
`docs/specs/networking.md`, through the decisions of 2026-11-11, before N603 fixes the wire
format. The [statechart](statechart.md) shows its control states.

**Status (2026-11-11): N000 is blocked; 35 of 43 profiles are complete.** All 33 known-bad and
reachability profiles pass, as do the base and `NoOnPath` positive profiles. Eight positive
profiles remain unverified. `FaultySender` repeated the resource failure with explicit memory
settings, so checking stopped under the repeated-failure rule. The [current evidence](#current-evidence)
retains both attempts. Earlier evidence cannot qualify the changed rules. The
[pending recurrence form](#pending-recurrence-form) is unimplemented and unmeasured.

## Promise

Each side datagram carries a tag that gives integrity and no confidentiality. The parent carries
authenticated control frames. The model checks these rules:

- The receiver holds bytes that the sender sent at their offsets. An acknowledgement of an
  offset below the final size means that its bytes are held or read. Only the final read-point
  frame completes the sender.
- Credit admits only bounded receive storage. Only an accepted datagram moves the bounded replay
  window. A final-size frame discards unread excess. A final size below the read point gives
  integrity at that endpoint.
- Each endpoint keeps its first terminal outcome. A later terminal frame ends an open peer.
  Completion can cross reset, or the parent can fail before notification, so the outcomes can
  differ.
- Each validation ends by success, abandonment, or parent failure. Migration attempts have no
  finite count. With finite loss inside the packet budget, eventual path stability, a live
  parent, and a consumer that keeps reading, both endpoints end. Without reset or parent
  failure, an honest transfer completes.

A concrete failure is the loss of the last ordinary ACK. If the sender does not run loss
recovery for that packet, its send window can stay full while the receiver waits for more data.
A reliable-ACK assumption would hide this failure. `NoAckRecovery_bad` must expose it.

## Run it

```sh
cargo xtask model attached-datagram
cargo xtask model attached-datagram/AttachedDatagram.NoAckRecovery_bad.cfg
```

[Check the design models](../../docs/content/design-models.md) gives the tool requirements,
budget, and verdict rules. Each run retains its input closure, command, source and tool
identities, checker output, exit status, and any trace under
`target/model/attached-datagram/<profile>/<run>/`. A known-bad or reachability profile checks one
property and passes only when that property is violated.

## Correspondence and atomicity

N603 and N604 have no implementation yet. This table maps actions to the design's contract rows;
the wire-element and production-transition mapping must be added when that code exists.

| Action | Contract row and one atomic step |
| --- | --- |
| `Init` | Explicit profile: open succeeds or refuses at both endpoints |
| `SendData(o)` | Packet numbers and replay; Receive credit; Congestion and loss; Retransmission; Path and routing: build and send one byte with a fresh packet number |
| `Deliver(d)` | Tag; Packet numbers and replay; Receive credit; Injection: arrival and the local receive procedure |
| `Replay(p)` | Injection: arrival of a sent datagram whose original copy did not arrive |
| `Lose(d)` | Network loss of one data copy, inside the packet budget |
| `DeclareLost(p)` | Congestion and loss: one loss declaration and shared-window reduction; an early declaration is allowed |
| `DeliverAck` | Control; Packet numbers and replay: process all packet numbers in one authenticated ordinary ACK frame |
| `LoseAck` | Control: lose the current ordinary ACK; a new accepted datagram replaces it with current receive state |
| `DeliverCredit(c)` | Receive credit: one credit frame arrives |
| `DeliverFinalSize` | Receive credit; Terminal outcomes: the final-size frame arrives, removes unread excess, and checks the read point |
| `Read` | Receive credit; Integrity: read one byte, check its application tag, release its storage, and grant new credit |
| `Complete` | Terminal outcomes: the receiver completes after the consumer reads the known final size |
| `DeliverReceiverEnd`, `DeliverSenderEnd` | Terminal outcomes: a terminal frame arrives at an open peer; receiver completion carries the final read point |
| `Reset(side)` | Terminal outcomes: a local reset at one endpoint |
| `ParentEnd` | Lifetime; Terminal outcomes: the parent ends; each open endpoint reports its local result |
| `ParentLoss` | Congestion and loss: a parent loss reduces the shared window |
| `MigrateStart`, `Spoof` | Migration: start a genuine or spurious validation of another abstract path |
| `Validated` | Migration: PATH_RESPONSE arrives, selects the candidate path, and resets its congestion state |
| `Abandon` | Migration: the timer or the last validated address ends the attempt; retain the old path and its congestion state |
| `Done` | Stuttering when both endpoints have ended |

`Forge`, `GrantBeyond`, `ResendSamePN`, and `CompleteAtAck` exist only in known-bad variants.
Other variants change the named production transition. `OldPacketReuse.tla` imports this
protocol unchanged and adds only the `NoAckLoss` action constraint for its canary. The complete
receive procedure is one local transition; network arrivals, consumer reads, and parent-frame
arrivals are separate.

The data domain has one byte per datagram. `good` means the correct application byte at that
offset, and `bad` means a byte its application tag rejects. `Authentic` accepts only a datagram
that the sender sent. A faulty sender can authenticate bad bytes and bytes beyond its later
final size. The receiver keeps the first accepted bytes at each offset.

## Properties and profiles

| Property | Claim | Known-bad check |
| --- | --- | --- |
| `HeldAreSenderBytes` | Held bytes came from the sender at that offset | `NoTag_bad` |
| `CreditBound` | Held bytes stay inside granted credit and admitted capacity | `CreditBeyond_bad` |
| `PNStateBound` | Replay state stays inside the window | `NoWindowBound_bad` |
| `WindowAfterTag` | The window moves only on an accepted packet number | `SlideBeforeTag_bad` |
| `AckMeansHeld` | Acknowledged offsets below the final size are held or read | `NoTagSquat_bad` |
| `CompletionSound` | Receiver completion needs the known final read point; sender completion needs receiver completion | `CompleteAtAck_bad` |
| `FinalSizeBound` | No unread excess remains after final-size arrival | `FinalKeepsJunk_bad` |
| `FinalReadIntegrity` | A final size below the read point reports integrity | `NoFinalIntegrity_bad` |
| `NoNetworkIntegrity` | Network events do not cause integrity with an honest sender below the failed-tag limit | `NoTagEnd_bad` |
| `OutcomeStable` | Each endpoint keeps its terminal outcome | `LateReset_bad` |
| `Progress` | `WF_vars(Read) /\ <>[](mig = "none")` implies eventual termination of both endpoints | `ReusePN_bad`, `OldPacketReuse.Spread_bad`, `NoAckRecovery_bad`, `NoFinalNotice_bad` |
| `ValidationEnds` | Each pending validation ends or the parent fails | `NoAbandon_bad` |

The main, `NoOnPath`, and raised-bound profiles check all these properties and `TypeOK`.
`FaultySender` and `Excess2` omit `NoNetworkIntegrity`: the faulty sender can cause integrity.
The new existential final-size and endpoint profiles use one byte; `NoAckRecovery_bad` uses
two bytes and a one-packet window. These smaller domains retain the named failures. They do not
replace the positive profiles or their raised bounds.

TLC also checks for deadlocks. `Done` keeps terminal states from being deadlocks.

The witnesses cover each outcome (`Completed`, `Reset`, `ParentEnd`, `Partial`, `Refused`,
`Integrity`); resumed sending, abandonment, completion after abandonment, and another attempt
(`Resumed`, `Abandoned`, `CompletedAfterAbandon`, `RepeatedMigration`); a passed replay window
and an accepted late copy (`WindowPassed`, `ReplayAccepted`); and the new boundaries (`Crossed`,
`ParentInterrupted`, `FinalDelayed`, `LastAckLost`, `FinalBelowRead`, `JunkDiscarded`). The
`LastAckLost`, `JunkDiscarded`, and `Resumed` action witnesses require the actual loss, discard,
and send steps. `CompletedAfterAbandon` requires delivery of the final read-point frame after
abandonment; both endpoints are then complete.

## Bounds and fairness

The base profile has `Bytes = 4`, `MaxPN = 6`, `Excess = 1`, `Paths = 2`, and
`Cap = Range = Window = 2`. `Paths` counts reusable abstract identities, not attempts. Ordinary
ACKs carry a set of accepted packet numbers; one arrival processes the frame together. The
network is a set of data copies, so arrival order is arbitrary.

The packet budget is `MaxPN - Bytes`. `Spent` counts declared losses, packets whose data or ACK
can no longer arrive, and excess-byte transmissions. A fault is allowed only while enough packet
numbers remain to send the required bytes again. Accepted data with no pending ACK is eligible
for fair loss detection. `NoAckRecovery` removes that timer obligation without changing the
fault budget. This is a finite-loss model; it does not prove progress for an arbitrary
unbounded fair-loss network. `ReusePN` counts faults separately because it reuses packet numbers.

Each argued bound has a raised profile: `Bytes5` (with seven packet numbers to keep two faults),
`MaxPN7`, `Paths3`, `Cap3`, `Range3`, `Cap3Range3Window3`, and `Excess2`. The congestion raise
also raises credit and packet-number spread so three packets can be in flight. `Excess2` uses a
faulty sender and permits two bytes beyond the final size.

| Fair action | Why it is fair | Failure retained by a known-bad check |
| --- | --- | --- |
| `SendData` | The side flow gets a share when admission stays possible | `ReusePN_bad`: repeated sends do not complete |
| `Deliver` | A copy that stays in the network eventually arrives, under the stated loss assumption | `OldPacketReuse.Spread_bad`: arrival below the window cannot repair reused numbers |
| `DeclareLost` for `Doomed` packets | Loss detection runs when no data or ACK copy remains | `NoAckRecovery_bad`: received data whose ACK was lost still needs recovery |
| `DeliverAck` | An ordinary ACK that stays pending eventually arrives; `LoseAck` can remove it | `NoAckRecovery_bad`: no fairness delivers a lost ACK |
| `DeliverCredit`, `DeliverFinalSize`, `Complete`, terminal-frame arrival | Local processing and reliable control progress while the parent is alive | `CompleteAtAck_bad`, `FinalKeepsJunk_bad`, `NoFinalIntegrity_bad`, `NoFinalNotice_bad` |
| `Validated \/ Abandon` | Validation ends by the peer response or a bounded timer | `NoAbandon_bad`: a spurious attempt cannot succeed and never ends without abandonment |

The consumer's read is a condition of `Progress`, not specification fairness. Reset, parent
failure, parent loss, early loss declarations, network loss, attackers, and migration starts have
no fairness. Success alone has no fairness. `ValidationEnds` does not assume eventual path
stability; it applies also when attempts repeat without end.

## Reductions and limits

1. One data delivery and one late replay suffice for copies: a later accepted copy is duplicate
   or old and changes no protocol state. `ReplayAccepted_reach` shows a useful late replay;
   `OldPacketReuse.Spread_bad` retains failure from repeated old copies.
2. An ordinary ACK contains current accepted packet numbers. New data replaces its pending
   state; arrival processes the whole frame. Older partial ACK frames and ACK range encoding
   are not separate state. Missing or delayed information is represented by loss and loss
   declarations. `NoAckRecovery_bad` still checks lost-last-ACK recovery. ACK encoding and
   frame processing need N604 tests.
3. In-flight packet numbers span fewer than `Range` values. This is a model bound, not a sender
   rule. Discard below the receiver's window is represented by data loss under the packet
   budget. `OldPacketReuse.Spread_bad` excludes ordinary ACK loss and must fail through reuse
   below the window. Its `NoAckLoss` action constraint applies only to this counterexample
   search; the resulting trace is also a behavior of the unconstrained bad variant.
   `WindowPassed_reach` reaches a passed number in the design.
4. A sent datagram can pass its tag with any issued connection ID. The real tag also covers the
   ID, so this adds acceptance behaviors. Inside that abstraction, every issued ID has the same
   `Fresh` and `Authentic` result. Store all issued IDs as 1 and unissued IDs as 0; keep `path`
   and `tried` separately. Fresh packet numbers distinguish live copies, so this removes only
   unused ID history. `Resumed_reach` requires an actual send on the selected path. The model
   retires no ID and does not check ID issuance, address history, or restoration of an earlier
   path after a successful migration. `NoTag_bad` and `NoTagSquat_bad` retain the authentication
   failures; `ReusePN_bad` retains the reused-copy failure.
5. Side sending pauses during validation. Production sends to the parent's non-probing address
   within its anti-amplification limit. The model does not check that admission or its scheduler.
   With repeated attempts, this pause can leave no send opportunity that stays enabled. Thus
   `Progress` explicitly requires an eventually stable path; it makes no progress claim under
   continuous migration. `ValidationEnds` and `RepeatedMigration_reach` check validation and
   repeatability separately, and `NoAbandon_bad` retains an endless spurious validation.
6. After both endpoints have ended and `mig = "none"`, parent failure only changes `parentLive`.
   The model omits that step. Project an original behavior by deleting such a `ParentEnd` step
   and keeping the earlier value of `parentLive`. No new migration can start because starts
   require `BothOpen`. All original fair actions are disabled in this suffix. The remaining
   optional ACK loss and the `LateReset` bug can still take their original steps or stutter.
   Thus the projection satisfies the original fairness conditions.

   The omitted step changes no byte, credit, replay, acknowledgement, read-point, or outcome
   predicate. `TypeOK` still has a Boolean `parentLive`; `WindowAfterTag` and `OutcomeStable`
   see no change. `Progress` is already satisfied. `ValidationEnds` has no pending or future
   attempt. `ParentInterrupted` still requires the parent failure that ends an open sender;
   a `partial` outcome cannot already exist while `parentLive = TRUE`. All other outcome and
   action targets retain the same transitions. In particular, `LateReset_bad` still changes a
   terminal outcome, and `NoAbandon_bad` still exposes pending validation after both endpoints
   end. Parent failure during pending validation, `Validated`, and `Abandon` remain unchanged.

   This removes at most one lifetime-state copy per terminal history with no pending validation.
   It does not merge the distinct data histories or reduce any declared bound. Ordinary ACK
   loss after termination remains: moving it before the final local outcome gives the same
   destination state, so suppressing that step would mainly remove duplicate edges.

The model assumes the application's tag check, ideal GMAC below its failed-tag limit, and
protected parent frames. It does not prove cryptographic computation, nonce safety, wire parsing,
parent packet scheduling, recovery periods, or arbitrary-size buffers. N603 and N604 own the
wire and implementation evidence. It proves no Rust code.

## Current evidence

After the terminal-lifetime reduction on 2026-11-11, one command selected all 33 `_bad.cfg`
and `_reach.cfg` profiles in name order. It was `RUSTUP_AUTO_INSTALL=0 cargo xtask model`
with those 33 `attached-datagram/<file>` arguments. Command exit: 0, after 93.97 seconds,
inside its five-minute cap. Each profile has its exact checker command, frozen input closure,
source status, tool identities, and original exit in `run.txt`. All runs in this batch end in
`-21984` below `target/model/attached-datagram/<profile>/`. The batch command and cap are in
`focused-cap-1794385671916803000/` under that output root.

- Source: uncommitted changes on `ca23158b35e212af6c53966f2bc6f7be77cc24c9`.
  Model digest: `sha256:0f3549cd6571a57bad725860cd234a2fbc2e82cdab2fd9c75ce66d228b6802da`
  (45 checked files). All 33 retained profile closures match the current inputs.
- Checkers: Temurin JRE 21.0.13+9; TLC 1.8.0+d8fb231de4e4, version
  2026.11.06.222357; Apalache 0.62.4 was present but not used.
  Runner digest: `4f1571c48d3379384a62391eb0a1ddf10d6ddbb829d734908a134e63e0b19117`.
  Each manifest records the checker-file digests and full arguments.
- Host: macOS 27.2.1 arm64, ten cores, 16 GB; TLC used ten workers and a 3,641 MB heap.
  Other work loaded this host. Durations are run records, not performance measurements.
- SANY parsed both current modules with exit 0 before TLC. Its retained source and output are
  in `target/model/attached-datagram/sany/1794385625781398000/`.
- The final shared validator passed all 11 tests and the scoped formatting, Clippy, and rustdoc
  checks before this run. Its two source-file hashes match the checked runner. No Rust input
  changed for the terminal-lifetime reduction.

A violation is the required result for these profiles. The reduction's boundary traces retain
both endpoints reset with a pending spurious validation (`NoAbandon_bad`), a refused endpoint
changed to reset (`LateReset_bad`), and parent failure while the sender still awaits the receiver's
completion frame (`ParentInterrupted_reach`). The old-window canary still has a fair failure
cycle with no pending ACK, as detailed below.

| Profile | Property violated as required | Checker exit | Distinct states | Seconds |
| --- | --- | --- | --- | --- |
| `AttachedDatagram.Abandoned_reach.cfg` | `NotAbandoned` | 12 | 116 | 1.30 |
| `AttachedDatagram.CompleteAtAck_bad.cfg` | `CompletionSound` | 12 | 333,507 | 7.28 |
| `AttachedDatagram.CompletedAfterAbandon_reach.cfg` | `NotCompletedAfterAbandon` | 13 | 1,113 | 1.58 |
| `AttachedDatagram.Completed_reach.cfg` | `NotCompleted` | 12 | 1,010,134 | 16.54 |
| `AttachedDatagram.CreditBeyond_bad.cfg` | `CreditBound` | 12 | 1,964 | 1.36 |
| `AttachedDatagram.Crossed_reach.cfg` | `NotCrossed` | 12 | 125 | 1.65 |
| `AttachedDatagram.FinalBelowRead_reach.cfg` | `NotFinalBelowRead` | 12 | 4,511 | 1.54 |
| `AttachedDatagram.FinalDelayed_reach.cfg` | `NotFinalDelayed` | 12 | 403,091 | 7.02 |
| `AttachedDatagram.FinalKeepsJunk_bad.cfg` | `FinalSizeBound` | 12 | 196 | 1.31 |
| `AttachedDatagram.Integrity_reach.cfg` | `NotIntegrity` | 12 | 332 | 1.30 |
| `AttachedDatagram.JunkDiscarded_reach.cfg` | `NotJunkDiscarded` | 13 | 432 | 1.50 |
| `AttachedDatagram.LastAckLost_reach.cfg` | `NotLastAckLost` | 13 | 279 | 1.57 |
| `AttachedDatagram.LateReset_bad.cfg` | `OutcomeStable` | 13 | 191 | 1.59 |
| `AttachedDatagram.NoAbandon_bad.cfg` | `ValidationEnds` | 13 | 865 | 1.65 |
| `AttachedDatagram.NoAckRecovery_bad.cfg` | `Progress` | 13 | 8,607 | 3.04 |
| `AttachedDatagram.NoFinalIntegrity_bad.cfg` | `FinalReadIntegrity` | 12 | 4,919 | 2.10 |
| `AttachedDatagram.NoFinalNotice_bad.cfg` | `Progress` | 13 | 125 | 1.63 |
| `AttachedDatagram.NoTagEnd_bad.cfg` | `NoNetworkIntegrity` | 12 | 410 | 1.61 |
| `AttachedDatagram.NoTagSquat_bad.cfg` | `AckMeansHeld` | 12 | 713 | 1.50 |
| `AttachedDatagram.NoTag_bad.cfg` | `HeldAreSenderBytes` | 12 | 32 | 1.39 |
| `AttachedDatagram.NoWindowBound_bad.cfg` | `PNStateBound` | 12 | 7,145 | 1.42 |
| `AttachedDatagram.ParentEnd_reach.cfg` | `NotParentEnd` | 12 | 558,496 | 10.11 |
| `AttachedDatagram.ParentInterrupted_reach.cfg` | `NotParentInterrupted` | 12 | 129 | 1.22 |
| `AttachedDatagram.Partial_reach.cfg` | `NotPartial` | 12 | 71 | 1.71 |
| `AttachedDatagram.Refused_reach.cfg` | `NotRefused` | 12 | initial state | 1.44 |
| `AttachedDatagram.RepeatedMigration_reach.cfg` | `NeverRepeatMigration` | 13 | 685 | 1.54 |
| `AttachedDatagram.ReplayAccepted_reach.cfg` | `NeverReplayAccepted` | 13 | 243 | 1.46 |
| `AttachedDatagram.Reset_reach.cfg` | `NotReset` | 12 | 47 | 1.62 |
| `AttachedDatagram.Resumed_reach.cfg` | `NotResumed` | 13 | 319 | 1.67 |
| `AttachedDatagram.ReusePN_bad.cfg` | `Progress` | 13 | 14,105 | 3.59 |
| `AttachedDatagram.SlideBeforeTag_bad.cfg` | `WindowAfterTag` | 13 | 9 | 1.58 |
| `AttachedDatagram.WindowPassed_reach.cfg` | `NotWindowPassed` | 12 | 4,057 | 1.74 |
| `OldPacketReuse.Spread_bad.cfg` | `Progress` | 13 | 10,483 | 3.77 |

`OldPacketReuse.Spread_bad.cfg` isolates the spread reduction from the lost-ACK duplicate
failure in `ReusePN_bad`. Its current source, log, and trace are in
`OldPacketReuse.Spread_bad.cfg/1794385762044512000-21984/` under the output root.
The constraint can also exclude a duplicate-ACK arrival whose state change is identical to
`LoseAck`. Thus the constrained verdict alone does not establish fairness in `ReuseSpec`.
The retained trace gives this argument for the original specification:

- The prefix declares packet number 1 at offset 1 lost early, charging one fault. Its copy
  remains delayed in the network. Packet numbers 2 and 3 deliver offsets 0 and 2, and both ACK
  frames arrive. The consumer reads offset 0, so `rRead = 1`.
- States 13, 14, and 15 repeat `Deliver`, `DeclareLost(1)`, and `ResendSamePN(1)`.
  The receiver discards each copy because `1 + Range = 3 <= rHigh = 3`. The missing byte is
  never held. `ack = {}` throughout this cycle, so `LoseAck` is disabled and the constraint
  excludes no cycle step.
- Each original fair resend, data-delivery, and doomed-loss action occurs each cycle. New-byte
  sending is disabled because all three offsets were sent. ACK delivery is disabled because
  `ack = {}`; credit delivery because both limits are 3; completion because `rRead = 1`;
  final-size delivery because `rFinal = TRUE`; terminal-frame delivery because both endpoints
  are open; and validation completion because `mig = "none"`.
- `Read` is disabled at the missing byte, so its weak-fairness condition holds. The path is
  stable, the parent stays alive, and both endpoints stay open. Thus this is a fair behavior
  of unconstrained `ReuseSpec` that violates `Progress`.

The earlier 32-profile batch (`-67140`) and the earlier wrapper run
(`OldPacketReuse.Spread_bad.cfg/1794381240450327000-75868/`) remain retained with their
source closures and traces. They predate the terminal-lifetime reduction and do not qualify
the changed module.

The dedicated-host run `20261111T084109Z-31147` completed the current base and `NoOnPath`
profiles. Both searches emptied the queue and completed both temporal-property branches.
Each positive profile had a 3,600-second cap. `FaultySender` was stopped before its cap after
its processing rate fell sharply; the remaining seven profiles did not start.

- Source digest: `sha256:0f3549cd6571a57bad725860cd234a2fbc2e82cdab2fd9c75ce66d228b6802da`.
  All three retained input closures match the current model files.
- Host: dedicated EC2 c8g.4xlarge, 16 vCPUs, 32 GiB, Linux 7.0.0-1016-aws arm64.
  TLC used 16 workers, `MSBDiskFPSet`, `DiskStateQueue`, and a 6,997 MB JVM heap.
  The pinned checker versions and TLC digest are the same as above; the Linux JRE digest is
  `360e5ff407299f11ec030ac45f87f4f5767d2c6fb0682c8a3d1ce08df5f69806`.
  Runner digest: `50350aa56427bf5958ce3dc248bbcb88057457a35b256d189db67660873e0b14`.
- No explicit heap or fingerprint size was set. The default on-heap fingerprint set uses
  25% of the JVM heap; the printed 64 MB off-heap figure is not its limit. This follows the
  pinned [TLC memory configuration](https://raw.githubusercontent.com/tlaplus/tlaplus/d8fb231de4e4/tlatools/org.lamport.tlatools/src/tlc2/tool/fp/FPSetConfiguration.java).
- The maintainer checkout retains the native archive at
  `target/model/remote-n000-20261111T084109Z-31147/node-1-artifacts.tar.gz`, SHA-256
  `a8164f1cad11507cf17bccac7dc98b2a1941c8e8c506228a418fbfbed430f753`.
  Artifact collection and teardown completed; `dev-machine status rsnetwork aws-linux-arm64-ubuntu2604`
  reported no instance or volume.

| Profile | Checker exit | Distinct states | Depth | Seconds | Result |
| --- | --- | --- | --- | --- | --- |
| `AttachedDatagram.cfg` | 0 | 33,436,881 | 36 | 1,259.61 | Complete pass |
| `AttachedDatagram.NoOnPath.cfg` | 0 | 24,458,225 | 36 | 776.27 | Complete pass |
| `AttachedDatagram.FaultySender.cfg` | 130 | 52,358,701 | 21 | 1,597.17 | Interrupted; no result |

Their canonical run directories below the output root are
`AttachedDatagram.cfg/1794386636648338486-15819/`,
`AttachedDatagram.NoOnPath.cfg/1794387909648671270-20238/`, and
`AttachedDatagram.FaultySender.cfg/1794388699314575360-22826/`.
The last faulty-sender checkpoint still had 15,493,182 queued states. The lead sent SIGINT to
the verified TLC process; this was not a completed search or a property violation.

### Blocked positive searches

Native run `20261111T101323Z-27234` tested whether explicit heap and fingerprint memory would
remove the processing-rate collapse. It used the same c8g.4xlarge host type, 16 workers, model
files, bounds, checker versions, and 3,600-second cap per positive profile. The command added
`--tlc-heap-mib=8192 --tlc-fp-mib=8192`. Its manifests record:

```text
-XX:+UseParallelGC
-Xmx8192m
-XX:MaxDirectMemorySize=8192m
-Dtlc2.tool.fp.FPSet.impl=tlc2.tool.fp.OffHeapDiskFPSet
-Xlog:gc*:file=../gc.log:time,uptime,level,tags:filecount=0
```

Both TLC headers confirm `OffHeapDiskFPSet`, 8,192 MB off-heap memory, and `DiskStateQueue`.
They print 7,282 MB heap at startup; the command sets its maximum to 8,192 MiB.
Native runner digest: `3bc80604e5238f72cbb178424b6a729896bf3a94c0a8fb1b3ceef36a04440876`.
The runner passed all 13 tests and scoped format, Clippy, and rustdoc checks before this run.

| Profile | Run | Checker exit | Distinct states | Seconds | Result |
| --- | --- | --- | --- | --- | --- |
| `NoAckRecovery_bad` | `1794392239107697262-15842` | 13 | 8,607 | 0.918258 | Required `Progress` violation |
| `FaultySender` | `1794392253407944087-16207` | 130 | 62,392,409 | 1,351.250926 | Interrupted; no result |

These runs are below `target/model/attached-datagram/AttachedDatagram.<profile>.cfg/`.
The canary repeats one of the 33 completed small profiles; it adds no distinct completed profile.
Both faulty-sender attempts have input-closure digest
`sha256:6460a539c08e6d90cea2bd7ae21797d975970620bf3de742c6e4a6a20b1db2d5`.
At the second attempt's final checkpoint, depth was 22 and 17,871,727 states remained queued.
Only 206,732 states were processed over about 62 seconds. At that rate, the existing queue alone
needed about 89 minutes, beyond the 38 minutes left in its cap. Full GC took about 2.3 seconds
every 2.55 seconds, while retaining about 5.36 GiB. `early-stop.txt` and `gc.log` retain the
observations. The lead sent SIGINT to verified TLC PID 16220 after the resource failure recurred.
There was no completed search or property verdict. The remaining seven profiles did not start.

The second native archive is retained in the maintainer checkout at
`target/model/remote-n000-20261111T101323Z-27234/node-1-artifacts.tar.gz`, SHA-256
`f5c5c2b2c3fc0f7c11f083d90533992be4fa771ece49323790e915d9d16f91d8`.
Collection and teardown both exited 0; fresh native status reported no instance or EBS volume.

The positive profiles still open are `FaultySender`, `Bytes5`, `MaxPN7`, `Paths3`, `Cap3`,
`Range3`, `Cap3Range3Window3`, and `Excess2`. No positive result from an earlier model is reused
for them. The 35 completed profiles retain matching current input closures and actual verdicts.
Their audit is in `target/model/attached-datagram-evidence-index.json` and
`target/model/attached-datagram-evidence-status.tsv`. No further checker run is part of this
blocked attempt.

All retained evidence except TLC state caches is also archived at
`~/.local/state/model-evidence/rsnetwork/N000/20261111T104325Z-network-model-evidence.tar.gz`,
with a duplicate under the maintainer checkout's `target/model/`: 1,423 files, 5,842,144 bytes,
SHA-256 `9292ee4e73b6694ef70761fc86218d116546da615f136a61653e042e38714a47`.
It preserves exact inputs, commands, exits, logs, traces, and GC evidence.

### Pending recurrence form

The following equivalent forms are a possible next change. They are not implemented, parsed,
model-checked, or measured. The frozen source still uses `<>BothDone` and the pending-validation
response formula.

```tla
Progress == (WF_vars(Read) /\ <>[](mig = "none")) => []<>BothDone
ValidationEnds == []<>(mig = "none" \/ ~parentLive)
```

`BothDone` stays true once reached in every current variant. The actions that can assign
`"open"` require that endpoint to be open; terminal-frame delivery changes only an open
destination to a terminal value. `ParentEnd` preserves terminal endpoints. `LateReset` can
change a terminal value to `"reset"`, but cannot reopen it. Other actions preserve outcomes
or end an open endpoint. Thus `<>BothDone` and `[]<>BothDone` are equivalent for all current
behaviors, including every known-bad variant. This uses the action guards, not `OutcomeStable`,
which `LateReset` violates. A future reopening action would require a new argument.

Let `Q == mig = "none" \/ ~parentLive`. Where `Q` holds, `<>Q` already holds; where it is
false, `mig # "none"` holds. Thus the current `[](mig # "none" => <>Q)` is exactly `[]<>Q`,
without an extra endpoint or parent assumption.

The names, consumer fairness, eventual-stable-path condition, fair actions, transitions, and
bounds stay the same. The unfinished cycles in `ReusePN`, `OldPacketReuse`, `NoAckRecovery`,
and `NoFinalNotice` still violate `Progress`. The `NoAbandon` cycle still has pending validation
and a live parent after both endpoints reset, so it violates either `ValidationEnds` form.
The unconstrained fair-cycle argument for `OldPacketReuse.Spread_bad` above is unchanged;
`NoAckLoss` remains inactive on that cycle.

The pinned [TLC classifier](https://raw.githubusercontent.com/tlaplus/tlaplus/d8fb231de4e4/tlatools/org.lamport.tlatools/src/tlc2/tool/liveness/Liveness.java)
leaves the current eventuality and response forms for tableau construction. From that source,
the proposed recurrence forms should use its direct classification without a tableau. This is
an inference, not a measured improvement. The ordinary
[graph index](https://raw.githubusercontent.com/tlaplus/tlaplus/d8fb231de4e4/tlatools/org.lamport.tlatools/src/tlc2/tool/liveness/NodePtrTable.java)
still grows on the Java heap. Resumed work needs independent review and new evidence for every
affected profile; no speedup or completed positive result is claimed.

### Earlier incomplete searches

A base-profile run before the terminal-lifetime reduction used a 30-minute command cap, with
a progress report at ten minutes.
It stopped at that cap with SIGTERM to its TLC process. Checker and command exit: 143;
checker duration: 1,799.01 seconds; command duration: 1,800.93 seconds. Its last checkpoint
reported 14,886,070 distinct states, 3,220,864 queued states, and depth 24. The queue still grew.
There was no completed positive verdict. This is functional evidence on a shared host, not a
qualified timing measurement. The run was not restarted.

- Command: `RUSTUP_AUTO_INSTALL=0 cargo xtask model attached-datagram/AttachedDatagram.cfg`.
- Model digest: `sha256:49c87cba20e44690727c7f04c7bdddb1baba6dc7555325dcdbd3547f61f2d2a7`.
  Profile closure: `sha256:447981639428ed76f93059e2b6c38070cbd94a2ded3f007efa18fae93a353230`.
- Runner digest: `4f1571c48d3379384a62391eb0a1ddf10d6ddbb829d734908a134e63e0b19117`.
  This final validator passed all 11 tests and the scoped formatting, Clippy, and rustdoc
  checks before the run. Checker and host identities are unchanged.
- Retained source, checker output, exit status, and stop reason:
  `AttachedDatagram.cfg/1794383355736838000-57245/` under the output root. The command cap,
  command output, elapsed time, and process identity are in `positive-cap-1794383353855807000/`.

A ten-minute sizing run of the base positive profile was stopped with SIGTERM, checker and
command exit 143, after 600.34 seconds. It used the earlier input digest
`cd4949b8317811e895b9a94dfb2efcc2f95dfe634f86cac0e6643a347f4cdcf3`.
Its last report had 8,326,074 distinct states, 2,185,760 queued states, and depth 22. The queue
still grew. External CPU and memory load reduced its rate during the run, so it gives no reliable
complete-size or quiet-host time estimate. It is not a pass. Its input, output, exit, and stop
reason are retained in `AttachedDatagram.cfg/1794376829683335000-81756/` under the output root.
The other stopped or failed development runs are retained beside their later results.

## Decisions

The defect (found 2026-11-06): the receiver changed its replay and acknowledgement state for a
datagram that nothing authenticated, and the sender used that packet number to find the bytes.
QUIC, ESP, DTLS 1.3, SRTP, and WireGuard each forbid that first step ([RFC 9000 section
13.1](https://www.rfc-editor.org/rfc/rfc9000#section-13.1), [RFC 4303 section
3.4.3](https://www.rfc-editor.org/rfc/rfc4303#section-3.4.3), [RFC 9147 section
4.5.1](https://www.rfc-editor.org/rfc/rfc9147#section-4.5.1), [RFC 3711 section
3.3.2](https://www.rfc-editor.org/rfc/rfc3711#section-3.3.2), and the [WireGuard
protocol](https://www.wireguard.com/protocol/)).

Selected on 2026-11-07 (option B1, simplified):

- Each side datagram carries a 16-byte AES-GMAC tag over the whole datagram: AES-128-GCM with the
  datagram as associated data and no plaintext, from rscrypto through a transport-neutral
  `rscrypto-rustls` helper. Each direction has its own key from the parent's exporter. The nonce
  is the packet number, never reused under one key. The receiver checks the tag first.
- The receiver slides its own replay window, as ESP and DTLS 1.3 do. The floor frames and the
  sender's range rule (gap 2b) are removed.
- Acknowledgements are packet-number acknowledgements, so RFC 9002 applies unchanged, and each
  frame names the consumer's read point (gap 2a). The sender completes when a frame names the
  final size.
- The receiver keeps the first bytes at an offset, as RFC 9000 section 2.2 permits. With the tag,
  other bytes at one offset come only from a faulty sender, and the application's tags then
  decide at the read. `FaultySender.cfg` checks that the channel still ends.
- Data at or past a known final size is junk (gap 2c), and the side flow is one stream of the
  parent's scheduler with a share that is never zero (gap 2d).
- The side flow follows the parent's path. It sends to the parent's non-probing peer address,
  within the parent's anti-amplification limit and that path's congestion controller and pacer;
  it returns with the parent when the parent abandons a validation, with that path's congestion
  state; and the receiver accepts a side datagram whose tag passes on each connection ID that it
  issued and did not retire. This replaces "while the parent validates a new path, the side flow
  does not send", which let each spoofed packet pause the side flow for a whole validation, a lever
  that the parent itself does not give an attacker (`NoAbandon_bad`).
- Cost: 16 bytes in each side datagram and one GMAC at each end. GMAC alone is not measured yet;
  N606 measures it on a quiet host. The bounds from rscrypto's AES-128-GCM rows (bench run
  41546963938 at `6926f298`) are more than 42 / 39 / 25 ns and less than 119 / 93 / 191 ns for
  a 1,200-byte datagram on Granite Rapids / Zen 5 / Arm64.

The rejected options, each rejected on 2026-11-07. Their proposal files were never committed.

- **D, held-range acknowledgement.** Each acknowledgement frame named the read point and the byte
  ranges that the receiver held; a packet number acknowledged without its bytes ended the channel
  with integrity. It passed with the attacker at small bounds (4,098,410 states at `Bytes = 3`,
  `MaxPN = 4`), and its declared attacker search was about 0.4 to 0.8 billion states. Rejected:
  any on-path attacker could still end any channel with one datagram, its receiver still changed
  state for unauthenticated datagrams, and it kept the floor frames and the held-bytes rule.
- **A, the acknowledgement names offset and length.** Each acknowledged packet number carried
  the offset and length that the receiver applied. It passed at small bounds (3,380,039 states at
  `Bytes = 3`, `MaxPN = 4`). Rejected: about 6 bytes for each acknowledged packet number, the same
  one-datagram end of the channel as D, and no read point.
- **A', one keyed digest for each acknowledgement frame.** A digest of the (packet number, offset,
  length) values that a frame covered. Not checked as a separate model; it detects the same cases
  as A. Rejected: a keyed PRF for each packet at each end, and on a mismatch it cannot name the
  packet. D was better on each count, and B1 better than D.
- **B0, a MAC over the header only.** An 8 to 16-byte MAC over the connection ID, packet number,
  and offset. Not checked as a separate model. Rejected: an attacker keeps a valid header and
  changes the body of a datagram in flight, so its copy can still win the race and end the
  channel; B1 costs the same 16 bytes and closes that race.
- **C, AEAD over the whole datagram.** Full encryption of each side datagram. Not checked as a
  separate model. Rejected: it is the second encryption pass that attached channels exist to
  remove, and each retransmission needs a new ciphertext, which removes the zero-copy send.

## Historical evidence

### Evidence host record of the final files

One complete run of every profile on the evidence host on 2026-11-09, from 02:07:44 to 02:32:38
UTC. It is the main record: one command, one digest, a host with no other workload, and the
original checker exit status of each profile. It includes the raise-by-one profiles of rule 4
([FP Design Models]). The records below it are the records of earlier runs.

- Command: `cargo xtask model attached-datagram`, from the repository root, with a limit of
  `timeout 7200`. Exit status 0.
- Source: the files of this directory, not yet committed. The xtask printed
  `sha256:55f1ef3fc57619676746967e800b52232b4eec299cfca8b9089aaf5e17c5a79a (31 files)`, the
  digest of the files as they are now.
- Checkers: temurin-jre 21.0.13+9 (Linux aarch64, SHA-256 checked against Adoptium), tla2tools
  1.8.0+d8fb231de4e4 (TLC2 Version 2026.11.06.222357, rev d8fb231; the pinned jar, SHA-256
  `e1f11b75c4b5bc4478ba0ac5cb6ae28e40a01b0016bc33e0aa97da22dfdbcd7f` checked), with `-workers auto
  -lncheck final` (16 workers, 6,997 MB heap). Apalache 0.62.4 was present and not used.
- Host: EC2 c8g.4xlarge on demand (16 vCPUs, 32 GiB), us-east-1b, image `ami-06b1a03fa3561aefb`
  (Ubuntu 26.04 arm64, 20261104.1), kernel 7.0.0-1016-aws, instance `i-009c5b322932ef2d1`. The
  instance is terminated. The host's own logs are not kept; this record holds their figures.
- Exit: the checker's own exit status: 0 for a complete search with no violation, 12 for an
  invariant violation, 13 for an action or temporal property violation. A known-bad or
  reachability search stops at the first violation that a worker finds, so its state count
  changes with the number of workers.

| Profile | Result (checker exit) | Distinct states | Depth | Duration (s) |
| --- | --- | --- | --- | --- |
| `AttachedDatagram.cfg` | Pass (0) | 2,330,763 | 30 | 28.97 |
| `AttachedDatagram.Abandoned_reach.cfg` | `NotAbandoned` reached (12) | 483 | 6 | 0.53 |
| `AttachedDatagram.Bytes5.cfg` | Pass (0) | 7,796,749 | 34 | 103.22 |
| `AttachedDatagram.Cap3.cfg` | Pass (0) | 8,470,530 | 29 | 103.64 |
| `AttachedDatagram.Cap3Range3Window3.cfg` | Pass (0) | 12,415,204 | 29 | 162.67 |
| `AttachedDatagram.CompleteAtAck_bad.cfg` | `CompletionSound` violated (12) | 184,405 | 17 | 1.17 |
| `AttachedDatagram.CompletedAfterAbandon_reach.cfg` | `NotCompletedAfterAbandon` reached (12) | 311,477 | 18 | 1.48 |
| `AttachedDatagram.Completed_reach.cfg` | `NotCompleted` reached (12) | 170,018 | 17 | 1.11 |
| `AttachedDatagram.CreditBeyond_bad.cfg` | `CreditBound` violated (12) | 1,230 | 7 | 0.53 |
| `AttachedDatagram.FaultySender.cfg` | Pass (0) | 23,259,395 | 30 | 268.35 |
| `AttachedDatagram.Integrity_reach.cfg` | `NotIntegrity` reached (12) | 746 | 6 | 0.54 |
| `AttachedDatagram.LateReset_bad.cfg` | `OutcomeStable` violated (13) | 398 | 6 | 0.53 |
| `AttachedDatagram.MaxPN7.cfg` | Pass (0) | 44,977,619 | 34 | 611.97 |
| `AttachedDatagram.NoAbandon_bad.cfg` | `Progress` violated (13) | 2,092,409 | 30 | 19.61 |
| `AttachedDatagram.NoOnPath.cfg` | Pass (0) | 2,092,409 | 30 | 25.59 |
| `AttachedDatagram.NoTagEnd_bad.cfg` | `NoNetworkIntegrity` violated (12) | 587 | 6 | 0.63 |
| `AttachedDatagram.NoTagSquat_bad.cfg` | `AckMeansHeld` violated (12) | 877 | 6 | 0.63 |
| `AttachedDatagram.NoTag_bad.cfg` | `HeldAreSenderBytes` violated (12) | 72 | 6 | 0.60 |
| `AttachedDatagram.NoWindowBound_bad.cfg` | `PNStateBound` violated (12) | 3,793 | 9 | 0.62 |
| `AttachedDatagram.ParentEnd_reach.cfg` | `NotParentEnd` reached (12) | 208,708 | 18 | 1.19 |
| `AttachedDatagram.Partial_reach.cfg` | `NotPartial` reached (12) | 89 | 5 | 0.52 |
| `AttachedDatagram.Paths3.cfg` | Pass (0) | 9,486,768 | 32 | 119.56 |
| `AttachedDatagram.Range3.cfg` | Pass (0) | 2,665,624 | 30 | 32.98 |
| `AttachedDatagram.Refused_reach.cfg` | `NotRefused` reached (12) | at the initial states | — | 0.46 |
| `AttachedDatagram.ReplayAccepted_reach.cfg` | `NeverReplayAccepted` reached (13) | 394 | 6 | 0.54 |
| `AttachedDatagram.Reset_reach.cfg` | `NotReset` reached (12) | 70 | 5 | 0.54 |
| `AttachedDatagram.Resumed_reach.cfg` | `NotResumed` reached (12) | 549 | 7 | 0.53 |
| `AttachedDatagram.ReusePN_bad.cfg` | `Progress` violated (13) | 262,468 | 27 | 3.44 |
| `AttachedDatagram.SlideBeforeTag_bad.cfg` | `WindowAfterTag` violated (13) | 35 | 6 | 0.60 |
| `AttachedDatagram.WindowPassed_reach.cfg` | `NotWindowPassed` reached (12) | 2,520 | 8 | 0.60 |

Each main and raised profile gives the same distinct-state count as its earlier record, on the
newer TLC build.

### Local runs of 2026-11-08

One complete run of every profile on 2026-11-08, from 00:32:42 to 00:51:41 EST (the first TLC
start and the last TLC end), under the host lock of the xtask. It replaces the records of
2026-11-07, whose checked files changed.

- Command: `cargo xtask model attached-datagram`, from the repository root. Exit status 0.
- Source: the checked files are not yet committed, on top of commit
  `887cf6dde62db6577e324e1ec433dbf8e877c7e8`, with the uncommitted model command change. The
  xtask printed `files of models/attached-datagram: 93b04d34c51b8adbd8ef6e1a56c2d34aec168f40
  (25 files)`; that digest names the checked files of this record.
- Checkers: temurin-jre 21.0.13+9, tla2tools 1.8.0+3ec1cc4f8c24 (TLC2 Version 2026.11.06.005304,
  rev 3ec1cc4), apalache 0.62.4 (not used). TLC flags: `-workers auto -lncheck final
  -noGenerateSpecTE -dumpTrace json`, 10 workers, 3,641 MB heap.
- Host: macOS 26.6.2 arm64, 10 cores, 16 GB. Another session's checkers ran on the host during
  this run, outside the xtask lock, so the durations are indicative only.
- SANY parsed `AttachedDatagram.tla` with no error before the first TLC run of each change.
- Bounds: `Bytes = 4`, `MaxPN = 6`, `Paths = 2`, `Cap = 2`, `Range = 2`, `Window = 2`, as in each
  profile. The profiles set `OnPath`, `FaultySender`, and `Bug`.
- Exit: the original TLC exit status. 0 is a complete search with no error, 12 an invariant
  violation, and 13 an action or temporal property violation. The xtask turns the required
  violation of a `_bad` or `_reach` profile into its own exit 0, so the TLC exit statuses of those
  profiles come from a direct TLC run of each with the same files and `-workers 2` (same
  verdicts).
- Replay: each profile's output is in `target/model/attached-datagram/<profile>/`: `checker.log`,
  and `trace.json` for a violation.

| Profile | Exit | Distinct states | Depth | Duration | Verdict |
| --- | --- | --- | --- | --- | --- |
| `AttachedDatagram.cfg` | 0 | 2,330,763 | 30 | 89.8 s | Pass: complete search, every property, `Progress`, no deadlock |
| `AttachedDatagram.NoOnPath.cfg` | 0 | 2,092,409 | 30 | 71.0 s | Pass. The attacker adds 238,354 states: the spurious migrations that only it can cause. Before the migration change, `Replay` added none (1,180,038 states with and without the attacker on 2026-11-07) |
| `AttachedDatagram.FaultySender.cfg` | 0 | 23,259,395 | 30 | 885.4 s | Pass, with `Progress`: the rule that keeps the first bytes lets the channel end with a faulty sender |
| `AttachedDatagram.NoTag_bad.cfg` | 12 | 32 | 5 | 0.6 s | `HeldAreSenderBytes` violated, as required |
| `AttachedDatagram.NoTagSquat_bad.cfg` | 12 | 627 | 6 | 0.6 s | `AckMeansHeld` violated, as required: the squatting trace |
| `AttachedDatagram.NoTagEnd_bad.cfg` | 12 | 470 | 5 | 0.7 s | `NoNetworkIntegrity` violated, as required |
| `AttachedDatagram.SlideBeforeTag_bad.cfg` | 13 | 29 | 5 | 0.6 s | `WindowAfterTag` violated, as required |
| `AttachedDatagram.ReusePN_bad.cfg` | 13 | 262,468 | 27 | 8.7 s | `Progress` violated, as required |
| `AttachedDatagram.CompleteAtAck_bad.cfg` | 12 | 156,520 | 17 | 2.0 s | `CompletionSound` violated, as required |
| `AttachedDatagram.CreditBeyond_bad.cfg` | 12 | 306 | 5 | 0.7 s | `CreditBound` violated, as required |
| `AttachedDatagram.NoWindowBound_bad.cfg` | 12 | 2,587 | 8 | 0.6 s | `PNStateBound` violated, as required |
| `AttachedDatagram.LateReset_bad.cfg` | 13 | 58 | 4 | 0.6 s | `OutcomeStable` violated, as required |
| `AttachedDatagram.NoAbandon_bad.cfg` | 13 | 2,092,409 | 30 | 66.1 s | `Progress` violated, as required: the side flow stays paused after a spurious migration. The fairness on success alone hid this failure in the record of 2026-11-07 |
| `AttachedDatagram.Completed_reach.cfg` | 12 | 173,553 | 17 | 1.9 s | Reached |
| `AttachedDatagram.Reset_reach.cfg` | 12 | 49 | 5 | 0.6 s | Reached |
| `AttachedDatagram.ParentEnd_reach.cfg` | 12 | 198,049 | 17 | 2.2 s | Reached |
| `AttachedDatagram.Partial_reach.cfg` | 12 | 41 | 4 | 0.5 s | Reached |
| `AttachedDatagram.Refused_reach.cfg` | 12 | initial state | 1 | 0.6 s | Reached |
| `AttachedDatagram.Integrity_reach.cfg` | 12 | 369 | 5 | 0.7 s | Reached, with a faulty sender |
| `AttachedDatagram.Resumed_reach.cfg` | 12 | 177 | 5 | 0.6 s | Reached |
| `AttachedDatagram.Abandoned_reach.cfg` | 12 | 116 | 4 | 0.7 s | Reached |
| `AttachedDatagram.CompletedAfterAbandon_reach.cfg` | 12 | 320,022 | 18 | 3.0 s | Reached |
| `AttachedDatagram.WindowPassed_reach.cfg` | 12 | 1,776 | 8 | 0.7 s | Reached |
| `AttachedDatagram.ReplayAccepted_reach.cfg` | 13 | 218 | 5 | 0.7 s | Reached |

TLC finds a violation with `-workers auto`, so another run can give another trace and state count
for the same violation. The counterexamples above are from this run.

### Evidence host record

One complete run of every profile on the evidence host on 2026-11-08, from 07:23:42 to 07:47:35
UTC, with the raise-by-one profiles of rule 4 ([FP Design Models]). It is the main record: one
digest, a quiet host, and the original exit status of each profile.

- Command: `cargo xtask model attached-datagram`, from the repository root. Exit status 0.
- Source: the files of this directory at that time. The xtask printed
  `d0315011bda44ecc1bd1f18111fd0a5ef81dae1f (32 files)`. The files then had two window profiles,
  `Window3` and `Cap3Window3`, which a later change replaced with `Cap3Range3Window3` (below).
  No other checked file changed.
- Checkers: temurin-jre 21.0.13+9 (Linux aarch64), tla2tools 1.8.0+3ec1cc4f8c24 (TLC2 Version
  2026.11.06.005304, rev 3ec1cc4; the pinned jar), with `-workers auto -lncheck final`.
- Host: EC2 m8g.4xlarge (16 vCPUs, 64 GiB), us-east-1a, image `ami-06b1a03fa3561aefb` (Ubuntu
  26.04 arm64, 20261104.1), kernel 7.0.0-1016-aws, instance `i-0b429594a0faf07f8`, no other
  workload.

| Profile | Exit | Distinct states | Depth | Duration | Verdict |
| --- | --- | --- | --- | --- | --- |
| `AttachedDatagram.cfg` | 0 | 2,330,763 | 30 | 28.7 s | Pass |
| `AttachedDatagram.NoOnPath.cfg` | 0 | 2,092,409 | 30 | 25.1 s | Pass |
| `AttachedDatagram.FaultySender.cfg` | 0 | 23,259,395 | 30 | 265.6 s | Pass |
| `AttachedDatagram.Paths3.cfg` (raise) | 0 | 9,486,768 | 32 | 119.3 s | Pass |
| `AttachedDatagram.Cap3.cfg` (raise) | 0 | 8,470,530 | 29 | 102.9 s | Pass |
| `AttachedDatagram.Range3.cfg` (raise) | 0 | 2,665,624 | 30 | 33.0 s | Pass |
| `AttachedDatagram.MaxPN7.cfg` (raise: three faults) | 0 | 44,977,619 | 34 | 588.1 s | Pass |
| `AttachedDatagram.Bytes5.cfg` (raise, with `MaxPN = 7`) | 0 | 7,796,749 | 34 | 101.4 s | Pass |
| `AttachedDatagram.Window3.cfg` (replaced) | 0 | 2,330,763 | 30 | 28.8 s | Pass, with the states of the main profile |
| `AttachedDatagram.Cap3Window3.cfg` (replaced) | 0 | 8,470,530 | 29 | 103.2 s | Pass, with the states of `Cap3` |
| `AttachedDatagram.NoAbandon_bad.cfg` | 13 | 2,092,409 | 30 | 19.4 s | `Progress` violated, as required |
| `AttachedDatagram.ReusePN_bad.cfg` | 13 | 262,468 | 27 | 3.6 s | `Progress` violated, as required |
| `AttachedDatagram.CompleteAtAck_bad.cfg` | 12 | 188,645 | 17 | 1.1 s | `CompletionSound` violated, as required |
| `AttachedDatagram.CreditBeyond_bad.cfg` | 12 | 758 | 6 | 0.5 s | `CreditBound` violated, as required |
| `AttachedDatagram.LateReset_bad.cfg` | 13 | 193 | 6 | 0.5 s | `OutcomeStable` violated, as required |
| `AttachedDatagram.NoTag_bad.cfg` | 12 | 72 | 6 | 0.6 s | `HeldAreSenderBytes` violated, as required |
| `AttachedDatagram.NoTagEnd_bad.cfg` | 12 | 630 | 6 | 0.6 s | `NoNetworkIntegrity` violated, as required |
| `AttachedDatagram.NoTagSquat_bad.cfg` | 12 | 778 | 6 | 0.6 s | `AckMeansHeld` violated, as required |
| `AttachedDatagram.NoWindowBound_bad.cfg` | 12 | 2,969 | 9 | 0.6 s | `PNStateBound` violated, as required |
| `AttachedDatagram.SlideBeforeTag_bad.cfg` | 13 | 35 | 6 | 0.6 s | `WindowAfterTag` violated, as required |
| `AttachedDatagram.Abandoned_reach.cfg` | 12 | 507 | 6 | 0.5 s | Reached |
| `AttachedDatagram.Completed_reach.cfg` | 12 | 190,178 | 17 | 1.2 s | Reached |
| `AttachedDatagram.CompletedAfterAbandon_reach.cfg` | 12 | 274,805 | 18 | 1.5 s | Reached |
| `AttachedDatagram.Integrity_reach.cfg` | 12 | 684 | 6 | 0.5 s | Reached |
| `AttachedDatagram.ParentEnd_reach.cfg` | 12 | 166,154 | 17 | 1.1 s | Reached |
| `AttachedDatagram.Partial_reach.cfg` | 12 | 81 | 5 | 0.5 s | Reached |
| `AttachedDatagram.Refused_reach.cfg` | 12 | initial state | 1 | 0.5 s | Reached |
| `AttachedDatagram.ReplayAccepted_reach.cfg` | 13 | 437 | 6 | 0.5 s | Reached |
| `AttachedDatagram.Reset_reach.cfg` | 12 | 64 | 5 | 0.5 s | Reached |
| `AttachedDatagram.Resumed_reach.cfg` | 12 | 360 | 6 | 0.5 s | Reached |
| `AttachedDatagram.WindowPassed_reach.cfg` | 12 | 2,793 | 9 | 0.6 s | Reached |

What the raises show. Each raise of rule 4 passed, so no argued bound hid a failure at one step
larger. Two raises tested nothing: `Window3` had exactly the states of the main profile, and
`Cap3Window3` exactly the states of `Cap3`. Three limits set the datagrams in flight, the credit
(`Cap`), the spread bound (`Range`, reduction 3), and the congestion window (`Window`), and the
smallest one wins. At the declared bounds the window is never above two, and it only binds after
a loss halves it to one. So the raise of `Window` is `Cap3Range3Window3`, where each of the three
limits allows three in flight; it replaces the two profiles that tested nothing.

The raise of `Window` ran on the development host after the replacement, on 2026-11-08 from
08:13 to 08:17 UTC, when no other checker loaded the host:

- Command: `cargo xtask model attached-datagram/AttachedDatagram.Cap3Range3Window3.cfg`. Exit
  status 0.
- Source: the files of this directory at that earlier revision. The xtask printed
  `9735eb8c9abe241f9b1d91b12d0c98b2400b3abc (31 files)`, a Git object ID. From 2026-11-08 the
  xtask prints a SHA-256 digest from rscrypto instead, and the same 31 files give
  `sha256:55f1ef3fc57619676746967e800b52232b4eec299cfca8b9089aaf5e17c5a79a`.
- Checkers and flags as above. Host: macOS 26.6.2 arm64, 10 cores, 16 GB.
- Replay: `target/model/attached-datagram/AttachedDatagram.Cap3Range3Window3.cfg/checker.log`.

| Profile | Exit | Distinct states | Depth | Duration | Verdict |
| --- | --- | --- | --- | --- | --- |
| `AttachedDatagram.Cap3Range3Window3.cfg` (raise) | 0 | 12,415,204 | 29 | 248.9 s | Pass |

It has more states than `Cap3` (8,470,530), so the window binds there, and the raise tests it.
Each argued bound of that earlier model had its complete raise-by-one search. Those results do
not qualify the revised model.

The earlier records, of the design as first written (2026-11-06) and of the decision round
(2026-11-07), checked files that are now deleted; the [Decisions](#decisions) section keeps
their numbers.

[FP Design Models]: ../../../rsasync/docs/specs/family-policy.md#design-models
[NET Attached Channels]: ../../docs/specs/networking.md#attached-channels
