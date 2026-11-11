# Attached channel: datagram form

This is the design model of task N000. It checks the rules of attached datagram channels in
`docs/specs/networking.md`, through the decisions of 2026-11-11, before N603 fixes the wire
format. The [statechart](statechart.md) shows its control states.

**Status (2026-11-11): N000 is blocked; 33 of 43 profiles are complete.** All known-bad and
reachability profiles pass on the current source. `FaultySender` did not finish within its
one-hour cap; the other nine positive profiles did not start. No positive profile is qualified
on this revision. The [current evidence](#current-evidence) records the exact boundary. Earlier
results remain retained and are not counted as current passes.

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

7. After the receiver ends, a new `SendData` chooses only `good`. Keep every payload sent before
   that endpoint ended, including bad bytes. Project a behavior by changing only later log
   entries and their matching network copies to `good`. The receiver cannot reopen in any
   current variant. Delivery, replay, forgery, reads, and final-size arrival are then disabled.
   Remaining send admission, loss accounting, ACKs, outcomes, and path decisions use packet
   numbers and offsets, not those new payloads. The projected steps remain allowed, and every
   fair action keeps its enabledness and occurrences. In particular, a send remains a send for
   `NotResumed`; pending validation, late reset, and terminal notifications are unchanged.

   All current profiles that permit bad sender bytes retain tag checking. Each held byte has
   its unchanged pre-terminal log witness, so `HeldAreSenderBytes` is preserved. Other safety,
   action, progress, and reachability predicates ignore the projected payloads. The tag-bypass,
   reused-number, and late-reset canaries use an honest sender, so this change is their identity.
   A future profile that combines a faulty sender with tag bypass needs a new property argument.
   Among positive profiles, this removes payload choices only in `FaultySender` and `Excess2`;
   it does not help the honest-sender bound raises. It preserves every bound and removes no
   control step. Its state-count and timing effect remain unmeasured.

The model assumes the application's tag check, ideal GMAC below its failed-tag limit, and
protected parent frames. It does not prove cryptographic computation, nonce safety, wire parsing,
parent packet scheduling, recovery periods, or arbitrary-size buffers. N603 and N604 own the
wire and implementation evidence. It proves no Rust code.

## Recurrence form

The resumed source replaces `<>BothDone` and the pending-validation response formula with
these equivalent forms. This changes no behavior or property meaning:

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
The unconstrained fair-cycle argument for `OldPacketReuse.Spread_bad` in the evidence is unchanged;
`NoAckLoss` remains inactive on that cycle.

The pinned [TLC classifier](https://raw.githubusercontent.com/tlaplus/tlaplus/d8fb231de4e4/tlatools/org.lamport.tlatools/src/tlc2/tool/liveness/Liveness.java)
leaves the earlier eventuality and response forms for tableau construction. From that source,
the recurrence forms should use its direct classification without a tableau. This is
an inference, not a measured improvement. The ordinary
[graph index](https://raw.githubusercontent.com/tlaplus/tlaplus/d8fb231de4e4/tlatools/org.lamport.tlatools/src/tlc2/tool/liveness/NodePtrTable.java)
still grows on the Java heap. The current positive searches remain incomplete; no speedup or
completed positive result is claimed.

## Current evidence

Native run `20261111T175227Z-47948` used the final model and checker command. SANY parsed both
modules. All 33 small profiles reported their required named violations; their checker times
sum to 25.418382 seconds. The first positive profile, `FaultySender`, reached the command cap.
No further experiment is part of this attempt.

| Check | Result | Exit and duration |
| --- | --- | --- |
| SANY: both modules | Pass | 0; 0.264015 seconds |
| All 33 `_bad` and `_reach` profiles | Required violation or target reached | Each 12 or 13; 25.418382 seconds total |
| `FaultySender` | Incomplete; no native final verdict | Supervisor 137 after the 3,600-second cap and 30-second kill grace |
| Other nine positive profiles | Not started | No result |

The open profiles are the base, `NoOnPath`, `FaultySender`, `MaxPN7`, `Cap3Range3Window3`,
`Bytes5`, `Paths3`, `Excess2`, `Cap3`, and `Range3`. The retained `FaultySender` manifest ends at
`state=started`: it has no native final exit or verdict. Supervisor exit 137 is not a checker
verdict. Its last checkpoint, at 19:02:36 UTC, reported 1,100,132,530 generated states,
308,276,384 distinct states, 11,736,258 queued states, and depth 31. The queue was not empty.

The host was a dedicated c8g.4xlarge with 16 vCPUs and 32 GiB, Linux 7.0.0-1016-aws arm64.
The native command used `--tlc-heap-mib=20480 --tlc-fp-mib=4096`, 16 TLC workers,
`OffHeapDiskFPSet`, and `DiskStateQueue`. Every TLC invocation included
`-XX:+UseParallelGC -XX:+ExitOnOutOfMemoryError -Xmx20480m -XX:MaxDirectMemorySize=4096m`
and retained its full `gc.log`. The complete faulty-sender GC log has no OOM or `System.gc()`
marker; its two full collections have cause `Ergonomics`, lasting 549.568 and 273.066 ms.
The time cap, not an observed allocation failure, ended this attempt.

The fixed OOM exit option prevents the pinned
[liveness index](https://raw.githubusercontent.com/tlaplus/tlaplus/d8fb231de4e4/tlatools/org.lamport.tlatools/src/tlc2/tool/liveness/NodePtrTable.java)
from retrying with mismatched key and pointer arrays after its second allocation fails. The
selected JDK exits with status 3 before that Java handler can recover. Such an exit is incomplete.

- Model digest: `sha256:1c1362c59b0ca8d652c6c0a4cdde37392672e60799ef5e6fab639ebe8dd41728`
  (45 files). The source is based on `6d996d9` with the recurrence and payload projections.
- `AttachedDatagram.tla` SHA-256:
  `705f4aa368c3a9eaab8cb10951a8c5586d0892860eac5153b01c9755771b7352`.
- Runner source SHA-256: `xtask/src/main.rs`
  `0374968811a54c712a00764bb5e6b06ba52481b17703834540116d19ad3f9cab`;
  `xtask/src/evidence.rs` `fe7b5c908f856a568fce731b9c8ae14d503004c64add7f734906b20054de0960`.
  Native executable digest: `db6b85d5c3fd036a6e8707fd34d9f506946580b8046068068981a0dd4eb35913`.
- Tools: Temurin 21.0.13+9, TLC 1.8.0+d8fb231de4e4. Each `run.txt` retains the tool identities,
  exact JVM command, source closure, and output. Apalache 0.62.4 was present but not used.
- The runner passed scoped fix/check and all 13 tests, with 0 skipped, before the native run.
  Nextest run: `c6981ba7-6d75-43dc-9a94-c8df65211f06`.

All 34 retained native profile closures match the current inputs. The exact per-profile
closure, named property, original exit, duration, and result are in
`target/model/attached-datagram-evidence-index.json` and `attached-datagram-evidence-status.tsv`.
SANY is in `target/model/attached-datagram/sany/1794419733-15824/`; the incomplete profile is in
`target/model/attached-datagram/AttachedDatagram.FaultySender.cfg/1794420213041422967-21107/`.

The current `OldPacketReuse.Spread_bad` run is `1794420198936226333-20932`. Its cycle resends
PN 1, discards it because `1 + Range = rHigh = 3`, and declares it lost. `ack = {}` throughout,
so `NoAckLoss` excludes no cycle step. The original fair actions recur or are disabled; `Read`
is disabled at the missing byte. The path stays stable and both endpoints stay open. Thus the
trace is also an unconstrained `ReuseSpec` behavior that violates `Progress`. Its run retains
the independently checked `fairness-audit.txt` and trace.

The native archive is
`target/model/remote-n000-20261111T175227Z-47948/node-1-artifacts.tar.gz`, SHA-256
`c221eda73d730aee609fa14bde09acddcd81c9655abaaf9192642c0d86cd4253`.
Collection and teardown both exited 0; fresh native status confirmed no instance or EBS volume.

## Retained history

The maintainer retains every prior result and stopped attempt. Each native archive below is
`target/model/remote-n000-<run>/node-1-artifacts.tar.gz`; earlier positive results do not qualify
the current module.

| Earlier native run | Boundary | Archive SHA-256 |
| --- | --- | --- |
| `20261111T084109Z-31147` | Earlier base and `NoOnPath` passed; default-memory `FaultySender` interrupted | `a8164f1cad11507cf17bccac7dc98b2a1941c8e8c506228a418fbfbed430f753` |
| `20261111T101323Z-27234` | 8 GiB heap / 8 GiB fingerprints; resource stall repeated | `f5c5c2b2c3fc0f7c11f083d90533992be4fa771ece49323790e915d9d16f91d8` |
| `20261111T165647Z-12282` | Recurrence form; stopped before the next index allocation exceeded the 8 GiB heap | `d068828ac4a7cc15ce07e5509426d3d1a6c994df199c7e9c6b4854a56adbe105` |

The combined closeout archive is
`~/.local/state/model-evidence/rsnetwork/N000/20261111-final-network-model-evidence.tar.gz`,
with a duplicate in the maintainer checkout's `target/model/` and an adjacent `.sha256` receipt.
It retains both checkouts' model evidence, exact source copies, native recipes and audits, the
prior durable archive, and `final-review-20261111.md`. Only TLC state caches are omitted.
The complete earlier README, including failed-attempt narratives and old verdict tables, is at
`worktree-target-model/n000-closeout-2026-11-11/before-closeout/models/attached-datagram/README.md`
inside that archive. These records preserve history without turning an incomplete run into a pass.

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
