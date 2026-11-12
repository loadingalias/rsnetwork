# Attached channel: datagram form

This is the design model of task N000. It checks the rules of attached datagram channels in
`docs/specs/networking.md`, through the decisions of 2026-11-11, before N603 fixes the wire
format. The [statechart](statechart.md) shows its control states.

**Status (2026-11-12 UTC): all 43 declared profiles passed.**
All 33 known-bad and reachability profiles gave their required violations. All ten positive
profiles completed the state search and final temporal check within their original one-hour
caps. The [state view](#state-view) merges retired sender-ledger histories and omits
[payload distinctions](#retired-payloads) and [ACK identities](#retired-ack-history) that cannot
affect a later step. Ordinary actions, weak fairness, properties, and bounds stay unchanged.
The [evidence record](#current-evidence) keeps the complete results and earlier incomplete attempts.

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

## State view

Every configuration selects `VIEW StateView`. The view changes the state identity that TLC
stores; it changes no action, guard, fairness condition, property, or bound. It uses no
`SYMMETRY`, state constraint, or action constraint. The
[pinned state implementation](https://raw.githubusercontent.com/tlaplus/tlaplus/d8fb231de4e4/tlatools/org.lamport.tlatools/src/tlc2/tool/TLCStateMut.java)
computes fingerprints from the view. The
[pinned liveness implementation](https://raw.githubusercontent.com/tlaplus/tlaplus/d8fb231de4e4/tlatools/org.lamport.tlatools/src/tlc2/tool/liveness/LiveCheck.java)
evaluates state and action conditions on the actual states and stores their results with the
fingerprints. Therefore, equal views must have the same observed conditions and the same
successor views with the same action observations. A smaller fingerprint alone is not evidence.

The previous search retained the full offset and payload of every sent packet at every later
state. Old packet permutations remained distinct even when no future action could use the
mapping. Fully terminal states also retained each data history. `StateView` has two cases.

### An endpoint is open

`OpenView` retains endpoint, path, final-size, credit, buffer, read, and replay-window state.
It retains the log length and these history and network summaries:

| Value | Use |
| --- | --- |
| Log entries in `LiveLogPNs` | Every packet in `Flight`, and each unaccepted packet at or above the replay floor |
| `SentHistoryView` | Sent offsets; full payload pairs in the two forgery variants |
| `AckedOffsets` | Send admission, `AllAcked`, `ParentEnd`, and `AckMeansHeld` |
| `OffsetsOf(ack)` and `OffsetsOf(rAck)` | The offsets that a pending or replacement ACK will add |
| `SenderLedgerView` | `Flight` and the exact combined loss/excess charge; the full ledger in `ReusePN` |
| `AckHistoryView` | ACK membership in `Flight`, pending-ACK presence, and the passed-window witness; full sets in the four variants below |
| Every packet number in `net` | The enabled delivery and loss steps, including stale copies |

A network entry is always the sole copy for its packet number, has connection ID 1, and has
the offset and payload in `sLog`. `Init`, `SendData`, and `ResendSamePN` establish this fact;
other actions only remove network entries. Thus its remaining fields add no independent state.

An omitted log entry is outside `Flight` and is either accepted or below the replay floor.
An accepted number stays in `rWin` while it is inside the floor. Once outside, it cannot become
fresh because the floor cannot move down. A normal packet number never returns to `Flight`
after acknowledgement or loss. The `ReusePN` and `NoWindowBound` variants keep every log entry
because they can revive old entries. This exception keeps the information their faulty
transitions need; it changes no variant.

This also holds in `NoTag` and `SlideBeforeTag`. Every accepted number is at most `rHigh`, so
a failed tag at an omitted number cannot slide the window. Packet-number squatting can accept
a number before the sender uses it. When the sender later appends that number, the retained
packet-number sets and offset summaries determine its effect on ACK processing. An entry still
in `Flight` is never omitted: send admission and loss accounting still need its offset.

For two reachable states with equal open views, the following correspondence holds:

- `SendData` uses the retained flight entries, credit, window, acknowledged offsets, and sent
  entries. It appends the same choice at the same new number. All summaries then have the same
  updates. `ResendSamePN` has the complete log.
- `Deliver` and `Replay` use a retained entry when a packet can pass the window. A removed
  entry always fails the window; its arrival only removes that network number, or stutters for
  replay. `Forge` at such a number cannot slide the window either. A tag comparison can differ
  there, but both branches leave receive state unchanged. Current log entries and the full
  `SentEntries` retained in both forgery variants determine every other tag and forgery result.
- `Lose` has the same receive effect, packet removal, and fault charge. `Doomed`, `DeclareLost`,
  and `Spent` use the retained flight, ACK and network numbers and the combined charge below.
  Their guards and results are the same. Live packet numbers remain visible after old history
  is omitted.
- `DeliverAck` adds `OffsetsOf(ack)` to the acknowledged offsets. A new receive replaces the
  ACK with `rAck` plus its newly accepted number; `OffsetsOf(rAck)` determines that update.
  ACK membership in `Flight` stays exact. The four exceptions below keep full sets,
  including unsent numbers in `NoTag`.
- Reads, credit, final size, completion, notification, reset, parent failure, and migration
  use retained values. `HeldAreSenderBytes` uses full `SentEntries` in `NoTag` and has an
  inductive true value in the reduced variants, as shown below. The other safety and state
  targets use retained values or summaries. These values and the inductive typing facts also
  determine `TypeOK`.

#### Sender ledger

Except in `ReusePN`, `SenderLedgerView` keeps `Flight` and the count
`B = Cardinality(sLost \cup JunkPNs)`. It omits which retired packet numbers are acknowledged,
lost, or both. The preceding view kept these histories even when they had the same future
effects. The reduction keeps the original sets in the model; it changes only their fingerprint.

The following facts hold initially and each action preserves them:

- `sLost \subseteq LogPNs` and `sAcked \subseteq PNs`. Only `DeclareLost` adds to `sLost`,
  and its number is in `Flight`. Only `DeliverAck` adds to `sAcked`, from `ack \subseteq PNs`.
  Log growth preserves earlier numbers; `ResendSamePN` only removes a lost number.
- While `sEnd = "open"`, `sAcked \subseteq LogPNs`. A `DeliverAck` with any unsent number
  ends that sender with `integrity`. No action reopens it. Thus a new `SendData` number is in
  neither sender set, including in `NoTag`.
- `Flight` is disjoint from `sLost`. Each flight entry remains in the retained live log, so
  its excess-byte status is known. Therefore the following identity is exact:

```tla
Spent = B + Cardinality({p \in Flight : Doomed(p) /\ sLog[p].off < Bytes})
```

The guards and updates follow from these facts:

| Action | Sender-ledger effect outside `ReusePN` |
| --- | --- |
| `SendData(o)` | Add the next number to `Flight`; increase `B` by one exactly when `o >= Bytes` |
| `DeclareLost(p)` | Remove `p` from `Flight`; increase `B` by one exactly when its offset is below `Bytes` |
| `DeliverAck` | Remove `ack` from `Flight`; union `OffsetsOf(ack)` into `AckedOffsets`; keep `B` |
| Every other action | Keep `Flight`, `B`, and `AckedOffsets` |

`DeclareLost` cannot count a prior loss twice because its number is in `Flight`. An excess
packet is already in the union counted by `B`, so declaring it lost adds no charge. New packet
numbers are outside both that union and `sAcked`. `Doomed` still sees exact flight, receiver-ACK,
pending-ACK, and network membership. The identity above thus preserves each `Spent' <= Budget`
guard, including ACK loss and an early declaration. `LoseAck` also tests `ack \ sAcked` through
`CountFault`, but that argument affects a transition only in `ReusePN`; otherwise `faults`
stays unchanged.

In `NoTag`, packet-number squatting can put an unsent number in `rAck` or `ack`. Both sets stay
exact. Sending that number before its ACK arrives puts it in `Flight` as usual, and the retained
offset summaries update from the new log entry. Processing its ACK while it is still unsent
ends the sender, exactly as before. Hidden unsent members of `sAcked` can then neither affect a
new send nor be made sent later. A following ACK is disabled. Receiver actions and terminal
notification use the retained state. This covers both orders of squatting and ACK arrival.

`ReusePN` keeps `sAcked`, `sLost`, and `JunkPNs` exactly. Its resend can remove a lost number
and return it to `Flight`, and `CountFault` observes acknowledged identity. Its current full-log
view and both reused-number counterexamples are unchanged by this ledger reduction.

For equal open views, the table gives matching transitions in both directions with the same
next view. Fair loss declarations remove a visible flight number; ACK arrival clears a visible
nonempty `ack`; sending changes the log length. None of these steps becomes a view self-loop.
Their original action predicates and the other fair actions keep their enabledness and
occurrences. No action changes only an omitted sender-ledger value.

The action witnesses keep their observations: `NotLastAckLost` uses exact `ack \cap Flight`;
`NotResumed` uses the same send guard; replay acceptance and window movement use the retained receiver observations described
below; migration and abandonment use exact path state; final-size discard and notification use
exact buffer, control, and endpoint state. `NotWindowPassed` remains an explicit observation. `NoAckLoss` and all original action/property definitions stay unchanged. The
ledger reduction therefore preserves the earlier fairness and terminal-view argument below,
including the safety labels and ACK-loss observations on a transition into `ClosedView`.

#### Retired payloads

`SentHistoryView` keeps full `SentEntries` for `NoTag` and `SlideBeforeTag`. In every other
variant it keeps only `{sLog[p].off : p \in LogPNs}`. The earlier view distinguished a past
good payload from a past bad payload even after neither could affect a later receive.
The source log, all actions, ordinary `WF_vars` clauses, and invariant checks stay unchanged.

These are all uses of a historical payload:

- `SeenGood(o)` controls `Forge` in both forgery variants. They retain the full pair set, so
  every forgery keeps its original guard and result. `NoTagSquat` keeps the same false ACK claim.
- `Authentic` and `Replay` use full entries while a packet can be accepted. Every such entry
  remains in `LiveLogPNs`. An omitted entry is accepted or below the monotone replay floor and
  cannot become fresh. Its delivery or replay still discards, with the same network removal
  or stutter. `ReusePN` and `NoWindowBound` retain the complete log, so the pair set can already
  be reconstructed there. The reused-number counterexamples lose no information.
- `HeldAreSenderBytes` has the true value by the following direct initial/step argument in
  every reduced variant. This is not an assumed safety result.

Initially no byte is held. `Accept` can write a new held byte only after `Tagged` passes.
Outside `NoTag`, this requires `Authentic`, which supplies the exact offset/payload witness
in `sLog`. An existing held byte stays unchanged. `Read` and final-size arrival remove or
preserve held bytes, including in `FinalKeepsJunk` and `NoFinalIntegrity`. Other actions preserve
the buffer. `SendData` only appends, and no action changes an earlier log entry. Thus every
held byte keeps its immutable witness. The original invariant still runs; no Boolean substitute
replaces it. `NoTag` retains the full evidence and can still violate it.

`Sent(o)` uses only offsets and is determined exactly by the new set. A send adds its offset
to that set and appends the same payload choice to the live log. Other admission tests and
fault charges use the retained live entries, receiver/ACK numbers, offset summaries, and exact
ledger charge. Every subsequent loss, ACK, read, control, outcome, and path transition has the
same enabledness and destination view. Retiring an entry can omit its payload, but it never
changes the sent-offset set. The earlier matching-transition argument therefore holds in both
directions with this smaller history.

For a concrete pair in `FaultySender`, send a good PN 1 at offset 0, deliver it, and read it.
Lose its ACK and declare the doomed PN 1 lost. Retry offset 0 as PN 2, once with `good` and
once with `bad`. Deliver PN 2 below `rRead = 1`, then deliver the replacement ACK. Both states
have open endpoints, log length 2, empty network and flight, `sLost = {1}`,
`sAcked = rAck = {1, 2}`, empty `ack`, `rHigh = 2`, `rWin = {1, 2}`, an empty buffer,
and burned charge 1. Both accepted entries are outside `LiveLogPNs`. The old pair sets differ,
but both sent-offset sets are `{0}` and every future behavior matches. No assumption restricts
the faulty sender to good bytes.

Every fair action still changes a retained observation: send changes log length, delivery
removes a network PN, declaration changes flight, ACK arrival clears `ack`, and read, credit,
outcome, final-size, and validation steps change their original visible values. None changes
only retired payload history. All action witnesses therefore keep their occurrences. Stale
replays remain optional stutters; they cannot replace a fair action. `NoAckLoss` applies only to
the full-log `ReusePN` variant. `ClosedView` and its safety/ACK-loss observations are unchanged,
including on transitions from these equal open views. Matching successors and fair occurrences
preserve both finite observations and infinite fair behaviors.

#### Retired ACK history

`AckHistoryView` keeps full `rAck` and `ack` in `NoTag`, `SlideBeforeTag`, `ReusePN`, and
`NoWindowBound`. Every other variant keeps `rAck \cap Flight`, `ack \cap Flight`, whether
`ack` is nonempty, and `NotWindowPassed`. The original sets stay in the model; only their
fingerprints change. The replay window and both ACK offset summaries remain in `OpenView`.

The following facts follow directly from `Init` and the actions:

- `ack` is empty or exactly `rAck`. Only `Accept` adds a receiver ACK; `Receive` then replaces
  `ack` with the new `rAck`. `DeliverAck` and `LoseAck` clear it. All other actions preserve it.
- Outside the four exceptions, acceptance requires `Authentic`. Thus `rAck` is a subset of
  `LogPNs`, each member is at most `rHigh`, and `rHigh <= Len(sLog)`. Acceptance adds a sent
  number and takes the maximum high point; other actions cannot invalidate these facts.
- `rWin` is exactly the accepted numbers above the monotone replay floor. `Accept` preserves
  this equality by union and filtering. A below-floor number can never be accepted later.

These are transition inductions, not assumed positive results. Above the floor, `rWin`
determines accepted membership. Below it, `Doomed` needs membership only for `Flight`, which
is retained. Thus `LiveLogPNs` is also determined: its non-flight part is the above-floor
logged numbers outside `rWin`. The original log/offset and ledger correspondence still holds.

The actions have matching results:

| Actions | Retained information and update |
| --- | --- |
| `SendData` | The same live entries, offsets, credit, window and budget admit the same append. Its new number is beyond every old receiver ACK. |
| `Deliver`, `Replay` | A possible acceptance uses the same live entry, window, credit and buffer. It adds the same number to the window and live ACK projection, adds the same offset, and replaces the pending-ACK projections with those of `rAck`. A below-floor delivery removes the same network number. |
| `Lose`, `DeclareLost` | The same flight membership, network numbers, live ACK membership and burned count give the same `Doomed`, post-budget and congestion updates. |
| `DeliverAck` | The nonempty flag enables it. Remove exactly `ack \cap Flight` from flight, union `OffsetsOf(ack)` into acknowledged offsets, and clear the pending projections. Unsent-ACK integrity is impossible by the subset induction; `NoTag` keeps full sets. |
| `LoseAck` | Clear the same pending projections and test the same resulting doomed-flight charge. `CountFault` observes ACK identity only in `ReusePN`, which keeps full sets. |
| Other actions | Read, credit, final size, outcome and path actions use the same retained values. They do not add or remove ACK membership. `Forge` and `ResendSamePN` are disabled in reduced variants. |

Replay of a retired number can be enabled in only one representative if the other accepted
it earlier. Such a difference is below the floor: the replay is a full-state stutter. It has
no fairness, and `[Next]_vars` already permits the matching stutter. It cannot replace a fair
occurrence. Both forgery variants and both variants that can revive old entries keep full sets.

`NotWindowPassed` becomes permanently false after a missing number falls below the floor:
`rHigh` cannot decrease, and that number cannot be accepted. If the observation is still true
when the high point increases, every newly crossed logged number was above the old floor,
where `rWin` determines its prior accepted membership. The new accepted high number is not
below its own floor. These facts determine the next observation. Appending a new number cannot
create a below-floor hole because `rHigh` is at most the previous log length.

`TypeOK`'s omitted ACK-set clauses follow the set inductions above; its other inputs remain
determined. `WindowAfterTag` has the true value by the same direct action argument: only an
acceptance raises `rHigh`, and its new high number exceeds every old `rAck` member. The original
invariant and action property still run. `NeverReplayAccepted` agrees for every above-floor
number; below the floor a replay never changes `rAck`, so that witness is false even if the
optional stutter is absent. `NotLastAckLost` uses the exact retained `ack \cap Flight` and
matching `LoseAck`. All other witnesses use the retained fields or matching actions already
described. `NoAckLoss` applies only to `ReusePN`, whose sets stay exact.

Every fair enabledness and nonstuttering occurrence is preserved. Send changes length,
delivery changes network numbers, declaration changes flight, ACK arrival clears a true flag,
and credit, read, final-size, outcome and validation change their retained values. Read's
conditional fairness in `Progress` keeps the same buffer/read/end inputs and result.
`ClosedView` is unchanged. Its safety observations and passed-window bit are determined as
above. Its `ENABLED LoseAck` is determined by ACK presence, live memberships, network numbers,
live entries and burned charge; its `ack \cap Flight` bit is explicit. This also proves the
correspondence on entry to a terminal view.

A concrete pair fits `FaultySender`'s existing bounds. Use good bytes. Both branches send PN 1
at offset 0, lose it, and declare it lost. Send PN 2 at offset 0. Branch A accepts and reads
it, loses its ACK, then declares it lost. Branch B loses PN 2 and declares it lost. Both send
and accept PN 3 at offset 0; B reads it, while A already did. Both process the ACK and
`DeliverCredit(3)`. Both send, accept, read and acknowledge PN 4 at offset 1, then
`DeliverCredit(4)`. Both do the same for PN 5 at offset 2, then `DeliverCredit(5)`.

Both states have the same log of length 5, `sLost = {1, 2}`, burned charge 2, empty flight,
network, buffer and pending ACK, read point 3, high point 5, window `{4, 5}`, congestion window
1, both credits 5, and sent and ACK offset summaries `{0, 1, 2}`. `NotWindowPassed` is false
in both because PN 1 was never accepted. A has `rAck = {2, 3, 4, 5}`, B has `{3, 4, 5}`;
`sAcked` differs in the same way, which the ledger view already omits. Their obsolete PN 2
acceptance identities now have equal views. All steps fit the original packet and fault bounds.

#### Type and action observations

`OpenView` does not compute `TypeOK` again for fingerprinting. Equal open views already agree
on it. Endpoint, path, final-size, credit, buffer, replay-window, read, and fault values
keep their type inputs directly. The ACK-set typing follows the preceding transition induction. `Len(sLog)` retains the log-length bound. Log entry typing follows
from `Init` and `SendData`: every append selects a wire offset and an allowed payload, and no
action changes an earlier entry. This also covers omitted retired payloads. By the network/log
fact above, every network entry has connection ID 1 and the log's offset and payload at its
packet number, so network typing follows too. The omitted sender-set type clauses hold by the
initial/step argument
above; they are not an assumed positive result. `ReusePN` retains those sets directly.
Finally, the retained endpoint values and the exact `Spent` identity determine the budget clause.

Omitting the repeated type calculation adds no further state merging. Every positive
profile still checks the original `TypeOK` invariant, and `ClosedView` still stores its type
observation. The previous view evaluated the full type and budget predicate for each generated
successor, then checked it again when the checker found a new state. The 35-minute sample had
about seven generated successors for each new state. Removing this repeated computation changes
no bound, transition, property, or observed result.

Each transition therefore has a matching transition with the same next view. This applies in
both directions. No fair action that changes the state becomes a view self-loop: a send changes
the length; a delivery removes a number or changes receive state; a loss declaration removes
a flight number; ACK arrival clears `ack`; credit, read, completion, notification, final size, and
validation each change a retained value. A stale replay matches a permitted stuttering step in the other state; it cannot replace
a fair delivery. Keeping every network number is
necessary here: removing a finite set of stale deliveries could otherwise create such a loop.

### Both endpoints have ended

An endpoint never reopens, including in `LateReset`. Only `Validated`, `Abandon`, `ParentEnd`,
`LoseAck`, and the `LateReset` action can still change state; `Done` can stutter. `ClosedView`
retains the endpoints, parent lifetime, path and candidate, validation kind, final-size flag,
and read point. It keeps each fixed data-safety predicate and the passed-window target.
Completion, integrity, and endpoint targets can then be computed from the retained values.

The only fair action still enabled is `Validated \/ Abandon`. Its enabledness, occurrence,
and destination view are unchanged. Its success and abandon still differ in `path` and
`tried`, so the abandonment observations remain. Parent failure retains its lifetime change.
`LateReset` retains its endpoint change and still violates `OutcomeStable`. `Progress` is
already true throughout this suffix. `ValidationEnds` still sees the full pending attempt.

`ClosedView` also keeps `ENABLED LoseAck` and whether `ack` intersects `Flight`. A permitted
loss clears `ack`, so the next view has both observations false. Other remaining steps can
only disable that loss by ending the parent; none can enable it. Thus the optional loss and
the `NotLastAckLost` action target keep their exact edge, without a spurious repeatable loss.
The fixed data predicates do not change on these steps; `TypeOK` remains unchanged because a
loss still applies `CountFault` and its original budget guard. Every other action target is
disabled after both endpoints end. The same successor-view and action-observation argument
therefore holds in the terminal phase and at the transition into it.

The correspondence preserves every declared safety and temporal property and every witness.
It preserves both enabledness and occurrence for all specification fairness and for the
consumer fairness in `Progress`. Consequently a fair cycle in either state representation
has a matching fair behavior in the other. All 33 known-bad and reachability profiles use the
view; they must still give their named results before the ten positive profiles qualify it.
In particular, `NoAckRecovery`, `NoFinalNotice`, `NoAbandon`, `LateReset`, and the final-size
variants retain their failures in the reduced phases. The declared and raised bounds are
unchanged.

## Recurrence form

The source replaces `<>BothDone` and the pending-validation response formula with these
equivalent recurrence semantics:

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
still grows on the Java heap. The complete positive results below qualify the current recurrence
form and state view together. They do not measure the effect of the recurrence change alone.

## Current evidence

The checked source is signed-off commit `e8a44d6cca08edf84f436416178e3fa6276b4e82`, with
model digest `sha256:c2f66810c5ab151205b2027bf795c0c4f267e4f324a24ab8ca9b54f16fbc14e2`
(45 files). Both modules passed SANY in 1.602129 seconds on that exact source and the pinned
tools. Independent source review cleared the transition, property, and fairness correspondence.
The ordinary actions and `WF_vars` clauses match the sender-ledger revision; only the exact
history views change its state representation.

Native run `20261112T053138Z-90307` kept the source fixed. It used one 16-vCPU, 32-GiB host
with an 80-GB disk, a 20-GiB Java heap, and 4-GiB fingerprint storage. The tools were JRE
`21.0.13+9`, TLC `1.8.0+d8fb231de4e4`, and Apalache `0.62.4`; TLC ran each profile.
All 33 known-bad and reachability profiles gave their required named violations once, in
29.061521 seconds of native checker time and 45.224359 seconds for the batch. The independent
review retained their traces, including both reused-number cycles and the `NoAckLoss` constraint.

All ten positives completed safety and final liveness, with no violation, an empty queue, and
native and supervisor exit 0. Each kept its original 3,600-second cap. The table includes final
temporal checking in the native time; the last column also shows that phase separately.

| Profile | Native seconds | Distinct states | Final temporal check |
| --- | ---: | ---: | ---: |
| `AttachedDatagram.cfg` | 285.241546 | 2,479,329 | 38 s |
| `NoOnPath` | 208.432595 | 1,859,449 | 28 s |
| `FaultySender` | 1568.354800 | 13,254,513 | 3 min 21 s |
| `MaxPN7` | 2153.364882 | 15,527,777 | 4 min 16 s |
| `Cap3Range3Window3` | 3195.420733 | 25,026,209 | 7 min 13 s |
| `Bytes5` | 485.218687 | 3,818,177 | 1 min 00 s |
| `Paths3` | 767.515523 | 6,508,309 | 1 min 38 s |
| `Excess2` | 1671.413264 | 13,873,369 | 3 min 30 s |
| `Cap3` | 871.090663 | 7,597,569 | 1 min 51 s |
| `Range3` | 580.792171 | 4,867,377 | 1 min 15 s |

The 43 native checks took 11,815.906385 seconds in total. This is a complete bounded model
result, with the assumptions and reductions above; it proves no Rust implementation.
The positive searches ran once, sequentially. No source or bound changed during the matrix.
The same-run sizing records keep the initial estimates and the decisions to continue. In the
combined raised profile, the estimates exceeded the actual search time; its original cap stayed
in force through the complete temporal verdict.

`target/model/attached-datagram-evidence-index.json` records all 43 profile identities,
configurations, source closures, tool hashes, native verdicts and times, and required trace hashes.
The adjacent `attached-datagram-evidence-status.tsv` is its compact table. Exact commands, source
copies, checker output, GC logs, and lifecycle records are in
`target/model/remote-n000-20261112T053138Z-90307/`. Its native archive has SHA-256
`75fc67a09cee2d44c1773a82ff49eac5bba89e3e19f50bbf4b71baed4de781b3`.
Collection and teardown returned 0. No checker was left running at completion, and the native
status command confirmed no AWS instance or EBS volume. The final index links that cleanup record.

The durable final archive is
`/Users/mr.wolf/.local/state/model-evidence/rsnetwork/N000/20261112-retired-history-network-model-evidence.tar.gz`.
Its adjacent `.sha256`, `.inventory.json`, and `.receipt.json` files record the archive checksum,
payload hashes, final source commit, and verified copies. The worktree-relative evidence paths
above survive under `worktree-target-model/` in that archive. Its `source/` directory contains
all 66 files of the reviewed final source.

This was the third and last cause-based implementation attempt in this continuation.
The earlier two attempts below remain incomplete at their own source closures. Their records,
source, CPU sample, reviews, and cleanup evidence remain retained with the completed matrix.

### Retained enabledness result

The second attempt is commit `590d09946da461e757d2c294147ac5fce3bceb19`, model digest
`sha256:e3c18e38323b6ef78f91c4377b8e2cdea96a147556ea30bf899fca3b68f0d3fc` (45 files).
It derived exact enabled-state predicates beside the actions and used an equivalent weak-fairness
formula. Independent review cleared the action, fairness, and pinned-tool correspondence.
The initial formula failed SANY's action syntax rule; the corrected recurrence form passed both
modules in 0.561904 seconds. Both syntax records are retained.

Native run `20261112T045122Z-74483` kept that corrected source fixed. All 33 bad/reach profiles
gave their required violations once: 28.129050 seconds of native checker time, 43.556868 seconds
for the batch, exit 0. Independent review checked all required progress/stall traces, the
unconstrained and `NoAckLoss` reused-number cycles, and `NoTagSquat`.

The ordinary `FaultySender` command began at 04:59:55 UTC with its original one-hour cap.
No standalone diagnostic was repeated. At 05:10:12, ten minutes into the checker, it had
60,004,992 generated states, 9,611,071 distinct states, 2,280,898 queued states, and depth 21.
Recent processing was 694,427 states per minute, only 1.68% above the first attempt. Two
graph-only fits gave 63.9 and 85.8 minutes; the shortest fitting window had no future drain root.
This did not support graph search plus final temporal checking within the cap.

The owned supervisor received SIGINT at 05:11:10.845 and exited 137 after its 30-second grace.
The last record at 05:11:12 has 65,595,698 generated states, 10,363,751 distinct states,
2,320,903 queued states, and depth 21. The native manifest remains `state=started`, with no
violation, OOM, full GC, or final temporal verdict. The other nine positives did not start.
The small measured gain did not justify the added enabledness code and proof obligations.
The current source restores the ordinary actions and `WF_vars` clauses from the first attempt.
The signed commit and its complete evidence remain retained.

Collection and teardown returned 0, and native status confirmed no instance or EBS volume.
The archive `~/.local/state/model-evidence/rsnetwork/N000/20261112-enabled-attempt2-evidence.tar.gz`
has SHA-256 `ee49060c2f61f5faa2d86263b5c536ec1ee88aab08a412a262062c502081afe8`.
Its 137 payloads retain the native output, exact source, syntax records, review, recipes,
sizing, and the next quotient argument. Both archive copies were hash-checked.

### Retained sender-ledger result

The first attempt in this continuation is commit `61ed5c0372aaaf90c74de0b81e40d9b11fc9367c`,
model digest `sha256:2d3ce4efd05a946b964df0b287822de0c8c516d23b34abdc9ae0f6a416ba702a`
(45 files). Native run `20261112T040532Z-98087` kept those inputs fixed. Local SANY passed for
both modules in 0.502338 seconds. The independent reviewer ran all 33 bad/reach profiles once:
each gave its required violation, with 27.355 seconds of native checker time and 43.570 seconds
for the batch. The reviewer checked the four progress cycles and the `NoTagSquat` fault.

A separate 150-second diagnostic ran the same `FaultySender` obligations with coverage counters
and a 120-second CPU recording. It stopped with native status 130 after 150.264 seconds, with
no final verdict. Coverage counts evaluations, not CPU time. Of 55,158 Java samples, 13,779
(24.98%) have a visible `LNStateEnabled` caller; 522 of those overlap coverage bookkeeping.
The samples show successor construction, unchanged-variable checks, and context lookup under
that caller. They do not identify an individual fair action. Some stacks are truncated, the
instrumentation adds cost, and no final temporal-cycle check occurred. This supports the
enabledness correction tried in the second attempt; it does not establish its speedup or a positive result.

The ordinary command began at 04:19:22 UTC, without diagnostic flags. At ten minutes it had
9,473,224 distinct states and 2,257,864 queued states. At the next sizing decision, the
13-minute record had 11,740,706 distinct states and 2,567,135 queued states; recent processing
was 653,781 states per minute. Queue fits estimated 62.6–70.9 minutes for graph search alone.
These estimates were unstable but did not support the one-hour cap including final temporal
checking. The owned supervisor received SIGINT at 04:34:11 and exited 137 after its existing
30-second grace. This was an early stop, not a completed search or a native verdict.

The last TLC record, during that grace at 04:34:39, has 85,203,034 generated states,
13,137,938 distinct states, 2,635,208 queued states, and depth 22. The native manifest remains
`state=started`. No full GC, OOM, violation, or final temporal verdict appears. The other nine
positives did not start. All ten positive obligations remain open.

The host, memory sizes, worker count, runner, and pinned tools are the same as the retained
state-view run below. Collection and teardown both returned 0; native status confirmed no
instance or EBS volume. The archive
`~/.local/state/model-evidence/rsnetwork/N000/20261112-ledger-attempt1-evidence.tar.gz`
has SHA-256 `f330cd7bba069e0a7bcfff35bb04aaee25bbec36cc84cb02e9ad9712ce85db8e`.
It retains the native archive, source commit, SANY, independent review, CPU recording and
attribution, recipes, sizing, and the proposed correction. Its 68 payloads and the copy under
`target/model/` were hash-checked. The preceding durable archives remain unchanged.

### Retained state-view result

Native run `20261112T012118Z-28397` checked the final state view at model digest
`sha256:d4103a23e1a548792ac2d74c34353257614a5ef3dbbb60327c50a772c6584b82` (45 files).
`AttachedDatagram.tla` has SHA-256
`2516e452767add30b7d10dbe744af3c5579d17c24662526b1784cdcbc004d654`. Source files stayed fixed
throughout the checks. All times in this record are UTC.

| Check | Result | Exit and duration |
| --- | --- | --- |
| SANY: both modules | Pass | 0; 0.264140 seconds |
| All 33 `_bad` and `_reach` profiles | Required named violation or target reached | Each 12 or 13; 30.012546 seconds total |
| `FaultySender` | Incomplete; no native final verdict | Supervisor 137 after the 3,600-second cap and 30-second kill grace |
| Other nine positive profiles | Not started | No result |

The open profiles are the base, `NoOnPath`, `FaultySender`, `MaxPN7`, `Cap3Range3Window3`,
`Bytes5`, `Paths3`, `Excess2`, `Cap3`, and `Range3`. The 33 small checks ran once in one
selection and completed in 45.507219 seconds including command setup. Independent review
confirmed that the four progress counterexamples are literal source behaviors and satisfy
their fairness conditions. In the `OldPacketReuse` cycle, the ACK is empty, so `NoAckLoss`
excludes no step. The retained notes and exact traces are in
`target/model/reviewer-network-traces-d4103a23/`.

The positive command began at 01:27:20 with the original 3,600-second cap. Its ten-minute
sample had 10,656,126 distinct states and 2,931,696 queued states. Queue estimates still
permitted completion near the cap, so the same run continued. They were estimates, not
acceptance. The last checkpoint, during the kill grace at 02:27:37, had 316,477,807 generated
states, 44,063,457 distinct states, 3,260,892 queued states, and depth 28. Its manifest remains
`state=started`, without a native final exit or verdict. Supervisor exit 137 is not a checker
verdict. The time cap ended this third and last implementation attempt; no further tuning or
checker run followed.

The dedicated c8g.4xlarge host had 16 vCPUs and 32 GiB, Linux 7.0.0-1016-aws arm64. The command
used `--tlc-heap-mib=20480 --tlc-fp-mib=4096`, 16 TLC workers, `OffHeapDiskFPSet`, and
`DiskStateQueue`. It kept Temurin 21.0.13+9, TLC 1.8.0+d8fb231de4e4, and the runner executable
SHA-256 `db6b85d5c3fd036a6e8707fd34d9f506946580b8046068068981a0dd4eb35913`. Apalache 0.62.4
was present but not used. The GC log has no OOM diagnostic; its one full collection had cause
`Ergonomics`, lasted 815.549 ms, and reduced the used heap from 15899M to 1041M. Memory
exhaustion did not end this run.

All 34 native run records and their frozen source remain in
`target/model/remote-n000-20261112T012118Z-28397/`. Its native archive has SHA-256
`750b46fad87d092771a1b4fb092d60959a0bdd61449010c63ba3c66bd670b6ff`. Collection and teardown
both returned 0; fresh native status confirmed no instance or EBS volume. The combined archive
at `~/.local/state/model-evidence/rsnetwork/N000/20261112-state-view-network-model-evidence.tar.gz`
retains all three attempts, their recipes and sizing records, all three independent
review directories, final source, and the preceding durable archive. Its adjacent `.sha256`
receipt identifies the archive. Only TLC state caches are omitted.

### Earlier state-view attempts

The first view, which still kept accepted non-flight entries inside the replay floor, passed
all 33 small profiles at digest `sha256:798b64d7e22b4969f73803b335c45024663c1fe45ccd8775330b76f925c5a1b4`.
Native run `20261112T001204Z-37209` sampled `FaultySender` with unchanged bounds and resources.
At 00:28:32 UTC, after ten minutes, it had 8,854,385 distinct states, 2,692,942 queued states,
and depth 19. The queue still grew; there was no complete-size or positive verdict. The lead
selected the additional exact omission above before the full matrix. The owned supervisor
received SIGINT at 00:29:04 UTC and exited 137 after its 30-second grace. Its native manifest
has no final checker verdict. Collection and teardown both returned 0; no instance or EBS
volume remains. The 34 run records, source, and logs remain in
`target/model/remote-n000-20261112T001204Z-37209/`; its native archive has SHA-256
`6d95eba95b106821ed5465c2baed892fb0f0f01bfa75108c2854f362d15b5014`. These results do not qualify
the final view. Independent notes retain the four progress counterexamples and their fairness
interpretation in `target/model/reviewer-network-traces-798b64d7/`.

The accepted-packet refinement passed all 33 small profiles at digest
`sha256:7de1eab46265965d55836672342db32fbf8161500a4a0358b123f8e53a0d6923` in native run
`20261112T003311Z-8667`. At its 35-minute checkpoint (01:14:22 UTC), `FaultySender` had
25,026,075 distinct states and 4,952,428 queued states, at depth 24. Its last progress before
the stop had 25,603,384 distinct states and 4,989,293 queued states. The lead selected removal
of the repeated open-view type calculation as the third and last implementation attempt in
this continuation. The owned supervisor received SIGINT at 01:16:19 UTC and exited 137 after
its 30-second grace; the native manifest has no final checker verdict. The 3,600-second cap
was unchanged and was not exhausted. This is an incomplete search, not a positive pass.
Collection and teardown both returned 0; no instance or EBS volume remains. Its 34 records
and exact source remain in `target/model/remote-n000-20261112T003311Z-8667/`, whose native
archive has SHA-256 `fb67210a584fd3e7b29cda2f44bb6c01720d8c89134b5d18c58b00fb611411f0`.
Independent notes are in `target/model/reviewer-network-traces-7de1eab4/`. These results do
not qualify the revision that omits `TypeOK` from `OpenView`.

### Retained result before the state view

Native run `20261111T175227Z-47948` used the source before the state view. SANY parsed both
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

All 34 retained native profile closures match that revision's inputs. The exact per-profile
closure, named property, original exit, duration, and result are in
`target/model/attached-datagram-evidence-index.json` and `attached-datagram-evidence-status.tsv`.
SANY is in `target/model/attached-datagram/sany/1794419733-15824/`; the incomplete profile is in
`target/model/attached-datagram/AttachedDatagram.FaultySender.cfg/1794420213041422967-21107/`.

Its `OldPacketReuse.Spread_bad` run is `1794420198936226333-20932`. Its cycle resends
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
