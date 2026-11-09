# Attached channel: datagram form

This is the design model of task N000. It checks the rules of the datagram form of attached
channels (`docs/specs/networking.md`, "Attached Channels" and "Datagram Form") before the N603
wire format is fixed. `AttachedDatagram.tla` models the design that was selected on 2026-11-07:
each side datagram carries an AES-GMAC tag, the receiver slides its own replay window, each
acknowledgement frame names packet numbers and the consumer's read point, and the side flow
follows the parent's path through migration, also through a spurious one.

**Status (2026-11-09): complete.** Every profile passes at the declared bounds, and each argued bound passes raised by one, in one command at the final digest ([Evidence host record of the final files](#evidence-host-record-of-the-final-files)).
The design as first written had a defect, packet-number squatting. The [Decisions](#decisions)
section gives the defect, the selected design, and each rejected option.

## Promise

A sender sends a stream of bytes to a receiver in side datagrams. The parent QUIC connection
carries all control in authenticated frames. Each side datagram has a tag that gives it integrity
and no confidentiality. The promise is:

- The receiver holds only the bytes that the sender sent, at the offsets where the sender sent
  them. With an honest sender, the network and an on-path attacker cannot end the channel.
- An acknowledgement means that the receiver's transport holds the bytes. Only the read point
  means that the consumer read them.
- Only a datagram that passes its tag moves the receiver's replay window, and the receiver's
  replay state stays inside its window.
- When loss is fair, the parent stays alive, and the consumer keeps reading, the channel ends.
  Without a reset or a parent end, it completes, also after a genuine or a spurious migration and
  with the on-path attacker. A spurious migration costs the side flow what it costs the parent.

A concrete failure, in the design before 2026-11-07: an on-path attacker sends one datagram with
a packet number that the sender uses next. The receiver accepts it. The sender then sends other
bytes with that packet number, and the acknowledgement of that number makes the sender count
bytes that the receiver never got. The consumer waits for them forever.

## Run it

```sh
cargo xtask model attached-datagram                                  # every profile
cargo xtask model attached-datagram/AttachedDatagram.cfg             # the design
```

The output of a profile goes to `target/model/attached-datagram/<file>/`: `checker.log` has the
checker output, and on a violation `trace.json` has the trace. [Check the design
models](../../docs/content/design-models.md) tells how to install the checkers and what a
failure means.

## Files and profiles

`AttachedDatagram.tla` is the only module. Each profile is `AttachedDatagram.<name>.cfg`; the
constant `Bug` selects a known-bad variant, and `"none"` is the design. A `_bad` profile is a
known-bad variant and a `_reach` profile is a reachability witness. Each of them checks one
property, and it passes only when TLC reports a violation of that property.

| Profile | Checks | Must |
| --- | --- | --- |
| `AttachedDatagram.cfg` | The design, the on-path attacker, an honest sender: every property and `Progress` | Pass |
| `AttachedDatagram.NoOnPath.cfg` | The same without the on-path attacker. The two state counts show what the attacker adds | Pass |
| `AttachedDatagram.FaultySender.cfg` | The design with a faulty sender that can send other bytes, and the attacker: every property except `NoNetworkIntegrity`, and `Progress` | Pass |
| `AttachedDatagram.<Bound>.cfg` | The attacker profile with one argued bound raised by one (rule 4 of [FP Design Models]): `Paths3`, `Cap3`, `Range3`, `MaxPN7` (three faults), `Bytes5` (with `MaxPN = 7`, so two faults), and `Cap3Range3Window3` (the window can bind only when the credit and the spread bound also allow three in flight) | Pass |
| `AttachedDatagram.NoTag_bad.cfg` | No tag check | Violate `HeldAreSenderBytes` |
| `AttachedDatagram.NoTagSquat_bad.cfg` | No tag check: the squatting trace | Violate `AckMeansHeld` |
| `AttachedDatagram.NoTagEnd_bad.cfg` | No tag check | Violate `NoNetworkIntegrity` |
| `AttachedDatagram.SlideBeforeTag_bad.cfg` | The window moves before the tag check | Violate `WindowAfterTag` |
| `AttachedDatagram.ReusePN_bad.cfg` | A retransmission reuses its packet number | Violate `Progress` |
| `AttachedDatagram.CompleteAtAck_bad.cfg` | Completion at acknowledgement, without the read | Violate `CompletionSound` |
| `AttachedDatagram.CreditBeyond_bad.cfg` | Credit one byte beyond admitted capacity | Violate `CreditBound` |
| `AttachedDatagram.NoWindowBound_bad.cfg` | The receiver has no window | Violate `PNStateBound` |
| `AttachedDatagram.LateReset_bad.cfg` | A reset after a terminal outcome | Violate `OutcomeStable` |
| `AttachedDatagram.NoAbandon_bad.cfg` | The design as written before 2026-11-07: the side flow pauses while the parent validates, and nothing abandons a validation | Violate `Progress` |
| `AttachedDatagram.<Target>_reach.cfg` | Each terminal outcome (`Completed`, `Reset`, `ParentEnd`, `Partial`, `Refused`, `Integrity`), `Resumed`, `Abandoned`, `CompletedAfterAbandon`, `WindowPassed`, and `ReplayAccepted` | Reach the target |

## Model

The model has one sender, one receiver, the parent's paths, the network, and an on-path
attacker. Each datagram carries one byte. A payload is `"good"` when it is the sender's correct
byte at the datagram's offset, and `"bad"` when it is not. The application's tags cover the
channel and the position, so the consumer's read rejects a `"bad"` byte. The model computes no
tags: a datagram passes the tag only when it is a datagram that the sender sent (`Authentic`).

The parent's frames (acknowledgements with the read point, credit, final size, and reset) are
reliable and authenticated, because the design puts them in the parent. They can arrive late and
in a different order. The model keeps one outcome for the channel: the first terminal event at
either end sets it, and the model merges the parent frame that tells the other end. The final
size is fixed at `Bytes`, because its frame is in the parent.

| Action | Contract row | Atomicity |
| --- | --- | --- |
| `Init` | Explicit profile: the open succeeds or refuses | Initial state |
| `SendData(o)` | Packet numbers and replay; Receive credit; Congestion and loss; Migration; Path and routing; Retransmission | The sender builds and sends one datagram with the next packet number and its tag |
| `Deliver(d)` | Tag; Packet numbers and replay; Receive credit; Injection: one arrival and the full receive procedure (`RecvState`) | One step. A later copy is a duplicate, so the model delivers each datagram once |
| `Replay(p)` | Injection: the on-path attacker sends again a datagram that the sender sent | One step: send and arrival |
| `Lose(d)` | Network loss | One step, inside the fault bound |
| `DeclareLost(p)` | Congestion and loss: the RFC 9002 thresholds and a congestion event of the shared window | One step. With no clock it can come too early, inside the fault bound |
| `DeliverAck(p)` | Control; Packet numbers and replay: a packet-number acknowledgement in a parent frame; a never-sent packet number shows a faulty peer | The sender processes one packet number |
| `DeliverCredit(c)` | Receive credit: a credit frame arrives | One step |
| `Read` | Receive credit; Integrity (Attached Channels): the consumer reads one byte, its application tag is checked, and the read admits capacity and grants credit | One step |
| `Complete` | Terminal outcomes: the consumer read to the final size, and the frame that names that read point arrives at the sender | One step |
| `Reset`, `ParentEnd` | Terminal outcomes; Lifetime; partial delivery at a parent end | One step |
| `ParentLoss` | Congestion and loss: a parent loss on the parent's validated path reduces the shared window | One step. During a validation, the parent's packets count for the new path's controller, which success resets and an abandon discards |
| `MigrateStart` | Migration: the peer moves, and the parent starts to validate the new address on a new path and connection ID | One step. A peer event |
| `Spoof` | Migration: the attacker's copy of a parent packet with a spoofed address arrives first (RFC 9000 sections 9.3.2 and 9.3.3) | One step. An attacker event; its validation cannot succeed |
| `Validated` | Migration; Path and routing: the PATH_RESPONSE arrives; the side flow follows the parent to the new path and its connection ID, with initial congestion state | One step |
| `Abandon` | Migration: the validation timer expires or the last validated address returns (RFC 9000 sections 8.2.4 and 9.3.2); the side flow returns with the parent to the last validated path and its congestion state | One step |
| `Done` | A terminal state stays as it is | Stuttering step, so the deadlock check stays on |
| `Forge(d)`, `GrantBeyond`, `ResendSamePN(p)` | Known-bad variants only: a datagram that the tag would refuse, credit beyond capacity, a reused packet number | One step each |

A datagram whose tag fails changes no state, so the design has no step for it. The receiver accepts
a side datagram on each connection ID that it issued for the channel; the model retires none. An
off-path attacker has no connection ID, so its datagram also fails the window check. The N603 wire element
and the N604 transition columns are added when that code exists.

### Properties

| Task property | Model property | Kind |
| --- | --- | --- |
| The receiver holds only bytes that the sender sent at that offset | `HeldAreSenderBytes` | Invariant. No step checks it; only the tag makes it hold |
| No data beyond granted credit is accepted; credit only for admitted capacity | `CreditBound` | Invariant |
| The receiver's replay state stays inside its declared window | `PNStateBound` | Invariant |
| The window moves only when the receiver accepts a datagram whose tag passed | `WindowAfterTag` | Action property |
| An acknowledgement means that the receiver's transport holds the bytes | `AckMeansHeld` | Invariant |
| Completion needs the consumer's read to the final size | `CompletionSound` | Invariant |
| With an honest sender, nothing from the network ends the channel with integrity | `NoNetworkIntegrity` | Invariant |
| The terminal outcomes stay distinct | `OutcomeStable`; one value for each outcome | Action property |
| Progress when loss is fair, the parent stays alive, and the consumer keeps reading | `Progress`: `WF_vars(Read) => <>(outcome # "open")`. The consumer's read is a caller event, so it is the condition of the property, not a fairness of the specification. Reset and parent end have no fairness, so a run without them must complete | Liveness |
| No state deadlocks | TLC's deadlock check, with `Done` in terminal states | Deadlock |

`TypeOK` is an invariant of each passing profile. The application's tag check at the read is an
assumption of the model ([NET Attached Channels], "Integrity"), not a checked property. The
earlier properties `ReadsSenderBytes` and `JunkInert` restated the read step and the discard rule,
so `HeldAreSenderBytes` and `PNStateBound` replace them (selected on 2026-11-07).

### Bounds, faults, and fairness

- Bounds: one channel, `Bytes = 4`, `MaxPN = 6`, `Paths = 2` (one migration attempt, genuine or
  spurious; each attempt takes a new path and connection ID), one injected
  datagram at a time, `Cap = 2`, `Window = 2`, and a replay window of `Range = 2` packet
  numbers. The design sizes the window from the packet rate and the declared reordering time; the
  model's window is small so that the window passes packet numbers (`WindowPassed_reach`).
- Faults: loss, duplication, reordering and delay (`net` is a set), early loss declarations, a
  genuine migration whose validation can fail, a spurious migration, the on-path attacker
  (`OnPath = TRUE`), and a faulty sender (`FaultySender = TRUE`, one profile).
- Fault bound: a loss or an early declaration happens only while the sender
  keeps a packet number to send each affected byte again (`Spent <= Budget`, `Budget = MaxPN -
  Bytes`, so two faults). The `ReusePN` variant counts its faults in `faults`, because a reuse
  takes a packet number out of `sLost`.
- Fairness: weak fairness on the sender's send and its loss declaration of a doomed packet; on
  each delivery of a datagram and of a parent frame; on completion, when the frame with the read
  point arrives; and on the end of a validation, `Validated \/ Abandon`, because its timer bounds
  it. Success alone has no fairness: only the peer can answer. Loss, early declarations, the
  attacker, spurious migrations, the consumer's read, reset, parent end, parent loss, and
  migration starts have no fairness.

## Physical assumptions

Each assumption about the world outside the two ends, with its primary source and its fairness.
The family policy ([FP Design Models]) gives a peer, an attacker, or a caller no fairness unless
the design bounds the event.

| Assumption | Source | In the model | Fairness, and why |
| --- | --- | --- | --- |
| The network loses, duplicates, reorders, and delays each datagram with no bound for one datagram | [RFC 8085 section 3.3](https://www.rfc-editor.org/rfc/rfc8085#section-3.3) | `Lose`, a set `net` with any delivery order, `Replay` for a late copy | No fairness on any one loss. Delivery of a datagram that is not lost is fair: loss is fair, the claim of `Progress` |
| An on-path attacker reads each side datagram and injects datagrams, but does not drop them. RFC 9000 calls this an off-path active attacker, or a limited on-path attacker when its copies arrive first | [RFC 9000 section 21.1.3.2](https://www.rfc-editor.org/rfc/rfc9000#section-21.1.3.2), [21.1.3.3](https://www.rfc-editor.org/rfc/rfc9000#section-21.1.3.3) | `Replay(p)`: it sends again any sent datagram. An attacker that drops datagrams can stop any channel, as it can stop the parent | None |
| The attacker cannot forge a GMAC tag, except with a probability of about l / 2^128 for each attempt on a datagram of l blocks of 16 bytes. The receiver counts each failed tag and ends the channel at 2^52 failures, which keeps the total forgery chance at or below 2^-57 | [RFC 9001 section 6.6](https://www.rfc-editor.org/rfc/rfc9001#section-6.6), [Appendix B.1.2](https://www.rfc-editor.org/rfc/rfc9001#appendix-B.1.2); [RFC 4543](https://www.rfc-editor.org/rfc/rfc4543) | The model abstracts a forgery below that limit as impossible: a datagram passes the tag only when the sender sent it (`Authentic`). The variants `NoTag` and `SlideBeforeTag` let the attacker send any datagram (`Forge`) | None |
| A packet number is never reused under one key. The space is finite (2^62), so the channel ends before reuse. A reused number is a reused GMAC nonce, which discloses the hash key | [RFC 9000 section 12.3](https://www.rfc-editor.org/rfc/rfc9000#section-12.3); [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final) section 8 | `MaxPN` bounds the packet numbers; `ReusePN` shows the progress failure of a reuse. The nonce failure is not modeled: the model computes no tags | Not an event |
| RTT and the RFC 9002 loss thresholds come from real clocks, and delay has no bound, so a loss declaration can be early | [RFC 9002 sections 5 and 6.1](https://www.rfc-editor.org/rfc/rfc9002#section-6.1) | The model has no clock. `DeclareLost` can come at any time, inside the fault bound | Fair only for a doomed packet: one in flight, not accepted, and with no copy in the network. An early declaration has no fairness |
| One congestion controller and pacer admit the parent's packets and the side datagrams on a path | [RFC 9002 section 7](https://www.rfc-editor.org/rfc/rfc9002#section-7); [RFC 9221 section 5.4](https://www.rfc-editor.org/rfc/rfc9221#section-5.4) | One window `cwnd` for both flows. A loss in either flow halves it, with no recovery period, which is conservative for `Progress` because the window stays at least 1 | `ParentLoss` has no fairness |
| The parent stays alive and delivers its frames, which it sends again until they are acknowledged | [RFC 9000 section 13.3](https://www.rfc-editor.org/rfc/rfc9000#section-13.3) | `DeliverAck`, `DeliverCredit`, `Complete` | Fair: the claim of `Progress` is for a parent that stays alive. `ParentEnd` has no fairness |
| A path validation succeeds only when the peer answers its PATH_CHALLENGE. The parent abandons it on a timer: "A value of three times the larger of the current PTO or the PTO for the new path ... is RECOMMENDED" (section 8.2.4). "An endpoint MUST revert to using the last validated peer address when validation of a new peer address fails" (section 9.3.2) | [RFC 9000 sections 8.2.4](https://www.rfc-editor.org/rfc/rfc9000#section-8.2.4), [9.3.2](https://www.rfc-editor.org/rfc/rfc9000#section-9.3.2) | `Validated` for a genuine migration only; `Abandon` for each | Fair on the end of a validation, `Validated \/ Abandon`, because the timer bounds it. No fairness on `Validated` alone |
| A peer migrates, and an on-path attacker causes a spurious migration "by copying and forwarding a packet with a spoofed address such that it arrives before the original packet" (section 9.3.2). Each attempt uses a new connection ID (section 9.5) | [RFC 9000 sections 9.3.2](https://www.rfc-editor.org/rfc/rfc9000#section-9.3.2), [9.3.3](https://www.rfc-editor.org/rfc/rfc9000#section-9.3.3), [9.5](https://www.rfc-editor.org/rfc/rfc9000#section-9.5) | `MigrateStart`, `Spoof`, each on a new path; `Paths` bounds the attempts | None: peer and attacker events |
| An attacker that keeps forwarding can make the path through itself the parent's path: "This places the attacker on-path, giving it the ability to observe or drop all subsequent packets" (section 9.3.3) | [RFC 9000 section 9.3.3](https://www.rfc-editor.org/rfc/rfc9000#section-9.3.3) | Outside the fault model: an attacker that drops can stop any channel, as it can stop the parent | Not modeled |
| Until the parent validates a new peer address, it "limits the amount of data it sends to that address" (section 9.3.1), and a return to a previously validated path can restore "loss detection and congestion state" (section 9.3) | [RFC 9000 sections 8](https://www.rfc-editor.org/rfc/rfc9000#section-8), [9.3](https://www.rfc-editor.org/rfc/rfc9000#section-9.3), [9.3.1](https://www.rfc-editor.org/rfc/rfc9000#section-9.3.1), [9.4](https://www.rfc-editor.org/rfc/rfc9000#section-9.4) | No side data during a validation (reduction 5); `Abandon` keeps `cwnd`, and `Validated` sets it to its initial value | Not an event |
| The consumer reads the bytes that the receiver holds | [NET Attached Channels], "Lifetime" (backpressure) | `Read` | None. `Progress` states it as its condition: a consumer that stops reading stops the channel by backpressure, and reset or the parent's lifetime then ends it |

Each fairness condition names the failure that it could hide, and a known-bad variant with that
failure still fails under it:

| Fairness condition | The failure it could hide | Known-bad variant that still fails |
| --- | --- | --- |
| The sender sends (`SendData`) | A sender that sends again and never makes progress | `ReusePN_bad`: `Progress` fails |
| The network delivers each datagram that it does not lose (`Deliver`) | A delivered datagram that the receiver must discard forever | `ReusePN_bad`: each copy of packet number 2 arrives and is discarded below the window |
| A doomed packet is declared lost (`DeclareLost`) | Loss detection that never stops the cycle | `ReusePN_bad`: the declaration repeats, and `Progress` fails |
| The parent delivers its frames and the sender completes (`DeliverAck`, `DeliverCredit`, `Complete`) | A completion that does not depend on the read | `CompleteAtAck_bad`: `CompletionSound` fails |
| A validation ends (`Validated \/ Abandon`) | A validation that never ends while the side flow waits; the fairness on success alone, before 2026-11-07, hid it | `NoAbandon_bad`: a spurious migration pauses the side flow for good, and `Progress` fails |

## Reductions

Each reduction removes behaviors that no property can tell apart, or that another behavior of the
model covers. After them, each known-bad variant still fails its own property.

1. One delivery for each datagram. A later copy of a datagram is a duplicate or old, which changes
   no state. The attacker's `Replay` covers the late copy of a lost datagram.
2. The attacker sends again only a datagram that the receiver did not accept and that is not in
   flight. A copy of an accepted datagram is a duplicate or old; a copy of a datagram in flight is
   the same as its early delivery.
3. The packets in flight span fewer than `Range` packet numbers (`SendData`). This is a bound of
   the model, not a design rule. A datagram that falls below the receiver's window is discarded
   with no state change and leaves the network, which is the same change as `Lose`. So the model
   lets the window pass only a packet number that the sender settled, and `Lose` under the fault
   bound covers the discard of one that it did not. The failure that this reduction could hide is
   a discard below the window that the sender never recovers from: `ReusePN_bad` sends outside
   the bound, its copies fall below the window, and `Progress` fails. `WindowPassed_reach` shows
   that the window passes packet numbers in the design.
4. The tag accepts a sent datagram with any connection ID, and the attacker's copy carries the
   current path's connection ID. The real tag covers the connection ID, so this only adds
   behaviors; the receiver accepts each issued connection ID in both cases.
5. No side data while the parent validates a new peer address (`SendData` needs `mig = "none"`).
   In the design, the side flow sends to that address within the parent's anti-amplification
   limit, after the parent's control frames, which have priority. Each such datagram either
   reaches the receiver, which accepts it on its issued connection ID, as a datagram that the
   model sends after the validation ends, or it is lost, as `Lose` does inside the fault bound.
   The parent's control frames have priority, so the side data cannot delay the validation. So
   the reduction removes no failure. The failure that it could hide is a validation that never
   ends while the side flow waits: `NoAbandon_bad` still fails `Progress` under it.

## Known-bad variants and their counterexamples

Each counterexample is from the evidence run below, as actions and observations.

- `NoTag_bad`, `HeldAreSenderBytes`: `SendData(1)` sends offset 1 in packet number 1. `Forge`
  sends packet number 1 with other bytes at offset 0, and the receiver accepts it. It holds bytes
  that the sender never sent.
- `NoTagSquat_bad`, `AckMeansHeld`, the squatting trace: `Forge` takes packet number 1, with other
  bytes at offset 0, before the sender uses it, and the receiver accepts it. `SendData(1)` sends
  offset 1 in packet number 1; that datagram will be a duplicate. `DeliverAck(1)` arrives, and the
  sender counts offset 1 as acknowledged; the receiver does not hold offset 1. In the design as
  first written, this squat made the channel stay open with no outcome.
- `NoTagEnd_bad`, `NoNetworkIntegrity`: `Forge` puts other bytes at offset 0 in packet number 1,
  and `DeliverAck(1)` of that never-sent packet number ends the channel with the integrity
  outcome. Without the tag, one datagram ends the channel.
- `SlideBeforeTag_bad`, `WindowAfterTag`: `Forge` sends a datagram with packet number 1 whose tag
  fails. The receiver moves its window to 1 and then discards the datagram.
- `ReusePN_bad`, `Progress`: offset 0 goes in packet number 1, and a genuine migration starts and
  is abandoned. The sender sends offset 2 in packet number 2, declares it lost early, and that
  datagram is lost. Offsets 1 and 3 go in packet numbers 3 and 4, and the receiver accepts them,
  so its window passes 2. Then the loop: the sender sends offset 2 again with the reused packet
  number 2, the receiver discards it below the window, and the sender declares 2 lost again. The
  consumer waits for offset 2 forever.
- `NoAbandon_bad`, `Progress`: offset 0 goes in packet number 1, arrives, and the consumer reads
  it; the sender declares packet number 1 lost early, and its acknowledgement arrives later.
  `Spoof` starts a validation of a spoofed address. That validation cannot succeed, and nothing
  abandons it, so the side flow never sends offset 1, the consumer has nothing to read, and the
  channel stays open: the stuttering lasso.
- `CompleteAtAck_bad`, `CompletionSound`: each byte is acknowledged and the channel completes
  before the consumer reads to the end.
- `CreditBeyond_bad`, `CreditBound`: the receiver grants credit one byte beyond the admitted
  capacity, and it holds a byte there.
- `NoWindowBound_bad`, `PNStateBound`: the receiver keeps each accepted packet number, and its
  replay state passes the window.
- `LateReset_bad`, `OutcomeStable`: a reset changes a terminal outcome.

## Reachability

| Profile | Target |
| --- | --- |
| `Completed_reach`, `Reset_reach`, `ParentEnd_reach`, `Partial_reach`, `Refused_reach` | Each terminal outcome, with an honest sender |
| `Integrity_reach` | A faulty sender's other bytes reach the consumer, and the application tag ends the channel |
| `Resumed_reach` | A migration completes, and a side datagram is in flight on the new path |
| `Abandoned_reach` | The parent abandons a validation and returns to its last validated path |
| `CompletedAfterAbandon_reach` | The channel completes after the parent abandoned a validation |
| `WindowPassed_reach` | The window passes a packet number that the receiver did not accept |
| `ReplayAccepted_reach` | The receiver accepts a datagram that the attacker sent again |

## Limits

- Data at or past a known final size (gap 2c): the model fixes the final size at `Bytes` and caps
  credit there. A model of the rule needs one offset past the end and a final-size frame step.
- Migration: the side data within the anti-amplification limit during a validation (reduction 5),
  the retirement of connection IDs, and an attacker that becomes on path through forwarding and
  then drops datagrams.
- The parent's own packets in the shared window and the scheduler share of gap 2d: the model's
  weak fairness on `SendData` states only that the side flow gets a share whenever the window has
  room.
- The tag's computation, its key derivation, and the nonce failure of a reused packet number: the
  model computes no tags. N603 vectors and N604 tests cover them.
- The model gives each acknowledgement frame the receiver's state at arrival, and it merges the
  read-point frame into `Complete`. The state only grows, so an older frame names less.
- The model proves no Rust code. When N603 and N604 exist, the correspondence table gets their
  wire elements and transitions, and a change to either side reopens this check.

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

## Evidence record

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
- Source: the files of this directory as they are now. The xtask printed
  `9735eb8c9abe241f9b1d91b12d0c98b2400b3abc (31 files)`, a Git object ID. From 2026-11-08 the
  xtask prints a SHA-256 digest from rscrypto instead, and the same 31 files give
  `sha256:55f1ef3fc57619676746967e800b52232b4eec299cfca8b9089aaf5e17c5a79a`.
- Checkers and flags as above. Host: macOS 26.6.2 arm64, 10 cores, 16 GB.
- Replay: `target/model/attached-datagram/AttachedDatagram.Cap3Range3Window3.cfg/checker.log`.

| Profile | Exit | Distinct states | Depth | Duration | Verdict |
| --- | --- | --- | --- | --- | --- |
| `AttachedDatagram.Cap3Range3Window3.cfg` (raise) | 0 | 12,415,204 | 29 | 248.9 s | Pass |

It has more states than `Cap3` (8,470,530), so the window binds there, and the raise tests it.
Each argued bound of this model now has its complete raise-by-one search, and every profile of
the model is complete at its bounds; nothing is pending.

The earlier records, of the design as first written (2026-11-06) and of the decision round
(2026-11-07), checked files that are now deleted; the [Decisions](#decisions) section keeps
their numbers.

[FP Design Models]: ../../../rsasync/docs/specs/family-policy.md#design-models
[NET Attached Channels]: ../../docs/specs/networking.md#attached-channels
