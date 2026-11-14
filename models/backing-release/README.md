# Backing ownership across acceptance, retransmission, and kernel release

This is the design model of task N014. It checks how two ownership contracts compose before the
action vocabulary (N004) and the datagram form (N604) exist. The protocol keeps output until exact
acceptance and peer acknowledgement. The runtime keeps each accepted submission until its terminal
event. The sources are in the local design `docs/specs/networking.md`: Backing and Completion
Ownership, Resource and Progress Bounds, and Datagram Form. The driver side is the terminal-release
contract of rsasync, which its model R000 checks (`models/operation-ownership/` in rsasync). This
model owns no driver. The Design Models section of `family-policy.md` in rsasync sets the
acceptance.

## The promise and a concrete failure

The promise: one charged backing stays alive and charged once while any holder retains a view of
it or the kernel can read it. The release runs once, in the step that ends the last obligation.
A partial acceptance keeps the unaccepted suffix with its writer. A repeated acknowledgement, or
an acknowledgement of a number that the sender never sent, changes no ownership.

Three concrete failures:

- The peer acknowledges the first copy of a slice while its retransmission is still in the
  kernel. The protocol frees the slice at the acknowledgement, and the kernel then reads freed
  pages for the retransmission (`ReleaseAtAck_bad`).
- The protocol accepts a prefix of a write and releases the whole region. The writer loses the
  suffix that it must write again (`WholeRelease_bad`).
- A request deadline ends the stream, and the binding frees the backing. The kernel still reads
  it for a send that has no terminal event yet (`DeadlineRelease_bad`).

## Run it

```sh
cargo xtask model backing-release                                      # every profile
cargo xtask model backing-release/BackingRelease.cfg                   # one profile
```

The output of a profile goes to `target/model/backing-release/<file>/<run>/`.
[Check the design models](../../docs/content/design-models.md) tells how to install the checkers,
what the command prints, and what a failure means.

## Files and profiles

| File | Role |
| --- | --- |
| `BackingRelease.tla` | The module: the state, the actions, the properties, and the reachability targets |
| `BackingRelease.cfg` | The main profile at the declared bounds: every property |
| `BackingRelease.Slices3.cfg`, `BackingRelease.Copies3.cfg` | One argued bound raised by one: a third slice, or a second retransmission |
| `BackingRelease.<Name>_bad.cfg` | The known-bad variants: each must violate its one property |
| `BackingRelease.<Name>_reach.cfg` | The reachability witnesses: each must violate its `Not<Name>` property, which shows a trace to the target |

Each profile is a TLC configuration of `BackingRelease.tla`. The constant `Bug` selects a
known-bad variant; `"none"` is the design.

## What the model contains

| Part | Model |
| --- | --- |
| Backing | One backing, charged once when it is created. It splits into `Slices` slices in stream order. Each holder keeps its own view of it |
| Writer | It gives its region to the protocol. `wr` is the stable offset: the first slice that the protocol has not accepted. The writer keeps a view of the suffix (`wv`) until it drops it (`wgone`) |
| Retransmit store | `st[s]`: `wait` (not accepted), `store` (accepted, not acknowledged), `acked`, or `dropped` (the stream ended first). The store keeps a view of each slice in `store` (`sv`) |
| Copies | Each slice goes out in up to `Copies` datagrams: the first one and each retransmission, each with a new packet number. One datagram carries one slice |
| Driver | `k[s][c]`: `none` (not submitted), `ref` (refused), `fly` (accepted, result pending), `zc` (the result came, and a notice follows), `res` (the result was terminal), or `ntc` (the notice came). The driver keeps a view of each copy in `fly` or `zc` (`dv`) |
| End | `end`: `none`, or the end of the stream: `cancel`, `deadline`, or `close` |
| Release | The release hook runs in the step that drops the last view. `rel` counts its runs, and `charge` counts the charges that the budget holds for the backing. `xv` counts views that no holder owns |
| History | `ev`: the kind of the last step. No action reads it. The acknowledgement property and the witnesses read it |

## Boundary assumptions

Each assumption is a fact of the runtime, the kernel, or the peer that the model uses. The
model checks no progress, so it gives no step fairness. The progress of each terminal event
belongs to R000 (`CloseReturns`, `DetachedReleased`).

| Assumption | Source | In the model |
| --- | --- | --- |
| An accepted submission gives the driver a stable backing until its terminal event. A refused submission returns the resources to the caller with a typed reason | rsasync design, Completion I/O and Buffers (the transition table); R000 `ReleaseOnce` | `Send` either adds a driver view or refuses. A refusal changes no view |
| A zero-copy send has a send result and, when the kernel armed one, a later notice. The notice releases the backing. Without a notice, the result is terminal. A copying send is the second case | io_uring_prep_send_zc(3) (`IORING_CQE_F_MORE`, then `IORING_CQE_F_NOTIF`); the terminal-event table of the rsasync design; R000 | `Result` goes to `zc` or `res`; `Notice` goes from `zc` to `ntc` |
| A notice comes when the kernel releases the pages, with no fixed order against other notices or against the peer's acknowledgement. A UDP send releases its pages after the device sends or drops the packet, and a delayed transmit completion can come after the peer's acknowledgement | Linux `Documentation/networking/msg_zerocopy.rst` ("the kernel returns a completion notification when it releases its hold on the shared pages") | `Result`, `Notice`, and `PeerAck` interleave in each order |
| Loss detection can declare a packet lost that the peer later acknowledges, so a retransmission and its original can both be in flight | RFC 9002 section 6 (packet and time thresholds) | `Send` of copy `c` needs only that copy `c - 1` was submitted |
| Acknowledgement frames repeat their ranges, so the sender gets a repeated acknowledgement as a normal event. A faulty peer can name a number that the sender never sent | RFC 9000 section 13.2.3; Datagram Form, Packet numbers row | `PeerAck(s, c)` is possible in each state, for each copy |
| Cancellation, a request deadline, and close stop interest and new production. They prove no kernel release. Close cancels each operation in flight, and each operation keeps its backing until its own terminal event | Backing and Completion Ownership; rsasync design, Completion I/O and Buffers ("No deadline converts uncertain completion into permission to release a resource"); R000 `CloseDone` | `End` drops the store's views and keeps each driver view |
| The writer, the peer, the loss detector, the driver's refusals, and the end of the stream are free | The design gives them no obligation | Each such step can come at any time, or never |

## Reductions and their soundness

Each reduction removes states or steps that no property can tell apart, or it adds behaviors.
Each known-bad variant still fails its own property under all of them (see the evidence record).

1. One backing. This bound is proved, not argued. Each step changes the state of one backing.
   `End` changes each backing of the stream, and the one-backing model allows `End` in each
   state. Backings can share one budget, so the charge of one backing can make the driver
   refuse a submission of another. The model makes each refusal a free choice of the
   environment: `Send` can refuse each first submission of a copy in each state, with no
   budget guard. So a refusal that another backing's charge causes adds no behavior to the
   projection. No property reads two backings. So each behavior with more backings projects to
   a behavior of this model for each backing, and each property holds for each projection. A
   datagram that gathers views of two backings is a limit (below).
2. One datagram carries one slice. A datagram that carries several slices of the backing maps to
   one copy of each slice, whose events come in consecutive steps. Its one driver view exists
   exactly while those copies are in the kernel, so the release comes in the same mapped state.
   The model only adds the intermediate states.
3. A refused copy is not refused again. A second refusal changes no view and no other variable
   except `ev`, so it repeats a state that the model has.
4. The kernel posts a result or a notice and the driver harvests it in one step, as in R000
   (its reduction 5). Between the two, no step of this model reads the event.
5. Cancellation, a request deadline, and close are one `End` step with a label. Each one ends
   production and the store's retention, and each leaves each kernel use to its terminal event.
   A reset, the end of the parent connection, and the integrity end after a faulty
   acknowledgement have the same ownership effect. `End` can come in each state, so the model
   has their behaviors.
6. Acceptance takes whole slices. An acceptance that ends inside a slice splits that slice in
   two, and the split is a model with one more slice (`Slices3`).

## Correspondence

Each action is one atomic step. N004 and N604 do not exist yet, so their columns name the
transition that each task must build. Each task replaces its column with the code that it
builds, and a change to either side reopens this check.

| Action | Design rule | N004 transition | N604 transition | R000 action |
| --- | --- | --- | --- | --- |
| `Accept(j)` | Backing and Completion Ownership: exact acceptance releases only the accepted prefix; partial output advances a stable offset and does not recopy the unchanged suffix | The acknowledgement that names the outstanding action and its exact accepted region | The side flow takes stream bytes within the granted receive credit (Receive credit row) | — |
| `WriterDrop` | Retention after a call needs an owning lease; the caller drops it | The end of the caller's lease on the suffix | The end of a cancelled write | — |
| `Send(s, c)` | Completion I/O: an accepted submission gives the driver the backing; a refused one returns it. Resource and Progress Bounds: backpressure is explicit, and submission pressure is not network loss | The output action and its capacity demand after a refusal | Retransmission with a new packet number; zero-copy UDP send that takes a payload view | `BeginTx` (`Submit`), and `Table::withdraw` for a refused push |
| `Result(s, c)` | Terminal-event table: the send result, with or without `IORING_CQE_F_MORE` | — | — | `Complete("tx")` |
| `Notice(s, c)` | Terminal-event table: the zero-copy notice releases its own backing | — | A payload region stays owned until the zero-copy notice of each datagram that carried it | `Notice(g)` |
| `PeerAck(s, c)` | Datagram Form: acknowledgements name packet numbers; an acknowledgement of a number that the sender never sent shows a faulty peer | A duplicate or unknown acknowledgement fails with a typed error and changes no state | RFC 9002 acknowledgement processing; the end of a range's retention at its acknowledgement | — |
| `End(why)` | Backing and Completion Ownership: cancellation, a dropped future, close, and a request deadline prove no release; final completion releases the remaining ownership | The terminal outcome, and the cancellation and deadline errors | Reset, the end of the parent, and the integrity outcome | `CloseDone`, and `EndTask` for a close at shutdown |

## Properties

| Property | Acceptance text | Kind |
| --- | --- | --- |
| `AliveWhileHeld` | Each retained reference and kernel obligation keeps the backing alive | Invariant |
| `ChargedOnce` | The budget charges the backing once while it is alive, and not after its release | Invariant |
| `ReleaseAtMostOnce` | Release occurs once: the hook never runs a second time | Invariant |
| `ReleasedAfterLast` | Release occurs after the last obligation ends: when no obligation remains, the hook has run. It runs in the step that drops the last view, so a leak shows as a violation | Invariant |
| `SuffixKept` | Partial acceptance preserves the suffix: the writer keeps a view of each slice that the protocol has not accepted, until the writer drops it | Invariant |
| `AckKeepsOwnership` | Repeated or unknown acknowledgements change no ownership: such a step changes no variable except `ev` | Action property |

`TypeOK` is also an invariant of each main profile. The obligations are the writer's unaccepted
suffix, each slice in the store, and each copy in `fly` or `zc`. They come from the logical
state, not from the views, so a holder that drops its view too early shows as a violation.
`AckKeepsOwnership` reads the class of the step from `ev`. TLC checks an action property on each
step that the search generates.

## Bounds and faults

The declared bounds: one backing (proved, reduction 1), two slices, and two copies of each
slice. Two slices give one partial acceptance and a suffix. Two copies give an original and a
retransmission, so one copy's notice can remain at the acknowledgement of the other. These two
bounds are argued, not proved, so each one has a profile with that bound raised by one:
`Slices3` and `Copies3`.

The faults and free choices: the protocol accepts any prefix, declares any submitted copy lost,
and sends its next copy. The driver accepts or refuses each first submission of a copy. The
kernel gives a result with or without a notice, and results, notices, and acknowledgements come
in each order. The peer repeats acknowledgements, and a faulty peer names numbers that the
sender never sent. The stream ends by cancellation, deadline, or close in any state. The writer
drops its suffix at any time.

## Known-bad variants

Each variant changes one rule through the constant `Bug`. Its profile checks only its own
property, at the declared bounds.

| Profile | Changed rule | Must violate |
| --- | --- | --- |
| `ReleaseAtAck_bad` | The first acknowledgement of a slice drops the views of its other copies, so the backing is released while a retransmission notice remains | `AliveWhileHeld` |
| `WholeRelease_bad` | A partial acceptance releases the whole region, also the writer's suffix | `SuffixKept` |
| `DeadlineRelease_bad` | A request deadline drops the driver's views as if the kernel had released them | `AliveWhileHeld` |
| `ChargePerCopy_bad` | The driver charges the backing again for each accepted copy, until its terminal event | `ChargedOnce` |
| `RefusalLeak_bad` | The binding keeps the view of a refused submission, so no release follows the last obligation | `ReleasedAfterLast` |
| `DoubleRelease_bad` | A close runs the release hook again for a backing that no view holds | `ReleaseAtMostOnce` |
| `UnknownAck_bad` | An acknowledgement of a number that the sender never sent ends the store's retention of its slice | `AckKeepsOwnership` |

## Reachability

Each witness profile must reach its target at the declared bounds.

| Profile | Target | Shows |
| --- | --- | --- |
| `AckBeforeNotices_reach` | The first acknowledgement of a slice comes while the notices of both copies are pending | The acknowledgement before each notice |
| `AckAfterFirstNotice_reach` | It comes after the notice of the first copy and before the notice of the retransmission | The acknowledgement between the notices |
| `AckAfterRetransmitNotice_reach` | It comes after the notice of the retransmission and before the notice of the first copy | The other order of the notices |
| `AckAfterNotices_reach` | It comes after both notices | The acknowledgement after each notice |
| `CancelThenNotice_reach` | After a cancellation, the release comes at a notice | Cancellation with a kernel use |
| `DeadlineThenNotice_reach` | After a request deadline, the release comes at a notice | A deadline with a kernel use |
| `CloseThenNotice_reach` | After a close, the release comes at a notice | Close with a kernel use |
| `RefusedRetry_reach` | The driver accepts a copy that it refused before | Refusal, then submission again |
| `RefusedRelease_reach` | The backing is released while a refused copy was never sent | Refusal, then the end of the stream |
| `SuffixLater_reach` | The protocol accepts the last slice after the peer acknowledged the first slice | Partial acceptance keeps the suffix for a later acceptance |

No submission follows the end of the stream, so a release at a notice after an end shows that
the notice was pending at the end.

## Limits

The model does not cover these items. Each one is outside the task, or a later task owns it.

- The input side: consumption of a received region, which releases only the consumed prefix
  (N004 tests it).
- A datagram that gathers views of two backings, such as framing from one and payload from
  another. Each backing then has its own obligations, but this model checks only one backing.
- Time and capacity. A refusal is a free choice. The budget's admission order and refusal record
  belong to rsasync R603 and the N004 tests.
- Progress. The model checks safety only. R000 checks that each terminal event comes and that
  detached debt ends.
- The TCP form. Its zero-copy notice waits for the peer's TCP acknowledgement, and R000 models
  that wait and the reset. The order of that notice against this protocol's acknowledgement is
  free here too, so the same composition applies.
- The model proves no Rust code. N004 and N604 add their transitions to the correspondence table
  when their code exists.

The shortest counterexamples, as actions and observations:

- `ReleaseAtAck_bad`: `Accept(1)`; `WriterDrop`; `Send(1,1)`; `Result(1,1)` (terminal);
  `Send(1,2)` (the retransmission is in the kernel); `PeerAck(1,1)`. The acknowledgement drops
  the retransmission's view, and the release runs while copy 2 is in `fly`.
- `DeadlineRelease_bad`: `Accept(2)`; `Send(1,1)`; `End("deadline")`. The release runs while
  copy 1 is in `fly`.
- `WholeRelease_bad`: `Accept(1)`. The writer has no view of slice 2, which the protocol did not
  accept.
- `ChargePerCopy_bad`: `Accept(2)`; `Send(1,1)`. The budget holds two charges of one backing.
- `RefusalLeak_bad`: `Accept(2)`; `Send(1,1)` (refused); `End("cancel")`. No obligation
  remains, and the release did not run.
- `DoubleRelease_bad`: `WriterDrop` (the release runs); `End("close")`. The hook runs a
  second time.
- `UnknownAck_bad`: `Accept(1)`; `Accept(2)`; `PeerAck(1,1)` for a number that was never sent.
  Slice 1 leaves the store, so the store never sends it.

## Evidence record

Run on 2026-11-13 on this Mac: macOS 27.2.1 (26B131), Darwin 27.2.0 arm64, MacBookPro18,3, 10
CPUs. The tools were temurin-jre `21.0.13+9`, tla2tools `1.8.0+d8fb231de4e4`, and Apalache
`0.62.4`. TLC ran each profile with the default memory settings. The command printed the model
digest `sha256:5f1d0c7861012a685f7d7f833990080261e20bb6bed400924524bd700b5613ed` (21 files).

```sh
cargo xtask model backing-release
```

| Profile | Verdict | Distinct states | Depth | Time |
| --- | --- | ---: | ---: | ---: |
| `BackingRelease.cfg` | ok: complete, 0 states left on the queue | 42,357 | 18 | 0.99 s |
| `BackingRelease.Copies3.cfg` | ok: complete, 0 states left on the queue | 776,789 | 24 | 16.96 s |
| `BackingRelease.Slices3.cfg` | ok: complete, 0 states left on the queue | 2,384,599 | 26 | 18.00 s |

Each of the seven known-bad profiles violated only its own property, in 0.41 to 1.04 seconds.
Each of the ten witnesses reached its target, in 0.39 to 1.32 seconds. Each profile fits the one-hour
budget on this host, so no evidence host was used. This is a complete bounded model result under
the assumptions and reductions above. It proves no Rust code.
