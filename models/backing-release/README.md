# Backing ownership across acceptance, retransmission, and kernel release

This is the design model of task N014. It checks how two ownership contracts compose in the
action vocabulary (N004, `src/drive.rs`) and the datagram form (N604). The protocol keeps output
until exact acceptance and peer acknowledgement. The runtime keeps each accepted submission until
its terminal event. The sources are in the local design `docs/specs/networking.md`: Backing and
Completion Ownership, Resource and Progress Bounds, and Datagram Form. The driver side is the
terminal-release contract of rsasync, which its model R000 checks (`models/operation-ownership/` in
rsasync). This model owns no driver. The Design Models section of `family-policy.md` in rsasync
sets the acceptance.

## The promise and a concrete failure

The promise: each charged backing stays alive and charged once while any holder retains a view of
it or the kernel can read it. Its release runs once, in the step that ends its last obligation.
One output can gather views of two backings, such as a frame header from a pool slot and its
payload from the body's backing. Each backing then keeps its own obligations and its own release.
A partial acceptance keeps the unaccepted suffix of each backing with its writer. A repeated
acknowledgement, or an acknowledgement of a number that the sender never sent, changes no
ownership.

Five concrete failures:

- The peer acknowledges the first copy of a slice while its retransmission is still in the
  kernel. The protocol frees the slice at the acknowledgement, and the kernel then reads freed
  pages for the retransmission (`ReleaseAtAck_bad`).
- The protocol accepts a prefix of a write and releases the whole region. The writer loses the
  suffix that it must write again (`WholeRelease_bad`).
- A request deadline ends the stream, and the binding frees the backing. The kernel still reads
  it for a send that has no terminal event yet (`DeadlineRelease_bad`).
- One datagram gathers a header and a payload of two backings. The driver keeps only the header's
  backing. The peer acknowledges the payload, and the payload's backing is released while the
  kernel reads it (`GatherOneView_bad`).
- The protocol accepts the whole header of a frame and none of its payload. It drops its views
  of the whole frame, so the payload's backing is released before the protocol accepts its bytes
  (`SpanRelease_bad`).

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
| `BackingRelease.Slices3.cfg`, `BackingRelease.Copies3.cfg` | One argued bound raised by one: a third slice, in each layout, or a second retransmission |
| `BackingRelease.<Name>_bad.cfg` | The known-bad variants: each must violate its one property |
| `BackingRelease.<Name>_reach.cfg` | The reachability witnesses: each must violate its `Not<Name>` property, which shows a trace to the target |

Each profile is a TLC configuration of `BackingRelease.tla`. The constant `Bug` selects a
known-bad variant; `"none"` is the design. Each profile checks each layout of its slices in
backings, because `Init` chooses the layout.

## What the model contains

| Part | Model |
| --- | --- |
| Backings | The layout `of[s]` gives the backing of each slice, and no step changes it. `Init` has each layout up to a renaming of the backings: with two slices, one backing of two slices, or two backings of one slice each. Each backing is charged once when it is created. A pool slot is a backing whose charge its pool took once, at the construction of the pool. For a slot, `charge[b]` counts the one slot that the backing holds, and the release returns that slot to the pool with no change of the pool's charge. Each holder keeps its own view of each backing that it uses |
| Writer | It gives its region of `Slices` slices, in stream order, to the protocol. `wr` is the stable offset: the first slice that the protocol has not accepted. The writer keeps a view of each backing of the suffix (`wv`) until it drops the suffix (`wgone`) |
| Retransmit store | `st[s]`: `wait` (not accepted), `store` (accepted, not acknowledged), `acked`, or `dropped` (the stream ended first). The store keeps a view of each slice in `store` (`sv`) |
| Outputs | Each slice goes out in up to `Copies` datagrams: the first one and each retransmission, each with a new packet number. One datagram is one output. It gathers the next copy of each slice in a set of stored slices, so it can hold views of two backings. `fl` holds the outputs in the kernel |
| Driver | `k[s][c]`: `none` (not submitted), `ref` (refused), `fly` (accepted, result pending), `zc` (the result came, and a notice follows), `res` (the result was terminal), or `ntc` (the notice came). All copies of one output change together. The driver keeps one view of each backing of each output in the kernel (`dv`) |
| End | `end`: `none`, or the end of the stream: `cancel`, `deadline`, or `close` |
| Release | The release hook of a backing runs in the step that drops its last view. `rel[b]` counts its runs, and `charge[b]` counts the charges that the budget holds for backing `b`. `xv[b]` counts views of `b` that no holder owns |
| History | `ev`: the kind of the last step. No action reads it. The acknowledgement property and the witnesses read it |

## Boundary assumptions

Each assumption is a fact of the runtime, the kernel, or the peer that the model uses. The
model checks no progress, so it gives no step fairness. The progress of each terminal event
belongs to R000 (`CloseReturns`, `DetachedReleased`).

| Assumption | Source | In the model |
| --- | --- | --- |
| An accepted submission gives the driver a stable backing for each of its regions until its terminal event. A refused submission returns the resources to the caller with a typed reason | rsasync design, Completion I/O and Buffers (the transition table); R000 `ReleaseOnce` | `Send` either adds a driver view of each backing of the output or refuses. A refusal changes no view |
| A zero-copy send has a send result and, when the kernel armed one, a later notice. The notice releases each buffer of the request, also each region of a gathered message. Without a notice, the result is terminal. A copying send is the second case | io_uring_prep_send_zc(3) (`IORING_CQE_F_MORE`, then `IORING_CQE_F_NOTIF`; `io_uring_prep_sendmsg_zc` for a gathered message); the terminal-event table of the rsasync design; R000 | `Result` goes to `zc` or `res`; `Notice` goes from `zc` to `ntc`. Each step changes all copies of the output |
| A datagram is sent whole or not at all | Datagram Form; the Datagram operations rule of Backing and Completion Ownership ("an unsent byte suffix never becomes a new datagram") | An output has no partial send |
| A notice comes when the kernel releases the pages, with no fixed order against other notices or against the peer's acknowledgement. A UDP send releases its pages after the device sends or drops the packet, and a delayed transmit completion can come after the peer's acknowledgement | Linux `Documentation/networking/msg_zerocopy.rst` ("the kernel returns a completion notification when it releases its hold on the shared pages") | `Result`, `Notice`, and `PeerAck` interleave in each order |
| Loss detection can declare a packet lost that the peer later acknowledges, so a retransmission and its original can both be in flight | RFC 9002 section 6 (packet and time thresholds) | `Send` of copy `c` needs only that copy `c - 1` was submitted |
| Acknowledgement frames repeat their ranges, so the sender gets a repeated acknowledgement as a normal event. A faulty peer can name a number that the sender never sent | RFC 9000 section 13.2.3; Datagram Form, Packet numbers row | `PeerAck(s, c)` is possible in each state, for each copy |
| Cancellation, a request deadline, and close stop interest and new production. They prove no kernel release. Close cancels each operation in flight, and each operation keeps its backing until its own terminal event | Backing and Completion Ownership; rsasync design, Completion I/O and Buffers ("No deadline converts uncertain completion into permission to release a resource"); R000 `CloseDone` | `End` drops the store's views and keeps each driver view |
| The writer, the peer, the loss detector, the driver's refusals, and the end of the stream are free | The design gives them no obligation | Each such step can come at any time, or never |

## Reductions and their soundness

Each reduction removes states or steps that no property can tell apart, or it adds behaviors.
Each known-bad variant still fails its own property under all of them (see the evidence record).

1. One writer region. This bound is proved, not argued. The layouts give the region each
   partition of its slices into backings. Other regions, such as other streams or the frames of
   other writers, have their own writers, stores, and outputs. The proof has three steps, and
   each one reads only the guards of the module:
   - A step of another region changes only the views of its own slices. Regions can share one
     budget, so the charge of another region can make the driver refuse a submission. `Send`
     can refuse each first submission of a copy in each state, with no budget guard, so such a
     refusal adds no behavior.
   - An output that gathers slices of this region and of another one projects to an output of
     this region's slices. `Send` has that output: its guard reads only `end` and the slices
     that it gathers. The output's result and notice change all of its copies in one step, so
     the projection has them in one step too.
   - A backing can have slices in two regions, for example one payload on two streams. Its views
     are then the sum of the views of the regions. An output that gathers slices of both regions
     can keep one view of the backing for both. Only a positive count matters (reduction 6), so
     the projection gives that view to each region, and it drops in the same step in each.

     No step adds a view of a backing of which its region holds none. `Accept` needs the
     writer's suffix, which `SuffixKept` ties to a view. `Send` needs `st[s] = "store"`, which
     holds exactly when `s \in sv`: `Init` starts both empty, and only `Accept`, `PeerAck`, and
     `End` change them, together (`BackingRelease.tla` lines 159-160, 249-250, and 268-269). A
     later region gets its first view of a shared backing as a clone or a view of a live `Lease`
     of `rstypes`, so no region adds a view to a backing whose count is zero.

     So the views of a region are positive exactly while an obligation of that region holds, by
     `AliveWhileHeld` and `ReleasedAfterLast`. The sum is positive exactly while an obligation of
     any region holds. The one release, and the end of the one charge, then follow the last
     obligation of all regions.

   No property reads another region. So each behavior with more regions projects to a behavior
   of this model for each region, and each property holds for each projection. The failure that
   this bound could hide is an output that keeps a view of only one of its backings. The main
   bound reaches it: `GatherOneView_bad` violates `AliveWhileHeld`.
2. A refused output is not refused again when each of its copies was refused before. That
   refusal changes no view and no other variable except `ev`, so it repeats a state that the
   model has.
3. The kernel posts a result or a notice and the driver harvests it in one step, as in R000
   (its reduction 5). Between the two, no step of this model reads the event.
4. Cancellation, a request deadline, and close are one `End` step with a label. Each one ends
   production and the store's retention, and each leaves each kernel use to its terminal event.
   A reset, the end of the parent connection, and the integrity end after a faulty
   acknowledgement have the same ownership effect. `End` can come in each state, so the model
   has their behaviors.
5. Acceptance takes whole slices. An acceptance that ends inside a slice splits that slice in
   two slices of the same backing, and the split is a model with one more slice (`Slices3`).
6. An output keeps one view of each backing that it gathers. An implementation can keep one view
   for each region, such as the header and the tag of one framing slot. All views of one output
   drop in its terminal step, so the count of a backing reaches zero in the same step.
7. A layout is one of each renaming of the backings. No action or property reads the name of a
   backing, so a renamed layout has the same behaviors with the names changed.

## Correspondence

Each action is one atomic step. The N004 column names the code in `src/drive.rs` (module
`rsnetwork::drive`). N604 does not exist yet, so its column names the transition that it must
build, and N604 replaces it with its code. A change to either side reopens this check.

HTTP/2 (N202) is the first writer of two backings. `h2::Connection::data` (`src/h2/connection.rs`)
pushes a DATA frame to `Outbound` as two regions: the frame header in a slot of its pool, and a
view of the caller's payload. That frame is the layout `<<1, 2>>`. The header's backing is a pool
slot: `ChargedOnce` reads its `charge` as the slot that it holds, which its release returns to the
pool.

| Action | Design rule | N004 transition | N604 transition | R000 action |
| --- | --- | --- | --- | --- |
| `Accept(j)` | Backing and Completion Ownership: exact acceptance releases only the accepted prefix; partial output advances a stable offset and does not recopy the unchanged suffix | `Outbound::ack(id, accepted)`: the acknowledgement of the outstanding `Output` with the exact accepted bytes. The queue keeps a view of the suffix, at its address | The side flow takes stream bytes within the granted receive credit (Receive credit row) | — |
| `WriterDrop` | Retention after a call needs an owning lease; the caller drops it | The drop of the `Outbound` queue, or of its view of the suffix | The end of a cancelled write | — |
| `Send(G)` | Completion I/O: an accepted submission gives the driver its backings; a refused one returns them. Resource and Progress Bounds: backpressure is explicit, and submission pressure is not network loss | `Outbound::submit` gives an `Output`, whose region is a view of its own: an output of one region, so `G` has the slices of one backing. A refusal is `ack(id, 0)` and `Progress::Blocked(Blocked::Capacity(n))` | Retransmission with a new packet number; a zero-copy UDP send that gathers the header and the tag from a framing slot and the payload from the writer's backing | `BeginTx` (`Submit`), and `Table::withdraw` for a refused push |
| `Result(o)` | Terminal-event table: the send result, with or without `IORING_CQE_F_MORE` | — | — | `Complete("tx")` |
| `Notice(o)` | Terminal-event table: the zero-copy notice releases the backings of its own request | — | A payload region stays owned until the zero-copy notice of each datagram that carried it | `Notice(g)` |
| `PeerAck(s, c)` | Datagram Form: acknowledgements name packet numbers; an acknowledgement of a number that the sender never sent shows a faulty peer | `AckError::Duplicate` and `AckError::Unknown`: the acknowledgement refuses and changes no state | RFC 9002 acknowledgement processing; the end of a range's retention at its acknowledgement | — |
| `End(why)` | Backing and Completion Ownership: cancellation, a dropped future, close, and a request deadline prove no release; final completion releases the remaining ownership | `Progress::Terminal`, and the errors of `Kind::Cancelled` and `Kind::Deadline`. The host keeps each `Output` until its terminal event | Reset, the end of the parent, and the integrity outcome | `CloseDone`, and `EndTask` for a close at shutdown |

## Properties

| Property | Acceptance text | Kind |
| --- | --- | --- |
| `AliveWhileHeld` | Each retained reference and kernel obligation keeps its backing alive | Invariant |
| `ChargedOnce` | The budget charges each backing once while it is alive, and not after its release. A pool slot holds one slot of its pool while it is alive, and its release returns that slot | Invariant |
| `ReleaseAtMostOnce` | Release occurs once: the hook of a backing never runs a second time | Invariant |
| `ReleasedAfterLast` | Release occurs after the last obligation ends: when no obligation of a backing remains, its hook has run. It runs in the step that drops the last view, so a leak shows as a violation | Invariant |
| `SuffixKept` | Partial acceptance preserves the suffix: the writer keeps a view of each backing of a slice that the protocol has not accepted, until the writer drops it | Invariant |
| `AckKeepsOwnership` | Repeated or unknown acknowledgements change no ownership: such a step changes no variable except `ev` | Action property |

Each invariant applies to each backing of the layout. `TypeOK` is also an invariant of each main
profile. The obligations of a backing are the writer's unaccepted suffix in it, each of its
slices in the store, and each copy of its slices in `fly` or `zc`. They come from the logical
state, not from the views, so a holder that drops its view too early shows as a violation.
`AckKeepsOwnership` reads the class of the step from `ev`. TLC checks an action property on each
step that the search generates.

## Bounds and faults

The declared bounds: one writer region (proved, reduction 1), two slices in each layout, and
two copies of each slice. Two slices give one partial acceptance and a suffix: inside one
backing, or at the end of the first of two backings. They also give an output that gathers two
backings. Two copies give an original and a retransmission, so one copy's notice can remain at
the acknowledgement of the other. These two bounds are argued, not proved, so each one has a
profile with that bound raised by one. `Slices3` checks the five layouts of three slices, and
`Copies3` the two layouts of two slices.

The faults and free choices: the protocol accepts any prefix, gathers any set of stored slices
in one datagram, declares any submitted copy lost, and sends its next copy. The driver accepts
each output, and it can refuse each output that has a first submission of a copy. The kernel
gives a result with or without a notice, and results, notices, and acknowledgements come in each
order. The peer repeats acknowledgements, and a faulty peer names numbers that the sender never
sent. The stream ends by cancellation, deadline, or close in any state. The writer drops its
suffix at any time.

## Known-bad variants

Each variant changes one rule through the constant `Bug`. Its profile checks only its own
property, at the declared bounds.

| Profile | Changed rule | Must violate |
| --- | --- | --- |
| `ReleaseAtAck_bad` | The first acknowledgement of a slice drops the driver's views of its backing in each output that carries another copy of the slice. So the backing is released while a retransmission notice remains | `AliveWhileHeld` |
| `WholeRelease_bad` | A partial acceptance releases the whole region, also the writer's suffix | `SuffixKept` |
| `DeadlineRelease_bad` | A request deadline drops the driver's views as if the kernel had released them | `AliveWhileHeld` |
| `ChargePerCopy_bad` | The driver charges each backing of an output again for each accepted output, until its terminal event | `ChargedOnce` |
| `RefusalLeak_bad` | The binding keeps the views of a refused submission, so no release follows the last obligation | `ReleasedAfterLast` |
| `DoubleRelease_bad` | A close runs the release hook again for each backing that no view holds | `ReleaseAtMostOnce` |
| `UnknownAck_bad` | An acknowledgement of a number that the sender never sent ends the store's retention of its slice | `AckKeepsOwnership` |
| `GatherOneView_bad` | The driver keeps a view of the backing of the first slice of an output only. So the other backing of a gathered output is released while the kernel reads it | `AliveWhileHeld` |
| `SpanRelease_bad` | A partial acceptance that covers the first region of the output, the run of slices of one backing, drops each view of the writer. So the next backing is released while the protocol has not accepted its bytes | `AliveWhileHeld` |

`SpanRelease_bad` stays for its own defect: a release of the next backing at a partial acceptance
that ends at the end of a backing. At two slices, its counterexample state equals the state of
`WholeRelease_bad`. So it shows that `AliveWhileHeld` also catches the header-and-payload case,
which `WholeRelease_bad` shows with `SuffixKept`. In the layout of one backing, its partial
acceptance keeps the suffix.

## Reachability

Each witness profile must reach its target at the declared bounds.

| Profile | Target | Shows |
| --- | --- | --- |
| `AckBeforeNotices_reach` | The first acknowledgement of a slice comes while the notices of both copies are pending | The acknowledgement before each notice |
| `AckAfterFirstNotice_reach` | It comes after the notice of the first copy and before the notice of the retransmission | The acknowledgement between the notices |
| `AckAfterRetransmitNotice_reach` | It comes after the notice of the retransmission and before the notice of the first copy | The other order of the notices |
| `AckAfterNotices_reach` | It comes after both notices | The acknowledgement after each notice |
| `CancelThenNotice_reach` | After a cancellation, the release of the last backing comes at a notice | Cancellation with a kernel use |
| `DeadlineThenNotice_reach` | After a request deadline, the release of the last backing comes at a notice | A deadline with a kernel use |
| `CloseThenNotice_reach` | After a close, the release of the last backing comes at a notice | Close with a kernel use |
| `RefusedRetry_reach` | The driver accepts a copy that it refused before | Refusal, then submission again |
| `RefusedRelease_reach` | A backing is released while a refused copy of its slice was never sent | Refusal, then the end of the stream |
| `SuffixLater_reach` | The protocol accepts the last slice after the peer acknowledged the first slice | Partial acceptance keeps the suffix for a later acceptance |
| `GatherWait_reach` | An output that gathers two backings waits for its notice, and no other holder keeps either backing | The kernel use of one output keeps both backings |
| `SplitRelease_reach` | One backing is released while the writer still holds the next backing | Partial acceptance at the end of a backing, and the release of backing 1 at its own last obligation while backing 2 is held |

No submission follows the end of the stream, so a release at a notice after an end shows that
the notice was pending at the end.

## Limits

The model does not cover these items. Each one is outside the task, or a later task owns it.

- The input side: consumption of a received region, which releases only the consumed prefix
  (`Inbound::consume`; `tests/drive.rs` tests it).
- Time and capacity. A refusal is a free choice. The budget's admission order belongs to rsasync
  R603 and N007. `tests/drive.rs` tests that a refused submission keeps its bytes.
- Progress. The model checks safety only. R000 checks that each terminal event comes and that
  detached debt ends.
- The TCP form. Its zero-copy notice waits for the peer's TCP acknowledgement, and R000 models
  that wait and the reset. The order of that notice against this protocol's acknowledgement is
  free here too, so the same composition applies. On IOCP, an explicit cancel of a TCP send in
  the kernel aborts the whole connection, and the backing waits for its packet (rsasync R507).
- The model proves no Rust code. N004 added its code to the correspondence table, and N604 adds
  its code when it exists.

The shortest counterexamples, as actions and observations, with the layout of each trace:

- `ReleaseAtAck_bad`, layout `<<1, 2>>`: `Accept(2)`; `Send({1})` (copy 1); `Send({1})` (copy 2,
  the retransmission); the terminal `Result` of copy 1; `PeerAck(1,1)`. The acknowledgement drops
  the retransmission's view of backing 1, and its release runs while copy 2 is in `fly`.
- `DeadlineRelease_bad`, layout `<<1, 2>>`: `Accept(1)`; `Send({1})`; `End("deadline")`. Backing
  1 is released while copy 1 is in `fly`.
- `WholeRelease_bad`, layout `<<1, 2>>`: `Accept(1)`. The writer has no view of backing 2, whose
  slice the protocol did not accept.
- `ChargePerCopy_bad`, layout `<<1, 1>>`: `Accept(1)`; `Send({1})`. The budget holds two charges
  of one backing.
- `RefusalLeak_bad`, layout `<<1, 1>>`: `Accept(2)`; `Send({1})` (refused); `End("cancel")`. No
  obligation remains, and the release did not run.
- `DoubleRelease_bad`, layout `<<1, 1>>`: `WriterDrop` (the release runs); `End("close")`. The
  hook runs a second time.
- `UnknownAck_bad`, layout `<<1, 1>>`: `Accept(1)`; `PeerAck(1,1)` for a number that was never
  sent. Slice 1 leaves the store, so the store never sends it.
- `GatherOneView_bad`, layout `<<1, 2>>`: `Accept(2)`; `Send({1, 2})`, one output with a driver
  view of backing 1 only; `PeerAck(2,1)`. The store drops slice 2, and backing 2 is released
  while its copy is in `fly`.
- `SpanRelease_bad`, layout `<<1, 2>>`: `Accept(1)`. The writer drops its view of backing 2, and
  backing 2 is released before the protocol accepts its slice.

## Evidence record

Each profile ran one time, at the model digest
`sha256:b55e2778a85da14e3d2fff6205e4a61270c49d7b6e9c0fb4350fe29adefd7a74` (25 files) that the
command printed. The tools were temurin-jre `21.0.13+9`, tla2tools
`1.8.0+bc1b506bdcad`, and Apalache `0.62.4`. TLC ran each profile with `-workers auto`.

```sh
cargo xtask model backing-release/<profile>
```

Two hosts ran the profiles:

- This Mac, on 2026-11-16: macOS 27.2.1 (26B131), Darwin 27.2.0 arm64, MacBookPro18,3, 10 CPUs,
  16 GiB. TLC used the default memory settings. Other sessions loaded the Mac to a load average
  of 47 to 60, so its times are functional evidence only.
- EC2 `aws-linux-arm64-debian12`, from 2026-11-17T03:17:03Z to 03:22:51Z: c8g.4xlarge
  (`ami-06bcda7571e75165c`), 16 vCPUs, 32 GiB, Debian 12, Linux 6.1.0-54-cloud-arm64. The host
  was created for dev-machine run `20261117T031314Z-81397` and deleted after it. TLC used
  `--tlc-heap-mib=20480 --tlc-fp-mib=4096` and a cap of 3,600 seconds.

| Profile | Host | Verdict | Distinct states | Depth | Time |
| --- | --- | --- | ---: | ---: | ---: |
| `BackingRelease.cfg` | this Mac | ok: complete, 0 states left on the queue | 107,482 | 16 | 13.37 s |
| `BackingRelease.Copies3.cfg` | this Mac | ok: complete, 0 states left on the queue | 2,760,450 | 21 | 243.66 s |
| `BackingRelease.Slices3.cfg` | EC2 | ok: complete, 0 states left on the queue | 25,161,615 | 22 | 335.02 s |

Each known-bad profile checks one property, and on this Mac it violated that property, in 1.45
to 5.89 seconds:

- `AliveWhileHeld`: `ReleaseAtAck_bad`, `DeadlineRelease_bad`, `GatherOneView_bad`, and
  `SpanRelease_bad`.
- `SuffixKept`: `WholeRelease_bad`.
- `ChargedOnce`: `ChargePerCopy_bad`.
- `ReleasedAfterLast`: `RefusalLeak_bad`.
- `ReleaseAtMostOnce`: `DoubleRelease_bad`.
- `AckKeepsOwnership`: `UnknownAck_bad`.

Each of the twelve witnesses reached its target on this Mac, in 1.74 to 15.74 seconds.
A first run of `Slices3` on this Mac stopped after its 10-minute sample, at 7,191,954 distinct
states with work on the queue, because it could not finish within its cap there. It is not
evidence.

The EC2 run reported exit, collection, and teardown 0, and `dev-machine status rsnetwork
aws-linux-arm64-debian12` then showed no AWS instance or EBS volume. The archive
`~/.local/state/model-evidence/rsnetwork/N014/20261116-backing-release-evidence.tar.gz` (SHA-256
`68c186be4e71956852907acc7a5809c01f88e4fd144eed7f9538a6e54b2e3994`) keeps the output, source
copy, and traces of each profile, and the remote run record. This is a complete bounded model
result under the assumptions and reductions above. It proves no Rust code.
