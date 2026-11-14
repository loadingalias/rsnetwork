--------------------------- MODULE BackingRelease ---------------------------
(***************************************************************************)
(* One charged backing across protocol acceptance, retransmission, peer   *)
(* acknowledgement, and kernel release (networking.md, "Backing and        *)
(* Completion Ownership", "Resource and Progress Bounds", and "Datagram    *)
(* Form"). The driver side is the terminal-release contract of rsasync    *)
(* (its model R000); this model owns no driver.                           *)
(*                                                                         *)
(* A writer gives its region of one backing, Slices slices in stream      *)
(* order, to the protocol. The protocol accepts a prefix, and the writer   *)
(* keeps the suffix at a stable offset. The retransmit store keeps each    *)
(* accepted slice until the peer acknowledges it or the stream ends. The   *)
(* protocol sends each slice in up to Copies datagrams, each with a new    *)
(* packet number, as zero-copy sends. The driver keeps each accepted       *)
(* submission until its terminal event: the send result, or the notice     *)
(* that follows a result with a notice armed.                              *)
(*                                                                         *)
(* Each holder keeps its own view of the backing. The release hook runs    *)
(* in the step that drops the last view. The properties compare the views  *)
(* with the obligations that the design names: the writer's unaccepted     *)
(* suffix, the store's unacknowledged slices, and each kernel use.         *)
(*                                                                         *)
(* Bug selects one known-bad variant. "none" is the design.                *)
(***************************************************************************)
EXTENDS Integers, FiniteSets

CONSTANTS
    Slices,  \* The slices of the backing, in stream order.
    Copies,  \* The datagrams that can carry one slice: the first one and each retransmission.
    Bug      \* "none", or the known-bad variant.

Bugs == {"none", "ReleaseAtAck", "WholeRelease", "DeadlineRelease",
         "ChargePerCopy", "RefusalLeak", "UnknownAck", "DoubleRelease"}

ASSUME
    /\ Slices \in Nat \ {0}
    /\ Copies \in Nat \ {0}
    /\ Bug \in Bugs

S == 1 .. Slices
C == 1 .. Copies
Ends == {"cancel", "deadline", "close"}
Events == {"init", "accept", "drop", "send", "retry", "refuse", "result",
           "notice", "ack", "repeat", "unknown", "end"}

VARIABLES
    wr,      \* The stable offset: the first slice that the protocol has not accepted.
    wgone,   \* The writer dropped its unaccepted suffix.
    st,      \* st[s]: "wait" (not accepted), "store" (accepted, not acknowledged),
             \* "acked" (the peer acknowledged it), or "dropped" (the stream ended first).
    k,       \* k[s][c]: copy c of slice s at the driver. "none": not submitted.
             \* "ref": refused, so the protocol submits it again. "fly": accepted,
             \* the result is pending. "zc": the result came, and its notice follows.
             \* "res": the result was terminal. "ntc": the notice came.
    end,     \* "none", or the end of the stream.
    wv,      \* The writer holds a view of its suffix.
    sv,      \* The slices of which the retransmit store holds a view.
    dv,      \* The copies of which the driver holds a view.
    xv,      \* Views that no holder owns: leaked views.
    rel,     \* How many times the release hook ran.
    charge,  \* How many charges of the backing the budget holds.
    ev       \* The kind of the last step. No action reads it.

vars == <<wr, wgone, st, k, end, wv, sv, dv, xv, rel, charge, ev>>

\* Everything except the history variable ev.
Own == <<wr, wgone, st, k, end, wv, sv, dv, xv, rel, charge>>

Views == (IF wv THEN 1 ELSE 0) + Cardinality(sv) + Cardinality(dv) + xv

InKernel(s, c) == k[s][c] \in {"fly", "zc"}

\* An obligation that the design names keeps the backing: the writer's
\* unaccepted suffix, a slice that the store must send again, or a kernel use.
Held ==
    \/ wr <= Slices /\ ~wgone
    \/ \E s \in S : st[s] = "store"
    \/ \E s \in S, c \in C : InKernel(s, c)

\* The release hook runs in the step that drops the last view. A bug runs it
\* `extra` more times, or charges the backing again with `charged`. Each
\* action ends with it, after every other update.
Settle(extra, charged) ==
    LET hook == (IF Views > 0 /\ Views' = 0 THEN 1 ELSE 0) + extra
    IN /\ rel' = rel + hook
       /\ charge' = charge + charged - hook

-----------------------------------------------------------------------------

Init ==
    /\ wr = 1
    /\ wgone = FALSE
    /\ st = [s \in S |-> "wait"]
    /\ k = [s \in S |-> [c \in C |-> "none"]]
    /\ end = "none"
    /\ wv = TRUE
    /\ sv = {}
    /\ dv = {}
    /\ xv = 0
    /\ rel = 0
    /\ charge = 1
    /\ ev = "init"

\* The protocol accepts the slices wr .. j of the writer's region. Each
\* accepted slice gets a view in the store. The writer keeps a view of the
\* suffix at the new stable offset, with no copy.
Accept(j) ==
    /\ end = "none"
    /\ ~wgone
    /\ wr <= j
    /\ UNCHANGED <<wgone, k, end, dv, xv>>
    /\ wr' = j + 1
    /\ st' = [s \in S |-> IF s \in wr .. j THEN "store" ELSE st[s]]
    /\ sv' = sv \cup (wr .. j)
    /\ wv' = (j < Slices /\ Bug # "WholeRelease")
    /\ ev' = "accept"
    /\ Settle(0, 0)

\* The writer drops its unaccepted suffix: a cancelled write, or a caller
\* that keeps no use for it after the stream ended.
WriterDrop ==
    /\ ~wgone
    /\ wr <= Slices
    /\ UNCHANGED <<wr, st, k, end, sv, dv, xv>>
    /\ wgone' = TRUE
    /\ wv' = FALSE
    /\ ev' = "drop"
    /\ Settle(0, 0)

\* The protocol sends copy c of slice s with a new packet number: the first
\* copy, or a retransmission after it declared copy c - 1 lost, which can be
\* a spurious loss. The driver accepts the submission and keeps a view until
\* the terminal event, or it refuses the submission. Then the binding gets
\* its view back and drops it, and the protocol submits the same copy again.
Send(s, c) ==
    /\ end = "none"
    /\ st[s] = "store"
    /\ k[s][c] \in {"none", "ref"}
    /\ IF c = 1 THEN TRUE ELSE k[s][c - 1] \notin {"none", "ref"}
    /\ UNCHANGED <<wr, wgone, st, end, wv, sv>>
    /\ \/ /\ k' = [k EXCEPT ![s][c] = "fly"]
          /\ dv' = dv \cup {<<s, c>>}
          /\ xv' = xv
          /\ ev' = IF k[s][c] = "ref" THEN "retry" ELSE "send"
          /\ Settle(0, IF Bug = "ChargePerCopy" THEN 1 ELSE 0)
       \/ /\ k[s][c] = "none"
          /\ k' = [k EXCEPT ![s][c] = "ref"]
          /\ dv' = dv
          /\ xv' = IF Bug = "RefusalLeak" THEN xv + 1 ELSE xv
          /\ ev' = "refuse"
          /\ Settle(0, 0)

\* The send result of copy c. With a notice armed, the driver keeps its view
\* for the notice. Without one, the result is terminal and the view drops.
Result(s, c) ==
    /\ k[s][c] = "fly"
    /\ UNCHANGED <<wr, wgone, st, end, wv, sv, xv>>
    /\ \/ /\ k' = [k EXCEPT ![s][c] = "zc"]
          /\ dv' = dv
          /\ ev' = "result"
          /\ Settle(0, 0)
       \/ /\ k' = [k EXCEPT ![s][c] = "res"]
          /\ dv' = dv \ {<<s, c>>}
          /\ ev' = "result"
          /\ Settle(0, IF Bug = "ChargePerCopy" THEN -1 ELSE 0)

\* The zero-copy notice of copy c: the kernel no longer reads the pages, and
\* the driver drops its view.
Notice(s, c) ==
    /\ k[s][c] = "zc"
    /\ UNCHANGED <<wr, wgone, st, end, wv, sv, xv>>
    /\ k' = [k EXCEPT ![s][c] = "ntc"]
    /\ dv' = dv \ {<<s, c>>}
    /\ ev' = "notice"
    /\ Settle(0, IF Bug = "ChargePerCopy" THEN -1 ELSE 0)

\* An acknowledgement frame names the packet number of copy c of slice s.
\* The peer can repeat it, acknowledge another copy of a slice that it
\* acknowledged, or, when faulty, name a number that the sender never sent.
\* Only the first acknowledgement of a sent copy ends the store's retention.
PeerAck(s, c) ==
    LET known == k[s][c] \notin {"none", "ref"}
        first == st[s] = "store" /\ (known \/ Bug = "UnknownAck")
    IN /\ UNCHANGED <<wr, wgone, k, end, wv, xv>>
       /\ st' = IF first THEN [st EXCEPT ![s] = "acked"] ELSE st
       /\ sv' = IF first THEN sv \ {s} ELSE sv
       /\ dv' = IF first /\ Bug = "ReleaseAtAck"
                THEN dv \ {<<s, d>> : d \in C \ {c}}
                ELSE dv
       /\ ev' = CASE ~known -> "unknown"
                  [] st[s] = "store" -> "ack"
                  [] OTHER -> "repeat"
       /\ Settle(0, 0)

\* The stream ends: a cancellation, a request deadline, or a close. It stops
\* new acceptance and new sends, and the store drops each slice that it kept.
\* Each kernel use keeps its view until its own terminal event.
\* DoubleRelease: the close runs the hook for a backing that no view holds.
End(why) ==
    /\ end = "none"
    /\ UNCHANGED <<wr, wgone, k, wv, xv>>
    /\ end' = why
    /\ st' = [s \in S |-> IF st[s] = "store" THEN "dropped" ELSE st[s]]
    /\ sv' = {}
    /\ dv' = IF why = "deadline" /\ Bug = "DeadlineRelease" THEN {} ELSE dv
    /\ ev' = "end"
    /\ Settle(IF why = "close" /\ Bug = "DoubleRelease" /\ Views = 0 THEN 1 ELSE 0, 0)

Next ==
    \/ \E j \in S : Accept(j)
    \/ WriterDrop
    \/ \E s \in S, c \in C :
          Send(s, c) \/ Result(s, c) \/ Notice(s, c) \/ PeerAck(s, c)
    \/ \E why \in Ends : End(why)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* Properties *)

TypeOK ==
    /\ wr \in 1 .. Slices + 1
    /\ wgone \in BOOLEAN
    /\ st \in [S -> {"wait", "store", "acked", "dropped"}]
    /\ k \in [S -> [C -> {"none", "ref", "fly", "zc", "res", "ntc"}]]
    /\ end \in {"none"} \cup Ends
    /\ wv \in BOOLEAN
    /\ sv \subseteq S
    /\ dv \subseteq S \X C
    /\ xv \in Nat
    /\ rel \in Nat
    /\ charge \in Int
    /\ ev \in Events

\* Each retained reference and each kernel use keeps the backing alive.
AliveWhileHeld == Held => rel = 0

\* The budget counts the backing once while it is alive, and not after its
\* release.
ChargedOnce == charge = IF rel = 0 THEN 1 ELSE 0

\* The release runs at most once.
ReleaseAtMostOnce == rel <= 1

\* The release has run when no obligation remains, so it runs in the step that
\* ends the last obligation.
ReleasedAfterLast == ~Held => rel = 1

\* After a partial acceptance, the writer keeps a view of the suffix that the
\* protocol has not accepted, until the writer drops it.
SuffixKept == (wr <= Slices /\ ~wgone) => wv

\* A repeated acknowledgement and an acknowledgement of a number that the
\* sender never sent change no ownership.
AckKeepsOwnership == [][ev' \in {"repeat", "unknown"} => UNCHANGED Own]_vars

-----------------------------------------------------------------------------
(* Reachability targets. Each witness profile names one Not<Target>       *)
(* property, and its violation shows a trace to the target.               *)

\* The last step was the first acknowledgement of slice s, and no other
\* slice is acknowledged, so the step acknowledged s.
AckedNow(s) == ev = "ack" /\ st[s] = "acked" /\ \A t \in S \ {s} : st[t] # "acked"

\* The four orders of the acknowledgement and the notices of two copies.
NotAckBeforeNotices == ~\E s \in S : AckedNow(s) /\ k[s][1] = "zc" /\ k[s][2] = "zc"
NotAckAfterFirstNotice == ~\E s \in S : AckedNow(s) /\ k[s][1] = "ntc" /\ k[s][2] = "zc"
NotAckAfterRetransmitNotice == ~\E s \in S : AckedNow(s) /\ k[s][1] = "zc" /\ k[s][2] = "ntc"
NotAckAfterNotices == ~\E s \in S : AckedNow(s) /\ k[s][1] = "ntc" /\ k[s][2] = "ntc"

\* A stream end with a kernel use: no submission follows an end, so a later
\* release at a notice shows that the notice was pending at the end.
NotEndedThenNotice(why) == ~(end = why /\ ev = "notice" /\ rel = 1)
NotCancelThenNotice == NotEndedThenNotice("cancel")
NotDeadlineThenNotice == NotEndedThenNotice("deadline")
NotCloseThenNotice == NotEndedThenNotice("close")

\* A refused copy is submitted again and accepted.
NotRefusedRetry == ev # "retry"

\* The backing is released while a refused copy was never sent.
NotRefusedRelease == ~(rel = 1 /\ \E s \in S, c \in C : k[s][c] = "ref")

\* The protocol accepts the last slice after the peer acknowledged the first.
NotSuffixLater == ~(ev = "accept" /\ wr = Slices + 1 /\ st[1] = "acked")

=============================================================================
