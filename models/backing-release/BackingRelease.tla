--------------------------- MODULE BackingRelease ---------------------------
(***************************************************************************)
(* Charged backings across protocol acceptance, retransmission, peer      *)
(* acknowledgement, and kernel release (networking.md, "Backing and        *)
(* Completion Ownership", "Resource and Progress Bounds", and "Datagram    *)
(* Form"). The driver side is the terminal-release contract of rsasync    *)
(* (its model R000); this model owns no driver.                           *)
(*                                                                         *)
(* A writer gives its region, Slices slices in stream order, to the       *)
(* protocol. The layout puts each slice in a backing: for example, all in *)
(* one backing, or a frame header in one backing and its payload in       *)
(* another. The protocol accepts a prefix, and the writer keeps the       *)
(* suffix at a stable offset. The retransmit store keeps each accepted    *)
(* slice until the peer acknowledges it or the stream ends. The protocol  *)
(* sends each slice in up to Copies datagrams, each with a new packet     *)
(* number, as zero-copy sends. One datagram is one output, and it can     *)
(* gather stored slices of different backings. The driver keeps each      *)
(* accepted output until its terminal event: the send result, or the     *)
(* notice that follows a result with a notice armed.                      *)
(*                                                                         *)
(* Each holder keeps its own view of each backing that it uses. The       *)
(* release hook of a backing runs in the step that drops its last view.   *)
(* The properties compare the views of each backing with the obligations  *)
(* that the design names: the writer's unaccepted suffix, the store's     *)
(* unacknowledged slices, and each kernel use.                            *)
(*                                                                         *)
(* Bug selects one known-bad variant. "none" is the design.                *)
(***************************************************************************)
EXTENDS Integers, FiniteSets

CONSTANTS
    Slices,  \* The slices of the writer's region, in stream order.
    Copies,  \* The datagrams that can carry one slice: the first one and each retransmission.
    Bug      \* "none", or the known-bad variant.

Bugs == {"none", "ReleaseAtAck", "WholeRelease", "DeadlineRelease",
         "ChargePerCopy", "RefusalLeak", "UnknownAck", "DoubleRelease",
         "GatherOneView", "SpanRelease"}

ASSUME
    /\ Slices \in Nat \ {0}
    /\ Copies \in Nat \ {0}
    /\ Bug \in Bugs

S == 1 .. Slices
C == 1 .. Copies
B == S  \* The names of the backings: a layout has at most one backing for each slice.
Ends == {"cancel", "deadline", "close"}
Events == {"init", "accept", "drop", "send", "retry", "refuse", "result",
           "notice", "ack", "repeat", "unknown", "end"}

Max(X) == CHOOSE m \in X : \A x \in X : x <= m
Min(X) == CHOOSE m \in X : \A x \in X : m <= x

\* Each layout of the slices in backings, one for each renaming of the
\* backings: slice 1 is in backing 1, and each later slice is in a backing of
\* an earlier slice or in the next new one. No action or property reads the
\* name of a backing, so a renamed layout adds no behavior.
Layouts == {f \in [S -> B] :
              \A s \in S : f[s] <= 1 + Max({0} \cup {f[t] : t \in 1 .. s - 1})}

VARIABLES
    of,      \* of[s]: the backing of slice s. It does not change.
    wr,      \* The stable offset: the first slice that the protocol has not accepted.
    wgone,   \* The writer dropped its unaccepted suffix.
    st,      \* st[s]: "wait" (not accepted), "store" (accepted, not acknowledged),
             \* "acked" (the peer acknowledged it), or "dropped" (the stream ended first).
    k,       \* k[s][c]: copy c of slice s at the driver. "none": not submitted.
             \* "ref": refused, so the protocol submits it again. "fly": accepted,
             \* the result is pending. "zc": the result came, and its notice follows.
             \* "res": the result was terminal. "ntc": the notice came.
    fl,      \* The outputs in the kernel, each one the set of copies <<s, c>> that it gathers.
    end,     \* "none", or the end of the stream.
    wv,      \* The backings of which the writer holds a view.
    sv,      \* The slices of which the retransmit store holds a view.
    dv,      \* The driver's views: <<o, b>> for output o and backing b.
    xv,      \* xv[b]: the views of backing b that no holder owns: leaked views.
    rel,     \* rel[b]: how many times the release hook of backing b ran.
    charge,  \* charge[b]: how many charges of backing b the budget holds.
    ev       \* The kind of the last step. No action reads it.

vars == <<of, wr, wgone, st, k, fl, end, wv, sv, dv, xv, rel, charge, ev>>

\* Everything except the history variable ev.
Own == <<of, wr, wgone, st, k, fl, end, wv, sv, dv, xv, rel, charge>>

\* The backings that the layout uses.
Used == {of[s] : s \in S}

\* The backings of the slices a .. e.
BackingsIn(a, e) == {of[s] : s \in a .. e}

\* The backings that output o gathers.
Out(o) == {of[p[1]] : p \in o}

Views(b) ==
    (IF b \in wv THEN 1 ELSE 0)
    + Cardinality({s \in sv : of[s] = b})
    + Cardinality({v \in dv : v[2] = b})
    + xv[b]

InKernel(s, c) == k[s][c] \in {"fly", "zc"}

\* An obligation that the design names keeps backing b: the writer's
\* unaccepted suffix in b, a slice of b that the store must send again, or a
\* kernel use of a slice of b.
Held(b) ==
    \/ ~wgone /\ b \in BackingsIn(wr, Slices)
    \/ \E s \in S : of[s] = b /\ st[s] = "store"
    \/ \E s \in S, c \in C : of[s] = b /\ InKernel(s, c)

Zero == [b \in B |-> 0]

\* The release hook of each backing runs in the step that drops its last
\* view. A bug runs it extra[b] more times, or charges backing b again with
\* charged[b]. Each action ends with it, after every other update.
Settle(extra, charged) ==
    LET hook == [b \in B |-> (IF Views(b) > 0 /\ (Views(b))' = 0 THEN 1 ELSE 0) + extra[b]]
    IN /\ rel' = [b \in B |-> rel[b] + hook[b]]
       /\ charge' = [b \in B |-> charge[b] + charged[b] - hook[b]]

-----------------------------------------------------------------------------

Init ==
    /\ of \in Layouts
    /\ wr = 1
    /\ wgone = FALSE
    /\ st = [s \in S |-> "wait"]
    /\ k = [s \in S |-> [c \in C |-> "none"]]
    /\ fl = {}
    /\ end = "none"
    /\ wv = Used
    /\ sv = {}
    /\ dv = {}
    /\ xv = Zero
    /\ rel = Zero
    /\ charge = [b \in B |-> IF b \in Used THEN 1 ELSE 0]
    /\ ev = "init"

\* The last slice of the run of one backing that starts at the stable offset:
\* the end of the first region of the writer's output. Only SpanRelease reads it.
FrontEnd ==
    CHOOSE e \in wr .. Slices :
        /\ \A t \in wr .. e : of[t] = of[wr]
        /\ e = Slices \/ of[e + 1] # of[wr]

\* The protocol accepts the slices wr .. j of the writer's region. Each
\* accepted slice gets a view in the store. The writer keeps a view of each
\* backing of the suffix at the new stable offset, with no copy.
\* WholeRelease: a partial acceptance drops each view of the writer.
\* SpanRelease: a partial acceptance that covers the first region drops each
\* view of the writer, also the view of the next backing.
Accept(j) ==
    /\ end = "none"
    /\ ~wgone
    /\ wr <= j
    /\ UNCHANGED <<of, wgone, k, fl, end, dv, xv>>
    /\ wr' = j + 1
    /\ st' = [s \in S |-> IF s \in wr .. j THEN "store" ELSE st[s]]
    /\ sv' = sv \cup (wr .. j)
    /\ wv' = CASE j < Slices /\ Bug = "WholeRelease" -> {}
               [] j < Slices /\ Bug = "SpanRelease" /\ FrontEnd <= j -> {}
               [] OTHER -> BackingsIn(j + 1, Slices)
    /\ ev' = "accept"
    /\ Settle(Zero, Zero)

\* The writer drops its unaccepted suffix: a cancelled write, or a caller
\* that keeps no use for it after the stream ended.
WriterDrop ==
    /\ ~wgone
    /\ wr <= Slices
    /\ UNCHANGED <<of, wr, st, k, fl, end, sv, dv, xv>>
    /\ wgone' = TRUE
    /\ wv' = {}
    /\ ev' = "drop"
    /\ Settle(Zero, Zero)

\* The next copy of slice s: the first copy that the driver did not accept.
\* A retransmission comes after the protocol declared the copy before it
\* lost, which can be a spurious loss, so that copy was submitted.
NextCopy(s) ==
    CHOOSE c \in C : k[s][c] \in {"none", "ref"} /\ (c = 1 \/ k[s][c - 1] \notin {"none", "ref"})

Sendable(s) == st[s] = "store" /\ \E c \in C : k[s][c] \in {"none", "ref"}

\* The protocol sends one datagram that gathers the next copy of each slice
\* in G, with a new packet number. The driver accepts the output and keeps a
\* view of each backing that it gathers until its terminal event, or it
\* refuses the output. Then the binding gets its views back and drops them,
\* and the protocol submits the same copies again.
\* GatherOneView: the driver keeps a view of the backing of the first slice only.
Send(G) ==
    LET o == {<<s, NextCopy(s)>> : s \in G}
        held == IF Bug = "GatherOneView" THEN {of[Min(G)]} ELSE Out(o)
    IN /\ end = "none"
       /\ \A s \in G : Sendable(s)
       /\ UNCHANGED <<of, wr, wgone, st, end, wv, sv>>
       /\ \/ /\ k' = [s \in S |-> [c \in C |-> IF <<s, c>> \in o THEN "fly" ELSE k[s][c]]]
             /\ fl' = fl \cup {o}
             /\ dv' = dv \cup {<<o, b>> : b \in held}
             /\ xv' = xv
             /\ ev' = IF \E p \in o : k[p[1]][p[2]] = "ref" THEN "retry" ELSE "send"
             /\ Settle(Zero, [b \in B |-> IF Bug = "ChargePerCopy" /\ b \in Out(o) THEN 1 ELSE 0])
          \/ /\ \E p \in o : k[p[1]][p[2]] = "none"
             /\ k' = [s \in S |-> [c \in C |-> IF <<s, c>> \in o THEN "ref" ELSE k[s][c]]]
             /\ UNCHANGED <<fl, dv>>
             /\ xv' = IF Bug = "RefusalLeak"
                      THEN [b \in B |-> IF b \in Out(o) THEN xv[b] + 1 ELSE xv[b]]
                      ELSE xv
             /\ ev' = "refuse"
             /\ Settle(Zero, Zero)

\* The send result of output o. With a notice armed, the driver keeps its
\* views for the notice. Without one, the result is terminal and the views drop.
Result(o) ==
    /\ \A p \in o : k[p[1]][p[2]] = "fly"
    /\ UNCHANGED <<of, wr, wgone, st, end, wv, sv, xv>>
    /\ \/ /\ k' = [s \in S |-> [c \in C |-> IF <<s, c>> \in o THEN "zc" ELSE k[s][c]]]
          /\ UNCHANGED <<fl, dv>>
          /\ ev' = "result"
          /\ Settle(Zero, Zero)
       \/ /\ k' = [s \in S |-> [c \in C |-> IF <<s, c>> \in o THEN "res" ELSE k[s][c]]]
          /\ fl' = fl \ {o}
          /\ dv' = {v \in dv : v[1] # o}
          /\ ev' = "result"
          /\ Settle(Zero, [b \in B |-> IF Bug = "ChargePerCopy" /\ b \in Out(o) THEN -1 ELSE 0])

\* The zero-copy notice of output o: the kernel no longer reads its pages,
\* and the driver drops its views.
Notice(o) ==
    /\ \A p \in o : k[p[1]][p[2]] = "zc"
    /\ UNCHANGED <<of, wr, wgone, st, end, wv, sv, xv>>
    /\ k' = [s \in S |-> [c \in C |-> IF <<s, c>> \in o THEN "ntc" ELSE k[s][c]]]
    /\ fl' = fl \ {o}
    /\ dv' = {v \in dv : v[1] # o}
    /\ ev' = "notice"
    /\ Settle(Zero, [b \in B |-> IF Bug = "ChargePerCopy" /\ b \in Out(o) THEN -1 ELSE 0])

\* An acknowledgement frame names the packet number of copy c of slice s.
\* The peer can repeat it, acknowledge another copy of a slice that it
\* acknowledged, or, when faulty, name a number that the sender never sent.
\* Only the first acknowledgement of a sent copy ends the store's retention.
\* ReleaseAtAck: it drops the driver's views of the backing of s in each
\* output that carries another copy of s.
PeerAck(s, c) ==
    LET known == k[s][c] \notin {"none", "ref"}
        first == st[s] = "store" /\ (known \/ Bug = "UnknownAck")
    IN /\ UNCHANGED <<of, wr, wgone, k, fl, end, wv, xv>>
       /\ st' = IF first THEN [st EXCEPT ![s] = "acked"] ELSE st
       /\ sv' = IF first THEN sv \ {s} ELSE sv
       /\ dv' = IF first /\ Bug = "ReleaseAtAck"
                THEN {v \in dv : ~(v[2] = of[s] /\ \E d \in C \ {c} : <<s, d>> \in v[1])}
                ELSE dv
       /\ ev' = CASE ~known -> "unknown"
                  [] st[s] = "store" -> "ack"
                  [] OTHER -> "repeat"
       /\ Settle(Zero, Zero)

\* The stream ends: a cancellation, a request deadline, or a close. It stops
\* new acceptance and new sends, and the store drops each slice that it kept.
\* Each kernel use keeps its views until its own terminal event.
\* DeadlineRelease: a deadline drops the driver's views.
\* DoubleRelease: the close runs the hook again for each backing that no view holds.
End(why) ==
    /\ end = "none"
    /\ UNCHANGED <<of, wr, wgone, k, fl, wv, xv>>
    /\ end' = why
    /\ st' = [s \in S |-> IF st[s] = "store" THEN "dropped" ELSE st[s]]
    /\ sv' = {}
    /\ dv' = IF why = "deadline" /\ Bug = "DeadlineRelease" THEN {} ELSE dv
    /\ ev' = "end"
    /\ Settle([b \in B |-> IF why = "close" /\ Bug = "DoubleRelease" /\ b \in Used /\ Views(b) = 0
                           THEN 1 ELSE 0],
              Zero)

Next ==
    \/ \E j \in S : Accept(j)
    \/ WriterDrop
    \/ \E G \in (SUBSET S) \ {{}} : Send(G)
    \/ \E o \in fl : Result(o) \/ Notice(o)
    \/ \E s \in S, c \in C : PeerAck(s, c)
    \/ \E why \in Ends : End(why)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* Properties *)

TypeOK ==
    /\ of \in Layouts
    /\ wr \in 1 .. Slices + 1
    /\ wgone \in BOOLEAN
    /\ st \in [S -> {"wait", "store", "acked", "dropped"}]
    /\ k \in [S -> [C -> {"none", "ref", "fly", "zc", "res", "ntc"}]]
    /\ fl \subseteq SUBSET (S \X C)
    /\ end \in {"none"} \cup Ends
    /\ wv \subseteq B
    /\ sv \subseteq S
    /\ dv \subseteq fl \X B
    /\ xv \in [B -> Nat]
    /\ rel \in [B -> Nat]
    /\ charge \in [B -> Int]
    /\ ev \in Events

\* Each retained reference and each kernel use keeps its backing alive.
AliveWhileHeld == \A b \in Used : Held(b) => rel[b] = 0

\* The budget counts each backing once while it is alive, and not after its
\* release.
ChargedOnce == \A b \in Used : charge[b] = IF rel[b] = 0 THEN 1 ELSE 0

\* The release of each backing runs at most once.
ReleaseAtMostOnce == \A b \in Used : rel[b] <= 1

\* The release of a backing has run when no obligation of it remains, so it
\* runs in the step that ends its last obligation.
ReleasedAfterLast == \A b \in Used : ~Held(b) => rel[b] = 1

\* After a partial acceptance, the writer keeps a view of each backing of the
\* suffix that the protocol has not accepted, until the writer drops it.
SuffixKept == \A b \in Used : (~wgone /\ b \in BackingsIn(wr, Slices)) => b \in wv

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

\* A stream end with a kernel use: no submission follows an end, so a notice
\* that releases the last backing after an end was pending at the end.
NotEndedThenNotice(why) == ~(end = why /\ ev = "notice" /\ \A b \in Used : rel[b] = 1)
NotCancelThenNotice == NotEndedThenNotice("cancel")
NotDeadlineThenNotice == NotEndedThenNotice("deadline")
NotCloseThenNotice == NotEndedThenNotice("close")

\* A refused copy is submitted again and accepted.
NotRefusedRetry == ev # "retry"

\* A backing is released while a refused copy of one of its slices was never sent.
NotRefusedRelease == ~\E s \in S, c \in C : rel[of[s]] = 1 /\ k[s][c] = "ref"

\* The protocol accepts the last slice after the peer acknowledged the first.
NotSuffixLater == ~(ev = "accept" /\ wr = Slices + 1 /\ st[1] = "acked")

\* An output that gathers two backings waits for its notice, and no other
\* holder keeps either backing: the store keeps none of its slices, and the
\* writer has no suffix.
NotGatherWait ==
    ~\E o \in fl :
        /\ Cardinality(Out(o)) >= 2
        /\ \A p \in o : k[p[1]][p[2]] = "zc" /\ st[p[1]] # "store"
        /\ wv = {}

\* One backing is released while the writer still holds another: a partial
\* acceptance ended at the end of the first backing, and the backings release
\* apart.
NotSplitRelease == ~\E b, d \in Used : b # d /\ rel[b] = 1 /\ d \in wv

=============================================================================
