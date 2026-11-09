-------------------------- MODULE AttachedDatagram --------------------------
(***************************************************************************)
(* The datagram form of an attached channel (networking.md, "Attached      *)
(* Channels" and "Datagram Form"), as selected on 2026-11-07.              *)
(*                                                                         *)
(* A sender sends a stream of Bytes bytes to a receiver in side datagrams. *)
(* A side datagram carries a connection ID, a packet number, a stream      *)
(* offset, payload bytes, and an AES-GMAC tag over all of them. The tag    *)
(* gives integrity and no confidentiality. The receiver checks the tag     *)
(* before any other step, and a datagram whose tag fails changes no state. *)
(* The model computes no tags: a datagram passes the tag only when it is a *)
(* datagram that the sender sent (Authentic). The receiver slides its own  *)
(* replay window on the datagrams that it accepts, on any connection ID    *)
(* that it issued for the channel. The side flow follows the parent's      *)
(* path: when the parent validates a new peer address, the validation ends *)
(* on a timer or with success, and an abandoned validation returns to the  *)
(* last validated path with its congestion state.                          *)
(*                                                                         *)
(* Acknowledgements, receive credit, the final size, and reset travel in   *)
(* frames inside the parent QUIC connection. The model takes these frames  *)
(* as reliable and authenticated, because the design puts them in the      *)
(* parent, which encrypts, authenticates, and resends them. They can       *)
(* arrive late and in a different order.                                   *)
(*                                                                         *)
(* Each datagram carries one byte. A payload is "good" when it is the      *)
(* sender's correct byte at the datagram's offset, and "bad" when it is    *)
(* not. The application's tags cover the channel and the position, so the  *)
(* consumer's read rejects a "bad" byte. An honest sender sends only       *)
(* "good" bytes. A faulty sender (FaultySender) can send "bad" bytes, and  *)
(* the tag passes for them, because the sender sent them.                  *)
(*                                                                         *)
(* The model keeps one outcome for the channel. The first terminal event   *)
(* at either end sets it, and the parent's frames tell the other end. The  *)
(* model merges that notification into the event.                          *)
(*                                                                         *)
(* Bug selects one known-bad variant. "none" is the design.                *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, Sequences

CONSTANTS
    Bytes,         \* The final size. The stream has the offsets 0 .. Bytes - 1.
    MaxPN,         \* The highest packet number that the sender can use.
    Paths,         \* The parent's paths: the first one and one new path for each migration attempt.
    Cap,           \* The receive capacity that the consumer admits after its read point.
    Range,         \* The receiver's window: the packet numbers that it keeps below its highest.
    Window,        \* The initial congestion window of a parent path, in datagrams.
    OnPath,        \* TRUE when an on-path attacker knows the current connection ID.
    FaultySender,  \* TRUE when the sender can send other bytes than its correct ones.
    Bug            \* "none", or the known-bad variant.

Bugs == {"none", "NoTag", "SlideBeforeTag", "ReusePN", "CompleteAtAck",
         "CreditBeyond", "NoWindowBound", "LateReset", "NoAbandon"}

ASSUME
    /\ Bytes \in Nat \ {0}
    /\ MaxPN \in Nat /\ MaxPN >= Bytes
    /\ Paths \in Nat \ {0}
    /\ Cap \in Nat \ {0}
    /\ Range \in Nat \ {0}
    /\ Window \in Nat \ {0}
    /\ OnPath \in BOOLEAN
    /\ FaultySender \in BOOLEAN
    /\ Bug \in Bugs

VARIABLES
    outcome,  \* "open", or the terminal outcome of the channel.
    path,     \* The parent's last validated path. The side flow sends on it.
    mig,      \* "none", or the kind of migration to path tried that the parent validates.
    tried,    \* The highest path that the parent used or tried. Each attempt takes a new one.
    cwnd,     \* The congestion window that the side flow shares with the parent.
    net,      \* The side datagrams in flight.
    sLog,     \* sLog[p] is the offset and the payload that the sender sent in packet number p.
    sAcked,   \* The packet numbers whose acknowledgement the sender processed.
    sLost,    \* The packet numbers that the sender declared lost.
    sCredit,  \* The credit limit that the sender has from the receiver.
    rAck,     \* The packet numbers that the receiver accepted. Its acknowledgement frames name them.
    rHigh,    \* The highest packet number that the receiver accepted, or 0.
    rWin,     \* The receiver's replay state: the accepted packet numbers that it keeps.
    rBuf,     \* rBuf[o] is the payload that the receiver holds at offset o.
    rRead,    \* The read point of the consumer.
    rCredit,  \* The credit limit that the receiver granted.
    faults    \* The faults of the ReusePN variant so far. It stays 0 in each other run.

vars == <<outcome, path, mig, tried, cwnd, net, sLog, sAcked, sLost, sCredit,
          rAck, rHigh, rWin, rBuf, rRead, rCredit, faults>>
senderVars == <<sLog, sAcked, sLost, sCredit>>
receiverVars == <<rAck, rHigh, rWin, rBuf, rRead, rCredit>>
pathVars == <<path, mig, tried, cwnd>>

-----------------------------------------------------------------------------
(* Values *)

Offsets == 0 .. Bytes - 1
PNs == 1 .. MaxPN
Payloads == {"good", "bad"}
Terminal == {"completed", "reset", "parentEnd", "partial", "integrity", "refused"}
\* Connection ID 0 is one that the receiver did not issue. Connection ID i is
\* the one that the receiver issued for the channel and the sender uses on
\* path i (RFC 9000 section 9.5: a new connection ID for each path).
Datagrams == [cid : 0 .. Paths, pn : PNs, off : Offsets, pay : Payloads]

Min(a, b) == IF a < b THEN a ELSE b
Max(a, b) == IF a > b THEN a ELSE b

-----------------------------------------------------------------------------
(* Facts that the actions and the properties use *)

\* The packet numbers that the sender sent and still waits for.
Flight == {p \in 1 .. Len(sLog) : p \notin sAcked \cup sLost}

\* The offsets that the sender counts as acknowledged.
AckedOffsets == {sLog[p].off : p \in sAcked \cap 1 .. Len(sLog)}
AllAcked == AckedOffsets = Offsets

\* Offset o needs a transmission: no acknowledgement and no packet in flight.
Needs(o) == o \notin AckedOffsets /\ \A p \in Flight : sLog[p].off # o

\* The sender sent offset o at least once.
Sent(o) == \E p \in 1 .. Len(sLog) : sLog[p].off = o

\* The on-path attacker saw the sender's correct byte at offset o.
SeenGood(o) == \E p \in 1 .. Len(sLog) : sLog[p] = [off |-> o, pay |-> "good"]

Held(o) == rBuf[o] # "none"

\* [Packet numbers and replay] The tag passes only for a datagram that the
\* sender sent. The tag also covers the connection ID; the model lets a sent
\* datagram pass with any connection ID, which only adds behaviors.
Authentic(d) ==
    d.pn \in 1 .. Len(sLog) /\ sLog[d.pn] = [off |-> d.off, pay |-> d.pay]

\* The receiver applies the tag. The NoTag variant has no tag check.
Tagged(d) == Bug = "NoTag" \/ Authentic(d)

\* [Packet numbers and replay] [Path and routing] The window check: a
\* connection ID that the receiver issued for the channel, a packet number
\* that the receiver did not accept, and a packet number inside the window
\* below its highest. The receiver accepts a datagram on any connection ID
\* that it issued and did not retire, because the tag, not the path, shows
\* that the sender sent it. The model retires no connection ID; a retired
\* one only discards a late copy, which is the same as its loss. The
\* NoWindowBound variant has no window.
Fresh(d) ==
    /\ d.cid \in 1 .. Paths
    /\ d.pn \notin rWin
    /\ Bug = "NoWindowBound" \/ d.pn + Range > rHigh

-----------------------------------------------------------------------------
(* The bound on faults *)

(* TLC cannot check unbounded fair loss with a finite packet-number space.  *)
(* The model therefore lets a fault happen only while the sender has a     *)
(* packet number to send each byte again that the faults can cost. Spent   *)
(* counts the packet numbers that losses used or will use. A packet is     *)
(* doomed when it is in flight, the receiver did not accept it, and no     *)
(* copy of it is in flight. A migration loses no datagram: the receiver    *)
(* accepts each issued connection ID, so a loss at a migration is a Lose.  *)
Doomed(p) == p \in Flight /\ p \notin rAck /\ \A d \in net : d.pn # p
Spent == Cardinality(sLost) + Cardinality({p \in Flight : Doomed(p)})
Budget == MaxPN - Bytes

\* The ReusePN variant takes packet numbers out of sLost, so Spent no longer
\* bounds its faults. It counts them instead: a loss of a datagram that the
\* receiver would accept, and an early loss declaration. Each other run
\* keeps faults at 0.
CountFault(fault) ==
    /\ faults' = IF Bug = "ReusePN" /\ fault THEN faults + 1 ELSE faults
    /\ faults' <= Budget

-----------------------------------------------------------------------------
(* Receive procedure *)

Unchanged == [ack |-> rAck, high |-> rHigh, win |-> rWin, buf |-> rBuf]

(* [Packet numbers and replay] [Receive credit] [Injection] The receiver   *)
(* accepts a datagram that passes the tag and the window check and is      *)
(* inside the credit. It slides its window to the highest accepted packet  *)
(* number and keeps only the packet numbers inside the window. It keeps    *)
(* the first bytes at an offset and discards bytes that arrive there       *)
(* again, as RFC 9000 section 2.2 permits; with the tag, other bytes there *)
(* can come only from a faulty sender. Bytes below the read point were     *)
(* read already; the receiver does not keep them.                          *)
Accept(d) ==
    LET high == Max(rHigh, d.pn) IN
    [ack |-> rAck \cup {d.pn},
     high |-> high,
     win |-> {q \in rWin \cup {d.pn} : Bug = "NoWindowBound" \/ q + Range > high},
     buf |-> IF d.off < rRead \/ Held(d.off) THEN rBuf
             ELSE [rBuf EXCEPT ![d.off] = d.pay]]

\* The SlideBeforeTag variant moves the window to a higher packet number
\* before it checks the tag.
Slid(d) ==
    IF Bug = "SlideBeforeTag" /\ d.cid \in 1 .. Paths /\ d.pn > rHigh
    THEN [Unchanged EXCEPT !.high = d.pn, !.win = {q \in rWin : q + Range > d.pn}]
    ELSE Unchanged

\* The receiver's state after it takes datagram d. A datagram that fails
\* the tag, an old or duplicate packet number, a connection ID that the
\* receiver did not issue, and data beyond the credit change no state; the
\* receiver discards and counts them.
RecvState(d) ==
    IF Tagged(d) /\ Fresh(d) /\ d.off < rCredit THEN Accept(d)
    ELSE IF ~Tagged(d) THEN Slid(d)
    ELSE Unchanged

Receive(d) ==
    LET r == RecvState(d) IN
    /\ rAck' = r.ack
    /\ rHigh' = r.high
    /\ rWin' = r.win
    /\ rBuf' = r.buf

-----------------------------------------------------------------------------
(* Actions. Each action is one atomic step. Its comment names the contract *)
(* row of "Datagram Form" in square brackets.                              *)

Init ==
    \* [Explicit profile] The open refuses, for example when the parent did
    \* not negotiate the extension.
    /\ outcome \in {"open", "refused"}
    /\ path = 1
    /\ mig = "none"
    /\ tried = 1
    /\ cwnd = Window
    /\ net = {}
    /\ sLog = <<>>
    /\ sAcked = {}
    /\ sLost = {}
    /\ sCredit = Min(Bytes, Cap)
    /\ rAck = {}
    /\ rHigh = 0
    /\ rWin = {}
    /\ rBuf = [o \in Offsets |-> "none"]
    /\ rRead = 0
    /\ rCredit = Min(Bytes, Cap)
    /\ faults = 0

\* [Packet numbers and replay] [Receive credit] [Congestion and loss]
\* [Migration] [Path and routing] [Retransmission] The sender sends offset o
\* in a datagram with the next packet number, on the parent's path, with
\* that path's connection ID. A lost offset goes again with a new packet
\* number. The sender stays inside the credit and the shared window. Two
\* conditions are bounds of the model, not design rules (README,
\* "Reductions"). While the parent validates a new peer address, the side
\* flow sends nothing: in the design it sends there within the parent's
\* anti-amplification limit, and each such datagram arrives as one that the
\* model sends after the validation ends, or is lost. And the packets in
\* flight span fewer than Range packet numbers, so the window never
\* discards a datagram that the sender still waits for; that discard changes
\* no state and removes the datagram from the network, as Lose does.
SendData(o) ==
    LET p == Len(sLog) + 1 IN
    /\ outcome = "open"
    /\ mig = "none"
    /\ Needs(o)
    /\ o < sCredit
    /\ p <= MaxPN
    /\ Cardinality(Flight) < cwnd
    /\ \A q \in Flight : q + Range > p
    /\ \E x \in (IF FaultySender THEN Payloads ELSE {"good"}) :
          /\ sLog' = Append(sLog, [off |-> o, pay |-> x])
          /\ net' = net \cup {[cid |-> path, pn |-> p, off |-> o, pay |-> x]}
    /\ UNCHANGED <<outcome, pathVars, sAcked, sLost, sCredit, receiverVars, faults>>

\* The network delivers datagram d once. A later copy is a duplicate, which
\* changes no state.
Deliver(d) ==
    /\ outcome = "open"
    /\ d \in net
    /\ net' = net \ {d}
    /\ Receive(d)
    /\ UNCHANGED <<outcome, pathVars, senderVars, rRead, rCredit, faults>>

\* The network loses datagram d.
Lose(d) ==
    /\ outcome = "open"
    /\ d \in net
    /\ net' = net \ {d}
    /\ UNCHANGED <<outcome, pathVars, senderVars, receiverVars>>
    /\ CountFault(RecvState(d) # Unchanged)
    /\ Spent' <= Budget

\* [Injection] The on-path attacker sends again a datagram that the sender
\* sent. Any other datagram fails the tag
\* and changes no state, so the design needs no step for it. A copy of an
\* accepted datagram is a duplicate or old, and a copy of a datagram in
\* flight is the same as its early delivery, so the attacker sends only a
\* datagram that the receiver did not accept and that is not in flight.
Replay(p) ==
    /\ OnPath
    /\ outcome = "open"
    /\ p \in 1 .. Len(sLog) \ rAck
    /\ \A d \in net : d.pn # p
    /\ Receive([cid |-> path, pn |-> p, off |-> sLog[p].off, pay |-> sLog[p].pay])
    /\ UNCHANGED <<outcome, net, pathVars, senderVars, rRead, rCredit, faults>>

\* [Injection] In the variants without the tag check or with the slide
\* before it, the on-path attacker sends any datagram with a connection ID
\* that the receiver issued, which it saw on the path. It copies only the sender's
\* bytes that it saw, at their own offset, or it sends other bytes. An
\* off-path attacker does not know a connection ID, so its datagram is
\* discarded by the window check in every variant.
Forge(d) ==
    /\ OnPath
    /\ Bug \in {"NoTag", "SlideBeforeTag"}
    /\ outcome = "open"
    /\ d.cid \in 1 .. Paths
    /\ d.pay = "good" => SeenGood(d.off)
    /\ Receive(d)
    /\ UNCHANGED <<outcome, net, pathVars, senderVars, rRead, rCredit, faults>>

\* [Congestion and loss] The sender declares packet p lost by the RFC 9002
\* packet or time threshold. The model has no clock, so a declaration can
\* come at any time, also too early. A loss is a congestion event for the
\* shared controller. The model does not keep recovery periods.
DeclareLost(p) ==
    /\ outcome = "open"
    /\ p \in Flight
    /\ sLost' = sLost \cup {p}
    /\ cwnd' = Max(1, cwnd \div 2)
    /\ UNCHANGED <<outcome, path, mig, tried, net, sLog, sAcked, sCredit, receiverVars>>
    /\ CountFault(~Doomed(p))
    /\ Spent' <= Budget

\* [Control] [Packet numbers and replay] The sender processes the
\* acknowledgement of packet number p in a parent frame and maps p to the
\* offset that it sent in p. An acknowledgement of a packet number that the
\* sender never sent shows a faulty peer and ends the channel with
\* integrity; with the tag, no datagram from the network causes one.
DeliverAck(p) ==
    /\ outcome = "open"
    /\ p \in rAck \ sAcked
    /\ sAcked' = sAcked \cup {p}
    /\ outcome' = IF p > Len(sLog) THEN "integrity" ELSE "open"
    /\ UNCHANGED <<pathVars, net, sLog, sLost, sCredit, receiverVars, faults>>

\* [Receive credit] A credit frame arrives at the sender.
DeliverCredit(c) ==
    /\ outcome = "open"
    /\ c \in sCredit + 1 .. rCredit
    /\ sCredit' = c
    /\ UNCHANGED <<outcome, pathVars, net, sLog, sAcked, sLost, receiverVars, faults>>

\* The CreditBeyond variant grants one byte of credit beyond the capacity
\* that the consumer admitted.
GrantBeyond ==
    /\ Bug = "CreditBeyond"
    /\ outcome = "open"
    /\ rCredit < Min(Bytes, rRead + Cap + 1)
    /\ rCredit' = Min(Bytes, rRead + Cap + 1)
    /\ UNCHANGED <<outcome, pathVars, net, senderVars, rAck, rHigh, rWin, rBuf, rRead, faults>>

\* [Receive credit] [Integrity] The consumer reads the byte at its read
\* point. The application's tag accepts only the sender's correct byte at
\* that offset; a tag failure ends the channel with integrity. Each read
\* admits capacity, and the receiver grants credit only for admitted
\* capacity.
Read ==
    /\ outcome = "open"
    /\ rRead < Bytes
    /\ Held(rRead)
    /\ IF rBuf[rRead] = "good"
       THEN /\ rRead' = rRead + 1
            /\ rBuf' = [rBuf EXCEPT ![rRead] = "none"]
            /\ rCredit' = Min(Bytes, rRead + 1 + Cap)
            /\ UNCHANGED outcome
       ELSE /\ outcome' = "integrity"
            /\ UNCHANGED <<rRead, rBuf, rCredit>>
    /\ UNCHANGED <<pathVars, net, senderVars, rAck, rHigh, rWin, faults>>

\* [Terminal outcomes] The consumer has read to the end. The receiver's next
\* acknowledgement frame names that read point, and the sender completes
\* when the frame arrives; the model merges the frame into this step. The
\* CompleteAtAck variant also completes when each byte is acknowledged,
\* without the read.
Complete ==
    /\ outcome = "open"
    /\ rRead = Bytes \/ (Bug = "CompleteAtAck" /\ AllAcked)
    /\ outcome' = "completed"
    /\ UNCHANGED <<pathVars, net, senderVars, receiverVars, faults>>

\* [Terminal outcomes] An application resets the channel with an error
\* code. The LateReset variant also resets a channel that has ended.
Reset ==
    /\ outcome = "open" \/ (Bug = "LateReset" /\ outcome \in Terminal \ {"reset"})
    /\ outcome' = "reset"
    /\ UNCHANGED <<pathVars, net, senderVars, receiverVars, faults>>

\* [Terminal outcomes] (Attached Channels: Lifetime) The parent ends. Bytes
\* that are not acknowledged give the partial-delivery outcome.
ParentEnd ==
    /\ outcome = "open"
    /\ outcome' = IF AllAcked THEN "parentEnd" ELSE "partial"
    /\ UNCHANGED <<pathVars, net, senderVars, receiverVars, faults>>

\* [Congestion and loss] A parent packet is lost on the parent's path: a
\* congestion event for the shared controller. During a validation, the
\* parent's packets go to the new peer address and count for that path's
\* controller (RFC 9000 section 9.4), which the model does not keep: success
\* resets it, and an abandon discards it.
ParentLoss ==
    /\ outcome = "open"
    /\ mig = "none"
    /\ cwnd > 1
    /\ cwnd' = cwnd \div 2
    /\ UNCHANGED <<outcome, path, mig, tried, net, senderVars, receiverVars, faults>>

\* [Migration] The peer moves to a new address, and the parent starts to
\* validate it on a new path with a new connection ID (RFC 9000 sections
\* 9.3 and 9.5). A peer event: no fairness.
MigrateStart ==
    /\ outcome = "open"
    /\ mig = "none"
    /\ tried < Paths
    /\ tried' = tried + 1
    /\ mig' = "genuine"
    /\ UNCHANGED <<outcome, path, cwnd, net, senderVars, receiverVars, faults>>

\* [Migration] A spurious migration: the on-path attacker forwards a copy of
\* a parent packet with a spoofed address, and its copy arrives first (RFC
\* 9000 sections 9.3.2 and 9.3.3). The parent starts to validate the
\* spoofed address on a new path. Nobody at that address has the keys, so
\* this validation cannot succeed. An attacker event: no fairness.
Spoof ==
    /\ OnPath
    /\ outcome = "open"
    /\ mig = "none"
    /\ tried < Paths
    /\ tried' = tried + 1
    /\ mig' = "spurious"
    /\ UNCHANGED <<outcome, path, cwnd, net, senderVars, receiverVars, faults>>

\* [Migration] The validation succeeds: the PATH_RESPONSE arrives (RFC 9000
\* section 8.2). The side flow follows the parent to the new path and its
\* connection ID, and the new path's congestion state starts at its
\* initial values (section 9.4).
Validated ==
    /\ outcome = "open"
    /\ mig = "genuine"
    /\ path' = tried
    /\ mig' = "none"
    /\ cwnd' = Window
    /\ UNCHANGED <<outcome, tried, net, senderVars, receiverVars, faults>>

\* [Migration] The validation timer expires (RFC 9000 section 8.2.4,
\* three times the larger PTO), or a higher-numbered packet from the last
\* validated address moves the parent back (section 9.3.2). The parent
\* abandons the validation and returns to its last validated path, and the
\* side flow returns with it. That path's congestion state is restored
\* (section 9.3): cwnd kept its value during the validation. The NoAbandon
\* variant, the design as written before 2026-11-07, has no such step.
Abandon ==
    /\ Bug # "NoAbandon"
    /\ outcome = "open"
    /\ mig # "none"
    /\ mig' = "none"
    /\ UNCHANGED <<outcome, path, tried, cwnd, net, senderVars, receiverVars, faults>>

\* A terminal state stays as it is.
Done ==
    /\ outcome \in Terminal
    /\ UNCHANGED vars

-----------------------------------------------------------------------------
(* The ReusePN variant: a retransmission reuses the packet number that the *)
(* sender declared lost. When the window has passed that number, the       *)
(* receiver discards each copy as old, and the sender sends it again       *)
(* forever. With the tag, a reused packet number is also a reused nonce.   *)

ResendSamePN(p) ==
    /\ Bug = "ReusePN"
    /\ outcome = "open"
    /\ mig = "none"
    /\ p \in sLost \ sAcked
    /\ Needs(sLog[p].off)
    /\ sLog[p].off < sCredit
    /\ Cardinality(Flight) < cwnd
    /\ sLost' = sLost \ {p}
    /\ net' = net \cup {[cid |-> path, pn |-> p, off |-> sLog[p].off, pay |-> sLog[p].pay]}
    /\ UNCHANGED <<outcome, pathVars, sLog, sAcked, sCredit, receiverVars, faults>>

-----------------------------------------------------------------------------
(* The next-state relation and the fairness *)

\* In the ReusePN variant, the first transmission of each offset is as in
\* the design, and each retransmission reuses its packet number.
SendNext ==
    IF Bug = "ReusePN"
    THEN \/ \E o \in Offsets : SendData(o) /\ ~Sent(o)
         \/ \E p \in PNs : ResendSamePN(p)
    ELSE \E o \in Offsets : SendData(o)

Next ==
    \/ SendNext
    \/ \E d \in net : Deliver(d)
    \/ \E p \in PNs : Replay(p)
    \/ Bug \in {"NoTag", "SlideBeforeTag"} /\ \E d \in Datagrams : Forge(d)
    \/ \E p \in PNs : DeliverAck(p)
    \/ \E d \in net : Lose(d)
    \/ \E p \in PNs : DeclareLost(p)
    \/ \E c \in 1 .. Bytes : DeliverCredit(c)
    \/ GrantBeyond
    \/ Read
    \/ Complete
    \/ Reset
    \/ ParentEnd
    \/ ParentLoss
    \/ MigrateStart
    \/ Spoof
    \/ Validated
    \/ Abandon
    \/ Done

(* Fairness: loss is fair and the parent stays alive. The ends take each   *)
(* step that stays possible: the sender sends and declares a doomed packet *)
(* lost. The network delivers each datagram that it does not lose. The     *)
(* parent delivers its frames, and each validation ends, by success or by  *)
(* its timer. Success alone has no fairness, because only the peer can     *)
(* answer. Loss, early loss declarations, the attacker, the consumer's     *)
(* read, reset, the parent's end, parent losses, and migration starts have *)
(* no fairness. Progress states the consumer's read as its condition.      *)
OtherFairness ==
    /\ WF_vars(\E p \in PNs : DeliverAck(p))
    /\ WF_vars(\E d \in net : Deliver(d))
    /\ WF_vars(\E p \in PNs : Doomed(p) /\ DeclareLost(p))
    /\ WF_vars(\E c \in 1 .. Bytes : DeliverCredit(c))
    /\ WF_vars(Complete)
    /\ WF_vars(Validated \/ Abandon)

Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ WF_vars(\E o \in Offsets : SendData(o))
    /\ OtherFairness

\* The ReusePN variant: the sender's fairness covers the first
\* transmissions and the retransmissions that reuse a packet number.
ReuseSpec ==
    /\ Init
    /\ [][Next]_vars
    /\ WF_vars(\E o \in Offsets : SendData(o) /\ ~Sent(o))
    /\ WF_vars(\E p \in PNs : ResendSamePN(p))
    /\ OtherFairness

-----------------------------------------------------------------------------
(* Properties *)

TypeOK ==
    /\ outcome \in {"open"} \cup Terminal
    /\ path \in 1 .. Paths
    /\ mig \in {"none", "genuine", "spurious"}
    /\ tried \in 1 .. Paths
    /\ path <= tried
    /\ cwnd \in 1 .. Window
    /\ net \subseteq Datagrams
    /\ sLog \in Seq([off : Offsets, pay : Payloads]) /\ Len(sLog) <= MaxPN
    /\ sAcked \subseteq PNs
    /\ sLost \subseteq PNs
    /\ sCredit \in 0 .. Bytes
    /\ rAck \subseteq PNs
    /\ rHigh \in 0 .. MaxPN
    /\ rWin \subseteq PNs
    /\ rBuf \in [Offsets -> {"none"} \cup Payloads]
    /\ rRead \in 0 .. Bytes
    /\ rCredit \in 0 .. Bytes
    /\ faults \in 0 .. Budget
    /\ outcome = "open" => Spent <= Budget

\* The receiver holds only bytes that the sender sent at that offset. No
\* step checks this; only the tag makes it hold.
HeldAreSenderBytes ==
    \A o \in Offsets :
        Held(o) => \E p \in 1 .. Len(sLog) : sLog[p] = [off |-> o, pay |-> rBuf[o]]

\* The receiver holds no data beyond the credit that it granted, and it
\* granted credit only for capacity that the consumer admitted.
CreditBound == \A o \in Offsets : Held(o) => o < rCredit /\ o < rRead + Cap

\* The receiver's replay state stays inside its declared window.
PNStateBound == \A q \in rWin : q + Range > rHigh

\* [Terminal outcomes] A transport acknowledgement means that the
\* receiver's transport holds the bytes: each offset that the sender counts
\* as acknowledged is held by the receiver or read by the consumer.
AckMeansHeld == \A o \in AckedOffsets : o < rRead \/ Held(o)

\* Completion needs the consumer's read to the final size.
CompletionSound == outcome = "completed" => rRead = Bytes

\* With an honest sender, no datagram from the network or from an attacker
\* ends the channel with the integrity outcome.
NoNetworkIntegrity == outcome # "integrity"

\* The window moves only when the receiver accepts a datagram, so only after
\* the datagram's tag passes.
WindowAfterTag == [][rHigh' # rHigh => rHigh' \in rAck' \ rAck]_vars

\* A terminal outcome never changes.
OutcomeStable == [][outcome # "open" => outcome' = outcome]_vars

\* Progress: when the consumer keeps reading, the channel ends. With no
\* reset and no parent end, the only end is completion. The consumer's read
\* is a caller event, so it is the condition of the property, not a
\* fairness of the specification.
Progress == WF_vars(Read) => <>(outcome # "open")

-----------------------------------------------------------------------------
(* Reachability targets. Each witness profile checks the negation of one   *)
(* target, and the checker must find a behavior that reaches it.           *)

NotCompleted == outcome # "completed"
NotReset == outcome # "reset"
NotParentEnd == outcome # "parentEnd"
NotPartial == outcome # "partial"
NotRefused == outcome # "refused"
NotIntegrity == outcome # "integrity"

\* A migration completes and a side datagram is in flight on the new path.
NotResumed == ~(path > 1 /\ \E d \in net : d.cid = path)

\* The parent abandons a validation and returns to its last validated path.
NotAbandoned == ~(mig = "none" /\ tried > path)

\* The channel completes after the parent abandoned a validation.
NotCompletedAfterAbandon == ~(outcome = "completed" /\ tried > path)

\* The window passes a packet number that the receiver did not accept.
NotWindowPassed == ~(\E p \in 1 .. Len(sLog) : p + Range <= rHigh /\ p \notin rAck)

\* The receiver accepts a datagram that the attacker sent again.
NeverReplayAccepted == [][\A p \in PNs : ~(Replay(p) /\ rAck' # rAck)]_vars

=============================================================================
