-------------------------- MODULE AttachedDatagram --------------------------
(***************************************************************************)
(* The datagram form of an attached channel (networking.md, "Attached      *)
(* Channels" and "Datagram Form"), through the 2026-11-11 decisions.        *)
(*                                                                         *)
(* A sender sends a stream of Bytes bytes to a receiver in side datagrams. *)
(* A side datagram carries a connection ID, a packet number, a stream      *)
(* offset, payload bytes, and an AES-GMAC tag over all of them. The tag    *)
(* gives integrity and no confidentiality. The receiver checks the tag     *)
(* before any state change; its read-only window check can come first.    *)
(* The model computes no tags: a datagram passes the tag only when it is a *)
(* datagram that the sender sent (Authentic). The receiver slides its own  *)
(* replay window on the datagrams that it accepts, on any connection ID    *)
(* that it issued for the channel. The side flow follows the parent's      *)
(* path: when the parent validates a new peer address, the validation ends *)
(* on a timer or with success, and an abandoned validation returns to the  *)
(* last validated path with its congestion state.                          *)
(*                                                                         *)
(* Ordinary ACK frames are authenticated, replaceable, and lossy. Their   *)
(* last loss enables sender loss recovery. Credit, final size, and terminal *)
(* frames have eventual delivery only while the parent remains alive.     *)
(*                                                                         *)
(* Each datagram carries one byte. A payload is "good" when it is the      *)
(* sender's correct byte at the datagram's offset, and "bad" when it is    *)
(* not. The application's tags cover the channel and the position, so the  *)
(* consumer's read rejects a "bad" byte. An honest sender sends only       *)
(* "good" bytes. A faulty sender (FaultySender) can send "bad" bytes, and  *)
(* the tag passes for them, because the sender sent them.                  *)
(*                                                                         *)
(* Each endpoint keeps its first local terminal outcome. Its notification *)
(* is a later parent-frame arrival. Crossing events and parent failure can *)
(* leave different stable outcomes at the two endpoints.                  *)
(*                                                                         *)
(* Bug selects one known-bad variant. "none" is the design.                *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, Sequences

CONSTANTS
    Bytes,         \* The final size. The stream has the offsets 0 .. Bytes - 1.
    MaxPN,         \* The highest packet number that the sender can use.
    Excess,        \* Bytes past the final size that a faulty sender can send.
    Paths,         \* Abstract path identities; repeated migration reuses them.
    Cap,           \* The receive capacity that the consumer admits after its read point.
    Range,         \* The receiver's window: the packet numbers that it keeps below its highest.
    Window,        \* The initial congestion window of a parent path, in datagrams.
    OnPath,        \* TRUE when an on-path attacker knows the current connection ID.
    FaultySender,  \* TRUE when the sender can send other bytes than its correct ones.
    Bug            \* "none", or the known-bad variant.

Bugs == {"none", "NoTag", "SlideBeforeTag", "ReusePN", "CompleteAtAck",
         "CreditBeyond", "NoWindowBound", "LateReset", "NoAbandon",
         "NoAckRecovery", "FinalKeepsJunk", "NoFinalNotice", "NoFinalIntegrity"}

ASSUME
    /\ Bytes \in Nat \ {0}
    /\ MaxPN \in Nat /\ MaxPN >= Bytes
    /\ Excess \in Nat \ {0}
    /\ Paths \in Nat \ {0}
    /\ Cap \in Nat \ {0}
    /\ Range \in Nat \ {0}
    /\ Window \in Nat \ {0}
    /\ OnPath \in BOOLEAN
    /\ FaultySender \in BOOLEAN
    /\ Bug \in Bugs

VARIABLES
    sEnd,     \* The sender's stable local outcome.
    rEnd,     \* The receiver's stable local outcome.
    parentLive, \* The parent can still deliver control frames.
    ack,      \* Packet numbers in the pending, replaceable ACK frame.
    rFinal,   \* The receiver received the final-size frame.
    path,     \* The parent's last validated path. The side flow sends on it.
    mig,      \* "none", or the kind of migration to path tried that the parent validates.
    tried,    \* The candidate path. Identities are reused; attempts have no finite bound.
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

ends == <<sEnd, rEnd, parentLive>>
controlVars == <<ack, rFinal>>
BothOpen == sEnd = "open" /\ rEnd = "open"
BothDone == sEnd # "open" /\ rEnd # "open"
\* A projection for the single-outcome reachability targets only.
outcome == IF sEnd # "open" THEN sEnd ELSE rEnd
vars == <<ends, controlVars, path, mig, tried, cwnd, net, sLog, sAcked, sLost, sCredit,
          rAck, rHigh, rWin, rBuf, rRead, rCredit, faults>>
senderVars == <<sLog, sAcked, sLost, sCredit>>
receiverVars == <<rAck, rHigh, rWin, rBuf, rRead, rCredit>>
pathVars == <<path, mig, tried, cwnd>>

-----------------------------------------------------------------------------
(* Values *)

Offsets == 0 .. Bytes - 1
WireOffsets == 0 .. (Bytes + Excess - 1)
PNs == 1 .. MaxPN
Payloads == {"good", "bad"}
Terminal == {"completed", "reset", "parentEnd", "partial", "integrity", "refused"}
\* The receiver treats every issued, unretired ID alike. The tag already
\* abstracts acceptance over those IDs. Keep 0 for an unissued ID and 1
\* for any issued ID; stored data need no path-history label. Paths and
\* migrations remain separate state. The design never reuses a packet
\* number, so this projection cannot merge two live data copies.
Datagrams == [cid : {0, 1}, pn : PNs, off : WireOffsets, pay : Payloads]

Min(a, b) == IF a < b THEN a ELSE b
Max(a, b) == IF a > b THEN a ELSE b

-----------------------------------------------------------------------------
(* Facts that the actions and the properties use *)

\* The packet numbers that the sender sent and still waits for.
Flight == {p \in 1 .. Len(sLog) : p \notin sAcked \cup sLost}

\* The offsets that the sender counts as acknowledged.
AckedOffsets == {sLog[p].off : p \in sAcked \cap 1 .. Len(sLog)} \cap Offsets
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
    /\ d.cid = 1
    /\ d.pn \notin rWin
    /\ Bug = "NoWindowBound" \/ d.pn + Range > rHigh

-----------------------------------------------------------------------------
(* The bound on faults *)

(* TLC cannot check unbounded fair loss with a finite packet-number space.  *)
(* The model therefore lets a fault happen only while the sender has a     *)
(* packet number to send each byte again that the faults can cost. Spent   *)
(* counts the packet numbers that losses used or will use. A packet is     *)
(* doomed when it has no data copy or ACK that can still arrive. A lost    *)
(* ACK can cost another packet number even after the byte arrives. Each   *)
(* excess byte from a faulty sender also uses this budget. A migration     *)
(* loses no datagram by itself: the receiver                               *)
(* accepts each issued connection ID, so a loss at a migration is a Lose.  *)
Doomed(p) ==
    /\ p \in Flight
    /\ ((p \notin rAck /\ (\A d \in net : d.pn # p))
        \/ (p \in rAck /\ p \notin ack))
JunkPNs == {p \in 1 .. Len(sLog) : sLog[p].off >= Bytes}
Spent == Cardinality(sLost \cup {p \in Flight : Doomed(p)} \cup JunkPNs)
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
    IF Bug = "SlideBeforeTag" /\ d.cid = 1 /\ d.pn > rHigh
    THEN [Unchanged EXCEPT !.high = d.pn, !.win = {q \in rWin : q + Range > d.pn}]
    ELSE Unchanged

\* The receiver's state after it takes datagram d. A datagram that fails
\* the tag, an old or duplicate packet number, a connection ID that the
\* receiver did not issue, and data beyond the credit change no state; the
\* receiver discards and counts them.
RecvState(d) ==
    IF Tagged(d) /\ Fresh(d) /\ d.off < rCredit
       /\ (~rFinal \/ d.off < Bytes) THEN Accept(d)
    ELSE IF ~Tagged(d) THEN Slid(d)
    ELSE Unchanged

Receive(d) ==
    LET r == RecvState(d) IN
    /\ rAck' = r.ack
    /\ rHigh' = r.high
    /\ rWin' = r.win
    /\ rBuf' = r.buf
    /\ ack' = IF r.ack # rAck THEN r.ack ELSE ack

-----------------------------------------------------------------------------
(* Actions. Each action is one atomic step. Its comment names the contract *)
(* row of "Datagram Form" in square brackets.                              *)

Init ==
    \* [Explicit profile] The open refuses, for example when the parent did
    \* not negotiate the extension.
    /\ sEnd \in {"open", "refused"}
    /\ rEnd = sEnd
    /\ parentLive = TRUE
    /\ ack = {}
    /\ rFinal = FALSE
    /\ path = 1
    /\ mig = "none"
    /\ tried = 1
    /\ cwnd = Window
    /\ net = {}
    /\ sLog = <<>>
    /\ sAcked = {}
    /\ sLost = {}
    /\ sCredit = Min(Bytes + Excess, Cap)
    /\ rAck = {}
    /\ rHigh = 0
    /\ rWin = {}
    /\ rBuf = [o \in WireOffsets |-> "none"]
    /\ rRead = 0
    /\ rCredit = Min(Bytes + Excess, Cap)
    /\ faults = 0

\* [Packet numbers and replay] [Receive credit] [Congestion and loss]
\* [Migration] [Path and routing] [Retransmission] The sender sends offset o
\* in a datagram with the next packet number, on the parent's path, with
\* that path's connection ID. A lost offset goes again with a new packet
\* number. The sender stays inside the credit and the shared window. Two
\* conditions are bounds of the model, not design rules (README,
\* "Reductions"). While the parent validates a new peer address, the side
\* flow sends nothing. Progress therefore assumes an eventually stable path;
\* ValidationEnds separately checks each validation. Attempts can repeat.
\* The packets in
\* flight span fewer than Range packet numbers, so the window never
\* discards a datagram that the sender still waits for; that discard changes
\* no state and removes the datagram from the network, as Lose does.
SendData(o) ==
    LET p == Len(sLog) + 1 IN
    /\ sEnd = "open" /\ parentLive
    /\ mig = "none"
    /\ Needs(o)
    /\ o < Bytes \/ (FaultySender /\ ~Sent(o))
    /\ o < sCredit
    /\ p <= MaxPN
    /\ Cardinality(Flight) < cwnd
    /\ \A q \in Flight : q + Range > p
    \* A terminal receiver cannot reopen or inspect a new payload. Keep all
    \* earlier payloads; choose one value only for this new send (README).
    /\ \E x \in (IF FaultySender /\ rEnd = "open" THEN Payloads ELSE {"good"}) :
          /\ sLog' = Append(sLog, [off |-> o, pay |-> x])
          /\ net' = net \cup {[cid |-> 1, pn |-> p, off |-> o, pay |-> x]}
    /\ UNCHANGED <<ends, pathVars, sAcked, sLost, sCredit, receiverVars, faults>>
    /\ UNCHANGED controlVars
    /\ Spent' <= Budget

\* The network delivers datagram d once. A later copy is a duplicate, which
\* changes no state.
Deliver(d) ==
    /\ rEnd = "open" /\ parentLive
    /\ d \in net
    /\ net' = net \ {d}
    /\ Receive(d)
    /\ UNCHANGED <<ends, pathVars, senderVars, rRead, rCredit, faults>>
    /\ UNCHANGED rFinal

\* The network loses datagram d.
Lose(d) ==
    /\ BothOpen
    /\ d \in net
    /\ net' = net \ {d}
    /\ UNCHANGED <<ends, pathVars, senderVars, receiverVars>>
    /\ CountFault(RecvState(d) # Unchanged)
    /\ UNCHANGED controlVars
    /\ Spent' <= Budget

\* [Injection] The on-path attacker sends again a datagram that the sender
\* sent. Any other datagram fails the tag
\* and changes no state, so the design needs no step for it. A copy of an
\* accepted datagram is a duplicate or old, and a copy of a datagram in
\* flight is the same as its early delivery, so the attacker sends only a
\* datagram that the receiver did not accept and that is not in flight.
Replay(p) ==
    /\ OnPath
    /\ rEnd = "open" /\ parentLive
    /\ p \in 1 .. Len(sLog) \ rAck
    /\ \A d \in net : d.pn # p
    /\ Receive([cid |-> 1, pn |-> p, off |-> sLog[p].off, pay |-> sLog[p].pay])
    /\ UNCHANGED <<ends, net, pathVars, senderVars, rRead, rCredit, faults>>
    /\ UNCHANGED rFinal

\* [Injection] In the variants without the tag check or with the slide
\* before it, the on-path attacker sends any datagram with a connection ID
\* that the receiver issued, which it saw on the path. It copies only the sender's
\* bytes that it saw, at their own offset, or it sends other bytes. An
\* off-path attacker does not know a connection ID, so its datagram is
\* discarded by the window check in every variant.
Forge(d) ==
    /\ OnPath
    /\ Bug \in {"NoTag", "SlideBeforeTag"}
    /\ rEnd = "open" /\ parentLive
    /\ d.cid = 1
    /\ d.pay = "good" => SeenGood(d.off)
    /\ Receive(d)
    /\ UNCHANGED <<ends, net, pathVars, senderVars, rRead, rCredit, faults>>
    /\ UNCHANGED rFinal

\* [Congestion and loss] The sender declares packet p lost by the RFC 9002
\* packet or time threshold. The model has no clock, so a declaration can
\* come at any time, also too early. A loss is a congestion event for the
\* shared controller. The model does not keep recovery periods.
DeclareLost(p) ==
    /\ sEnd = "open" /\ parentLive
    /\ p \in Flight
    /\ sLost' = sLost \cup {p}
    /\ cwnd' = Max(1, cwnd \div 2)
    /\ UNCHANGED <<ends, path, mig, tried, net, sLog, sAcked, sCredit, receiverVars>>
    /\ CountFault(~Doomed(p))
    /\ UNCHANGED controlVars
    /\ Spent' <= Budget

\* [Control] [Packet numbers and replay] The sender processes the
\* packet-number set in one parent frame and maps each number to the
\* offset that it sent. An acknowledgement of a packet number that the
\* sender never sent shows a faulty peer and ends the channel with
\* integrity; with the tag, no datagram from the network causes one.
DeliverAck ==
    /\ sEnd = "open" /\ parentLive
    /\ ack # {}
    /\ ack' = {}
    /\ sAcked' = sAcked \cup ack
    /\ sEnd' = IF ack \subseteq 1 .. Len(sLog) THEN "open" ELSE "integrity"
    /\ UNCHANGED <<rEnd, parentLive, pathVars, net, sLog, sLost, sCredit, receiverVars, faults>>
    /\ UNCHANGED rFinal

\* [Receive credit] A credit frame arrives at the sender.
DeliverCredit(c) ==
    /\ sEnd = "open" /\ parentLive
    /\ c \in sCredit + 1 .. rCredit
    /\ sCredit' = c
    /\ UNCHANGED <<ends, pathVars, net, sLog, sAcked, sLost, receiverVars, faults>>
    /\ UNCHANGED controlVars

\* The CreditBeyond variant grants one byte of credit beyond the capacity
\* that the consumer admitted.
GrantBeyond ==
    /\ Bug = "CreditBeyond"
    /\ BothOpen
    /\ rCredit < Min(Bytes + Excess, rRead + Cap + 1)
    /\ rCredit' = Min(Bytes + Excess, rRead + Cap + 1)
    /\ UNCHANGED <<ends, pathVars, net, senderVars, rAck, rHigh, rWin, rBuf, rRead, faults>>
    /\ UNCHANGED controlVars

\* [Receive credit] [Integrity] The consumer reads the byte at its read
\* point. The application's tag accepts only the sender's correct byte at
\* that offset; a tag failure ends the channel with integrity. Each read
\* admits capacity, and the receiver grants credit only for admitted
\* capacity.
Read ==
    /\ rEnd = "open" /\ parentLive
    /\ rRead < (IF rFinal THEN Bytes ELSE Bytes + Excess)
    /\ Held(rRead)
    /\ IF rBuf[rRead] = "good"
       THEN /\ rRead' = rRead + 1
            /\ rBuf' = [rBuf EXCEPT ![rRead] = "none"]
            /\ rCredit' = Min(Bytes + Excess, rRead + 1 + Cap)
            /\ UNCHANGED rEnd
       ELSE /\ rEnd' = "integrity"
            /\ UNCHANGED <<rRead, rBuf, rCredit>>
    /\ UNCHANGED <<sEnd, parentLive, pathVars, net, senderVars, rAck, rHigh, rWin, faults>>
    /\ UNCHANGED controlVars

\* [Terminal outcomes] The consumer has read to the end. The receiver's next
\* acknowledgement frame names that read point. DeliverReceiverEnd later
\* gives that outcome to an open sender. The
\* CompleteAtAck variant also completes when each byte is acknowledged,
\* without the read.
Complete ==
    /\ rEnd = "open" /\ parentLive /\ rFinal
    /\ rRead = Bytes
    /\ rEnd' = "completed"
    /\ UNCHANGED <<sEnd, parentLive, pathVars, net, senderVars, receiverVars, faults>>
    /\ UNCHANGED controlVars

CompleteAtAck ==
    /\ Bug = "CompleteAtAck" /\ sEnd = "open" /\ AllAcked
    /\ sEnd' = "completed"
    /\ UNCHANGED <<rEnd, parentLive, pathVars, net, senderVars, receiverVars, faults>>
    /\ UNCHANGED controlVars

\* A terminal frame changes only an open endpoint. The parent's reliable
\* delivery is conditional on its lifetime, including the final read point.
DeliverReceiverEnd ==
    /\ Bug # "NoFinalNotice" \/ rEnd # "completed"
    /\ parentLive /\ rEnd \in Terminal /\ sEnd = "open"
    /\ sEnd' = rEnd
    /\ UNCHANGED <<rEnd, parentLive, pathVars, net, senderVars, receiverVars, faults>>
    /\ UNCHANGED controlVars

DeliverSenderEnd ==
    /\ parentLive /\ sEnd \in Terminal /\ rEnd = "open"
    /\ rEnd' = sEnd
    /\ UNCHANGED <<sEnd, parentLive, pathVars, net, senderVars, receiverVars, faults>>
    /\ UNCHANGED controlVars

\* [Terminal outcomes] An application resets the channel with an error
\* code. The LateReset variant also resets a channel that has ended.
Reset(side) ==
    /\ parentLive
    /\ IF side = "sender"
        THEN /\ sEnd = "open" \/ (Bug = "LateReset" /\ sEnd # "reset")
             /\ sEnd' = "reset" /\ UNCHANGED rEnd
        ELSE /\ rEnd = "open" \/ (Bug = "LateReset" /\ rEnd # "reset")
             /\ rEnd' = "reset" /\ UNCHANGED sEnd
    /\ UNCHANGED <<parentLive, pathVars, net, senderVars, receiverVars, faults>>
    /\ UNCHANGED controlVars

\* [Terminal outcomes] (Attached Channels: Lifetime) The parent ends. Bytes
\* that are not acknowledged give the partial-delivery outcome.
ParentEnd ==
    /\ parentLive
    \* Omit parent failure after both endpoints and validation end. It only
    \* changes an unused lifetime bit there (README, "Reductions"). Keep
    \* failure during pending validation: ValidationEnds still observes it.
    /\ ~BothDone \/ mig # "none"
    /\ parentLive' = FALSE
    /\ sEnd' = IF sEnd # "open" THEN sEnd ELSE IF AllAcked THEN "parentEnd" ELSE "partial"
    /\ rEnd' = IF rEnd # "open" THEN rEnd
                ELSE IF \A o \in Offsets : o < rRead \/ Held(o) THEN "parentEnd" ELSE "partial"
    /\ UNCHANGED <<pathVars, net, senderVars, receiverVars, faults>>
    /\ UNCHANGED controlVars

\* [Congestion and loss] A parent packet is lost on the parent's path: a
\* congestion event for the shared controller. During a validation, the
\* parent's packets go to the new peer address and count for that path's
\* controller (RFC 9000 section 9.4), which the model does not keep: success
\* resets it, and an abandon discards it.
ParentLoss ==
    /\ BothOpen
    /\ mig = "none"
    /\ cwnd > 1
    /\ cwnd' = cwnd \div 2
    /\ UNCHANGED <<ends, path, mig, tried, net, senderVars, receiverVars, faults>>
    /\ UNCHANGED controlVars

\* [Migration] The peer moves, and the parent starts to validate a different
\* path (RFC 9000 section 9.3). Abstract identities can be used again.
\* A peer event: no fairness and no finite attempt budget.
MigrateStart ==
    /\ BothOpen
    /\ mig = "none"
    /\ tried' \in (1 .. Paths) \ {path}
    /\ mig' = "genuine"
    /\ UNCHANGED <<ends, path, cwnd, net, senderVars, receiverVars, faults>>
    /\ UNCHANGED controlVars

\* [Migration] A spurious migration: the on-path attacker forwards a copy of
\* a parent packet with a spoofed address, and its copy arrives first (RFC
\* 9000 sections 9.3.2 and 9.3.3). The parent starts to validate the
\* spoofed address on a new path. Nobody at that address has the keys, so
\* this validation cannot succeed. An attacker event: no fairness.
Spoof ==
    /\ OnPath
    /\ BothOpen
    /\ mig = "none"
    /\ tried' \in (1 .. Paths) \ {path}
    /\ mig' = "spurious"
    /\ UNCHANGED <<ends, path, cwnd, net, senderVars, receiverVars, faults>>
    /\ UNCHANGED controlVars

\* [Migration] The validation succeeds: the PATH_RESPONSE arrives (RFC 9000
\* section 8.2). The side flow follows the parent to the new path and its
\* connection ID, and the new path's congestion state starts at its
\* initial values (section 9.4).
Validated ==
    /\ parentLive
    /\ mig = "genuine"
    /\ path' = tried
    /\ mig' = "none"
    /\ cwnd' = Window
    /\ UNCHANGED <<ends, tried, net, senderVars, receiverVars, faults>>
    /\ UNCHANGED controlVars

\* [Migration] The validation timer expires (RFC 9000 section 8.2.4,
\* three times the larger PTO), or a higher-numbered packet from the last
\* validated address moves the parent back (section 9.3.2). The parent
\* abandons the validation and returns to its last validated path, and the
\* side flow returns with it. That path's congestion state is restored
\* (section 9.3): cwnd kept its value during the validation. The NoAbandon
\* variant, the design as written before 2026-11-07, has no such step.
Abandon ==
    /\ Bug # "NoAbandon"
    /\ parentLive
    /\ mig # "none"
    /\ mig' = "none"
    /\ UNCHANGED <<ends, path, tried, cwnd, net, senderVars, receiverVars, faults>>
    /\ UNCHANGED controlVars

\* A terminal state stays as it is.
Done ==
    /\ BothDone
    /\ UNCHANGED vars

-----------------------------------------------------------------------------
(* The ReusePN variant: a retransmission reuses the packet number that the *)
(* sender declared lost. When the window has passed that number, the       *)
(* receiver discards each copy as old, and the sender sends it again       *)
(* forever. With the tag, a reused packet number is also a reused nonce.   *)

ResendSamePN(p) ==
    /\ Bug = "ReusePN"
    /\ sEnd = "open" /\ parentLive
    /\ mig = "none"
    /\ p \in sLost \ sAcked
    /\ Needs(sLog[p].off)
    /\ sLog[p].off < sCredit
    /\ Cardinality(Flight) < cwnd
    /\ sLost' = sLost \ {p}
    /\ net' = net \cup {[cid |-> 1, pn |-> p, off |-> sLog[p].off, pay |-> sLog[p].pay]}
    /\ UNCHANGED <<ends, pathVars, sLog, sAcked, sCredit, receiverVars, faults>>
    /\ UNCHANGED controlVars

-----------------------------------------------------------------------------
(* The next-state relation and the fairness *)

\* Ordinary ACK frames may be lost. A later data arrival replaces their
\* state. A lost last ACK also enables the sender's loss timer.
LoseAck ==
    /\ parentLive /\ ack # {}
    /\ ack' = {}
    /\ UNCHANGED <<ends, rFinal, pathVars, net, senderVars, receiverVars>>
    /\ CountFault(ack \ sAcked # {})
    /\ Spent' <= Budget

\* Final-size arrival is separate from data. Unread excess is discarded.
DeliverFinalSize ==
    /\ parentLive /\ rEnd = "open" /\ ~rFinal
    /\ rFinal' = TRUE
    /\ rEnd' = IF rRead > Bytes /\ Bug # "NoFinalIntegrity" THEN "integrity" ELSE rEnd
    /\ rBuf' = IF Bug = "FinalKeepsJunk" THEN rBuf
                ELSE [o \in WireOffsets |-> IF o < Bytes THEN rBuf[o] ELSE "none"]
    /\ UNCHANGED <<sEnd, parentLive, ack, pathVars, net, senderVars, rAck, rHigh, rWin, rRead, rCredit, faults>>

\* The ReusePN variant keeps first sends and reuses the number on a retry.
SendNext ==
    IF Bug = "ReusePN"
    THEN \/ \E o \in WireOffsets : SendData(o) /\ ~Sent(o)
         \/ \E p \in PNs : ResendSamePN(p)
    ELSE \E o \in WireOffsets : SendData(o)

Next ==
    \/ SendNext
    \/ \E d \in net : Deliver(d)
    \/ \E p \in PNs : Replay(p)
    \/ Bug \in {"NoTag", "SlideBeforeTag"} /\ \E d \in Datagrams : Forge(d)
    \/ DeliverAck
    \/ \E d \in net : Lose(d)
    \/ \E p \in PNs : DeclareLost(p)
    \/ \E c \in 1 .. (Bytes + Excess) : DeliverCredit(c)
    \/ GrantBeyond
    \/ Read
    \/ Complete \/ CompleteAtAck \/ DeliverReceiverEnd \/ DeliverSenderEnd
    \/ LoseAck \/ DeliverFinalSize
    \/ \E side \in {"sender", "receiver"} : Reset(side)
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
    /\ WF_vars(DeliverAck)
    /\ WF_vars(\E d \in net : Deliver(d))
    \* The bad timer omits accepted packets whose last ACK was lost. The
    \* fault budget still charges those losses, as it does in the design.
    /\ WF_vars(\E p \in PNs : Doomed(p)
                              /\ (Bug # "NoAckRecovery" \/ p \notin rAck)
                              /\ DeclareLost(p))
    /\ WF_vars(\E c \in 1 .. (Bytes + Excess) : DeliverCredit(c))
    /\ WF_vars(Complete)
    /\ WF_vars(DeliverFinalSize)
    /\ WF_vars(DeliverReceiverEnd)
    /\ WF_vars(DeliverSenderEnd)
    /\ WF_vars(Validated \/ Abandon)

Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ WF_vars(\E o \in WireOffsets : SendData(o))
    /\ OtherFairness

\* The ReusePN variant: the sender's fairness covers the first
\* transmissions and the retransmissions that reuse a packet number.
ReuseSpec ==
    /\ Init
    /\ [][Next]_vars
    /\ WF_vars(\E o \in WireOffsets : SendData(o) /\ ~Sent(o))
    /\ WF_vars(\E p \in PNs : ResendSamePN(p))
    /\ OtherFairness

-----------------------------------------------------------------------------
(* Properties *)

TypeOK ==
    /\ sEnd \in {"open"} \cup Terminal
    /\ rEnd \in {"open"} \cup Terminal
    /\ parentLive \in BOOLEAN
    /\ ack \subseteq PNs /\ ack \subseteq rAck
    /\ rFinal \in BOOLEAN
    /\ path \in 1 .. Paths
    /\ mig \in {"none", "genuine", "spurious"}
    /\ tried \in 1 .. Paths
    /\ cwnd \in 1 .. Window
    /\ net \subseteq Datagrams
    /\ sLog \in Seq([off : WireOffsets, pay : Payloads]) /\ Len(sLog) <= MaxPN
    /\ sAcked \subseteq PNs
    /\ sLost \subseteq PNs
    /\ sCredit \in 0 .. (Bytes + Excess)
    /\ rAck \subseteq PNs
    /\ rHigh \in 0 .. MaxPN
    /\ rWin \subseteq PNs
    /\ rBuf \in [WireOffsets -> {"none"} \cup Payloads]
    /\ rRead \in 0 .. (Bytes + Excess)
    /\ rCredit \in 0 .. (Bytes + Excess)
    /\ faults \in 0 .. Budget
    /\ BothOpen => Spent <= Budget

\* The receiver holds only bytes that the sender sent at that offset. No
\* step checks this; only the tag makes it hold.
HeldAreSenderBytes ==
    \A o \in WireOffsets :
        Held(o) => \E p \in 1 .. Len(sLog) : sLog[p] = [off |-> o, pay |-> rBuf[o]]

\* The receiver holds no data beyond the credit that it granted, and it
\* granted credit only for capacity that the consumer admitted.
CreditBound == \A o \in WireOffsets : Held(o) => o < rCredit /\ o < rRead + Cap

\* The receiver's replay state stays inside its declared window.
PNStateBound == \A q \in rWin : q + Range > rHigh

\* [Terminal outcomes] A transport acknowledgement means that the
\* receiver's transport holds the bytes: each offset that the sender counts
\* as acknowledged is held by the receiver or read by the consumer.
AckMeansHeld == \A o \in AckedOffsets : o < rRead \/ Held(o)

\* Completion needs the consumer's read to the final size.
CompletionSound ==
    /\ sEnd = "completed" => rEnd = "completed"
    /\ rEnd = "completed" => rFinal /\ rRead = Bytes
FinalSizeBound == rFinal => \A o \in WireOffsets \ Offsets : ~Held(o)
FinalReadIntegrity == rFinal /\ rRead > Bytes => rEnd = "integrity"

\* With an honest sender, no datagram from the network or from an attacker
\* ends the channel with the integrity outcome.
NoNetworkIntegrity == sEnd # "integrity" /\ rEnd # "integrity"

\* The window moves only when the receiver accepts a datagram, so only after
\* the datagram's tag passes.
WindowAfterTag == [][rHigh' # rHigh => rHigh' \in rAck' \ rAck]_vars

\* Each endpoint keeps its terminal outcome, including after a late frame.
OutcomeStable ==
    [][(sEnd # "open" => sEnd' = sEnd)
       /\ (rEnd # "open" => rEnd' = rEnd)]_vars

\* Progress: with a stable path and a reading consumer, both ends terminate. With no
\* reset and no parent end, an honest transfer completes. The consumer's read
\* is a caller event, so it is the condition of the property, not a
\* fairness of the specification.
\* BothDone is absorbing, including in LateReset: no action reopens an end.
\* Thus <>BothDone equals []<>BothDone. If validation is not pending, its
\* target already holds, so the response property also equals recurrence.
\* These forms avoid tableaux without changing fairness (README).
Progress == (WF_vars(Read) /\ <>[](mig = "none")) => []<>BothDone
ValidationEnds == []<>(mig = "none" \/ ~parentLive)

-----------------------------------------------------------------------------
(* Reachability targets. Each witness profile checks the negation of one   *)
(* target, and the checker must find a behavior that reaches it.           *)

NotCompleted == outcome # "completed"
NotReset == outcome # "reset"
NotParentEnd == outcome # "parentEnd"
NotPartial == outcome # "partial"
NotRefused == outcome # "refused"
NotIntegrity == outcome # "integrity"

\* A migration completed and the sender sends on the selected path.
NotResumed == [][~(path > 1 /\ (\E o \in WireOffsets : SendData(o)))]_vars

\* The parent abandons a validation and returns to its last validated path.
NotAbandoned == ~(mig = "none" /\ tried # path)

\* The sender receives the final read point after an abandoned validation.
\* Both endpoints are complete after this step; abandonment cannot come later.
NotCompletedAfterAbandon ==
    [][~(mig = "none" /\ tried # path /\ rEnd = "completed" /\ DeliverReceiverEnd)]_vars

\* An earlier attempt was abandoned; another genuine or spurious attempt
\* starts. No history counter bounds the number of attempts.
NeverRepeatMigration == [][~(mig = "none" /\ tried # path /\ (MigrateStart \/ Spoof))]_vars

\* The window passes a packet number that the receiver did not accept.
NotWindowPassed == ~(\E p \in 1 .. Len(sLog) : p + Range <= rHigh /\ p \notin rAck)

\* The receiver accepts a datagram that the attacker sent again.
NeverReplayAccepted == [][\A p \in PNs : ~(Replay(p) /\ rAck' # rAck)]_vars


\* Witnesses of the split control and endpoint states.
NotCrossed == ~(rEnd = "completed" /\ sEnd = "reset")
NotParentInterrupted == ~(rEnd = "completed" /\ sEnd = "partial" /\ ~parentLive)
NotFinalDelayed == ~(rRead = Bytes /\ ~rFinal /\ rEnd = "open")
NotLastAckLost == [][~(LoseAck /\ ack \cap Flight # {})]_vars
NotFinalBelowRead == ~(rFinal /\ rRead > Bytes /\ rEnd = "integrity")
NotJunkDiscarded == [][~(DeliverFinalSize /\ Held(Bytes) /\ ~Held(Bytes)')]_vars

-----------------------------------------------------------------------------
(* Exact state view. The actions and properties above keep their original *)
(* state. README, "State view", gives the transition and fairness argument. *)

\* Outside Flight, an accepted or below-floor entry cannot be accepted or
\* become live again. Variants that can revive old entries keep the full log.
LogPNs == 1 .. Len(sLog)
LiveLogPNs ==
    IF Bug \in {"ReusePN", "NoWindowBound"} THEN LogPNs
    ELSE {p \in LogPNs : p \in Flight \/ (p \notin rAck /\ p + Range > rHigh)}

\* Historical uses of the log need these sets, not the old packet mapping.
SentEntries == {sLog[p] : p \in LogPNs}
OffsetsOf(packets) == {sLog[p].off : p \in packets \cap LogPNs} \cap Offsets

OpenView ==
    <<ends, controlVars, pathVars, {d.pn : d \in net}, Len(sLog),
      [p \in LiveLogPNs |-> sLog[p]], SentEntries,
      AckedOffsets, OffsetsOf(ack), OffsetsOf(rAck), JunkPNs,
      sAcked, sLost, sCredit, receiverVars, faults>>

\* Both terminal endpoints stay terminal. Only validation, parent failure,
\* optional ACK loss, and LateReset can still change state. Keep their
\* observations and the fixed data predicates. Keep ACK-loss enabledness:
\* loss then leads to FALSE and cannot create an artificial repeatable edge.
ClosedView ==
    <<ends, path, mig, tried, rFinal, rRead,
      TypeOK, HeldAreSenderBytes, CreditBound, PNStateBound, AckMeansHeld,
      FinalSizeBound, NotWindowPassed,
      ENABLED LoseAck, ack \cap Flight # {}>>

StateView == IF BothDone THEN <<"closed", ClosedView>> ELSE <<"open", OpenView>>

=============================================================================
