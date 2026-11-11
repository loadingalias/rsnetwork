-------------------------- MODULE OldPacketReuse ---------------------------
EXTENDS AttachedDatagram

\* Keep ordinary ACKs in this known-bad run. The counterexample must expose
\* reuse below the replay window, independently of lost-ACK recovery.
NoAckLoss == ~LoseAck

===========================================================================
