------------------------ MODULE CheckpointSelection ------------------------
EXTENDS Integers, FiniteSets

CONSTANTS CandidateCount, RingSlots

NoXid == 0
Xids == 1..CandidateCount
Slots == 1..RingSlots
MapStates == {"complete", "missing", "torn", "wrongXid", "unsupported", "unreadable"}
CorruptMaps == {"missing", "torn", "wrongXid"}
Evidence ==
    {[xid |-> NoXid, descriptor |-> status, map |-> "unchecked"] :
        status \in {"missing", "torn"}}
    \cup [xid : Xids, descriptor : {"verified"}, map : MapStates]

VARIABLES ring, origin, requested, scanned, pending, rejected, result

vars == <<ring, origin, requested, scanned, pending, rejected, result>>

Report(status, xid) == [status |-> status, xid |-> xid]
Searching == Report("searching", NoXid)
Finished == result /= Searching

Init ==
    /\ ring \in [Slots -> Evidence]
    /\ origin \in Slots
    /\ requested \in {NoXid} \cup Xids
    /\ scanned = 0
    /\ pending = {}
    /\ rejected = {}
    /\ result = Searching

Visit ==
    /\ scanned < RingSlots
    /\ LET slot == 1 + ((origin - 1 + scanned) % RingSlots)
           descriptor == ring[slot]
       IN pending' =
           IF descriptor.descriptor = "verified"
               /\ (requested = NoXid \/ requested = descriptor.xid)
           THEN pending \cup {slot}
           ELSE pending
    /\ scanned' = scanned + 1
    /\ UNCHANGED <<ring, origin, requested, rejected, result>>

Newest(slots) == {s \in slots : \A t \in slots : ring[s].xid >= ring[t].xid}

TryCandidate ==
    /\ scanned = RingSlots
    /\ pending /= {}
    /\ LET newest == Newest(pending)
           slot == CHOOSE s \in newest : TRUE
           candidate == ring[slot]
           xid == candidate.xid
       IN IF Cardinality(newest) > 1 THEN
              /\ result' = Report("ambiguous", xid)
              /\ UNCHANGED <<pending, rejected>>
          ELSE CASE candidate.map = "complete" ->
                        /\ result' = Report("selected", xid)
                        /\ UNCHANGED <<pending, rejected>>
                 [] candidate.map \in {"unsupported", "unreadable"} ->
                        /\ result' = Report(candidate.map, xid)
                        /\ UNCHANGED <<pending, rejected>>
                 [] candidate.map \in CorruptMaps /\ requested /= NoXid ->
                        /\ result' = Report("corrupt", xid)
                        /\ UNCHANGED <<pending, rejected>>
                 [] OTHER ->
                        /\ pending' = pending \ {slot}
                        /\ rejected' = rejected \cup {slot}
                        /\ UNCHANGED result
    /\ UNCHANGED <<ring, origin, requested, scanned>>

Exhausted ==
    /\ scanned = RingSlots
    /\ pending = {}
    /\ result' = IF requested = NoXid THEN Report("noCheckpoint", NoXid)
                 ELSE Report("notFound", requested)
    /\ UNCHANGED <<ring, origin, requested, scanned, pending, rejected>>

Next == IF Finished THEN UNCHANGED vars ELSE Visit \/ TryCandidate \/ Exhausted
Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

TypeOK ==
    /\ ring \in [Slots -> Evidence]
    /\ origin \in Slots
    /\ requested \in {NoXid} \cup Xids
    /\ scanned \in 0..RingSlots
    /\ pending \in SUBSET Slots
    /\ rejected \in SUBSET Slots
    /\ result \in [status : {"searching", "selected", "ambiguous", "corrupt",
                           "unsupported", "unreadable", "noCheckpoint", "notFound"},
                  xid : {NoXid} \cup Xids]

\* Declarative policy over all ring evidence, independent of scan order and removals.
\* A transaction can halt selection if it has duplicate descriptors, is complete,
\* is inconclusive, or is the exact transaction requested.
Eligible == {s \in Slots : ring[s].descriptor = "verified"
                         /\ (requested = NoXid \/ requested = ring[s].xid)}
Count(xid) == Cardinality({s \in Eligible : ring[s].xid = xid})
Decisive == {s \in Eligible : Count(ring[s].xid) > 1
                           \/ requested /= NoXid \/ ring[s].map \notin CorruptMaps}

Expected ==
    IF Decisive = {} THEN
        IF requested = NoXid THEN Report("noCheckpoint", NoXid)
        ELSE Report("notFound", requested)
    ELSE
        LET xid == CHOOSE x \in Xids : (\E s \in Decisive : ring[s].xid = x)
                                    /\ (\A s \in Decisive : x >= ring[s].xid)
            slot == CHOOSE s \in Decisive : ring[s].xid = xid
            map == ring[slot].map
        IN Report(IF Count(xid) > 1 THEN "ambiguous"
                  ELSE CASE map = "complete" -> "selected"
                         [] map \in CorruptMaps -> "corrupt"
                         [] OTHER -> map, xid)

SelectionMatchesEvidence == Finished => result = Expected

FallbackIsExplained ==
    /\ (requested /= NoXid => rejected = {})
    /\ (result.status = "selected" =>
            rejected = {s \in Eligible : ring[s].xid > result.xid})
    /\ (result.status = "noCheckpoint" => rejected = Eligible)
    /\ (\A s \in rejected : s \in Eligible /\ ring[s].map \in CorruptMaps)

Terminates == <>Finished
=============================================================================
