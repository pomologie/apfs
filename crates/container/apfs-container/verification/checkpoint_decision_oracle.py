"""Compare the bounded A-V02 resolver observations with typed decision rules."""

import hashlib
import itertools
import sys


PREFIX = "APFS checkpoint outcome "
XIDS = (1, 2, 3)
STATES = (
    "Complete",
    "AbsentDescriptor",
    "TornDescriptor",
    "BlankMap",
    "MismatchedMap",
    "UnsupportedMap",
    "UnreadablePayload",
)
REQUESTS = ("automatic", *XIDS)
POSITIONS = (2, 4)
ADVERTISED_XID = 3
PAYLOAD_BLOCK_BASE = 9
BLOCK_BYTES = 4096
UNSUPPORTED_FLAGS = 1 << 31
MAP_REJECTIONS = {"BlankMap": "invalid-checksum", "MismatchedMap": "object"}
DESCRIPTOR_REJECTIONS = ("AbsentDescriptor", "TornDescriptor")
NO_FIELD = "-"


def observation(slots, request):
    diagnostics = [
        f"rejected:{position}:{NO_FIELD}:invalid-checksum"
        for position, _, state in slots
        if state == "TornDescriptor"
    ]
    candidates = [
        (xid, position, state)
        for position, xid, state in slots
        if state not in DESCRIPTOR_REJECTIONS and (request == "automatic" or xid == request)
    ]
    attempts = []
    requested_xid = NO_FIELD if request == "automatic" else request
    result = f"absent {requested_xid}"

    # An XID's candidates must be unique before any can be verified. Walking
    # descending groups keeps earlier rejection and attempt order observable.
    for xid, group in itertools.groupby(sorted(candidates, reverse=True), key=lambda item: item[0]):
        descriptors = list(group)
        if len(descriptors) > 1:
            return f"ambiguous {xid}", attempts, []
        _, position, state = descriptors[0]
        attempts.append(position)
        if state in MAP_REJECTIONS:
            damage = f"{position}:{xid}:{MAP_REJECTIONS[state]}"
            if request != "automatic":
                return f"corrupt {damage}", attempts, []
            diagnostics.append(f"rejected:{damage}")
            continue
        if state == "UnsupportedMap":
            return f"unsupported {position} {xid} checkpoint-map-flags {UNSUPPORTED_FLAGS}", attempts, []
        if state == "UnreadablePayload":
            payload = PAYLOAD_BLOCK_BASE + position
            return f"unreadable {payload * BLOCK_BYTES} {payload}", attempts, []
        if state != "Complete":
            raise ValueError(f"Unexpected candidate state {state}")
        if request == "automatic" and xid < ADVERTISED_XID:
            diagnostics.append(f"newer-bootstrap:{ADVERTISED_XID}:{xid}")
        result = f"selected {position} {xid}"
        break
    return result, attempts, diagnostics


def sequence_field(values):
    return ",".join(map(str, values)) or NO_FIELD


def expected_rows():
    for first_xid, second_xid, first_state, second_state, request in itertools.product(
        XIDS, XIDS, STATES, STATES, REQUESTS
    ):
        slots = ((POSITIONS[0], first_xid, first_state), (POSITIONS[1], second_xid, second_state))
        result, attempts, diagnostics = observation(slots, request)
        case = f"{first_xid} {first_state} {second_xid} {second_state} {request}"
        yield f"{PREFIX}{case} | {result} | {sequence_field(attempts)} | {sequence_field(diagnostics)}"


def verify(lines):
    versions = []
    rows = []
    for line in lines:
        if line.startswith("rustc "):
            versions.append(line.rstrip("\n"))
        elif line.startswith(PREFIX):
            if not line.endswith("\n"):
                raise ValueError("Incomplete checkpoint decision row")
            rows.append(line.removesuffix("\n"))
    if len(versions) != 1:
        raise ValueError(f"Expected one rustc version, observed {len(versions)}")
    expected = list(expected_rows())
    if len(rows) != len(expected):
        raise ValueError(f"Expected {len(expected)} decision rows, observed {len(rows)}")
    for index, (actual, wanted) in enumerate(zip(rows, expected), start=1):
        if actual != wanted:
            raise ValueError(f"Decision row {index} differs\nExpected {wanted}\nObserved {actual}")
    digest = hashlib.sha256("".join(row + "\n" for row in rows).encode("ascii")).hexdigest()
    return versions[0], rows, digest


if __name__ == "__main__":
    try:
        version, matched_rows, sha256 = verify(sys.stdin)
    except ValueError as error:
        sys.exit(str(error))
    print(version)
    for row in matched_rows:
        print(row)
    print(f"APFS checkpoint decision differential rows: {len(matched_rows)}")
    print(f"APFS checkpoint decision differential sha256: {sha256}")
