"""Compare the positive native checkpoint replay with an independent wire scan."""

import json
from pathlib import Path
from struct import unpack_from
import sys

from native_checkpoint_fixtures import ADDRESS_BYTES, BASE, DERIVED, FIXTURES


BLOCK_SIZE = 4096
WORD_BYTES = 4
CHECKSUM_BYTES = 8
FLETCHER_MODULUS = (1 << 32) - 1
NXSB_TYPE = 0x8000_0001
NXSB_OBJECT_ID = 1
CHECKPOINT_MAP_TYPE = 0x4000_000C
OBJECT_MAP_TYPE = 0x4000_000B
LAST_MAP = 1
RING_SLOTS = 8
DESCRIPTORS_PER_CANDIDATE = 2
MAPPING_BYTES = 40
HEADER = "<QQII"
MAPPING = "<III4xQQQ"
NXSB_MAGIC_OFFSET = 32
DESCRIPTOR_COUNT_OFFSET = 104
DESCRIPTOR_BASE_OFFSET = 112
DATA_BASE_OFFSET = 120
DESCRIPTOR_NEXT_OFFSET = 128
DESCRIPTOR_INDEX_OFFSET = 136
DATA_INDEX_OFFSET = 144
OBJECT_MAP_OFFSET = 160
MAP_HEADER_OFFSET = 32
MAPPINGS_OFFSET = 40
PRODUCTION_PREFIX = "APFS native checkpoints replay "
COMPARISON_PREFIX = "APFS checkpoint differential matched "


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def u32(block, offset):
    return unpack_from("<I", block, offset)[0]


def u64(block, offset):
    return unpack_from("<Q", block, offset)[0]


def header(block):
    check = unpack_from("<II", block)
    words = unpack_from(f"<{(BLOCK_SIZE - CHECKSUM_BYTES) // WORD_BYTES}I", block, CHECKSUM_BYTES)
    message = words + check
    weighted = sum(weight * value for weight, value in enumerate(reversed(message), start=1))
    require(all(check) and sum(message) % FLETCHER_MODULUS == weighted % FLETCHER_MODULUS == 0,
            "expected a complete checksummed native object")
    return unpack_from(HEADER, block, CHECKSUM_BYTES)


def read_blocks(name):
    packed = (FIXTURES / f"{name}.bin").read_bytes()
    stride = ADDRESS_BYTES + BLOCK_SIZE
    return {u64(packed, offset): packed[offset + ADDRESS_BYTES:offset + stride]
            for offset in range(0, len(packed), stride)}


def read_candidates(blocks, ring_base, data_base, slots):
    candidates = []
    for descriptor in range(ring_base, ring_base + slots):
        nxsb = blocks[descriptor]
        oid, xid, kind, subtype = header(nxsb)
        if kind == CHECKPOINT_MAP_TYPE:
            continue
        require((oid, kind, subtype) == (NXSB_OBJECT_ID, NXSB_TYPE, 0)
                and nxsb[NXSB_MAGIC_OFFSET:NXSB_MAGIC_OFFSET + WORD_BYTES] == b"NXSB",
                "fixture requires ordinary NXSB and checkpoint map blocks")
        index, length = unpack_from("<II", nxsb, DESCRIPTOR_INDEX_OFFSET)
        require(index < slots and length == DESCRIPTORS_PER_CANDIDATE, "expected a two-block descriptor span")
        live = [(index + step) % slots for step in range(length)]
        next_slot = u32(nxsb, DESCRIPTOR_NEXT_OFFSET)
        require(ring_base + live[-1] == descriptor and next_slot == (index + length) % slots,
                "expected one map followed by a live NXSB")
        mapping = blocks[ring_base + live[0]]
        require(header(mapping) == (ring_base + live[0], xid, CHECKPOINT_MAP_TYPE, 0),
                "checkpoint map identity differs from its descriptor")
        flags, count = unpack_from("<II", mapping, MAP_HEADER_OFFSET)
        require(flags == LAST_MAP and 0 < count <= (BLOCK_SIZE - MAPPINGS_OFFSET) // MAPPING_BYTES,
                "expected one terminal checkpoint map")
        entries = [unpack_from(MAPPING, mapping, MAPPINGS_OFFSET + index * MAPPING_BYTES)
                   for index in range(count)]
        data_index, data_length = unpack_from("<II", nxsb, DATA_INDEX_OFFSET)
        physical = sorted(entry[-1] for entry in entries)
        require(all(size == BLOCK_SIZE for _, _, size, _, _, _ in entries)
                and data_length == count
                and physical == list(range(data_base + data_index, data_base + data_index + data_length)),
                "expected the observed one-block mappings to cover the contiguous data span")
        candidates.append((xid, descriptor, next_slot, live, entries, u64(nxsb, OBJECT_MAP_OFFSET)))
    return candidates


def compare(name, production_rows):
    blocks = read_blocks(name)
    bootstrap = blocks[0]
    require(header(bootstrap)[2] == NXSB_TYPE, "expected a native NXSB bootstrap")
    slots = u32(bootstrap, DESCRIPTOR_COUNT_OFFSET)
    require(slots == RING_SLOTS, "comparison is limited to the retained eight-slot rings")
    candidates = read_candidates(blocks, u64(bootstrap, DESCRIPTOR_BASE_OFFSET),
                                 u64(bootstrap, DATA_BASE_OFFSET), slots)
    xids = [candidate[0] for candidate in candidates]
    require(len(xids) == slots // DESCRIPTORS_PER_CANDIDATE and len(set(xids)) == len(xids),
            "expected a full ring of distinct candidate descriptors")
    xid, descriptor, next_slot, live, entries, object_map = max(candidates)
    for kind, subtype, _, _, oid, physical in entries:
        require(header(blocks[physical]) == (oid, xid, kind, subtype), "selected payload identity differs")
    oid, map_xid, kind, subtype = header(blocks[object_map])
    require((oid, kind, subtype) == (object_map, OBJECT_MAP_TYPE, 0) and 0 < map_xid <= xid,
            "selected object map identity differs")
    ledger = json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))
    require(xid == ledger["native_checker"]["checkpoint_xid"], "independent XID differs from Apple's checker")
    payloads = [entry[-1] for entry in sorted(entries, key=lambda entry: entry[-2])]
    facts = f"{name} {xid} {descriptor} {slots} {next_slot} {live} {xids} {payloads}"
    require(production_rows.count(f"{PRODUCTION_PREFIX}{facts}") == 1,
            "independent selection differs from production replay")
    print(f"{COMPARISON_PREFIX}{facts}")


if __name__ == "__main__":
    rows = Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
    require(rows[-1:] == [f"{PRODUCTION_PREFIX}completed"], "expected a completed production replay")
    observations = [line for line in rows[:-1] if line.startswith(PRODUCTION_PREFIX)]
    require(len(observations) == 2,
            "expected one production observation for each retained fixture")
    for fixture in (BASE, DERIVED):
        compare(fixture, observations)
