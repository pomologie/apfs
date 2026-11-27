#!/usr/bin/env python3
"""Compare the retained native APFS volume-growth pair against the Rust replay."""

from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
from struct import unpack_from
import subprocess
from uuid import UUID


CRATE = Path(__file__).resolve().parent.parent
ROOT = CRATE.parents[2]
FIXTURES = CRATE / "tests" / "fixtures" / "native-volume-growth"
TOOLCHAIN = "1.99.1"
TEST = "native_checkpoint_and_volume_selection_agree_with_apple_after_volume_growth"
REPLAY = "APFS native volume growth"
BLOCK_BYTES = 4096
ADDRESS_BYTES = 8
RECORD_BYTES = ADDRESS_BYTES + BLOCK_BYTES
FLETCHER_MODULUS = (1 << 32) - 1
HEADER = "<QQQII"
NXSB = 0x80000001
MAP = 0x4000000C
OBJECT_MAP = 0x4000000B
VOLUME = 13
NXSB_MAGIC = b"NXSB"
VOLUME_MAGIC = b"APSB"
MAGIC = 32
BLOCK_SIZE = 36
BLOCK_COUNT = 40
OBJECT_MAP_ADDRESS = 160
VOLUME_SLOT_COUNT = 180
VOLUME_IDS = 184
MAX_VOLUME_SLOTS = 100
VOLUME_UUID = 240
VOLUME_NAME = 704
VOLUME_NAME_BYTES = 256
MAP_FLAGS = 32
MAP_COUNT = 36
TERMINAL_MAP = 1
MAPPING_FIELDS = "<III4xQQQ"
MAPPING_RECORD_BYTES = 40
MAPPING_TABLE = 40


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return sha256(data).hexdigest()


def u32(data, offset):
    return unpack_from("<I", data, offset)[0]


def u64(data, offset):
    return unpack_from("<Q", data, offset)[0]


def header(data):
    return unpack_from(HEADER, data)


def verify_checksum(data):
    words = unpack_from("<1024I", data)
    ordered = words[2:] + words[:2]
    unweighted = sum(ordered)
    weighted = sum(position * value for position, value in enumerate(reversed(ordered), 1))
    require(all(words[:2]) and unweighted % FLETCHER_MODULUS == weighted % FLETCHER_MODULUS == 0,
            "retained APFS object has the wrong Fletcher-64 residue")


@dataclass(frozen=True)
class Ring:
    base: int
    blocks: int
    index: int
    length: int
    next: int

    @property
    def slots(self):
        return [(self.index + ordinal) % self.blocks for ordinal in range(self.length)]

    @property
    def addresses(self):
        return [self.base + slot for slot in self.slots]

    def validate(self, capacity):
        require(self.base > 0 and self.base + self.blocks <= capacity
                and 0 <= self.index < self.blocks and 0 < self.length <= self.blocks
                and self.next == (self.index + self.length) % self.blocks,
                "unexpected retained ring geometry")
        return self

    def facts(self):
        return f"{self.base} {self.blocks} {self.index} {self.length} {self.next}"

    def ledger_record(self):
        return vars(self) | {"live_slots": self.slots}


def ring_fields(data, count, base, index, length, next_slot):
    return Ring(u64(data, base), u32(data, count), u32(data, index),
                u32(data, length), u32(data, next_slot))


def descriptor_ring(data):
    return ring_fields(data, 104, 112, 136, 140, 128)


def data_ring(data):
    return ring_fields(data, 108, 120, 144, 148, 132)


def load_blocks(stage):
    fixture = stage["fixtures"]
    packed = (FIXTURES / fixture["file"]).read_bytes()
    require(digest(packed) == fixture["sha256"] and len(packed) % RECORD_BYTES == 0,
            "packed checkpoint bytes disagree with the acquisition ledger")
    blocks = {}
    for offset in range(0, len(packed), RECORD_BYTES):
        address = u64(packed, offset)
        block = packed[offset + ADDRESS_BYTES:offset + RECORD_BYTES]
        require(address * BLOCK_BYTES < stage["raw_length"] and address not in blocks,
                "packed address is duplicate or exceeds the source")
        if any(block):
            verify_checksum(block)
        blocks[address] = block
    require(list(blocks) == sorted(blocks) == fixture["blocks"], "wrong retained block addresses")
    return blocks


def checkpoint_map(data, address, xid):
    require(header(data)[1:] == (address, xid, MAP, 0) and u32(data, MAP_FLAGS) == TERMINAL_MAP,
            "descriptor span requires its one terminal checkpoint map")
    count = u32(data, MAP_COUNT)
    require(0 < count <= (BLOCK_BYTES - MAPPING_TABLE) // MAPPING_RECORD_BYTES,
            "checkpoint map count outside the retained block")
    return [unpack_from(MAPPING_FIELDS, data, MAPPING_TABLE + n * MAPPING_RECORD_BYTES)
            for n in range(count)]


def observe_candidates(blocks, ring, data, capacity, unused):
    available = range(ring.base, ring.base + ring.blocks)
    zero_slots = []
    candidates = {}
    claimed = []
    for address in available:
        block = blocks[address]
        if not any(block):
            zero_slots.append(address)
            continue
        _, oid, xid, kind, subtype = header(block)
        if kind == MAP:
            continue
        require((oid, kind, subtype) == (1, NXSB, 0) and block[MAGIC:MAGIC + len(NXSB_MAGIC)] == NXSB_MAGIC
                and xid > 0 and xid not in candidates, "unexpected occupied descriptor slot")
        descriptors = descriptor_ring(block).validate(capacity)
        payloads = data_ring(block).validate(capacity)
        require((descriptors.base, descriptors.blocks, payloads.base, payloads.blocks)
                == (ring.base, ring.blocks, data.base, data.blocks)
                and descriptors.length == 2 and descriptors.addresses[-1] == address,
                "retained candidate differs from the bootstrap ring layout")
        mapping_address = descriptors.addresses[0]
        mappings = checkpoint_map(blocks[mapping_address], mapping_address, xid)
        require(all(entry[2] == BLOCK_BYTES for entry in mappings)
                and sorted(entry[-1] for entry in mappings) == sorted(payloads.addresses),
                "retained map does not cover the candidate data span")
        claimed.extend(descriptors.addresses)
        candidates[xid] = (address, block, descriptors, payloads, mappings)
    require(zero_slots == unused and sorted(claimed + zero_slots) == list(available),
            "occupied and unused descriptor slots do not partition the ring")
    return candidates


def checker_observation(stage):
    checker = stage["native_checker"]
    transcript = (FIXTURES / checker["transcript"]).read_bytes()
    require(checker["exit_code"] == 0 and checker["command"][:2] == ["/sbin/fsck_apfs", "-n"]
            and checker["sha256"] == digest(transcript) and stage["raw_unchanged"],
            "expected a successful read-only Apple receipt with unchanged raw bytes")
    text = transcript.decode("utf-8")
    xids = re.findall(r"Checking the checkpoint with transaction ID (\d+)\.", text)
    uuids = re.findall(r"with UUID ([0-9A-Fa-f-]+) appears to be OK\.", text)
    require(xids == [str(checker["checkpoint_xid"])]
            and re.search(r"The container \$scratch/detached\.raw\.cdr appears to be OK\.", text)
            and re.search(rf"\({re.escape(checker['tool_version'])}\)", text),
            "retained Apple transcript does not report the pinned successful checkpoint")
    return int(xids[0]), sorted(UUID(value).hex for value in uuids)


def compare_stage(stage):
    blocks = load_blocks(stage)
    bootstrap = blocks[0]
    _, bootstrap_oid, _, bootstrap_type, bootstrap_subtype = header(bootstrap)
    capacity = u64(bootstrap, BLOCK_COUNT)
    require((bootstrap_oid, bootstrap_type, bootstrap_subtype) == (1, NXSB, 0)
            and bootstrap[MAGIC:MAGIC + len(NXSB_MAGIC)] == NXSB_MAGIC
            and u32(bootstrap, BLOCK_SIZE) == BLOCK_BYTES and capacity * BLOCK_BYTES == stage["raw_length"],
            "wrong native bootstrap geometry")
    ring = descriptor_ring(bootstrap).validate(capacity)
    data = data_ring(bootstrap).validate(capacity)
    require(ring.blocks == 16, "the growth comparison expects the captured sixteen-slot ring")
    candidates = observe_candidates(blocks, ring, data, capacity, stage["unused_zero_slots"])
    selected_xid = max(candidates)
    apple_xid, apple_uuids = checker_observation(stage)
    require(selected_xid == apple_xid, "newest captured candidate and Apple's checkpoint differ")
    address, chosen, descriptors, payloads, mappings = candidates[selected_xid]
    require(descriptors.ledger_record() == stage["descriptor_ring"]
            and payloads.ledger_record() == stage["data_ring"],
            "wire ring spans disagree with the recorded native acquisition")

    object_map = u64(chosen, OBJECT_MAP_ADDRESS)
    _, omap_oid, omap_xid, omap_type, omap_subtype = header(blocks[object_map])
    require((omap_oid, omap_type, omap_subtype) == (object_map, OBJECT_MAP, 0)
            and 0 < omap_xid <= selected_xid, "selected object-map header differs")

    prefix = f"{REPLAY} {stage['stage']}"
    rows = [
        f"{prefix} checkpoint {selected_xid} {address} {u64(chosen, 0):016x} {BLOCK_BYTES} {capacity} {object_map}",
        f"{prefix} descriptors {descriptors.facts()}",
        f"{prefix} data {payloads.facts()}",
    ]
    for kind, subtype, size, volume, oid, physical in sorted(mappings, key=lambda item: item[-2]):
        require(header(blocks[physical])[1:] == (oid, selected_xid, kind, subtype),
                "selected payload identity differs from its mapping")
        rows.append(f"{prefix} mapping {oid} {physical} {size} {kind} {subtype} {volume}")

    observed = {}
    for block in blocks.values():
        _, oid, xid, kind, subtype = header(block)
        if (kind, subtype) == (VOLUME, 0) and block[MAGIC:MAGIC + len(VOLUME_MAGIC)] == VOLUME_MAGIC:
            require(oid not in observed and 0 < xid <= selected_xid, "unexpected volume identity")
            uuid = UUID(bytes=block[VOLUME_UUID:VOLUME_UUID + 16]).hex
            label = block[VOLUME_NAME:VOLUME_NAME + VOLUME_NAME_BYTES].split(b"\0", 1)[0].decode("utf-8")
            observed[oid] = label, uuid
    count = u32(chosen, VOLUME_SLOT_COUNT)
    require(0 < count <= MAX_VOLUME_SLOTS, "volume table count outside the represented NXSB profile")
    volume_table = [u64(chosen, VOLUME_IDS + n * ADDRESS_BYTES) for n in range(count)]
    volume_ids = [oid for oid in volume_table if oid]
    require(len(volume_ids) == len(observed) and set(volume_ids) == observed.keys()
            and {label: uuid for label, uuid in observed.values()} == stage["volume_labels_and_uuids"]
            and sorted(uuid for _, uuid in observed.values()) == apple_uuids,
            "wire volume table and UUIDs disagree with the native acquisition")
    for oid in volume_ids:
        label, uuid = observed[oid]
        rows.append(f"{prefix} volume {oid} {uuid} {label}")
    return rows, len(candidates)


def main():
    ledger = (FIXTURES / "acquisition.json").read_bytes()
    stages = json.loads(ledger)["stages"]
    require([stage["stage"] for stage in stages] == ["baseline", "two-volume"],
            "expected the retained baseline and ordinary volume-add capture")
    expected = []
    summaries = []
    for stage in stages:
        rows, candidates = compare_stage(stage)
        expected.extend(rows)
        summaries.append((stage, candidates, len(rows)))
    env = os.environ | {"CARGO_NET_OFFLINE": "true"}
    rustc = subprocess.check_output(["rustup", "which", "--toolchain", TOOLCHAIN, "rustc"],
                                    cwd=ROOT, text=True, env=env).strip()
    output = subprocess.check_output(
        [str(Path(rustc).with_name("cargo")), "test", "--color", "never", "--locked", "--offline",
         "-p", "apfs-container", "--test", "native_volume_growth", "--", "--exact", "--show-output", TEST],
        cwd=ROOT, text=True, env=env | {"RUSTC": rustc},
    )
    actual = [line for line in output.splitlines() if line.startswith(f"{REPLAY} ")]
    require(actual == expected, "portable Rust replay disagrees with independent native wire facts")
    print(subprocess.check_output([rustc, "--version"], cwd=ROOT, text=True).strip())
    for row in actual:
        print(row)
    for stage, candidates, rows in summaries:
        print(f"APFS native volume growth matched {stage['stage']} {candidates} "
              f"{len(stage['unused_zero_slots'])} {rows}")
    print(f"APFS native volume growth ledger {digest(ledger)}")
    print("APFS native volume growth differential completed")


if __name__ == "__main__":
    main()
