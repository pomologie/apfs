"""Compare verified Rust decodes with wire fields from retained native APFS blocks."""

from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
from struct import Struct, unpack_from
import sys


FIXTURES = Path(__file__).resolve().parents[1] / "tests/fixtures"
PREFIX = "APFS native geometry "
OBJECT_HEADER = Struct("<QQQII")
NXSB_MAGIC_OFFSET = 32
BLOCK_SIZE_OFFSET = 36
OPTIONAL_FEATURES_OFFSET = 48
OBJECT_MAP_OFFSET = 160
KEYLOCKER_BLOCK_COUNT_OFFSET = 1304
FRAGMENT_TREE_FLAG = 1 << 31
MAP_HEADER_OFFSET = 32
MAP_ENTRY_OFFSET = 40
MAP_ENTRY = Struct("<III4xQQq")
AREA_FIELDS = {"descriptor": (104, 112, 128, 136), "data": (108, 120, 132, 144)}
CHECKPOINT_MAP_LAST = 1
ROW_GROUPS = ("nxsb", "area", "map", "mapping", "header", "profile")


def native_rows(ledger):
    block_bytes = ledger["block_size"]
    for name, facts in ledger["fixtures"].items():
        data = (FIXTURES / name).read_bytes()
        if sha256(data).hexdigest() != facts["sha256"] or len(data) != block_bytes:
            raise ValueError(f"native block differs from its acquisition ledger: {name}")
        address = facts["physical_block"]
        checksum, oid, xid, kind, subtype = OBJECT_HEADER.unpack_from(data)
        if xid != facts["xid"]:
            raise ValueError(f"transaction ID disagrees with the ledger: {name}")
        if f"{checksum:016x}" != facts["checksum"]:
            raise ValueError(f"stored checksum disagrees with the ledger: {name}")
        yield f"header {address} {checksum:016x} {oid} {xid} {kind} {subtype}"
        if data[NXSB_MAGIC_OFFSET:BLOCK_SIZE_OFFSET] == b"NXSB":
            geometry, count = unpack_from("<IQ", data, BLOCK_SIZE_OFFSET)
            omap, = unpack_from("<q", data, OBJECT_MAP_OFFSET)
            optional, readonly, incompatible = unpack_from("<QQQ", data, OPTIONAL_FEATURES_OFFSET)
            keylocker_blocks, = unpack_from("<Q", data, KEYLOCKER_BLOCK_COUNT_OFFSET)
            fragmented = any(unpack_from("<I", data, fields[0])[0] & FRAGMENT_TREE_FLAG
                             for fields in AREA_FIELDS.values())
            yield f"profile {address} {optional} {readonly} {incompatible} {int(bool(keylocker_blocks))} {int(fragmented)}"
            if (geometry, count, geometry * count) != (block_bytes, ledger["block_count"], ledger["raw_length"]):
                raise ValueError(f"native geometry disagrees with the container ledger: {name}")
            yield f"nxsb {address} {xid} {geometry} {count} {geometry * count} {omap} {incompatible}"
            for area, (blocks_at, base_at, next_at, index_at) in AREA_FIELDS.items():
                blocks, = unpack_from("<I", data, blocks_at)
                base, = unpack_from("<q", data, base_at)
                next_slot, = unpack_from("<I", data, next_at)
                index, length = unpack_from("<II", data, index_at)
                yield (f"area {address} {area} {base} {blocks} {index} {length} {next_slot} "
                       f"{base * block_bytes} {(base + blocks) * block_bytes}")
        else:
            flags, count = unpack_from("<II", data, MAP_HEADER_OFFSET)
            yield f"map {address} {xid} {flags & CHECKPOINT_MAP_LAST} {count}"
            for index in range(count):
                kind, subtype, size, volume, oid, physical = MAP_ENTRY.unpack_from(
                    data, MAP_ENTRY_OFFSET + index * MAP_ENTRY.size,
                )
                start = physical * block_bytes
                yield f"mapping {address} {index} {kind} {subtype} {size} {volume} {oid} {physical} {start} {start + size}"


def main():
    ledger_text = (FIXTURES / "native-apfs.json").read_text(encoding="utf-8")
    expected = sorted(PREFIX + row for row in native_rows(json.loads(ledger_text)))
    actual = sorted(line.rstrip("\n") for line in sys.stdin if line.startswith(PREFIX))
    if actual != expected:
        raise ValueError(f"geometry differs from the independent oracle\nexpected: {expected}\nobserved: {actual}")
    counts = Counter(row[len(PREFIX):].split()[0] for row in expected)
    print("\n".join(expected))
    print(PREFIX + "ledger", sha256(ledger_text.encode("utf-8")).hexdigest())
    print(PREFIX + "comparison", *(counts[group] for group in ROW_GROUPS),
          sha256("\n".join(expected).encode("ascii")).hexdigest())


if __name__ == "__main__":
    main()
