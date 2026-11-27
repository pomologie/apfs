"""Compare verified Rust decodes with wire fields from retained native APFS blocks."""

from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
from struct import Struct, unpack_from
import sys


FIXTURES = Path(__file__).resolve().parents[1] / "tests/fixtures"
MATRIX_FIXTURES = Path(__file__).resolve().parents[3] / "container/apfs-container/tests/fixtures/native-bootstrap-sizes"
MATRIX_BLOCK_SIZES = (4096, 8192, 16384, 32768, 65536)
MATRIX_SOURCE_BYTES = 128 << 20
FLETCHER_WORD_BYTES = 4
FLETCHER_MODULUS = (1 << 32) - 1
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


def superblock_rows(data, key, geometry, *, include_object_map_span=False):
    block_bytes, count, source_bytes = geometry
    stored_size, stored_count = unpack_from("<IQ", data, BLOCK_SIZE_OFFSET)
    if data[NXSB_MAGIC_OFFSET:BLOCK_SIZE_OFFSET] != b"NXSB" or (stored_size, stored_count) != (block_bytes, count):
        raise ValueError(f"native geometry disagrees with the container ledger: {key}")
    if block_bytes * count != source_bytes:
        raise ValueError(f"native declared extent differs from the source: {key}")
    _, _, xid, _, _ = OBJECT_HEADER.unpack_from(data)
    omap, = unpack_from("<q", data, OBJECT_MAP_OFFSET)
    optional, readonly, incompatible = unpack_from("<QQQ", data, OPTIONAL_FEATURES_OFFSET)
    keylocker_blocks, = unpack_from("<Q", data, KEYLOCKER_BLOCK_COUNT_OFFSET)
    fragmented = any(unpack_from("<I", data, fields[0])[0] & FRAGMENT_TREE_FLAG
                     for fields in AREA_FIELDS.values())
    yield f"profile {key} {optional} {readonly} {incompatible} {int(bool(keylocker_blocks))} {int(fragmented)}"
    locator = ""
    if include_object_map_span:
        start, end = bounded_span(omap, 1, block_bytes, count)
        locator = f" {start} {end}"
    yield f"nxsb {key} {xid} {block_bytes} {count} {source_bytes} {omap} {incompatible}{locator}"
    for area, (blocks_at, base_at, next_at, index_at) in AREA_FIELDS.items():
        blocks, = unpack_from("<I", data, blocks_at)
        base, = unpack_from("<q", data, base_at)
        next_slot, = unpack_from("<I", data, next_at)
        index, length = unpack_from("<II", data, index_at)
        start, end = bounded_span(base, blocks, block_bytes, count)
        yield f"area {key} {area} {base} {blocks} {index} {length} {next_slot} {start} {end}"


def bounded_span(base, blocks, block_bytes, count):
    if not 0 < base < base + blocks <= count:
        raise ValueError("retained native block span is out of bounds")
    return base * block_bytes, (base + blocks) * block_bytes


def checked_checksum(data):
    offset = FLETCHER_WORD_BYTES * 2
    check_words = unpack_from("<II", data)
    payload = unpack_from(f"<{(len(data) - offset) // FLETCHER_WORD_BYTES}I", data, offset)
    words = payload + check_words
    weighted = sum(weight * value for weight, value in enumerate(reversed(words), start=1))
    if not all(check_words) or sum(words) % FLETCHER_MODULUS or weighted % FLETCHER_MODULUS:
        raise ValueError("retained native object fails the independent checksum")
    return f"{check_words[1]:08x}{check_words[0]:08x}"


def native_size_matrix_rows(ledger):
    records = ledger["results"]
    if tuple(record["block_bytes"] for record in records) != MATRIX_BLOCK_SIZES:
        raise ValueError("the ledger must contain all five block sizes exactly once")
    for record in records:
        size = record["block_bytes"]
        fixture = f"native-block-zero-{size}.bin"
        data = (MATRIX_FIXTURES / fixture).read_bytes()
        if record["fixture"] != fixture or len(data) != size or sha256(data).hexdigest() != record["fixture_sha256"]:
            raise ValueError(f"retained matrix block differs from its acquisition ledger: {fixture}")
        checksum = checked_checksum(data)
        _, oid, xid, kind, subtype = OBJECT_HEADER.unpack_from(data)
        expected = MATRIX_SOURCE_BYTES, record["object_checksum"], record["bootstrap_xid"], record["checkpoint_xid"]
        if (record["raw_bytes"], checksum, xid, xid) != expected:
            raise ValueError(f"retained matrix object conflicts with the acquisition ledger: {fixture}")
        yield f"header {size} {checksum} {oid} {xid} {kind} {subtype}"
        yield from superblock_rows(data, size, (size, record["block_count"], MATRIX_SOURCE_BYTES),
                                   include_object_map_span=True)


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
            yield from superblock_rows(data, address, (block_bytes, ledger["block_count"], ledger["raw_length"]))
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
    if sys.argv[1:] == ["--size-matrix"]:
        ledger_path = MATRIX_FIXTURES / "acquisition.json"
        compare = native_size_matrix_rows
    elif not sys.argv[1:]:
        ledger_path = FIXTURES / "native-apfs.json"
        compare = native_rows
    else:
        raise ValueError("expected --size-matrix or no arguments")
    ledger_text = ledger_path.read_text(encoding="utf-8")
    expected = sorted(PREFIX + row for row in compare(json.loads(ledger_text)))
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
