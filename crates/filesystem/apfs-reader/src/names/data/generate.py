#!/usr/bin/env python3
"""Generate the APFS reader's bounded Unicode 9 comparison tables."""

import argparse
from hashlib import sha256
from itertools import groupby
from pathlib import Path
from struct import Struct


VERSION = (9, 0)
SOURCE_DIGESTS = {
    "CaseFolding.txt": "37d40cf8c2c35637f4a04e746814e1fc4eb764c272bed9238a87ee96a4866857",
    "DerivedAge.txt": "5cb15b04693c43df16e0d304deca049e93b001445d163184e0ff1b7c8c852146",
    "UnicodeData.txt": "68dfc414d28257b9b5d6ddbb8b466c768c00ebdf6cbf7784364a9b6cad55ee8f",
}
MAX_CODEPOINT = 0x10FFFF
SURROGATES = range(0xD800, 0xE000)
NONCHARACTERS = range(0xFDD0, 0xFDF0)
PLANE_BITS = 16
LOW_WORD = (1 << PLANE_BITS) - 1
FIRST_PLANE_NONCHARACTER = 0xFFFE
FULL_FOLD_STATUSES = frozenset({"C", "F"})
MAPPING_SLOTS = 3
DIRECT_DECOMPOSITION_SLOTS = 2
EMPTY_SLOT = 0
AGE_RECORD = Struct("<II")
COMBINING_RECORD = Struct("<IB")
MAPPING_RECORD = Struct("<IIII")


def source(directory, name):
    data = (directory / name).read_bytes()
    actual = sha256(data).hexdigest()
    if actual != SOURCE_DIGESTS[name]:
        raise ValueError(f"{name} has unexpected SHA-256 {actual}")
    return data.decode("utf-8")


def records(data):
    for line in data.splitlines():
        values = line.partition("#")[0].strip()
        if values:
            yield tuple(field.strip() for field in values.split(";"))


def admitted_scalar(codepoint):
    return (
        0 <= codepoint <= MAX_CODEPOINT
        and codepoint not in SURROGATES
        and codepoint not in NONCHARACTERS
        and (codepoint & LOW_WORD) < FIRST_PLANE_NONCHARACTER
    )


def assigned_codepoints(data):
    assigned = set()
    for interval, version in records(data):
        if tuple(map(int, version.split("."))) > VERSION:
            raise ValueError(f"unexpected age {version}")
        first, _, last = interval.partition("..")
        start, end = int(first, 16), int(last or first, 16)
        for codepoint in range(start, end + 1):
            if admitted_scalar(codepoint):
                assigned.add(codepoint)
    return assigned


def encode_age(assigned):
    # For consecutive sorted points, point minus index stays constant.
    ranges = groupby(enumerate(sorted(assigned)), key=lambda item: item[1] - item[0])
    result = bytearray()
    for _, group in ranges:
        _, start = next(group)
        end = start
        for _, end in group:
            pass
        result.extend(AGE_RECORD.pack(start, end))
    return bytes(result)


def normalization_data(data):
    combining = {}
    decomposition = {}
    for fields in records(data):
        scalar, _name, _category, combining_class, _bidi, mapping, *_ = fields
        codepoint = int(scalar, 16)
        canonical_combining_class = int(combining_class)
        if canonical_combining_class:
            combining[codepoint] = canonical_combining_class
        if mapping and not mapping.startswith("<"):
            # Hangul syllable decomposition is algorithmic and absent here.
            decomposition[codepoint] = tuple(int(unit, 16) for unit in mapping.split())
    return combining, decomposition


def folding_data(data):
    folding = {}
    for codepoint, status, mapping, _ in records(data):
        if status in FULL_FOLD_STATUSES:
            key = int(codepoint, 16)
            if key in folding:
                raise ValueError(f"duplicate full fold for U+{key:04X}")
            folding[key] = tuple(int(unit, 16) for unit in mapping.split())
    return folding


def encode_mappings(mappings, assigned, limit):
    result = bytearray()
    for codepoint, mapping in sorted(mappings.items()):
        if codepoint not in assigned or not 0 < len(mapping) <= limit:
            raise ValueError(f"invalid mapping for U+{codepoint:04X}")
        if any(unit == EMPTY_SLOT or unit not in assigned for unit in mapping):
            raise ValueError(f"invalid mapped scalar for U+{codepoint:04X}")
        padding = (EMPTY_SLOT,) * (MAPPING_SLOTS - len(mapping))
        result.extend(MAPPING_RECORD.pack(codepoint, *mapping, *padding))
    return bytes(result)


def tables(directory):
    assigned = assigned_codepoints(source(directory, "DerivedAge.txt"))
    combining, decomposition = normalization_data(source(directory, "UnicodeData.txt"))
    if not assigned.issuperset(combining):
        raise ValueError("combining class assigned outside Unicode 9")
    folding = folding_data(source(directory, "CaseFolding.txt"))
    return {
        "age.bin": encode_age(assigned),
        "combining.bin": b"".join(
            COMBINING_RECORD.pack(codepoint, combining_class)
            for codepoint, combining_class in sorted(combining.items())
        ),
        "decomposition.bin": encode_mappings(decomposition, assigned, DIRECT_DECOMPOSITION_SLOTS),
        "casefold.bin": encode_mappings(folding, assigned, MAPPING_SLOTS),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ucd", type=Path, help="directory containing the pinned UCD inputs")
    parser.add_argument("--check", action="store_true", help="check the existing tables without writing")
    args = parser.parse_args()
    output = Path(__file__).resolve().parent
    for name, data in tables(args.ucd).items():
        path = output / name
        if args.check:
            if path.read_bytes() != data:
                parser.error(f"{name} differs from the generated table")
        elif not path.exists() or path.read_bytes() != data:
            path.write_bytes(data)


if __name__ == "__main__":
    main()
