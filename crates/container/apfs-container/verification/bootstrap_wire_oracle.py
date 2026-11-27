"""Compare observed bootstrap API decisions with a widened wire-format model."""

from collections import Counter
from hashlib import sha256
from itertools import product
from struct import Struct, unpack
import sys


PREFIX = "APFS bootstrap observation "
MIN_EXTENT = 1 << 20
MAX_ADDRESS = (1 << 64) - 1
SIZE_CASES = (4096, 8192, 16384, 32768, 65536, 0, 1, 2048, 4095, 4097, 65537, (1 << 32) - 1)
VERSION_TWO = 1 << 1
REQUIRED_EXTENSIONS = (1 << 62, 1 << 63)
COMPATIBLE_AXES = ((0, 1), (0, 1 << 63))
OBJECT_HEADER = Struct("<QQQII")
HEADER_SAMPLE = bytes(range(64))
WORD_BYTES = 4
FLETCHER_MODULUS = (1 << (8 * WORD_BYTES)) - 1
OBSERVATION_GROUPS = ("size", "geometry", "span", "header", "feature-bit", "feature-open")


def admitted_size(size):
    return 4096 <= size <= 65536 and size.bit_count() == 1


def geometry_cases(size):
    minimum = MIN_EXTENT // size
    maximum = MAX_ADDRESS // size
    return (
        (minimum - 1, MIN_EXTENT), (minimum, MIN_EXTENT - 1),
        (minimum, MIN_EXTENT), (minimum, MIN_EXTENT + 1),
        (maximum, MAX_ADDRESS), (maximum + 1, MAX_ADDRESS), (MAX_ADDRESS, MAX_ADDRESS),
    )


def range_cases(count):
    return (
        (0, 0), (0, count), (count - 1, 1), (count, 0), (count, 1),
        (count + 1, 0), (MAX_ADDRESS, 1), (1, MAX_ADDRESS),
    )


def geometry_rows(size):
    for count, source_bytes in geometry_cases(size):
        extent = size * count
        row = f"{size} {count} {source_bytes}"
        if extent < MIN_EXTENT or extent > source_bytes:
            # Extent probing, automatic open, and exact open all refuse the count.
            yield f"geometry {row} refused 3"
            continue
        yield f"geometry {row} admitted {extent}"
        for start, length in range_cases(count):
            begin, end = start * size, (start + length) * size
            result = f"{begin} {end}" if end <= extent else "refused"
            yield f"span {row} {start} {length} {result}"


def expected_rows():
    for size in SIZE_CASES:
        admitted = admitted_size(size)
        yield f"size {size} {int(admitted)}"
        if admitted:
            yield from geometry_rows(size)
            first, second = REQUIRED_EXTENSIONS
            masks = (0, VERSION_TWO | first, VERSION_TWO | second, VERSION_TWO | first | second)
            for optional, readonly, required, mode in product(*COMPATIBLE_AXES, masks, (0, 1)):
                # These feature words refuse opens after reading the size prefix and block zero.
                yield f"feature-open {size} {optional} {readonly} {required} {mode} 2"
    for bit in range(MAX_ADDRESS.bit_length()):
        mask = VERSION_TWO | (1 << bit)
        if mask != VERSION_TWO:
            yield f"feature-bit {bit} {mask} 2"
    _, oid, xid, kind, subtype = OBJECT_HEADER.unpack_from(HEADER_SAMPLE)
    checksum_bytes = 2 * WORD_BYTES
    for length in range(len(HEADER_SAMPLE) + 1):
        if length < OBJECT_HEADER.size or length % WORD_BYTES:
            yield f"header {length} truncated"
            continue
        data = HEADER_SAMPLE[checksum_bytes:length]
        words = unpack(f"<{len(data) // WORD_BYTES}I", data)
        # Choose the two checksum words so that both modular sums vanish.
        first = FLETCHER_MODULUS - sum(weight * word for weight, word in enumerate(reversed(words), 2)) % FLETCHER_MODULUS
        second = FLETCHER_MODULUS - (sum(words) + first) % FLETCHER_MODULUS
        yield f"header {length} {oid} {xid} {kind} {subtype} {second:08x}{first:08x} invalid-checksum"


def main():
    expected = Counter(expected_rows())
    observed = Counter()
    for line in sys.stdin:
        if line.startswith(PREFIX):
            observed[line.removeprefix(PREFIX).strip()] += 1
        else:
            print(line, end="")
    if observed != expected:
        raise ValueError(f"bootstrap observations differ: missing={expected - observed}; extra={observed - expected}")
    rows = sorted(observed.elements())
    counts = Counter(row.split()[0] for row in rows)
    print("\n".join(PREFIX + row for row in rows))
    print("APFS bootstrap differential", *(counts[name] for name in OBSERVATION_GROUPS),
          sha256("\n".join(rows).encode("ascii")).hexdigest())


if __name__ == "__main__":
    main()
