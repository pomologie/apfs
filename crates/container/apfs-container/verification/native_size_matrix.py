"""Check provenance, retained bytes and positive probe results for native block sizes."""

from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
from struct import Struct
import sys

from native_extent_fixture import CHECKPOINT_LINE, HEADER_GEOMETRY, NXSB_MAGIC, NXSB_TYPE


FIXTURES = Path(__file__).resolve().parents[1] / "tests/fixtures/native-bootstrap-sizes"
SIZES = [4096, 8192, 16384, 32768, 65536]
FEATURE_OFFSET = 48
FEATURES = Struct("<QQQ")
FEATURE_MASKS = (0, 0, 2)
OBJECT_ID = 1
PREFIX = "APFS native bootstrap matrix "


def retained_row(record):
    size = record["block_bytes"]
    write, check = record["commands"]
    if write[:3] != ["/sbin/newfs_apfs", "-b", str(size)] or check != ["/sbin/fsck_apfs", "-n", write[-1]]:
        raise ValueError(f"invalid acquisition commands for the {size}-byte source")
    if record["newfs_exit_code"] != 0 or record["fsck_exit_code"] != 0 or record["raw_unchanged"] is not True:
        raise ValueError(f"the {size}-byte acquisition requires a successful checker and stable source hash")
    checkpoint = CHECKPOINT_LINE.format(record["checkpoint_xid"])
    if checkpoint not in map(str.strip, record["fsck_output"]):
        raise ValueError(f"missing recorded Apple checkpoint for the {size}-byte source")

    fixture = f"native-block-zero-{size}.bin"
    if record["fixture"] != fixture:
        raise ValueError(f"incorrect retained fixture name for the {size}-byte source")
    block = (FIXTURES / fixture).read_bytes()
    if len(block) != size or sha256(block).hexdigest() != record["fixture_sha256"]:
        raise ValueError(f"retained {size}-byte block differs from its ledger")
    checksum, oid, xid, kind, subtype, magic, stored_size, count = HEADER_GEOMETRY.unpack_from(block)
    if (oid, kind, subtype, magic) != (OBJECT_ID, NXSB_TYPE, 0, NXSB_MAGIC):
        raise ValueError("retained block is not an ordinary NXSB")
    if (xid, stored_size, count, f"{checksum:016x}") != (
        record["bootstrap_xid"], size, record["block_count"], record["object_checksum"],
    ) or xid != record["checkpoint_xid"] or size * count != record["raw_bytes"]:
        raise ValueError("retained NXSB identity or geometry differs from its ledger")
    if FEATURES.unpack_from(block, FEATURE_OFFSET) != FEATURE_MASKS or record["feature_masks"] != list(FEATURE_MASKS):
        raise ValueError("the retained NXSB must have the observed version-two feature mask")
    return f"{PREFIX}{size} {count} {size * count} {checksum:016x}"


def verify(transcript):
    text = (FIXTURES / "acquisition.json").read_text(encoding="utf-8")
    ledger = json.loads(text)
    records = ledger["results"]
    if [record["block_bytes"] for record in records] != SIZES:
        raise ValueError("the ledger must cover all five native block sizes")
    expected = Counter(retained_row(record) for record in records)
    actual = Counter(line for line in transcript.splitlines()
                     if line.startswith(PREFIX) and not line.startswith(PREFIX + "probe "))
    if actual != expected:
        raise ValueError("the observed probe rows differ from the acquisition ledgers")
    print(PREFIX + f"ledger {sha256(text.encode('utf-8')).hexdigest()}")
    print(PREFIX + f"oracle {ledger['os']} {ledger['build']} {ledger['architecture']}")


if __name__ == "__main__":
    verify(Path(sys.argv[1]).read_text(encoding="utf-8"))
