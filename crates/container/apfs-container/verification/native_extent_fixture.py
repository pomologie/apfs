"""Check the retained block-zero bytes against the 128 MiB acquisition ledger."""

from hashlib import sha256
import json
from pathlib import Path
from struct import Struct


FIXTURE_DIRECTORY = Path(__file__).resolve().parents[1] / "tests/fixtures"
NAME = "sonoma-128m-bootstrap"
CHECKPOINT_LINE = "Checking the checkpoint with transaction ID {}."
HEADER_GEOMETRY = Struct("<QQQII4sIQ")
NXSB_TYPE = 0x8000_0001
NXSB_MAGIC = b"NXSB"
PREFIX = "APFS native extent"


def verify():
    ledger_text = (FIXTURE_DIRECTORY / f"{NAME}.json").read_text(encoding="utf-8")
    ledger = json.loads(ledger_text)
    checker = ledger["native_checker"]
    checkpoint = CHECKPOINT_LINE.format(checker["checkpoint_xid"])
    if ledger["commands"][-1][:2] != ["/sbin/fsck_apfs", "-n"] or checker["exit_code"] != 0:
        raise ValueError("the ledger does not record a successful read-only Apple check")
    if checker["raw_sha256_unchanged"] is not True or checkpoint not in map(str.strip, checker["transcript"]):
        raise ValueError("the Apple transcript does not establish the recorded checkpoint")
    if ledger["fixture"] != f"{NAME}.bin":
        raise ValueError("the ledger names a different block-zero fixture")

    block = (FIXTURE_DIRECTORY / ledger["fixture"]).read_bytes()
    block_hash = sha256(block).hexdigest()
    if block_hash != ledger["bootstrap_sha256"] or len(block) != ledger["block_bytes"]:
        raise ValueError("the retained block differs from the acquisition ledger")
    checksum, oid, xid, kind, subtype, magic, size, count = HEADER_GEOMETRY.unpack_from(block)
    if (kind, subtype, magic) != (NXSB_TYPE, 0, NXSB_MAGIC):
        raise ValueError("the retained block is outside the ordinary NXSB profile")
    if (size, count, oid, xid, f"{checksum:016x}") != (
        ledger["block_bytes"], ledger["block_count"], ledger["oid"], ledger["xid"], ledger["stored_checksum"],
    ) or size * count != ledger["full_image_bytes"]:
        raise ValueError("stored geometry or object identity differs from the ledger")
    if xid != checker["checkpoint_xid"]:
        raise ValueError("the bootstrap transaction differs from the recorded Apple result")

    host = dict(line.split(":") for line in ledger["host"].splitlines())
    print(PREFIX, "ledger", sha256(ledger_text.encode("utf-8")).hexdigest())
    print(PREFIX, "fixture", block_hash, ledger["full_image_sha256"])
    print(PREFIX, "oracle", host["ProductVersion"].strip(), host["BuildVersion"].strip(),
          ledger["architecture"], checker["tool_version"], checker["exit_code"], checker["checkpoint_xid"])


if __name__ == "__main__":
    verify()
