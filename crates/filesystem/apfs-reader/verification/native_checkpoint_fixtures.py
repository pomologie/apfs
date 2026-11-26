"""Verify two retained positive checkpoints against their native acquisition ledgers."""

from hashlib import sha256
import json
from pathlib import Path


FIXTURES = Path(__file__).resolve().parents[1] / "tests/fixtures"
BASE = "sonoma-payload-blocks"
DERIVED = "sonoma-fragmented-blocks"
ADDRESS_BYTES = 8
PREFIX = "APFS native checkpoints"


def verify(name):
    text = (FIXTURES / f"{name}.json").read_text(encoding="utf-8")
    ledger = json.loads(text)
    checker = ledger["native_checker"]
    if name == BASE:
        read_only = ledger["commands"][-1][:2] == ["/sbin/fsck_apfs", "-n"]
    else:
        read_only = (ledger["base_image"] == f"{BASE}.json"
                     and ledger["steps"][-1] == "Check the exported image with /sbin/fsck_apfs -n.")
    if not read_only or checker["exit_code"] != 0:
        raise ValueError(f"{name} does not record a successful read-only Apple checker run")

    stored = ledger["fixtures"]
    if stored["file"] != f"{name}.bin":
        raise ValueError(f"{name} names a different block fixture")
    packed = (FIXTURES / stored["file"]).read_bytes()
    packed_hash = sha256(packed).hexdigest()
    stride = ADDRESS_BYTES + ledger["block_size"]
    addresses = [int.from_bytes(packed[offset:offset + ADDRESS_BYTES], "little")
                 for offset in range(0, len(packed), stride)]
    if packed_hash != stored["sha256"] or len(packed) % stride or addresses != stored["blocks"]:
        raise ValueError(f"{name} retained block bytes or offsets disagree with the ledger")

    ledger_hash = sha256(text.encode("utf-8")).hexdigest()
    print(PREFIX, "fixture", name, ledger_hash, packed_hash, ledger["raw_sha256"])
    print(PREFIX, "oracle", name, ledger["os"], ledger["build"], ledger["architecture"],
          checker["tool_version"], checker["exit_code"], checker["checkpoint_xid"])
    return ledger_hash


if __name__ == "__main__":
    ledgers = "".join(f"{verify(name)}\n" for name in (BASE, DERIVED))
    print(PREFIX, "ledgers", sha256(ledgers.encode("ascii")).hexdigest())
