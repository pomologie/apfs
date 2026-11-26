"""Verify the retained fixture blocks against their native acquisition ledger."""

from hashlib import sha256
import json
from pathlib import Path


FIXTURES = Path(__file__).resolve().parents[1] / "tests/fixtures"
NAME = "sonoma-populated"
ADDRESS_BYTES = 8
PREFIX = "APFS native bootstrap"


def verify():
    ledger_text = (FIXTURES / f"{NAME}-fsroot.json").read_text(encoding="utf-8")
    ledger = json.loads(ledger_text)
    checker = ledger["native_checker"]
    bootstrap = ledger["bootstrap"]
    if checker["exit_code"] != 0 or ledger["commands"][-1][:2] != ["/sbin/fsck_apfs", "-n"]:
        raise ValueError("acquisition ledger does not record a successful read-only Apple checker run")
    if bootstrap["xid"] != checker["checkpoint_xid"]:
        raise ValueError("native bootstrap and selected checkpoint XIDs disagree")

    metadata = (FIXTURES / f"{NAME}-metadata.bin").read_bytes()
    metadata_hash = sha256(metadata).hexdigest()
    fsroot_hash = sha256((FIXTURES / f"{NAME}-fsroot.bin").read_bytes()).hexdigest()
    if metadata_hash != ledger["metadata_fixture"]["sha256"] or fsroot_hash != ledger["fsroot"]["sha256"]:
        raise ValueError("retained native bytes disagree with fixture hashes")
    stride = ADDRESS_BYTES + bootstrap["block_bytes"]
    addresses = [int.from_bytes(metadata[offset:offset + ADDRESS_BYTES], "little")
                 for offset in range(0, len(metadata), stride)]
    if len(metadata) % stride or not addresses or addresses != ledger["metadata_fixture"]["block_numbers_in_order"]:
        raise ValueError("packed block layout disagrees with the acquisition ledger")
    if addresses[0] != bootstrap["physical_block"] or bootstrap["physical_block"] != 0:
        raise ValueError("the first retained record must be native block zero")
    bootstrap_hash = sha256(metadata[ADDRESS_BYTES:stride]).hexdigest()
    if bootstrap_hash != bootstrap["sha256"]:
        raise ValueError("retained block zero disagrees with the bootstrap hash")

    print(PREFIX, "ledger", sha256(ledger_text.encode("utf-8")).hexdigest())
    print(PREFIX, "oracle", ledger["os"], ledger["build"], ledger["architecture"],
          checker["tool_version"], checker["exit_code"], checker["checkpoint_xid"], ledger["raw_sha256"])
    print(PREFIX, "fixture", metadata_hash, bootstrap_hash, fsroot_hash)


if __name__ == "__main__":
    verify()
