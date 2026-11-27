#!/usr/bin/env python3
"""Compare fresh ordinary APFS checkpoints with Apple's read-only checker."""

import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tempfile
from uuid import UUID


IMAGE_BYTES = 128 << 20
BLOCK_SIZES = (4096, 8192, 16384, 32768, 65536)
TOOLCHAIN = "1.99.1"
FORMATTER = "/sbin/newfs_apfs"
CHECKER = "/sbin/fsck_apfs"
XID = re.compile(r"Checking the checkpoint with transaction ID (\d+)\.")
VOLUME_UUID = re.compile(r"with UUID ([0-9a-fA-F-]{36}) appears to be OK\.")
HEALTHY_CONTAINER = re.compile(r"The container .+ appears to be OK\.")
RUST_HARNESS = Path(__file__).with_name("native_checkpoint_open.rs").resolve()
CRATE_DIR = RUST_HARNESS.parent.parent


def run(*args, env=None, timeout=120):
    result = subprocess.run(args, env=env, timeout=timeout,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if result.returncode:
        raise RuntimeError(f"{args[0]} exited with {result.returncode}:\n{result.stdout}")
    return result.stdout


def hash_file(path):
    with path.open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def build_harness(scratch):
    rustc = Path(run("rustup", "which", "--toolchain", TOOLCHAIN, "rustc").strip())
    cargo = rustc.with_name("cargo")
    target = scratch / "target"
    manifest = scratch / "Cargo.toml"
    manifest.write_text(f'''[package]
name = "native-checkpoint-open"
version = "0.0.0"
edition = "2024"
publish = false

[[bin]]
name = "native-checkpoint-open"
path = {json.dumps(str(RUST_HARNESS), ensure_ascii=False)}

[dependencies]
apfs-container = {{ path = {json.dumps(str(CRATE_DIR), ensure_ascii=False)}, default-features = false }}
''')
    env = os.environ | {"PATH": str(rustc.parent) + os.pathsep + os.environ["PATH"],
                        "RUSTC": str(rustc)}
    run(cargo, "generate-lockfile", "--offline", "--manifest-path", manifest, env=env)
    build_log = run(cargo, "build", "--offline", "--locked", "--manifest-path", manifest,
                    "--target-dir", target, env=env)
    return target / "debug" / "native-checkpoint-open", run(rustc, "--version").strip(), build_log


def compare_checkpoint(oracle, rust, block_bytes, label):
    xids = [int(value) for value in XID.findall(oracle)]
    uuids = [UUID(value).hex for value in VOLUME_UUID.findall(oracle)]
    if len(xids) != 1 or len(uuids) != 1 or not HEALTHY_CONTAINER.search(oracle):
        raise ValueError(f"Apple checker did not verify one checkpoint and volume at {block_bytes}")

    checkpoint, volume = rust.splitlines()
    prefix, size, count, xid, address, slots, index, length, next_slot, mappings = checkpoint.split()
    rust_uuid, rust_label = volume.removeprefix("volume ").split(" ", 1)
    if (prefix, int(size), int(size) * int(count), int(xid), rust_uuid, rust_label) != (
        "checkpoint", block_bytes, IMAGE_BYTES, xids[0], uuids[0], label
    ) or not volume.startswith("volume "):
        raise ValueError(f"Rust and Apple checkpoint observations disagree at {block_bytes}")
    return {"block_bytes": block_bytes, "block_count": int(count), "xid": int(xid),
            "descriptor": int(address), "descriptor_ring_slots": int(slots),
            "descriptor_ring_index": int(index), "descriptor_ring_length": int(length),
            "descriptor_ring_next": int(next_slot), "mapping_count": int(mappings),
            "volume_uuid": rust_uuid, "volume_label": rust_label}


def observe(scratch, harness, block_bytes):
    label = f"Pomologie {block_bytes}"
    raw = scratch / "checkpoint.raw"
    with raw.open("xb") as file:
        file.truncate(IMAGE_BYTES)
    try:
        formatter_log = run(FORMATTER, "-b", str(block_bytes), "-v", label, raw)
        digest = hash_file(raw)
        oracle_log = run(CHECKER, "-n", raw)
        rust_log = run(harness, raw)
        if hash_file(raw) != digest:
            raise ValueError(f"raw image changed during read-only checks at {block_bytes}")
        facts = compare_checkpoint(oracle_log, rust_log, block_bytes, label)
        return facts | {"raw_sha256": digest, "raw_unchanged": True,
                        "formatter": [FORMATTER, "-b", str(block_bytes), "-v", label,
                                      "$scratch/checkpoint.raw"],
                        "checker": [CHECKER, "-n", "$scratch/checkpoint.raw"],
                        "formatter_log": formatter_log.replace(str(scratch), "$scratch"),
                        "checker_log": oracle_log.replace(str(scratch), "$scratch"),
                        "rust_log": rust_log}
    finally:
        raw.unlink(missing_ok=True)


def main():
    if platform.system() != "Darwin":
        raise SystemExit("the native checkpoint comparison requires macOS")
    with tempfile.TemporaryDirectory(prefix="apfs-native-checkpoint-open.") as temporary:
        scratch = Path(temporary)
        harness, rust_version, build_log = build_harness(scratch)
        report = {"macos": run("sw_vers", "-productVersion").strip(),
                  "macos_build": run("sw_vers", "-buildVersion").strip(),
                  "arch": platform.machine(), "rust": rust_version, "image_bytes": IMAGE_BYTES,
                  "harness_sha256": hash_file(RUST_HARNESS),
                  "runner_sha256": hash_file(Path(__file__)),
                  "build_log": build_log.replace(str(scratch), "$scratch"),
                  "results": [observe(scratch, harness, size) for size in BLOCK_SIZES]}
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
