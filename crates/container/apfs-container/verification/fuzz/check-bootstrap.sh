#!/usr/bin/env bash
set -euo pipefail

fuzz_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_dir=$(cd -- "$fuzz_dir/../../../../.." && pwd)
fixture="$repo_dir/crates/filesystem/apfs-reader/tests/fixtures/sonoma-populated-metadata.bin"
scratch=$(mktemp -d "${TMPDIR:-/tmp}/apfs-bootstrap-fuzz.XXXXXXXX")
trap 'rm -rf -- "$scratch"' EXIT
mkdir "$scratch/corpus"

# The first fixture record contains an eight-byte address and one native block.
address_bytes=8
block_bytes=4096
dd if="$fixture" of="$scratch/block-zero" bs=1 skip="$address_bytes" count="$block_bytes" 2>/dev/null
test "$(wc -c < "$scratch/block-zero")" -eq "$block_bytes"
{ printf '\000'; cat "$scratch/block-zero"; } > "$scratch/corpus/native"
{ printf '\001'; cat "$scratch/block-zero"; } > "$scratch/corpus/recomputed"

toolchain=nightly-2026-11-04
nightly_bin=$(dirname -- "$(rustup which --toolchain "$toolchain" rustc)")
PATH="$nightly_bin:$PATH" cargo fuzz run --fuzz-dir "$fuzz_dir" \
	--target-dir "$scratch/target" bootstrap "$scratch/corpus" -- \
	-seed=7 -runs=20000 -max_len=65537 "-artifact_prefix=$scratch/"
