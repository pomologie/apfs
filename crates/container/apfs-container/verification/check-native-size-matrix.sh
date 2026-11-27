#!/usr/bin/env bash
set -euo pipefail

verification_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
toolchain=1.99.1
toolchain_bin=$(dirname -- "$(rustup which --toolchain "$toolchain" rustc)")
export PATH="$toolchain_bin:$PATH"
scratch=$(mktemp -d "${TMPDIR:-/tmp}/apfs-native-size-matrix.XXXXXXXX")
trap 'rm -rf -- "$scratch"' EXIT

rustc --version
status=0
cargo test --locked --manifest-path "$verification_dir/../Cargo.toml" --no-default-features \
	--test probe_extent native_block_sizes::native_probe_matches_all_admitted_block_sizes \
	-- --exact --show-output --test-threads=1 > "$scratch/probes.log" 2>&1 || status=$?
cat "$scratch/probes.log"
test "$status" -eq 0
python3 -B "$verification_dir/native_size_matrix.py" "$scratch/probes.log"
printf 'APFS native bootstrap matrix completed\n'
