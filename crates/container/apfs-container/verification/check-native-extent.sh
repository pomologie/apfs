#!/usr/bin/env bash
set -euo pipefail

verification_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
toolchain=1.99.1
toolchain_bin=$(dirname -- "$(rustup which --toolchain "$toolchain" rustc)")
export PATH="$toolchain_bin:$PATH"
rustc --version
python3 -B "$verification_dir/native_extent_fixture.py"
cargo test --locked --manifest-path "$verification_dir/../Cargo.toml" --no-default-features \
	--test probe_extent probes_a_second_apple_geometry_from_its_native_block_zero \
	-- --exact --nocapture --test-threads=1
printf 'APFS native extent replay completed\n'
