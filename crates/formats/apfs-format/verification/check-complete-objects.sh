#!/usr/bin/env bash
set -euo pipefail

verification_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
manifest="$verification_dir/../Cargo.toml"
toolchain=1.99.1
toolchain_bin=$(dirname -- "$(rustup which --toolchain "$toolchain" rustc)")
export PATH="$toolchain_bin:$PATH"
rustc --version
cargo tree --locked --manifest-path "$manifest" --no-default-features --edges dev --depth 1 --prefix none
cargo test --locked --manifest-path "$manifest" --no-default-features \
	--test locator_properties generated_complete_nxsb_objects_match_widened_checksums_and_ranges \
	-- --exact --nocapture --test-threads=1
printf 'APFS complete object properties completed\n'
