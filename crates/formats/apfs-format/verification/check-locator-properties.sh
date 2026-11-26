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
	--test locator_properties generated_nxsb_locators_match_the_independent_wide_model \
	-- --exact --nocapture --test-threads=1
printf 'APFS locator properties completed\n'
