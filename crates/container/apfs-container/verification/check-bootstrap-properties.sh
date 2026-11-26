#!/usr/bin/env bash
set -euo pipefail

verification_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
toolchain=1.99.1
toolchain_bin=$(dirname -- "$(rustup which --toolchain "$toolchain" rustc)")
export PATH="$toolchain_bin:$PATH"
rustc --version
cargo test --locked --manifest-path "$verification_dir/../Cargo.toml" \
	--no-default-features --test bootstrap_properties -- --nocapture --test-threads=1
cargo test --locked --manifest-path "$verification_dir/../Cargo.toml" \
	--no-default-features --lib checkpoint::tests::required_feature_sets_match_typed_admission \
	-- --exact --nocapture --test-threads=1
printf 'APFS bootstrap properties completed\n'
