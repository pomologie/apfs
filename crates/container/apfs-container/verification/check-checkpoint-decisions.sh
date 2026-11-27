#!/usr/bin/env bash
set -euo pipefail

verification_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
toolchain=1.99.1
toolchain_bin=$(dirname -- "$(rustup which --toolchain "$toolchain" rustc)")
export PATH="$toolchain_bin:$PATH"
rustc --version
cargo test --locked --manifest-path "$verification_dir/../Cargo.toml" --no-default-features \
	--lib checkpoint::decision_tests::typed_checkpoint_decisions_match_a_decisive_xid_model \
	-- --exact --nocapture --test-threads=1
printf 'APFS checkpoint decisions completed\n'
