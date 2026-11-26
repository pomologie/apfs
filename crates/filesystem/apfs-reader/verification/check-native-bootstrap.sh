#!/usr/bin/env bash
set -euo pipefail

verification_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
toolchain=1.99.1
toolchain_bin=$(dirname -- "$(rustup which --toolchain "$toolchain" rustc)")
export PATH="$toolchain_bin:$PATH"
rustc --version
python3 -B "$verification_dir/native_bootstrap_fixture.py"
cargo test --locked --manifest-path "$verification_dir/../Cargo.toml" \
	--no-default-features --test view bootstrap:: -- --nocapture --test-threads=1
printf 'APFS native bootstrap replay completed\n'
