#!/usr/bin/env bash
set -euo pipefail

verification_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
case "$#:${1:-}" in
	0:|1:--size-matrix) toolchain=1.99.1 ;;
	1:--asan) toolchain=nightly-2026-11-04 ;;
	*) printf 'usage: %s [--asan|--size-matrix]\n' "$0" >&2; exit 2 ;;
esac
toolchain_bin=$(dirname -- "$(rustup which --toolchain "$toolchain" rustc)")
export PATH="$toolchain_bin:$PATH"
rustc --version
test_args=(test)
if [[ ${1:-} == --asan ]]; then
	target=$(rustc --print host-tuple)
	test_args+=(--target "$target")
	if [[ -z ${CARGO_TARGET_DIR:-} ]]; then
		scratch=$(mktemp -d "${TMPDIR:-/tmp}/apfs-native-windows.XXXXXXXX")
		trap 'rm -rf -- "$scratch"' EXIT
		export CARGO_TARGET_DIR="$scratch/target"
	fi
	# Apply instrumentation to target code while leaving build scripts and host dependencies alone.
	export CARGO_ENCODED_RUSTFLAGS=-Zsanitizer=address
	export ASAN_OPTIONS=halt_on_error=1:abort_on_error=1
	printf 'APFS native windows AddressSanitizer %s %s\n' "$toolchain" "$target"
fi
test_name=checks_aligned_native_prefixes_against_wire_model
harness_args=(--exact --nocapture --test-threads=1)
if [[ ${1:-} == --size-matrix ]]; then
	test_name=checks_every_prefix_of_retained_native_block_sizes
	harness_args+=(--ignored)
	export APFS_NATIVE_WINDOW_FIXTURES="$verification_dir/../../../container/apfs-container/tests/fixtures/native-bootstrap-sizes"
	python3 -B - "$verification_dir" <<'PYTHON'
from hashlib import sha256
import json
import sys

sys.path.insert(0, sys.argv[1])
from native_geometry_oracle import MATRIX_FIXTURES, native_size_matrix_rows

ledger = (MATRIX_FIXTURES / "acquisition.json").read_text(encoding="utf-8")
for _ in native_size_matrix_rows(json.loads(ledger)):
    pass
print("APFS native window matrix ledger", sha256(ledger.encode("utf-8")).hexdigest())
PYTHON
fi
cargo "${test_args[@]}" --locked --manifest-path "$verification_dir/../Cargo.toml" --no-default-features \
	--test checksum "$test_name" -- "${harness_args[@]}"
printf 'APFS native windows completed\n'
