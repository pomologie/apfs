#!/usr/bin/env bash
set -euo pipefail

verification_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
case "$#:${1:-}" in
	0:) toolchain=1.99.1 ;;
	1:--asan) toolchain=nightly-2026-11-04 ;;
	*) printf 'usage: %s [--asan]\n' "$0" >&2; exit 2 ;;
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
cargo "${test_args[@]}" --locked --manifest-path "$verification_dir/../Cargo.toml" --no-default-features \
	--test checksum checks_aligned_native_prefixes_against_wire_model -- --exact --nocapture --test-threads=1
printf 'APFS native windows completed\n'
